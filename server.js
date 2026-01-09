require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { BlobServiceClient } = require('@azure/storage-blob');
const { getConnection, sql } = require('./db');

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, '.')));

// --- AZURE BLOB SETUP (For KML & Attachments) ---
// If variable is missing, app will start but Maps won't work
const AZURE_CONN_STR = process.env.AZURE_STORAGE_CONNECTION_STRING;
let containerClient, kmlContainerClient;

if (AZURE_CONN_STR) {
    try {
        const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN_STR);
        containerClient = blobServiceClient.getContainerClient("permit-attachments");
        kmlContainerClient = blobServiceClient.getContainerClient("map-layers");
        // Create containers if they don't exist
        (async () => {
            await containerClient.createIfNotExists();
            await kmlContainerClient.createIfNotExists({ access: 'blob' }); // Public for Google Maps
        })();
    } catch (err) { console.error("Blob Storage Error:", err.message); }
}

const upload = multer({ storage: multer.memoryStorage() });

// --- UTILS ---
function getNowIST() { return new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }); }

// --- API ROUTES ---

// 1. LOGIN (FIXED: Checks Email column now)
app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        // req.body.name contains the EMAIL from the dropdown value
        const result = await pool.request()
            .input('role', sql.NVarChar, req.body.role)
            .input('email', sql.NVarChar, req.body.name) 
            .input('pass', sql.NVarChar, req.body.password)
            .query('SELECT * FROM Users WHERE Role = @role AND Email = @email AND Password = @pass');
        
        if (result.recordset.length > 0) {
            res.json({ success: true, user: result.recordset[0] });
        } else {
            res.json({ success: false, message: "Invalid Credentials" });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. GET USERS
app.get('/api/users', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query('SELECT Name, Role, Email FROM Users');
        res.json({
            Requesters: result.recordset.filter(u => u.Role === 'Requester').map(u => ({ name: u.Name, email: u.Email })),
            Reviewers: result.recordset.filter(u => u.Role === 'Reviewer').map(u => ({ name: u.Name, email: u.Email })),
            Approvers: result.recordset.filter(u => u.Role === 'Approver').map(u => ({ name: u.Name, email: u.Email }))
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. DASHBOARD (Mimics GAS Logic)
app.post('/api/dashboard', async (req, res) => {
    try {
        const { role, email } = req.body;
        const pool = await getConnection();
        const result = await pool.request().query('SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON FROM Permits');
        
        const permits = result.recordset.map(p => {
            const d = JSON.parse(p.FullDataJSON || "{}");
            return { ...d, PermitID: p.PermitID, Status: p.Status, ValidFrom: p.ValidFrom, ValidTo: p.ValidTo };
        });

        const filtered = permits.filter(p => {
            const st = (p.Status || "").toLowerCase();
            if (role === 'Requester') return p.RequesterEmail === email;
            if (role === 'Reviewer') return (p.ReviewerEmail === email && (st.includes('pending review') || st.includes('closure') || st === 'closed' || st.includes('renewal')));
            if (role === 'Approver') return (p.ApproverEmail === email && (st.includes('pending approval') || st === 'active' || st === 'closed'));
            return false;
        });
        
        res.json(filtered.sort((a, b) => b.PermitID.localeCompare(a.PermitID)));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. SAVE PERMIT
app.post('/api/save-permit', upload.single('file'), async (req, res) => {
    try {
        const pool = await getConnection();
        // Generate ID
        const idRes = await pool.request().query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
        const lastId = idRes.recordset.length > 0 ? idRes.recordset[0].PermitID : "WP-1000";
        const newId = `WP-${parseInt(lastId.split('-')[1]) + 1}`;

        const fullData = { ...req.body, PermitID: newId };
        
        await pool.request()
            .input('pid', sql.NVarChar, newId)
            .input('status', sql.NVarChar, 'Pending Review')
            .input('wt', sql.NVarChar, req.body.WorkType)
            .input('req', sql.NVarChar, req.body.RequesterEmail)
            .input('rev', sql.NVarChar, req.body.ReviewerEmail)
            .input('app', sql.NVarChar, req.body.ApproverEmail)
            .input('vf', sql.DateTime, new Date(req.body.ValidFrom))
            .input('vt', sql.DateTime, new Date(req.body.ValidTo))
            .input('lat', sql.NVarChar, req.body.Latitude || null)
            .input('lng', sql.NVarChar, req.body.Longitude || null)
            .input('json', sql.NVarChar, JSON.stringify(fullData))
            .query(`INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, RenewalsJSON, FullDataJSON) 
                    VALUES (@pid, @status, @wt, @req, @rev, @app, @vf, @vt, @lat, @lng, '[]', @json)`);

        res.json({ success: true, permitId: newId });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. UPDATE STATUS (Review/Approve/Closure/Reject)
app.post('/api/update-status', async (req, res) => {
    try {
        const { PermitID, action, role, user, comment, ...extras } = req.body;
        const pool = await getConnection();
        
        const current = await pool.request().input('pid', sql.NVarChar, PermitID).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if(current.recordset.length === 0) return res.json({ error: "Not found" });
        
        let p = current.recordset[0];
        let data = JSON.parse(p.FullDataJSON);
        let status = p.Status;
        const now = getNowIST();
        const sig = `${user} on ${now}`;

        if (role === 'Reviewer') {
            if (action === 'reject') { status = 'Rejected'; data.Reviewer_Remarks = (data.Reviewer_Remarks||"") + `\n[Rejected by ${user}: ${comment}]`; }
            else if (action === 'review') { status = 'Pending Approval'; data.Reviewer_Sig = sig; data.Reviewer_Remarks = comment; Object.assign(data, extras); }
            else if (action === 'approve' && status.includes('Closure')) { status = 'Closure Pending Approval'; data.Reviewer_Remarks = (data.Reviewer_Remarks||"") + `\n[Closure Verified by ${user} on ${now}]`; }
        }
        else if (role === 'Approver') {
            if (action === 'reject') { status = 'Rejected'; data.Approver_Remarks = (data.Approver_Remarks||"") + `\n[Rejected by ${user}: ${comment}]`; }
            else if (action === 'approve' && status === 'Pending Approval') { status = 'Active'; data.Approver_Sig = sig; data.Approver_Remarks = comment; Object.assign(data, extras); }
            else if (action === 'approve' && status.includes('Closure')) { status = 'Closed'; data.Closure_Issuer_Sig = sig; data.Closure_Issuer_Remarks = comment; }
        }
        else if (role === 'Requester' && action === 'initiate_closure') {
            status = 'Closure Pending Review'; data.Closure_Receiver_Sig = sig;
        }

        await pool.request().input('pid', sql.NVarChar, PermitID).input('status', sql.NVarChar, status).input('json', sql.NVarChar, JSON.stringify(data))
            .query("UPDATE Permits SET Status = @status, FullDataJSON = @json WHERE PermitID = @pid");

        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 6. PERMIT DATA
app.post('/api/permit-data', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('pid', sql.NVarChar, req.body.permitId).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if (result.recordset.length === 0) return res.json({ error: "Not found" });
        const p = result.recordset[0];
        res.json({ ...JSON.parse(p.FullDataJSON), PermitID: p.PermitID, Status: p.Status, RenewalsJSON: p.RenewalsJSON, Latitude: p.Latitude, Longitude: p.Longitude });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 7. RENEWALS (Strict GAS Logic)
app.post('/api/renewal', async (req, res) => {
    try {
        const { PermitID, userRole, userName, action, ...data } = req.body;
        const pool = await getConnection();
        const current = await pool.request().input('pid', sql.NVarChar, PermitID).query("SELECT RenewalsJSON, Status, ValidFrom, ValidTo FROM Permits WHERE PermitID = @pid");
        
        let renewals = JSON.parse(current.recordset[0].RenewalsJSON || "[]");
        let status = current.recordset[0].Status;
        const now = getNowIST();

        if (userRole === 'Requester') {
             // Basic Check (Strict checks are also in frontend)
             renewals.push({ status: 'pending_review', valid_from: data.RenewalValidFrom, valid_till: data.RenewalValidTill, hc: data.RenewalHC, toxic: data.RenewalToxic, oxygen: data.RenewalOxygen, precautions: data.RenewalPrecautions, req_sig: `${userName} on ${now}` });
             status = "Renewal Pending Review";
        } 
        else if (userRole === 'Reviewer') {
            const last = renewals[renewals.length - 1];
            if (action === 'reject') { last.status = 'rejected'; last.rev_sig = `${userName} (Rejected)`; status = 'Active'; }
            else { 
                last.status = 'pending_approval'; last.rev_sig = `${userName} on ${now}`; 
                Object.assign(last, { valid_from: data.RenewalValidFrom, valid_till: data.RenewalValidTill, hc: data.RenewalHC, toxic: data.RenewalToxic, oxygen: data.RenewalOxygen, precautions: data.RenewalPrecautions });
                status = "Renewal Pending Approval"; 
            }
        }
        else if (userRole === 'Approver') {
            const last = renewals[renewals.length - 1];
            if (action === 'reject') { last.status = 'rejected'; last.app_sig = `${userName} (Rejected)`; status = 'Active'; }
            else { last.status = 'approved'; last.app_sig = `${userName} on ${now}`; status = "Active"; }
        }

        await pool.request().input('pid', sql.NVarChar, PermitID).input('status', sql.NVarChar, status).input('ren', sql.NVarChar, JSON.stringify(renewals))
            .query("UPDATE Permits SET Status = @status, RenewalsJSON = @ren WHERE PermitID = @pid");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 8. MAP DATA
app.post('/api/map-data', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status = 'Active' AND Latitude IS NOT NULL");
        const mapPoints = result.recordset.map(row => {
            const d = JSON.parse(row.FullDataJSON);
            return { PermitID: row.PermitID, lat: parseFloat(row.Latitude), lng: parseFloat(row.Longitude), WorkType: d.WorkType, Desc: d.Desc, RequesterName: d.RequesterName, ValidFrom: d.ValidFrom, ValidTo: d.ValidTo };
        });
        res.json(mapPoints);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 9. KML LAYERS
app.get('/api/kml', async (req, res) => {
    if(!kmlContainerClient) return res.json([]);
    try {
        let blobs = [];
        for await (const blob of kmlContainerClient.listBlobsFlat()) {
            blobs.push({ name: blob.name, url: kmlContainerClient.getBlockBlobClient(blob.name).url });
        }
        res.json(blobs);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/kml', upload.single('file'), async (req, res) => {
    if(!kmlContainerClient) return res.status(500).json({error: "Storage not configured"});
    try {
        if (!req.file) return res.status(400).json({ error: "No file" });
        const blobName = `${Date.now()}-${req.file.originalname}`;
        const blockBlobClient = kmlContainerClient.getBlockBlobClient(blobName);
        await blockBlobClient.uploadData(req.file.buffer, { blobHTTPHeaders: { blobContentType: "application/vnd.google-earth.kml+xml" } });
        res.json({ success: true, url: blockBlobClient.url });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/kml/:name', async (req, res) => {
    if(!kmlContainerClient) return res.status(500).json({error: "Storage not configured"});
    try {
        await kmlContainerClient.getBlockBlobClient(req.params.name).delete();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 10. REPORT & STATS
app.post('/api/report', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT * FROM Permits");
        const report = result.recordset.map(r => {
            const d = JSON.parse(r.FullDataJSON);
            return [r.PermitID, d.Desc, r.ValidFrom, r.ValidTo, d.RequesterName, d.Vendor, d.LocationUnit, d.ExactLocation, r.Status];
        });
        report.unshift(["Permit ID", "Work Details", "Valid From", "Valid To", "Requester Name", "Vendor", "Location Unit", "Exact Location", "Status"]);
        res.json({ success: true, data: report });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stats', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT Status FROM Permits");
        const stats = { total: 0, counts: {} };
        result.recordset.forEach(r => { stats.total++; stats.counts[r.Status] = (stats.counts[r.Status] || 0) + 1; });
        res.json({ success: true, stats });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`✅ SYSTEM LIVE ON PORT ${PORT}`));
