require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const PDFDocument = require('pdfkit'); 
const ExcelJS = require('exceljs'); 
const { BlobServiceClient } = require('@azure/storage-blob');
const { getConnection, sql } = require('./db');

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, '.')));

// --- AZURE STORAGE SETUP ---
const AZURE_CONN_STR = process.env.AZURE_STORAGE_CONNECTION_STRING;
let containerClient, kmlContainerClient;

if (AZURE_CONN_STR) {
    try {
        const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN_STR);
        containerClient = blobServiceClient.getContainerClient("permit-attachments");
        kmlContainerClient = blobServiceClient.getContainerClient("map-layers");
        (async () => {
            try { await containerClient.createIfNotExists(); } catch(e) {}
            try { await kmlContainerClient.createIfNotExists({ access: 'blob' }); } catch(e) {}
        })();
    } catch (err) { 
        console.error("Blob Storage Error:", err.message); 
    }
}

const upload = multer({ storage: multer.memoryStorage() });

// --- HELPER FUNCTIONS ---
function getNowIST() { 
    return new Date().toLocaleString("en-GB", { 
        timeZone: "Asia/Kolkata", 
        day: '2-digit', month: '2-digit', year: 'numeric', 
        hour: '2-digit', minute: '2-digit', hour12: false 
    }).replace(',', ''); 
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr; 
    return d.toLocaleString("en-GB", { 
        day: '2-digit', month: '2-digit', year: 'numeric', 
        hour: '2-digit', minute: '2-digit', hour12: false 
    }).replace(',', '');
}

// --- CHECKLIST DATA (EXACT OISD-105 TEXT) ---
// Note: This must match the Frontend exactly for ID mapping
const CHECKLIST_DATA = {
    A: [
        "1. Equipment / Work Area inspected.",
        "2. Surrounding area checked, cleaned and covered. Oil/RAGS/Grass Etc removed.",
        "3. Manholes, Sewers, CBD etc. and hot nearby surface covered.",
        "4. Considered hazards from other routine, non-routine operations and concerned person alerted.",
        "5. Equipment blinded/ disconnected/ closed/ isolated/ wedge opened.",
        "6. Equipment properly drained and depressurized.",
        "7. Equipment properly steamed/purged.",
        "8. Equipment water flushed.",
        "9. Access for Free approach of Fire Tender.",
        "10. Iron Sulfide removed/ Kept wet.",
        "11. Equipment electrically isolated and tagged vide Permit no.",
        "12. Gas Test: HC / Toxic / O2 checked.",
        "13. Running water hose / Fire extinguisher provided. Fire water system available.",
        "14. Area cordoned off and Precautionary tag/Board provided.",
        "15. CCTV monitoring facility available at site.",
        "16. Proper ventilation and Lighting provided."
    ],
    B: [
        "1. Proper means of exit / escape provided.",
        "2. Standby personnel provided from Mainline/ Maint. / Contractor/HSE.",
        "3. Checked for oil and Gas trapped behind the lining in equipment.",
        "4. Shield provided against spark.",
        "5. Portable equipment / nozzle properly grounded.",
        "6. Standby persons provided for entry to confined space.",
        "7. Adequate Communication Provided to Stand by Person.",
        "8. Attendant Trained Provided With Rescue Equipment/SCBA.",
        "9. Space Adequately Cooled for Safe Entry Of Person.",
        "10. Continuous Inert Gas Flow Arranged.",
        "11. Check For Earthing/ELCB of all Temporary Electrical Connections being used for welding.",
        "12. Gas Cylinders are kept outside the confined Space.",
        "13. Spark arrestor Checked on mobile Equipments.",
        "14. Welding Machine Checked for Safe Location.",
        "15. Permit taken for working at height Vide Permit No."
    ],
    C: [
        "1. PESO approved spark elimination system provided on the mobile equipment/ vehicle provided."
    ],
    D: [
        "1. For excavated trench/ pit proper slop/ shoring/ shuttering provided to prevent soil collapse.",
        "2. Excavated soil kept at safe distance from trench/pit edge (min. pit depth).",
        "3. Safe means of access provided inside trench/pit.",
        "4. Movement of heavy vehicle prohibited."
    ]
};

// --- PDF DRAWING FUNCTIONS ---
function drawHeader(doc) {
    const startX = 30; const startY = 30; const fullW = 535;
    doc.lineWidth(1);

    // Main Box
    doc.rect(startX, startY, fullW, 95).stroke();
    
    // Logo Area (Left)
    doc.rect(startX, startY, 80, 95).stroke();
    // doc.image('iocl_logo.png', startX + 15, startY + 25, {width: 50}); 

    // Title Area (Center)
    doc.rect(startX + 80, startY, 320, 95).stroke();
    doc.font('Helvetica-Bold').fontSize(12).text('INDIAN OIL CORPORATION LIMITED', startX + 80, startY + 15, {width: 320, align: 'center'});
    doc.fontSize(10).text('EASTERN REGION PIPELINES', startX + 80, startY + 30, {width: 320, align: 'center'});
    doc.text('HSE DEPT.', startX + 80, startY + 45, {width: 320, align: 'center'});
    doc.fontSize(9).text('COMPOSITE WORK PERMIT (OISD-105)', startX + 80, startY + 65, {width: 320, align: 'center'});

    // Doc Control Area (Right)
    const rightX = startX + 400;
    doc.rect(rightX, startY, 135, 95).stroke();
    // doc.image('rhino_logo.png', rightX + 40, startY + 5, {width: 50}); 
    doc.fontSize(8).font('Helvetica');
    doc.text('Doc No: ERPL/HS&E/25-26', rightX + 5, startY + 60);
    doc.text('Issue No: 01', rightX + 5, startY + 70);
    doc.text('Date: 01.09.2025', rightX + 5, startY + 80);
}

// --- API ROUTES ---

// 1. LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        // Case-insensitive mapping attempt in query or JS
        const result = await pool.request()
            .input('role', sql.NVarChar, req.body.role)
            .input('email', sql.NVarChar, req.body.name) 
            .input('pass', sql.NVarChar, req.body.password)
            .query('SELECT * FROM Users WHERE Role = @role AND Email = @email AND Password = @pass');
        
        if (result.recordset.length > 0) {
            const u = result.recordset[0];
            // Normalize casing
            const safeUser = {
                Name: u.Name || u.name || u.NAME,
                Email: u.Email || u.email || u.EMAIL,
                Role: u.Role || u.role || u.ROLE
            };
            res.json({ success: true, user: safeUser });
        } else {
            res.json({ success: false, message: "Invalid Credentials" });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. GET USERS
app.get('/api/users', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().query('SELECT Name, Role, Email FROM Users');
        
        const mapU = (u) => ({
            name: u.Name || u.name || u.NAME,
            email: u.Email || u.email || u.EMAIL,
            role: u.Role || u.role || u.ROLE
        });

        const users = r.recordset.map(mapU);

        res.json({
            Requesters: users.filter(u => u.role === 'Requester'),
            Reviewers: users.filter(u => u.role === 'Reviewer'),
            Approvers: users.filter(u => u.role === 'Approver')
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. ADD USER
app.post('/api/add-user', async (req, res) => {
    try {
        const { name, email, role, password } = req.body;
        if (!name || !email || !role || !password) return res.status(400).json({ error: "All fields required" });
        const pool = await getConnection();
        const check = await pool.request().input('e', sql.NVarChar, email).query("SELECT * FROM Users WHERE Email = @e");
        if(check.recordset.length > 0) return res.status(400).json({ error: "User already exists." });
        await pool.request().input('n', sql.NVarChar, name).input('e', sql.NVarChar, email).input('r', sql.NVarChar, role).input('p', sql.NVarChar, password)
            .query("INSERT INTO Users (Name, Email, Role, Password) VALUES (@n, @e, @r, @p)");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. DASHBOARD
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
            if (role === 'Approver') return (p.ApproverEmail === email || st === 'active' || st === 'closed' || st.includes('renewal') || st.includes('closure'));
            return false;
        });
        res.json(filtered.sort((a, b) => b.PermitID.localeCompare(a.PermitID)));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. SAVE PERMIT (STRICT UPDATE LOGIC)
app.post('/api/save-permit', upload.single('file'), async (req, res) => {
    try {
        const vf = new Date(req.body.ValidFrom);
        const vt = new Date(req.body.ValidTo);
        if (vt <= vf) return res.status(400).json({ error: "End time must be greater than Start time." });
        const diffDays = Math.ceil(Math.abs(vt - vf) / (1000 * 60 * 60 * 24)); 
        if (diffDays > 7) return res.status(400).json({ error: "Permit duration cannot exceed 7 days." });

        const pool = await getConnection();
        let rawId = req.body.PermitID;
        // Sanitize
        if (!rawId || rawId === 'undefined' || rawId === 'null' || rawId.trim() === '') rawId = null;

        let permitId = rawId;
        let isUpdate = false;

        // Check if ID exists (Separate Request)
        if (permitId) {
            const checkReq = pool.request(); 
            const check = await checkReq.input('pid', sql.NVarChar, String(permitId)).query("SELECT Status FROM Permits WHERE PermitID = @pid");
            
            if (check.recordset.length > 0) {
                const currentStatus = check.recordset[0].Status;
                if (currentStatus === 'Pending Review' || currentStatus === 'New') {
                    isUpdate = true;
                } else {
                    return res.status(400).json({ error: "Cannot edit an Active/Processed permit." });
                }
            } else {
                permitId = null; // ID passed but not found, create new
            }
        }

        // Generate ID
        if (!permitId) {
            const idReq = pool.request();
            const idRes = await idReq.query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
            const lastId = idRes.recordset.length > 0 ? idRes.recordset[0].PermitID : "WP-1000";
            permitId = `WP-${parseInt(lastId.split('-')[1]) + 1}`;
        }

        const fullData = { ...req.body, PermitID: permitId };
        
        // Execute Save (Separate Request)
        const saveReq = pool.request();
        saveReq.input('pid', sql.NVarChar, String(permitId))
               .input('status', sql.NVarChar, 'Pending Review')
               .input('wt', sql.NVarChar, req.body.WorkType)
               .input('req', sql.NVarChar, req.body.RequesterEmail)
               .input('rev', sql.NVarChar, req.body.ReviewerEmail)
               .input('app', sql.NVarChar, req.body.ApproverEmail)
               .input('vf', sql.DateTime, vf)
               .input('vt', sql.DateTime, vt)
               .input('lat', sql.NVarChar, req.body.Latitude || null)
               .input('lng', sql.NVarChar, req.body.Longitude || null)
               .input('locSno', sql.NVarChar, req.body.LocationPermitSno)
               .input('iso', sql.NVarChar, req.body.RefIsolationCert)
               .input('cross', sql.NVarChar, req.body.CrossRefPermits)
               .input('jsa', sql.NVarChar, req.body.JsaRef)
               .input('mocReq', sql.NVarChar, req.body.MocRequired)
               .input('mocRef', sql.NVarChar, req.body.MocRef)
               .input('cctv', sql.NVarChar, req.body.CctvAvailable)
               .input('cctvDet', sql.NVarChar, req.body.CctvDetail)
               .input('vendor', sql.NVarChar, req.body.Vendor)
               .input('dept', sql.NVarChar, req.body.IssuedToDept)
               .input('locUnit', sql.NVarChar, req.body.LocationUnit)
               .input('exactLoc', sql.NVarChar, req.body.ExactLocation)
               .input('desc', sql.NVarChar, req.body.Desc)
               .input('offName', sql.NVarChar, req.body.OfficialName)
               .input('json', sql.NVarChar, JSON.stringify(fullData));

        if (isUpdate) {
            await saveReq.query(`UPDATE Permits SET 
                WorkType=@wt, ReviewerEmail=@rev, ApproverEmail=@app, ValidFrom=@vf, ValidTo=@vt, 
                Latitude=@lat, Longitude=@lng, LocationPermitSno=@locSno, RefIsolationCert=@iso, 
                CrossRefPermits=@cross, JsaRef=@jsa, MocRequired=@mocReq, MocRef=@mocRef, 
                CctvAvailable=@cctv, CctvDetail=@cctvDet, Vendor=@vendor, IssuedToDept=@dept, 
                LocationUnit=@locUnit, ExactLocation=@exactLoc, [Desc]=@desc, OfficialName=@offName, 
                FullDataJSON=@json, Status='Pending Review' 
                WHERE PermitID=@pid`);
        } else {
            await saveReq.query(`INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, 
                    LocationPermitSno, RefIsolationCert, CrossRefPermits, JsaRef, MocRequired, MocRef, CctvAvailable, CctvDetail, Vendor, IssuedToDept, LocationUnit, ExactLocation, [Desc], OfficialName, RenewalsJSON, FullDataJSON) 
                    VALUES (@pid, @status, @wt, @req, @rev, @app, @vf, @vt, @lat, @lng, 
                    @locSno, @iso, @cross, @jsa, @mocReq, @mocRef, @cctv, @cctvDet, @vendor, @dept, @locUnit, @exactLoc, @desc, @offName, '[]', @json)`);
        }

        if(req.file && containerClient) {
            await containerClient.getBlockBlobClient(`${permitId}_${req.file.originalname}`).uploadData(req.file.buffer);
        }
        res.json({ success: true, permitId: permitId });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 6. UPDATE STATUS
app.post('/api/update-status', async (req, res) => {
    try {
        const { PermitID, action, role, user, comment, rejectionReason, ...extras } = req.body;
        const pool = await getConnection();
        const current = await pool.request().input('pid', sql.NVarChar, PermitID).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if(current.recordset.length === 0) return res.json({ error: "Not found" });
        
        let p = current.recordset[0];
        let data = JSON.parse(p.FullDataJSON);
        let status = p.Status;
        const now = getNowIST();
        const sig = `${user} on ${now}`;

        Object.assign(data, extras);

        if (role === 'Requester' && action === 'initiate_closure') {
            status = 'Closure Pending Review'; 
            data.Closure_Receiver_Sig = sig; 
            data.Site_Restored_Check = "Yes"; 
            data.Closure_Requestor_Remarks = req.body.Closure_Requestor_Remarks;
            data.Closure_Requestor_Date = now;
        }
        else if (role === 'Reviewer') {
            if (action === 'reject') { status = 'Rejected'; data.Reviewer_Remarks = (data.Reviewer_Remarks||"") + `\n[Rejected by ${user}: ${comment}]`; }
            else if (action === 'review') { status = 'Pending Approval'; data.Reviewer_Sig = sig; data.Reviewer_Remarks = comment; }
            else if (action === 'approve' && status.includes('Closure')) { status = 'Closure Pending Approval'; data.Closure_Reviewer_Remarks = req.body.Closure_Reviewer_Remarks; data.Closure_Reviewer_Date = now; data.Closure_Reviewer_Sig = sig; }
            else if (action === 'reject_closure') { status = 'Active'; data.Closure_Reviewer_Remarks = `[REJECTED by ${user}]: ${req.body.Closure_Reviewer_Remarks}`; data.Closure_Reviewer_Date = now; }
        }
        else if (role === 'Approver') {
            if (action === 'reject') { status = 'Rejected'; data.Approver_Remarks = (data.Approver_Remarks||"") + `\n[Rejected by ${user}: ${comment}]`; }
            else if (action === 'approve' && status === 'Pending Approval') { status = 'Active'; data.Approver_Sig = sig; data.Approver_Remarks = comment; }
            else if (action === 'approve' && status.includes('Closure')) { status = 'Closed'; data.Closure_Approver_Remarks = req.body.Closure_Approver_Remarks; data.Closure_Approver_Date = now; data.Closure_Issuer_Sig = sig; data.Closure_Issuer_Remarks = comment; }
            else if (action === 'reject_closure') { status = 'Active'; data.Closure_Approver_Remarks = `[REJECTED by ${user}]: ${req.body.Closure_Approver_Remarks}`; data.Closure_Approver_Date = now; }
        }

        let q = pool.request().input('pid', sql.NVarChar, PermitID).input('status', sql.NVarChar, status).input('json', sql.NVarChar, JSON.stringify(data));
        if(extras.WorkType) q.input('wt', sql.NVarChar, extras.WorkType).query("UPDATE Permits SET Status = @status, FullDataJSON = @json, WorkType = @wt WHERE PermitID = @pid");
        else q.query("UPDATE Permits SET Status = @status, FullDataJSON = @json WHERE PermitID = @pid");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 7. RENEWALS
app.post('/api/renewal', async (req, res) => {
    try {
        const { PermitID, userRole, userName, action, rejectionReason, ...data } = req.body;
        const pool = await getConnection();
        const current = await pool.request().input('pid', sql.NVarChar, PermitID).query("SELECT RenewalsJSON, Status, ValidFrom, ValidTo FROM Permits WHERE PermitID = @pid");
        let renewals = JSON.parse(current.recordset[0].RenewalsJSON || "[]");
        let status = current.recordset[0].Status;
        const now = getNowIST();

        if (userRole === 'Requester') {
             const reqStart = new Date(data.RenewalValidFrom);
             const reqEnd = new Date(data.RenewalValidTill);
             const permitEnd = new Date(current.recordset[0].ValidTo);

             if (reqEnd > permitEnd) return res.status(400).json({ error: "Cannot exceed original Permit Validity." });
             if ((reqEnd - reqStart) / 36e5 > 8) return res.status(400).json({ error: "Renewal cannot exceed 8 Hours." });

             renewals.push({ 
                 status: 'pending_review', valid_from: data.RenewalValidFrom, valid_till: data.RenewalValidTill, 
                 hc: data.RenewalHC, toxic: data.RenewalToxic, oxygen: data.RenewalOxygen, precautions: data.RenewalPrecautions, 
                 req_name: userName, req_at: now 
             });
             status = "Renewal Pending Review";
        } 
        else if (userRole === 'Reviewer') {
            const last = renewals[renewals.length - 1];
            if (action === 'reject') { last.status = 'rejected'; last.rev_name = userName; last.rejection_reason = rejectionReason; status = 'Active'; }
            else { last.status = 'pending_approval'; last.rev_name = userName; status = "Renewal Pending Approval"; }
        }
        else if (userRole === 'Approver') {
            const last = renewals[renewals.length - 1];
            if (action === 'reject') { last.status = 'rejected'; last.app_name = userName; last.rejection_reason = rejectionReason; status = 'Active'; }
            else { last.status = 'approved'; last.app_name = userName; status = "Active"; }
        }

        await pool.request().input('pid', sql.NVarChar, PermitID).input('status', sql.NVarChar, status).input('ren', sql.NVarChar, JSON.stringify(renewals)).query("UPDATE Permits SET Status = @status, RenewalsJSON = @ren WHERE PermitID = @pid");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 8. OISD-105 PDF GENERATOR
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('pid', sql.NVarChar, req.params.id).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if(result.recordset.length === 0) return res.status(404).send('Not Found');
        const p = result.recordset[0];
        const d = JSON.parse(p.FullDataJSON);
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`); doc.pipe(res);

        // Header Function
        const drawHeader = () => {
             const startX = 30; const startY = 30;
             doc.rect(startX, startY, 535, 95).stroke(); // Box
             doc.rect(startX, startY, 80, 95).stroke(); // Logo Area
             doc.rect(startX + 80, startY, 320, 95).stroke(); // Title Area
             doc.rect(startX + 400, startY, 135, 95).stroke(); // Doc Control
             
             doc.font('Helvetica-Bold').fontSize(12).text('INDIAN OIL CORPORATION LIMITED', startX+80, startY+15, {width:320, align:'center'});
             doc.fontSize(10).text('EASTERN REGION PIPELINES', startX+80, startY+30, {width:320, align:'center'});
             doc.text('HSE DEPT.', startX+80, startY+45, {width:320, align:'center'});
             doc.fontSize(9).text('COMPOSITE WORK PERMIT (OISD-105)', startX+80, startY+65, {width:320, align:'center'});
             
             doc.fontSize(8).font('Helvetica');
             doc.text('Doc No: ERPL/HS&E/25-26', startX+405, startY+20);
             doc.text('Date: 01.09.2025', startX+405, startY+50);
        };

        // Page 1
        drawHeader();
        doc.y = 135; 
        
        doc.fontSize(9).font('Helvetica');
        const infoY = doc.y;
        const col1 = 40, col2 = 300;
        doc.text(`Permit No: ${p.PermitID}`, col1, infoY);
        doc.text(`Valid From: ${formatDate(p.ValidFrom)} To: ${formatDate(p.ValidTo)}`, col2, infoY);
        doc.text(`Issued To: ${d.IssuedToDept} (${d.Vendor || 'Self'})`, col1, infoY + 15);
        doc.text(`Location: ${d.ExactLocation} (${d.LocationUnit})`, col2, infoY + 15);
        doc.text(`Description: ${d.Desc}`, col1, infoY + 30, {width: 500});
        doc.text(`Site Person: ${d.RequesterName}`, col1, infoY + 60);
        doc.text(`Security/Patrol: ${d.SecurityGuard || '-'}`, col2, infoY + 60);
        doc.text(`Emergency: ${d.EmergencyContact || '-'}`, col1, infoY + 75);
        doc.text(`Fire Stn/Hosp: ${d.FireStation || '-'}`, col2, infoY + 75);
        doc.rect(30, infoY - 5, 535, 95).stroke(); 
        doc.y = infoY + 100;

        // Checklists
        const drawChecklistTable = (title, items, idPrefix) => {
            if(doc.y > 650) { doc.addPage(); drawHeader(); doc.y = 135; }
            doc.font('Helvetica-Bold').fontSize(10).text(title, 30, doc.y + 10);
            doc.y += 25;
            let y = doc.y;
            doc.rect(30, y, 30, 20).stroke().text("SN", 35, y+5);
            doc.rect(60, y, 350, 20).stroke().text("Item / Condition", 65, y+5);
            doc.rect(410, y, 60, 20).stroke().text("Status", 415, y+5);
            doc.rect(470, y, 95, 20).stroke().text("Remarks", 475, y+5);
            y += 20;

            doc.font('Helvetica').fontSize(8);
            items.forEach((itemText, i) => {
                if(y > 750) { doc.addPage(); drawHeader(); doc.y = 135; y = 135; }
                const qId = `${idPrefix}_Q${i+1}`;
                const status = d[qId] === 'Yes' ? 'YES' : (d[qId] === 'NA' ? 'NA' : 'NO');
                let remarks = d[`${idPrefix}_Q${i+1}_Detail`] || '';
                if(idPrefix === 'A' && i === 11) remarks = `HC:${d.GP_Q12_HC||0}% Tox:${d.GP_Q12_ToxicGas||0} O2:${d.GP_Q12_Oxygen||21}%`;

                doc.rect(30, y, 30, 25).stroke().text(i+1, 35, y+8);
                doc.rect(60, y, 350, 25).stroke().text(itemText, 65, y+8, {width: 340});
                doc.rect(410, y, 60, 25).stroke().text(status, 415, y+8);
                doc.rect(470, y, 95, 25).stroke().text(remarks, 475, y+8);
                y += 25;
            });
            doc.y = y;
        };

        drawChecklistTable("SECTION A: GENERAL POINTS", CHECKLIST_DATA.A, 'A');
        drawChecklistTable("SECTION B: HOT WORK / CONFINED SPACE", CHECKLIST_DATA.B, 'B');
        drawChecklistTable("SECTION C: VEHICLE ENTRY", CHECKLIST_DATA.C, 'C');
        drawChecklistTable("SECTION D: EXCAVATION WORK", CHECKLIST_DATA.D, 'D');

        // Hazards & Signatures
        doc.addPage(); drawHeader(); doc.y = 135;
        doc.font('Helvetica-Bold').fontSize(10).text("HAZARDS & PRECAUTIONS", 30, doc.y);
        doc.y += 15;
        doc.rect(30, doc.y, 535, 60).stroke();
        doc.fontSize(8).font('Helvetica');
        const hazKeys = ["Lack of Oxygen", "H2S", "Toxic Gases", "Combustible gases", "Pyrophoric Iron", "Corrosive Chemicals", "cave in formation"];
        const foundHaz = hazKeys.filter(k => d[`H_${k.replace(/ /g,'')}`] === 'Y');
        if(d.H_Others==='Y') foundHaz.push(`Others: ${d.H_Others_Detail}`);
        doc.text(`Identified Hazards: ${foundHaz.join(', ') || 'None'}`, 35, doc.y + 5, {width: 525});
        const ppeKeys = ["Helmet","Safety Shoes","Hand gloves","Boiler suit","Face Shield","Apron","Goggles","Dust Respirator","Fresh Air Mask","Lifeline","Safety Harness","Airline","Earmuff"];
        const foundPPE = ppeKeys.filter(k => d[`P_${k.replace(/ /g,'')}`] === 'Y');
        doc.text(`PPE Required: ${foundPPE.join(', ') || 'Standard Only'}`, 35, doc.y + 25, {width: 525});
        doc.y += 70;

        doc.font('Helvetica-Bold').fontSize(10).text("DIGITAL SIGNATURES (ISSUANCE)", 30, doc.y);
        doc.y += 15;
        const sigY = doc.y;
        doc.rect(30, sigY, 178, 50).stroke().text(`REQUESTER\n${d.RequesterName}\n${formatDate(p.ValidFrom)}`, 35, sigY + 5);
        doc.rect(208, sigY, 178, 50).stroke().text(`SAFETY OFFICER\n${d.Reviewer_Sig||'Pending'}`, 213, sigY + 5);
        doc.rect(386, sigY, 179, 50).stroke().text(`ISSUING AUTHORITY\n${d.Approver_Sig||'Pending'}`, 391, sigY + 5);
        doc.y = sigY + 60;

        // Renewals & Closure
        doc.font('Helvetica-Bold').fontSize(10).text("RENEWALS", 30, doc.y); doc.y+=15;
        const renewals = JSON.parse(p.RenewalsJSON || "[]");
        renewals.forEach(r => {
             doc.text(`${formatDate(r.valid_from)} to ${formatDate(r.valid_till)} | Gas: ${r.hc}/${r.toxic}/${r.oxygen} | By: ${r.req_name}/${r.rev_name}/${r.app_name}`, 35, doc.y);
             doc.y += 15;
        });

        doc.moveDown();
        doc.font('Helvetica-Bold').fontSize(10).text("CLOSURE", 30, doc.y); doc.y+=15;
        doc.rect(30, doc.y, 535, 60).stroke();
        doc.text(`Receiver: ${d.Closure_Requestor_Remarks||'-'}`, 35, doc.y+5);
        doc.text(`Safety: ${d.Closure_Reviewer_Remarks||'-'}`, 35, doc.y+20);
        doc.text(`Issuer: ${d.Closure_Approver_Remarks||'-'}`, 35, doc.y+35);

        // General Instructions
        doc.addPage(); drawHeader(); doc.y=135;
        doc.font('Helvetica-Bold').fontSize(10).text("GENERAL INSTRUCTIONS", 30, doc.y); doc.y+=15;
        const instructions = ["1. Fill carefully.", "2. Determine PPE.", "3. Standby required.", "4. Communication.", "5. Control Room.", "6. Certified vehicles.", "7. Welding ventilation.", "8. Explosive meter zero.", "9. Confined space standby.", "10. No cylinders inside.", "11. Trench safety.", "12. Renewal checks.", "13. Max 7 days.", "14. Permit at site.", "15. Close on completion.", "16. Trench SOP.", "17. CCTV.", "18. PLHO guidelines."];
        instructions.forEach(i => { doc.text(i, 30, doc.y); doc.y+=12; });

        doc.end();
    } catch (e) { res.status(500).send(e.message); }
});

// OTHER ROUTES (STATS, EXCEL, MAP)
app.post('/api/permit-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().input('p', sql.NVarChar, req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p"); if(r.recordset.length) res.json({...JSON.parse(r.recordset[0].FullDataJSON), Status:r.recordset[0].Status, RenewalsJSON:r.recordset[0].RenewalsJSON}); else res.json({error:"404"}); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/map-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status='Active'"); res.json(r.recordset.map(x=>({PermitID:x.PermitID, lat:parseFloat(x.Latitude), lng:parseFloat(x.Longitude), ...JSON.parse(x.FullDataJSON)}))); } catch(e){res.status(500).json({error:e.message})} });

app.listen(8080, () => console.log('Server Ready'));
