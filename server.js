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

// --- AZURE BLOB SETUP ---
const AZURE_CONN_STR = process.env.AZURE_STORAGE_CONNECTION_STRING;
let containerClient, kmlContainerClient;

if (AZURE_CONN_STR) {
    try {
        const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN_STR);
        containerClient = blobServiceClient.getContainerClient("permit-attachments");
        kmlContainerClient = blobServiceClient.getContainerClient("map-layers");
        (async () => {
            try { await containerClient.createIfNotExists(); } catch(e){}
            try { await kmlContainerClient.createIfNotExists({ access: 'blob' }); } catch(e){}
        })();
    } catch (err) { console.error("Blob Storage Error:", err.message); }
}

const upload = multer({ storage: multer.memoryStorage() });

function getNowIST() { return new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }); }

// --- API ROUTES ---

// 1. LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request()
            .input('role', sql.NVarChar, req.body.role)
            .input('email', sql.NVarChar, req.body.name) 
            .input('pass', sql.NVarChar, req.body.password)
            .query('SELECT * FROM Users WHERE Role = @role AND Email = @email AND Password = @pass');
        
        if (result.recordset.length > 0) res.json({ success: true, user: result.recordset[0] });
        else res.json({ success: false, message: "Invalid Credentials" });
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

// 3. DASHBOARD
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
            if (role === 'Approver') return (p.ApproverEmail === email && (st.includes('pending approval') || st === 'active' || st === 'closed' || st.includes('renewal') || st.includes('closure')));
            return false;
        });
        
        res.json(filtered.sort((a, b) => b.PermitID.localeCompare(a.PermitID)));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. SAVE PERMIT
app.post('/api/save-permit', upload.single('file'), async (req, res) => {
    try {
        const vf = new Date(req.body.ValidFrom);
        const vt = new Date(req.body.ValidTo);

        if (vt <= vf) return res.status(400).json({ error: "End time must be greater than Start time." });
        
        const diffTime = Math.abs(vt - vf);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
        if (diffDays > 7) return res.status(400).json({ error: "Permit duration cannot exceed 7 days." });

        const pool = await getConnection();
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
            .input('json', sql.NVarChar, JSON.stringify(fullData))
            .query(`INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, 
                    LocationPermitSno, RefIsolationCert, CrossRefPermits, JsaRef, MocRequired, MocRef, CctvAvailable, CctvDetail, Vendor, IssuedToDept, LocationUnit, ExactLocation, [Desc], OfficialName, RenewalsJSON, FullDataJSON) 
                    VALUES (@pid, @status, @wt, @req, @rev, @app, @vf, @vt, @lat, @lng, 
                    @locSno, @iso, @cross, @jsa, @mocReq, @mocRef, @cctv, @cctvDet, @vendor, @dept, @locUnit, @exactLoc, @desc, @offName, '[]', @json)`);

        res.json({ success: true, permitId: newId });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. UPDATE STATUS
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

        Object.assign(data, extras);

        if (role === 'Reviewer') {
            if (action === 'reject') { status = 'Rejected'; data.Reviewer_Remarks = (data.Reviewer_Remarks||"") + `\n[Rejected by ${user}: ${comment}]`; }
            else if (action === 'review') { status = 'Pending Approval'; data.Reviewer_Sig = sig; data.Reviewer_Remarks = comment; }
            else if (action === 'approve' && status.includes('Closure')) { status = 'Closure Pending Approval'; data.Reviewer_Remarks = (data.Reviewer_Remarks||"") + `\n[Closure Verified by ${user} on ${now}]`; }
        }
        else if (role === 'Approver') {
            if (action === 'reject') { status = 'Rejected'; data.Approver_Remarks = (data.Approver_Remarks||"") + `\n[Rejected by ${user}: ${comment}]`; }
            else if (action === 'approve' && status === 'Pending Approval') { status = 'Active'; data.Approver_Sig = sig; data.Approver_Remarks = comment; }
            else if (action === 'approve' && status.includes('Closure')) { status = 'Closed'; data.Closure_Issuer_Sig = sig; data.Closure_Issuer_Remarks = comment; }
        }
        else if (role === 'Requester' && action === 'initiate_closure') {
            status = 'Closure Pending Review'; data.Closure_Receiver_Sig = sig;
        }

        let q = pool.request()
            .input('pid', sql.NVarChar, PermitID)
            .input('status', sql.NVarChar, status)
            .input('json', sql.NVarChar, JSON.stringify(data));
            
        if(extras.WorkType) {
             q.input('wt', sql.NVarChar, extras.WorkType)
              .query("UPDATE Permits SET Status = @status, FullDataJSON = @json, WorkType = @wt WHERE PermitID = @pid");
        } else {
             q.query("UPDATE Permits SET Status = @status, FullDataJSON = @json WHERE PermitID = @pid");
        }

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

// 7. RENEWALS (With 8-Hour Logic & History)
app.post('/api/renewal', async (req, res) => {
    try {
        const { PermitID, userRole, userName, action, ...data } = req.body;
        const pool = await getConnection();
        const current = await pool.request().input('pid', sql.NVarChar, PermitID).query("SELECT RenewalsJSON, Status, ValidFrom, ValidTo FROM Permits WHERE PermitID = @pid");
        
        let renewals = JSON.parse(current.recordset[0].RenewalsJSON || "[]");
        let status = current.recordset[0].Status;
        const permitStart = new Date(current.recordset[0].ValidFrom);
        const permitEnd = new Date(current.recordset[0].ValidTo);
        const now = getNowIST();

        if (userRole === 'Requester') {
             const reqStart = new Date(data.RenewalValidFrom);
             const reqEnd = new Date(data.RenewalValidTill);

             // 1. Within Permit Period
             if (reqStart < permitStart || reqEnd > permitEnd) return res.status(400).json({ error: "Renewal must be within original Permit Validity." });
             
             // 2. Start < End
             if (reqStart >= reqEnd) return res.status(400).json({ error: "Invalid Time Range." });

             // 3. Max 8 Hours
             const duration = (reqEnd - reqStart) / (1000 * 60 * 60);
             if (duration > 8) return res.status(400).json({ error: "Renewal cannot exceed 8 Hours." });

             // 4. Sequential
             if (renewals.length > 0) {
                 const lastRen = renewals[renewals.length - 1];
                 // Allow new renewal only if previous one is approved/rejected/completed
                 const lastEnd = new Date(lastRen.valid_till);
                 if (reqStart < lastEnd) return res.status(400).json({ error: "Renewal must start after the previous renewal ends." });
             }

             renewals.push({ 
                 status: 'pending_review', 
                 valid_from: data.RenewalValidFrom, 
                 valid_till: data.RenewalValidTill, 
                 hc: data.RenewalHC, 
                 toxic: data.RenewalToxic, 
                 oxygen: data.RenewalOxygen, 
                 precautions: data.RenewalPrecautions, 
                 req_name: userName,
                 req_at: now
             });
             status = "Renewal Pending Review";
        } 
        else if (userRole === 'Reviewer') {
            const last = renewals[renewals.length - 1];
            if (action === 'reject') { 
                last.status = 'rejected'; 
                last.rev_name = userName; 
                last.rev_at = now; 
                status = 'Active'; 
            } else { 
                last.status = 'pending_approval'; 
                last.rev_name = userName; 
                last.rev_at = now;
                // Update technical fields if changed by reviewer
                Object.assign(last, { 
                    valid_from: data.RenewalValidFrom, 
                    valid_till: data.RenewalValidTill, 
                    hc: data.RenewalHC, 
                    toxic: data.RenewalToxic, 
                    oxygen: data.RenewalOxygen, 
                    precautions: data.RenewalPrecautions 
                });
                status = "Renewal Pending Approval"; 
            }
        }
        else if (userRole === 'Approver') {
            const last = renewals[renewals.length - 1];
            if (action === 'reject') { 
                last.status = 'rejected'; 
                last.app_name = userName; 
                last.app_at = now; 
                status = 'Active'; 
            } else { 
                last.status = 'approved'; 
                last.app_name = userName; 
                last.app_at = now; 
                status = "Active"; 
            }
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

app.get('/api/kml', async (req, res) => { if(!kmlContainerClient) return res.json([]); let b=[]; for await(const x of kmlContainerClient.listBlobsFlat()) b.push({name:x.name,url:kmlContainerClient.getBlockBlobClient(x.name).url}); res.json(b); });
app.post('/api/kml', upload.single('file'), async (req, res) => { if(!kmlContainerClient) return; const b = kmlContainerClient.getBlockBlobClient(`${Date.now()}-${req.file.originalname}`); await b.uploadData(req.file.buffer, {blobHTTPHeaders:{blobContentType:"application/vnd.google-earth.kml+xml"}}); res.json({success:true, url:b.url}); });
app.delete('/api/kml/:name', async (req, res) => { if(!kmlContainerClient) return; await kmlContainerClient.getBlockBlobClient(req.params.name).delete(); res.json({success:true}); });

// 10. STATISTICS API
app.post('/api/stats', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT Status, WorkType FROM Permits");
        const statusCounts = {};
        const typeCounts = {};
        result.recordset.forEach(r => { statusCounts[r.Status] = (statusCounts[r.Status] || 0) + 1; typeCounts[r.WorkType] = (typeCounts[r.WorkType] || 0) + 1; });
        res.json({ success: true, statusCounts, typeCounts });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 11. EXCEL DOWNLOAD
app.get('/api/download-excel', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC");
        
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Permits Summary');

        // Headers
        worksheet.columns = [
            { header: 'Permit ID', key: 'id', width: 15 },
            { header: 'Status', key: 'status', width: 20 },
            { header: 'Work Type', key: 'wt', width: 20 },
            { header: 'Requester', key: 'req', width: 25 },
            { header: 'Department', key: 'dept', width: 20 },
            { header: 'Vendor', key: 'vendor', width: 20 },
            { header: 'Description', key: 'desc', width: 40 },
            { header: 'Location', key: 'loc', width: 30 },
            { header: 'Valid From', key: 'vf', width: 20 },
            { header: 'Valid To', key: 'vt', width: 20 }
        ];

        worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
        worksheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4F46E5' } };

        result.recordset.forEach(r => {
            const d = JSON.parse(r.FullDataJSON || "{}");
            worksheet.addRow({
                id: r.PermitID,
                status: r.Status,
                wt: d.WorkType,
                req: d.RequesterName,
                dept: d.IssuedToDept,
                vendor: d.Vendor,
                desc: d.Desc,
                loc: d.ExactLocation,
                vf: new Date(r.ValidFrom).toLocaleString(),
                vt: new Date(r.ValidTo).toLocaleString()
            });
        });

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=Permit_Summary.xlsx');
        await workbook.xlsx.write(res);
        res.end();
    } catch (e) { res.status(500).send(e.message); }
});

// 12. PDF DOWNLOAD (Format & Watermark)
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('pid', sql.NVarChar, req.params.id).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if(result.recordset.length === 0) return res.status(404).send('Not Found');
        
        const p = result.recordset[0];
        const d = JSON.parse(p.FullDataJSON);
        const doc = new PDFDocument({ margin: 30, size: 'A4' });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`);
        doc.pipe(res);

        // WATERMARK
        const addWatermark = () => {
            const watermarkText = p.Status.includes('Closed') ? 'CLOSED' : 'ACTIVE';
            const color = p.Status.includes('Closed') ? '#ef4444' : '#22c55e'; 
            doc.save();
            doc.rotate(-45, { origin: [300, 400] });
            doc.fontSize(80).fillColor(color).opacity(0.15).text(watermarkText, 100, 350, { align: 'center', width: 400 });
            doc.restore();
        };

        // --- PAGE 1 ---
        addWatermark();
        doc.font('Helvetica-Bold').fontSize(14).text('INDIAN OIL CORPORATION LIMITED', { align: 'center' });
        doc.fontSize(10).text('Pipeline Division', { align: 'center' });
        doc.text('COMPOSITE WORK PERMIT', { align: 'center', underline:true });
        doc.moveDown();

        doc.fontSize(9).font('Helvetica');
        const row = (l, r, y) => { doc.text(l, 50, y); doc.text(r, 320, y); };
        
        doc.font('Helvetica-Bold').text(`Type of Work: ${d.WorkType}`, 50, doc.y); doc.moveDown(0.5);
        row(`Permit No: ${p.PermitID}`, `Plant: Pipeline`, doc.y); doc.moveDown(0.5);
        row(`Applicant: ${d.OfficialName}`, `Dept: ${d.IssuedToDept}`, doc.y); doc.moveDown(0.5);
        doc.text(`Description: ${d.Desc}`); doc.moveDown(0.5);
        doc.text(`Exact Location: ${d.ExactLocation} (${d.LocationUnit})`); doc.moveDown(0.5);
        row(`Valid From: ${new Date(p.ValidFrom).toLocaleString()}`, `Valid To: ${new Date(p.ValidTo).toLocaleString()}`, doc.y); doc.moveDown();

        doc.rect(40, doc.y, 520, 20).fill('#eee').stroke();
        doc.fillColor('black').font('Helvetica-Bold').text('OTHER PERMIT DETAILS', 50, doc.y - 15);
        doc.moveDown(0.5);
        
        row(`Vendor: ${d.Vendor || '-'}`, `Loc Permit No: ${d.LocationPermitSno || '-'}`, doc.y); doc.moveDown(0.5);
        row(`Ref Isolation: ${d.RefIsolationCert || '-'}`, `Cross Ref: ${d.CrossRefPermits || '-'}`, doc.y); doc.moveDown(0.5);
        row(`JSA Ref: ${d.JsaRef || '-'}`, `MOC: ${d.MocRequired} (Ref: ${d.MocRef || '-'})`, doc.y); doc.moveDown(0.5);
        doc.text(`CCTV Available: ${d.CctvAvailable} | Details: ${d.CctvDetail || '-'}`);
        doc.moveDown();

        doc.font('Helvetica-Bold').text('SAFETY CHECKLIST (GENERAL POINTS)', {underline:true});
        doc.font('Helvetica').fontSize(9);
        const gpQs = [
            {id:"GP_Q1", t:"Equipment/Area Inspected"}, {id:"GP_Q2", t:"Surrounding Area Cleaned"}, {id:"GP_Q3", t:"Sewers Covered"}, 
            {id:"GP_Q4", t:"Hazards Considered"}, {id:"GP_Q5", t:"Equipment Blinded", d:"GP_Q5_Detail"}, 
            {id:"GP_Q6", t:"Drained & Depressurized"}, {id:"GP_Q7", t:"Steamed/Purged"}, {id:"GP_Q8", t:"Water Flushed"},
            {id:"GP_Q9", t:"Fire Tender Access"}, {id:"GP_Q10", t:"Iron Sulfide Removed"},
            {id:"GP_Q11", t:"Electrically Isolated", d:"GP_Q11_Detail"}, {id:"GP_Q12", t:"Gas Test (Toxic/HC/O2)"}, 
            {id:"GP_Q13", t:"Fire Extinguisher"}, {id:"GP_Q14", t:"Area Cordoned Off"}
        ];
        
        gpQs.forEach((q, i) => {
            let val = d[q.id] === 'Yes' ? '[YES]' : '[NA]';
            if(q.id === "GP_Q12") val = `Tox:${d.GP_Q12_ToxicGas||'-'} HC:${d.GP_Q12_HC||'-'} O2:${d.GP_Q12_Oxygen||'-'}`;
            doc.text(`${i+1}. ${q.t}`);
            doc.text(val, 450, doc.y - 10);
            if(q.d && d[q.d]) doc.text(`   Details: ${d[q.d]}`, {indent: 20});
        });

        // --- PAGE 2 ---
        doc.addPage();
        addWatermark();
        doc.font('Helvetica-Bold').text('SPECIFIC WORK CHECKLIST');
        doc.font('Helvetica');
        const spQs = [
            {id:"HW_Q1", t:"Ventilation"}, {id:"HW_Q2", t:"Exit Means"}, {id:"HW_Q3", t:"Standby Person"},
            {id:"HW_Q16", t:"Height Permit Taken", d:"HW_Q16_Detail"}, {id:"VE_Q1", t:"Spark Arrestor (Veh)"}, {id:"EX_Q1", t:"Excavation Clear"}
        ];
        spQs.forEach((q, i) => {
            const val = d[q.id] === 'Yes' ? '[YES]' : '[NA]';
            doc.text(`${String.fromCharCode(65+i)}. ${q.t}`);
            doc.text(val, 450, doc.y - 10);
        });

        doc.moveDown();
        doc.font('Helvetica-Bold').text('REMARKS / HAZARDS IDENTIFIED:');
        const hazards = ["H_H2S", "H_LackOxygen", "H_Corrosive", "H_ToxicGas", "H_Combustible", "H_Steam", "H_PyroIron", "H_N2Gas", "H_Height", "H_LooseEarth", "H_HighNoise", "H_Radiation"];
        let hText = "";
        hazards.forEach(h => { if(d[h] === 'Y') hText += `[X] ${h.replace('H_','')}  `; });
        doc.font('Helvetica').text(hText || "None");

        doc.moveDown();
        doc.font('Helvetica-Bold').text('PPE REQUIRED:');
        const ppe = ["P_FaceShield", "P_FreshAirMask", "P_CompressedBA", "P_Goggles", "P_DustRespirator", "P_Earmuff", "P_LifeLine", "P_Apron", "P_SafetyHarness", "P_SafetyNet", "P_Airline"];
        let pText = "";
        ppe.forEach(p => { if(d[p] === 'Y') pText += `[X] ${p.replace('P_','')}  `; });
        doc.font('Helvetica').text(pText || "Standard PPE");

        doc.moveDown();
        doc.text(`Additional Precautions: ${d.AdditionalPrecautions || '-'}`);
        doc.moveDown();
        doc.font('Helvetica-Bold').text('DIGITAL SIGNATURES', {underline:true});
        doc.font('Helvetica');
        doc.text(`Requested By: ${d.RequesterName} (${d.RequesterEmail})`);
        doc.text(`Reviewed By: ${d.Reviewer_Sig || 'Pending'} (${d.Reviewer_Remarks || '-'})`);
        doc.text(`Approved By: ${d.Approver_Sig || 'Pending'} (${d.Approver_Remarks || '-'})`);

        // --- PAGE 3 ---
        doc.addPage();
        addWatermark();
        doc.font('Helvetica-Bold').text('CLEARANCE RENEWAL HISTORY');
        doc.font('Helvetica');
        const rens = JSON.parse(p.RenewalsJSON || "[]");
        if(rens.length === 0) doc.text("No renewals recorded.");
        else {
            rens.forEach(r => {
                doc.text(`Period: ${r.valid_from.replace('T',' ')} to ${r.valid_till.replace('T',' ')}`);
                doc.text(`Status: ${r.status.toUpperCase()} | HC: ${r.hc}% | Tox: ${r.toxic} | O2: ${r.oxygen}%`);
                doc.text(`Req By: ${r.req_name} (${r.req_at})`);
                if(r.rev_name) doc.text(`Rev By: ${r.rev_name} (${r.rev_at})`);
                if(r.app_name) doc.text(`App By: ${r.app_name} (${r.app_at})`);
                doc.moveDown(0.5);
                doc.text('------------------------------------------------');
                doc.moveDown(0.5);
            });
        }

        doc.moveDown(2);
        doc.font('Helvetica-Bold').text('CLOSING OF WORK PERMIT');
        doc.font('Helvetica');
        doc.text(`Receiver Sig: ${d.Closure_Receiver_Sig || 'Not Signed'}`);
        doc.text(`Issuer Sig: ${d.Closure_Issuer_Sig || 'Not Signed'} (Remarks: ${d.Closure_Issuer_Remarks || '-'})`);

        doc.end();
    } catch (e) { res.status(500).send(e.message); }
});

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`✅ SYSTEM LIVE ON PORT ${PORT}`));
