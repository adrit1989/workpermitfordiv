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

// --- CHECKLIST DATA (FULL OISD-105 TEXT - DO NOT SHORTEN) ---
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

// --- PDF HEADER DRAWING ---
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

// 1. LOGIN (Case Insensitive Mapping)
app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
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
        let pid = req.body.PermitID;
        // Sanitize ID
        if (!pid || pid === 'undefined' || pid === 'null' || (typeof pid === 'string' && pid.trim() === '')) pid = null;
        
        let isUpdate = false;

        // Check if ID exists
        if (pid) {
            const checkReq = pool.request(); 
            const check = await checkReq.input('pid', sql.NVarChar, String(pid)).query("SELECT Status FROM Permits WHERE PermitID = @pid");
            
            if (check.recordset.length > 0) {
                const currentStatus = check.recordset[0].Status;
                if (currentStatus === 'Pending Review' || currentStatus === 'New') {
                    isUpdate = true;
                } else {
                    return res.status(400).json({ error: "Cannot edit an Active/Processed permit." });
                }
            } else {
                pid = null; // ID passed but not found, treat as new
            }
        }

        // Generate ID if new
        if (!pid) {
            const idReq = pool.request();
            const idRes = await idReq.query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
            const lastId = idRes.recordset.length > 0 ? idRes.recordset[0].PermitID : "WP-1000";
            pid = `WP-${parseInt(lastId.split('-')[1]) + 1}`;
        }

        const fullData = { ...req.body, PermitID: pid };
        
        // Execute Save
        const saveReq = pool.request();
        saveReq.input('pid', sql.NVarChar, String(pid))
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
            await containerClient.getBlockBlobClient(`${pid}_${req.file.originalname}`).uploadData(req.file.buffer);
        }
        res.json({ success: true, permitId: pid });
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
            if (action === 'reject') { 
                status = 'Rejected'; 
                data.Reviewer_Remarks = (data.Reviewer_Remarks||"") + `\n[Rejected by ${user}: ${comment}]`; 
            } else if (action === 'review') { 
                status = 'Pending Approval'; 
                data.Reviewer_Sig = sig; 
                data.Reviewer_Remarks = comment; 
            } else if (action === 'approve' && status.includes('Closure')) { 
                status = 'Closure Pending Approval'; 
                data.Closure_Reviewer_Remarks = req.body.Closure_Reviewer_Remarks;
                data.Closure_Reviewer_Date = now;
                data.Closure_Reviewer_Sig = sig; 
            } else if (action === 'reject_closure') {
                status = 'Active'; 
                data.Closure_Reviewer_Remarks = `[REJECTED by ${user}]: ${req.body.Closure_Reviewer_Remarks}`;
                data.Closure_Reviewer_Date = now;
            }
        }
        else if (role === 'Approver') {
            if (action === 'reject') { 
                status = 'Rejected'; 
                data.Approver_Remarks = (data.Approver_Remarks||"") + `\n[Rejected by ${user}: ${comment}]`; 
            } else if (action === 'approve' && status === 'Pending Approval') { 
                status = 'Active'; 
                data.Approver_Sig = sig; 
                data.Approver_Remarks = comment; 
            } else if (action === 'approve' && status.includes('Closure')) { 
                status = 'Closed'; 
                data.Closure_Approver_Remarks = req.body.Closure_Approver_Remarks;
                data.Closure_Approver_Date = now;
                data.Closure_Issuer_Sig = sig; 
                data.Closure_Issuer_Remarks = comment; 
            } else if (action === 'reject_closure') {
                status = 'Active'; 
                data.Closure_Approver_Remarks = `[REJECTED by ${user}]: ${req.body.Closure_Approver_Remarks}`;
                data.Closure_Approver_Date = now;
            }
        }

        let q = pool.request().input('pid', sql.NVarChar, PermitID).input('status', sql.NVarChar, status).input('json', sql.NVarChar, JSON.stringify(data));
        
        if(extras.WorkType) {
             q.input('wt', sql.NVarChar, extras.WorkType)
              .query("UPDATE Permits SET Status = @status, FullDataJSON = @json, WorkType = @wt WHERE PermitID = @pid");
        } else {
             q.query("UPDATE Permits SET Status = @status, FullDataJSON = @json WHERE PermitID = @pid");
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 7. RENEWALS (8 Hr Limit, Sequential, 3-Part Gas)
app.post('/api/renewal', async (req, res) => {
    try {
        const { PermitID, userRole, userName, action, rejectionReason, ...data } = req.body;
        const pool = await getConnection();
        const cur = await pool.request().input('p', PermitID).query("SELECT RenewalsJSON, Status, ValidFrom, ValidTo FROM Permits WHERE PermitID=@p");
        let r = JSON.parse(cur.recordset[0].RenewalsJSON||"[]"); 
        const pStart = new Date(cur.recordset[0].ValidFrom); const pEnd = new Date(cur.recordset[0].ValidTo);
        const now = getNowIST();

        if (userRole === 'Requester') {
             const rs = new Date(data.RenewalValidFrom); const re = new Date(data.RenewalValidTo);
             
             // A. Validation
             if (rs < pStart || re > pEnd) return res.status(400).json({error: "Renewal must be within permit validity"});
             if ((re - rs) / 36e5 > 8) return res.status(400).json({error: "Max 8 hours per clearance"});
             
             // Sequential & Overlap Check
             if(r.length > 0) {
                 const last = r[r.length-1];
                 const lastEnd = new Date(last.valid_till);
                 
                 // Block if previous is still pending
                 if(last.status === 'pending_review' || last.status === 'pending_approval') {
                     return res.status(400).json({error: "Previous renewal is still pending."});
                 }
                 
                 // Chronological check (unless last was rejected)
                 if(last.status !== 'rejected' && rs < lastEnd) {
                     return res.status(400).json({error: "New renewal cannot overlap with previous approved renewal."});
                 }
             }
             
             // B. Push Data (Split Gas)
             r.push({ 
                 status: 'pending_review', 
                 valid_from: data.RenewalValidFrom, 
                 valid_till: data.RenewalValidTo, 
                 hc: data.hc, toxic: data.toxic, oxygen: data.oxygen, // B. 3 sub items
                 precautions: data.precautions, 
                 req_name: userName, req_at: now 
             });
        } 
        else {
            // Processing by Rev/App
            const last = r[r.length-1];
            if (action === 'reject') { 
                last.status = 'rejected'; 
                last.rej_by = userName; 
                last.rej_at = now;
                last.rej_reason = rejectionReason; 
            }
            else { 
                last.status = userRole==='Reviewer'?'pending_approval':'approved'; 
                if(userRole==='Reviewer') { last.rev_name = userName; last.rev_at = now; last.rev_rem = rejectionReason; }
                if(userRole==='Approver') { last.app_name = userName; last.app_at = now; last.app_rem = rejectionReason; }
            }
        }
        
        let newStatus = r[r.length-1].status==='approved'?'Active':(r[r.length-1].status==='rejected'?'Active':(r[r.length-1].status==='pending_approval'?'Renewal Pending Approval':'Renewal Pending Review'));
        await pool.request().input('p', PermitID).input('r', JSON.stringify(r)).input('s', newStatus).query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/permit-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().input('p', sql.NVarChar, req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p"); if(r.recordset.length) res.json({...JSON.parse(r.recordset[0].FullDataJSON), Status:r.recordset[0].Status, RenewalsJSON:r.recordset[0].RenewalsJSON, FullDataJSON:null}); else res.json({error:"404"}); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/map-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status='Active'"); res.json(r.recordset.map(x=>({PermitID:x.PermitID, lat:parseFloat(x.Latitude), lng:parseFloat(x.Longitude), ...JSON.parse(x.FullDataJSON)}))); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/stats', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT Status, WorkType FROM Permits"); const s={}, t={}; r.recordset.forEach(x=>{s[x.Status]=(s[x.Status]||0)+1; t[x.WorkType]=(t[x.WorkType]||0)+1;}); res.json({success:true, statusCounts:s, typeCounts:t}); } catch(e){res.status(500).json({error:e.message})} });
app.get('/api/download-excel', async (req, res) => { try { const pool = await getConnection(); const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC"); const workbook = new ExcelJS.Workbook(); const sheet = workbook.addWorksheet('Permits Summary'); sheet.columns = [{header:'Permit ID',key:'id',width:15},{header:'Status',key:'status',width:20},{header:'Work Type',key:'wt',width:25},{header:'Requester',key:'req',width:25},{header:'Location',key:'loc',width:30},{header:'Vendor',key:'ven',width:20},{header:'Valid From',key:'vf',width:20},{header:'Valid To',key:'vt',width:20}]; sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 }; sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFED7D31' } }; result.recordset.forEach(r => { const d = JSON.parse(r.FullDataJSON || "{}"); sheet.addRow({ id: r.PermitID, status: r.Status, wt: d.WorkType, req: d.RequesterName, loc: d.ExactLocation, ven: d.Vendor, vf: formatDate(r.ValidFrom), vt: formatDate(r.ValidTo) }); }); res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'); res.setHeader('Content-Disposition', 'attachment; filename=IndianOil_Permits.xlsx'); await workbook.xlsx.write(res); res.end(); } catch (e) { res.status(500).send(e.message); } });

// 8. PDF GENERATION (EXACT OISD-105 FORMAT)
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('p', req.params.id).query("SELECT * FROM Permits WHERE PermitID = @p");
        if(!result.recordset.length) return res.status(404).send('Not Found');
        const p = result.recordset[0]; const d = JSON.parse(p.FullDataJSON);
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`); doc.pipe(res);

        // Header
        drawHeader(doc); doc.y = 135; doc.fontSize(9).font('Helvetica');
        const infoY = doc.y; const c1 = 40, c2 = 300;
        doc.text(`Permit No: ${p.PermitID}`, c1, infoY).text(`Validity: ${formatDate(p.ValidFrom)} - ${formatDate(p.ValidTo)}`, c2, infoY);
        doc.text(`Issued To: ${d.IssuedToDept} (${d.Vendor})`, c1, infoY+15).text(`Location: ${d.ExactLocation}`, c2, infoY+15);
        doc.text(`Desc: ${d.Desc}`, c1, infoY+30,{width:500}).text(`Site Person: ${d.RequesterName}`, c1, infoY+60).text(`Security: ${d.SecurityGuard||'-'}`, c2, infoY+60);
        doc.text(`Emergency: ${d.EmergencyContact||'-'}`, c1, infoY+75).text(`Fire Stn: ${d.FireStation||'-'}`, c2, infoY+75);
        doc.rect(30,infoY-5,535,95).stroke(); doc.y=infoY+100;

        // Checklists
        const drawChecklist = (t,i,pr) => { 
            if(doc.y>650){doc.addPage(); drawHeader(doc); doc.y=135;} 
            doc.font('Helvetica-Bold').text(t,30,doc.y+10); doc.y+=25; 
            let y=doc.y; doc.rect(30,y,350,20).stroke().text("Item",35,y+5); doc.rect(380,y,60,20).stroke().text("Sts",385,y+5); doc.rect(440,y,125,20).stroke().text("Rem",445,y+5); y+=20;
            doc.font('Helvetica').fontSize(8);
            i.forEach((x,k)=>{
                if(y>750){doc.addPage(); drawHeader(doc); doc.y=135; y=135;}
                const st = d[`${pr}_Q${k+1}`]||'NA';
                doc.rect(30,y,350,20).stroke().text(x,35,y+5,{width:340});
                doc.rect(380,y,60,20).stroke().text(st,385,y+5);
                doc.rect(440,y,125,20).stroke().text(d[`${pr}_Q${k+1}_Detail`]||'',445,y+5); y+=20;
            }); doc.y=y;
        };
        drawChecklist("SECTION A", CHECKLIST_DATA.A,'A'); drawChecklist("SECTION B", CHECKLIST_DATA.B,'B'); drawChecklist("SECTION C", CHECKLIST_DATA.C,'C'); drawChecklist("SECTION D", CHECKLIST_DATA.D,'D');

        // Hazards
        doc.addPage(); drawHeader(doc); doc.y=135;
        doc.font('Helvetica-Bold').text("HAZARDS & PRECAUTIONS",30,doc.y); doc.y+=15; doc.rect(30,doc.y,535,60).stroke();
        const hazKeys = ["Lack of Oxygen", "H2S", "Toxic Gases", "Combustible gases", "Pyrophoric Iron", "Corrosive Chemicals", "cave in formation"];
        const foundHaz = hazKeys.filter(k => d[`H_${k.replace(/ /g,'')}`] === 'Y'); if(d.H_Others==='Y') foundHaz.push(`Others: ${d.H_Others_Detail}`);
        doc.text(`Hazards: ${foundHaz.join(', ')}`,35,doc.y+5); 
        
        const ppeKeys = ["Helmet","Safety Shoes","Hand gloves","Boiler suit","Face Shield","Apron","Goggles","Dust Respirator","Fresh Air Mask","Lifeline","Safety Harness","Airline","Earmuff"];
        const foundPPE = ppeKeys.filter(k => d[`P_${k.replace(/ /g,'')}`] === 'Y');
        doc.text(`PPE: ${foundPPE.join(', ')}`,35,doc.y+25); doc.y+=70;

        // Signatures
        doc.font('Helvetica-Bold').text("SIGNATURES",30,doc.y); doc.y+=15; const sY=doc.y;
        doc.rect(30,sY,178,40).stroke().text(`REQ: ${d.RequesterName}`,35,sY+5);
        doc.rect(208,sY,178,40).stroke().text(`REV: ${d.Reviewer_Sig||'-'}`,213,sY+5);
        doc.rect(386,sY,179,40).stroke().text(`APP: ${d.Approver_Sig||'-'}`,391,sY+5); doc.y=sY+50;

        // Renewals
        doc.font('Helvetica-Bold').text("CLEARANCE RENEWAL",30,doc.y); doc.y+=15;
        let ry = doc.y;
        doc.rect(30,ry,60,25).stroke().text("From",32,ry+5); doc.rect(90,ry,60,25).stroke().text("To",92,ry+5); doc.rect(150,ry,100,25).stroke().text("Gas (HC/Tox/O2)",152,ry+5); doc.rect(250,ry,100,25).stroke().text("Precautions",252,ry+5); doc.rect(350,ry,70,25).stroke().text("Req",352,ry+5); doc.rect(420,ry,70,25).stroke().text("Rev",422,ry+5); doc.rect(490,ry,75,25).stroke().text("App",492,ry+5); ry+=25;
        const renewals = JSON.parse(p.RenewalsJSON || "[]");
        doc.font('Helvetica').fontSize(8);
        renewals.forEach(r => {
             doc.rect(30,ry,60,35).stroke().text(r.valid_from.replace('T','\n'), 32, ry+5);
             doc.rect(90,ry,60,35).stroke().text(r.valid_till.replace('T','\n'), 92, ry+5);
             doc.rect(150,ry,100,35).stroke().text(`${r.hc}/${r.toxic}/${r.oxygen}`, 152, ry+5);
             doc.rect(250,ry,100,35).stroke().text(r.precautions||'-', 252, ry+5);
             doc.rect(350,ry,70,35).stroke().text(`${r.req_name}\n${r.req_at}`, 352, ry+5);
             doc.rect(420,ry,70,35).stroke().text(`${r.rev_name||'-'}\n${r.rev_at||'-'}`, 422, ry+5);
             doc.rect(490,ry,75,35).stroke().text(`${r.app_name||'-'}\n${r.app_at||'-'}`, 492, ry+5);
             ry += 35;
        });
        doc.y = ry + 20;

        // Closure
        doc.font('Helvetica-Bold').text("CLOSURE",30,doc.y); doc.y+=15; doc.rect(30,doc.y,535,60).stroke();
        doc.text(`Receiver: ${d.Closure_Requestor_Remarks||'-'}`,35,doc.y+5);
        doc.text(`Safety: ${d.Closure_Reviewer_Remarks||'-'}`,35,doc.y+20);
        doc.text(`Issuer: ${d.Closure_Approver_Remarks||'-'}`,35,doc.y+35);
        
        // General Instructions
        doc.addPage(); drawHeader(doc); doc.y = 135; doc.font('Helvetica-Bold').fontSize(10).text("GENERAL INSTRUCTIONS", 30, doc.y); doc.y += 15; doc.font('Helvetica').fontSize(8);
        const instructions = ["1. The work permit shall be filled up carefully.", "2. Appropriate safeguards and PPEs shall be determined.", "3. Requirement of standby personnel shall be mentioned.", "4. Means of communication must be available.", "5. Shift-wise communication to Main Control Room.", "6. Only certified vehicles and electrical equipment allowed.", "7. Welding machines shall be placed in ventilated areas.", "8. No hot work unless explosive meter reading is Zero.", "9. Standby person mandatory for confined space.", "10. Compressed gas cylinders not allowed inside.", "11. While filling trench, men/equipment must be outside.", "12. For renewal, issuer must ensure conditions are satisfactory.", "13. Max renewal up to 7 calendar days.", "14. Permit must be available at site.", "15. On completion, permit must be closed.", "16. Follow latest SOP for Trenching.", "17. CCTV and gas monitoring should be utilized.", "18. Refer to PLHO guidelines for details."];
        instructions.forEach(i => { doc.text(i, 30, doc.y); doc.y += 12; });

        // Watermark
        const wm = p.Status.includes('Closed') ? 'CLOSED' : 'ACTIVE';
        const color = p.Status.includes('Closed') ? '#ef4444' : '#22c55e';
        const range = doc.bufferedPageRange();
        for(let i=0; i<range.count; i++) {
            doc.switchToPage(i); doc.save(); doc.rotate(-45, {origin:[300,400]}); 
            doc.fontSize(80).fillColor(color).opacity(0.15).text(wm, 100, 350, {align:'center'}); doc.restore();
        }
        doc.end();
    } catch (e) { res.status(500).send(e.message); }
});

app.listen(8080, () => console.log('Server Ready'));
