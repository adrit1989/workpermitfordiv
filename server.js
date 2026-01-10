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

// --- AZURE STORAGE ---
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
    } catch (err) { console.error("Blob Storage Error:", err.message); }
}
const upload = multer({ storage: multer.memoryStorage() });

// --- HELPERS ---
function getNowIST() { return new Date().toLocaleString("en-GB", { timeZone: "Asia/Kolkata", day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).replace(',', ''); }
function formatDate(dateStr) { if (!dateStr) return '-'; const d = new Date(dateStr); if (isNaN(d.getTime())) return dateStr; return d.toLocaleString("en-GB", { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).replace(',', ''); }

// --- CHECKLIST DATA ---
const CHECKLIST_DATA = {
    A: ["1. Equipment / Work Area inspected.", "2. Surrounding area checked, cleaned and covered. Oil/RAGS/Grass Etc removed.", "3. Manholes, Sewers, CBD etc. and hot nearby surface covered.", "4. Considered hazards from other routine, non-routine operations and concerned person alerted.", "5. Equipment blinded/ disconnected/ closed/ isolated/ wedge opened.", "6. Equipment properly drained and depressurized.", "7. Equipment properly steamed/purged.", "8. Equipment water flushed.", "9. Access for Free approach of Fire Tender.", "10. Iron Sulfide removed/ Kept wet.", "11. Equipment electrically isolated and tagged vide Permit no.", "12. Gas Test: HC / Toxic / O2 checked.", "13. Running water hose / Fire extinguisher provided. Fire water system available.", "14. Area cordoned off and Precautionary tag/Board provided.", "15. CCTV monitoring facility available at site.", "16. Proper ventilation and Lighting provided."],
    B: ["1. Proper means of exit / escape provided.", "2. Standby personnel provided from Mainline/ Maint. / Contractor/HSE.", "3. Checked for oil and Gas trapped behind the lining in equipment.", "4. Shield provided against spark.", "5. Portable equipment / nozzle properly grounded.", "6. Standby persons provided for entry to confined space.", "7. Adequate Communication Provided to Stand by Person.", "8. Attendant Trained Provided With Rescue Equipment/SCBA.", "9. Space Adequately Cooled for Safe Entry Of Person.", "10. Continuous Inert Gas Flow Arranged.", "11. Check For Earthing/ELCB of all Temporary Electrical Connections being used for welding.", "12. Gas Cylinders are kept outside the confined Space.", "13. Spark arrestor Checked on mobile Equipments.", "14. Welding Machine Checked for Safe Location.", "15. Permit taken for working at height Vide Permit No."],
    C: ["1. PESO approved spark elimination system provided on the mobile equipment/ vehicle provided."],
    D: ["1. For excavated trench/ pit proper slop/ shoring/ shuttering provided to prevent soil collapse.", "2. Excavated soil kept at safe distance from trench/pit edge (min. pit depth).", "3. Safe means of access provided inside trench/pit.", "4. Movement of heavy vehicle prohibited."]
};

// --- PDF HEADER ---
function drawHeader(doc) {
    const startX = 30; const startY = 30; const fullW = 535;
    doc.lineWidth(1);
    doc.rect(startX, startY, fullW, 95).stroke();
    doc.rect(startX, startY, 80, 95).stroke(); // Logo Area
    // doc.image('iocl_logo.png', startX+15, startY+25, {width:50}); 
    doc.rect(startX + 80, startY, 320, 95).stroke();
    doc.font('Helvetica-Bold').fontSize(12).text('INDIAN OIL CORPORATION LIMITED', startX + 80, startY + 15, {width: 320, align: 'center'});
    doc.fontSize(10).text('EASTERN REGION PIPELINES', startX + 80, startY + 30, {width: 320, align: 'center'});
    doc.text('HSE DEPT.', startX + 80, startY + 45, {width: 320, align: 'center'});
    doc.fontSize(9).text('COMPOSITE WORK PERMIT (OISD-105)', startX + 80, startY + 65, {width: 320, align: 'center'});
    const rightX = startX + 400;
    doc.rect(rightX, startY, 135, 95).stroke();
    doc.fontSize(8).font('Helvetica');
    doc.text('Doc No: ERPL/HS&E/25-26', rightX + 5, startY + 60);
    doc.text('Issue No: 01', rightX + 5, startY + 70);
    doc.text('Date: 01.09.2025', rightX + 5, startY + 80);
}

// --- ROUTES ---

// 1. LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        // req.body.name holds the email in this logic
        const result = await pool.request()
            .input('role', sql.NVarChar, req.body.role)
            .input('email', sql.NVarChar, req.body.name) 
            .input('pass', sql.NVarChar, req.body.password)
            .query('SELECT * FROM Users WHERE Role = @role AND Email = @email AND Password = @pass');
        
        if (result.recordset.length > 0) {
            const u = result.recordset[0];
            // Normalize response user object
            const userObj = { 
                Name: u.Name || u.name || u.NAME, 
                Email: u.Email || u.email || u.EMAIL, 
                Role: u.Role || u.role || u.ROLE 
            };
            res.json({ success: true, user: userObj });
        } else {
            res.json({ success: false, message: "Invalid Credentials" });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. GET USERS (FIXED: ROBUST MAPPING)
app.get('/api/users', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().query('SELECT Name, Role, Email FROM Users');
        
        // Helper to normalize user object safely
        const mapUser = (u) => ({
            name: u.Name || u.name || u.NAME || "Unknown",
            email: u.Email || u.email || u.EMAIL || ""
        });

        // Helper to check role safely
        const checkRole = (u, role) => (u.Role || u.role || u.ROLE || "") === role;

        res.json({
            Requesters: r.recordset.filter(u => checkRole(u, 'Requester')).map(mapUser),
            Reviewers: r.recordset.filter(u => checkRole(u, 'Reviewer')).map(mapUser),
            Approvers: r.recordset.filter(u => checkRole(u, 'Approver')).map(mapUser)
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2.5 ADD USER
app.post('/api/add-user', async (req, res) => {
    try {
        const pool = await getConnection();
        const check = await pool.request().input('e', sql.NVarChar, req.body.email).query("SELECT * FROM Users WHERE Email = @e");
        if(check.recordset.length > 0) return res.status(400).json({ error: "User exists" });
        await pool.request().input('n', sql.NVarChar, req.body.name).input('e', sql.NVarChar, req.body.email).input('r', sql.NVarChar, req.body.role).input('p', sql.NVarChar, req.body.password).query("INSERT INTO Users (Name, Email, Role, Password) VALUES (@n, @e, @r, @p)");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. DASHBOARD
app.post('/api/dashboard', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().query("SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON FROM Permits");
        const p = r.recordset.map(x=>({...JSON.parse(x.FullDataJSON || "{}"), PermitID:x.PermitID, Status:x.Status, ValidFrom:x.ValidFrom, ValidTo:x.ValidTo}));
        
        const f = p.filter(x => {
            const s = (x.Status || "").toLowerCase();
            if (req.body.role==='Requester') return x.RequesterEmail === req.body.email;
            if (req.body.role==='Reviewer') return x.ReviewerEmail === req.body.email && (s.includes('pending review') || s.includes('closure') || s === 'closed' || s.includes('renewal'));
            if (req.body.role==='Approver') return x.ApproverEmail === req.body.email || s === 'active' || s === 'closed';
            return false;
        });
        res.json(f.sort((a,b)=>b.PermitID.localeCompare(a.PermitID)));
    } catch(e){res.status(500).json({error:e.message})} 
});

// 4. SAVE PERMIT
app.post('/api/save-permit', upload.single('file'), async (req, res) => {
    try {
        const vf = new Date(req.body.ValidFrom); const vt = new Date(req.body.ValidTo);
        const diff = (vt - vf) / (1000 * 60 * 60 * 24);
        if (diff > 7) return res.status(400).json({ error: "Permit duration cannot exceed 7 days." });

        const pool = await getConnection();
        
        // Sanitize ID
        let pid = req.body.PermitID;
        if (!pid || pid === 'undefined' || pid === 'null' || pid.trim() === '') pid = null;
        
        let isUpdate = false;

        if (pid) {
            const c = await pool.request().input('p', sql.NVarChar, pid).query("SELECT Status FROM Permits WHERE PermitID=@p");
            if (c.recordset.length > 0) {
                const s = c.recordset[0].Status;
                if (s === 'Pending Review' || s === 'New') isUpdate = true;
                else return res.status(400).json({error: "Cannot edit processed permit"});
            } else pid = null;
        }

        if (!pid) {
            const idRes = await pool.request().query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
            pid = `WP-${parseInt(idRes.recordset.length > 0 ? idRes.recordset[0].PermitID.split('-')[1] : 1000) + 1}`;
        }

        const data = { ...req.body, PermitID: pid };
        const q = pool.request();
        
        q.input('p', sql.NVarChar, pid)
         .input('s', sql.NVarChar, 'Pending Review')
         .input('w', sql.NVarChar, req.body.WorkType)
         .input('re', sql.NVarChar, req.body.RequesterEmail)
         .input('rv', sql.NVarChar, req.body.ReviewerEmail)
         .input('ap', sql.NVarChar, req.body.ApproverEmail)
         .input('vf', sql.DateTime, new Date(req.body.ValidFrom))
         .input('vt', sql.DateTime, new Date(req.body.ValidTo))
         .input('lat', sql.NVarChar, req.body.Latitude || null)
         .input('lng', sql.NVarChar, req.body.Longitude || null)
         .input('j', sql.NVarChar, JSON.stringify(data));

        if (isUpdate) {
            await q.query("UPDATE Permits SET FullDataJSON=@j, WorkType=@w, ReviewerEmail=@rv, ApproverEmail=@ap, ValidFrom=@vf, ValidTo=@vt, Latitude=@lat, Longitude=@lng WHERE PermitID=@p");
        } else {
            await q.query("INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, FullDataJSON, RenewalsJSON) VALUES (@p, @s, @w, @re, @rv, @ap, @vf, @vt, @lat, @lng, @j, '[]')");
        }
        
        if(req.file && containerClient) await containerClient.getBlockBlobClient(`${pid}_${req.file.originalname}`).uploadData(req.file.buffer);
        res.json({ success: true, permitId: pid });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. STATUS UPDATE
app.post('/api/update-status', async (req, res) => {
    try {
        const pool = await getConnection();
        const cur = await pool.request().input('p', sql.NVarChar, req.body.PermitID).query("SELECT * FROM Permits WHERE PermitID=@p");
        if(!cur.recordset.length) return res.json({error:"Not found"});
        
        let d = JSON.parse(cur.recordset[0].FullDataJSON);
        Object.assign(d, req.body); // Merge
        
        let st = cur.recordset[0].Status;
        const now = getNowIST();
        
        if(req.body.role==='Reviewer' && req.body.action==='review') { st='Pending Approval'; d.Reviewer_Sig=`${req.body.user} on ${now}`; }
        if(req.body.role==='Approver' && req.body.action==='approve') { st=st.includes('Closure')?'Closed':'Active'; if(!st.includes('Closed')) d.Approver_Sig=`${req.body.user} on ${now}`; else d.Closure_Issuer_Sig=`${req.body.user} on ${now}`; }
        if(req.body.action==='reject') { st='Rejected'; }
        if(req.body.action==='initiate_closure') { st='Closure Pending Review'; d.Closure_Requestor_Date=now; }
        
        await pool.request().input('p', req.body.PermitID).input('s', st).input('j', JSON.stringify(d)).query("UPDATE Permits SET Status=@s, FullDataJSON=@j WHERE PermitID=@p");
        res.json({success:true});
    } catch(e){res.status(500).json({error:e.message})} 
});

app.post('/api/renewal', async (req, res) => { try { const pool = await getConnection(); const cur = await pool.request().input('p', sql.NVarChar, req.body.PermitID).query("SELECT * FROM Permits WHERE PermitID=@p"); let r = JSON.parse(cur.recordset[0].RenewalsJSON||"[]"); 
    if(req.body.userRole==='Requester') { r.push({status:'pending_review', ...req.body, req_at: getNowIST()}); }
    else if(req.body.action==='reject') { r[r.length-1].status='rejected'; } 
    else { r[r.length-1].status = req.body.userRole==='Reviewer'?'pending_approval':'approved'; }
    await pool.request().input('p', req.body.PermitID).input('r', JSON.stringify(r)).input('s', r[r.length-1].status==='approved'?'Active':(r[r.length-1].status==='rejected'?'Active':(req.body.userRole==='Requester'?'Renewal Pending Review':'Renewal Pending Approval'))).query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p"); res.json({success:true}); } catch(e){res.status(500).json({error:e.message})} });

app.post('/api/permit-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().input('p', sql.NVarChar, req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p"); if(r.recordset.length) res.json({...JSON.parse(r.recordset[0].FullDataJSON), Status:r.recordset[0].Status, RenewalsJSON:r.recordset[0].RenewalsJSON}); else res.json({error:"404"}); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/map-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status='Active' AND Latitude IS NOT NULL"); res.json(r.recordset.map(x=>({PermitID:x.PermitID, lat:parseFloat(x.Latitude), lng:parseFloat(x.Longitude), ...JSON.parse(x.FullDataJSON)}))); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/stats', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT Status, WorkType FROM Permits"); const s={}, t={}; r.recordset.forEach(x=>{s[x.Status]=(s[x.Status]||0)+1; t[x.WorkType]=(t[x.WorkType]||0)+1;}); res.json({success:true, statusCounts:s, typeCounts:t}); } catch(e){res.status(500).json({error:e.message})} });

// EXCEL
app.get('/api/download-excel', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC");
        const workbook = new ExcelJS.Workbook();
        const sheet = workbook.addWorksheet('Permits Summary');
        sheet.columns = [{ header: 'Permit ID', key: 'id', width: 15 }, { header: 'Status', key: 'status', width: 20 }, { header: 'Work Type', key: 'wt', width: 25 }, { header: 'Requester', key: 'req', width: 25 }, { header: 'Location', key: 'loc', width: 30 }, { header: 'Vendor', key: 'ven', width: 20 }, { header: 'Valid From', key: 'vf', width: 20 }, { header: 'Valid To', key: 'vt', width: 20 }];
        sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 }; sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFED7D31' } };
        result.recordset.forEach(r => { const d = JSON.parse(r.FullDataJSON || "{}"); sheet.addRow({ id: r.PermitID, status: r.Status, wt: d.WorkType, req: d.RequesterName, loc: d.ExactLocation, ven: d.Vendor, vf: formatDate(r.ValidFrom), vt: formatDate(r.ValidTo) }); });
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'); res.setHeader('Content-Disposition', 'attachment; filename=IndianOil_Permits.xlsx'); await workbook.xlsx.write(res); res.end();
    } catch (e) { res.status(500).send(e.message); }
});

// PDF (OISD-105)
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('pid', sql.NVarChar, req.params.id).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if(result.recordset.length === 0) return res.status(404).send('Not Found');
        const p = result.recordset[0]; const d = JSON.parse(p.FullDataJSON);
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`); doc.pipe(res);

        drawHeader(doc); doc.y = 135; doc.fontSize(9).font('Helvetica');
        const infoY = doc.y; const col1 = 40, col2 = 300;
        doc.text(`Permit No: ${p.PermitID}`, col1, infoY); doc.text(`Valid From: ${formatDate(p.ValidFrom)} To: ${formatDate(p.ValidTo)}`, col2, infoY);
        doc.text(`Issued To: ${d.IssuedToDept} (${d.Vendor || 'Self'})`, col1, infoY + 15); doc.text(`Location: ${d.ExactLocation} (${d.LocationUnit})`, col2, infoY + 15);
        doc.text(`Description: ${d.Desc}`, col1, infoY + 30, {width: 500});
        doc.text(`Site Person: ${d.RequesterName}`, col1, infoY + 60); doc.text(`Security/Patrol: ${d.SecurityGuard || '-'}`, col2, infoY + 60);
        doc.text(`Emergency: ${d.EmergencyContact || '-'}`, col1, infoY + 75); doc.text(`Fire Stn/Hosp: ${d.FireStation || '-'}`, col2, infoY + 75);
        doc.rect(30, infoY - 5, 535, 95).stroke(); doc.y = infoY + 100;

        const drawChecklistTable = (title, items, idPrefix) => {
            if(doc.y > 650) { doc.addPage(); drawHeader(doc); doc.y = 135; }
            doc.font('Helvetica-Bold').fontSize(10).text(title, 30, doc.y + 10); doc.y += 25;
            let y = doc.y;
            doc.rect(30, y, 30, 20).stroke().text("SN", 35, y+5); doc.rect(60, y, 350, 20).stroke().text("Item / Condition", 65, y+5);
            doc.rect(410, y, 60, 20).stroke().text("Status", 415, y+5); doc.rect(470, y, 95, 20).stroke().text("Remarks", 475, y+5); y += 20;
            doc.font('Helvetica').fontSize(8);
            items.forEach((itemText, i) => {
                if(y > 750) { doc.addPage(); drawHeader(doc); doc.y = 135; y = 135; }
                const qId = `${idPrefix}_Q${i+1}`; const status = d[qId] === 'Yes' ? 'YES' : (d[qId] === 'NA' ? 'NA' : 'NO');
                let remarks = d[`${idPrefix}_Q${i+1}_Detail`] || ''; if(idPrefix === 'A' && i === 11) remarks = `HC:${d.GP_Q12_HC||0}% Tox:${d.GP_Q12_ToxicGas||0} O2:${d.GP_Q12_Oxygen||21}%`;
                doc.rect(30, y, 30, 25).stroke().text(i+1, 35, y+8); doc.rect(60, y, 350, 25).stroke().text(itemText, 65, y+8, {width: 340});
                doc.rect(410, y, 60, 25).stroke().text(status, 415, y+8); doc.rect(470, y, 95, 25).stroke().text(remarks, 475, y+8); y += 25;
            });
            doc.y = y;
        };
        drawChecklistTable("SECTION A: GENERAL POINTS", CHECKLIST_DATA.A, 'A'); drawChecklistTable("SECTION B: HOT WORK / CONFINED SPACE", CHECKLIST_DATA.B, 'B'); drawChecklistTable("SECTION C: VEHICLE ENTRY", CHECKLIST_DATA.C, 'C'); drawChecklistTable("SECTION D: EXCAVATION WORK", CHECKLIST_DATA.D, 'D');

        doc.addPage(); drawHeader(doc); doc.y = 135; doc.font('Helvetica-Bold').fontSize(10).text("HAZARDS & PRECAUTIONS", 30, doc.y); doc.y += 15; doc.rect(30, doc.y, 535, 60).stroke(); doc.fontSize(8).font('Helvetica');
        const hazKeys = ["Lack of Oxygen", "H2S", "Toxic Gases", "Combustible gases", "Pyrophoric Iron", "Corrosive Chemicals", "cave in formation"];
        const foundHaz = hazKeys.filter(k => d[`H_${k.replace(/ /g,'')}`] === 'Y'); if(d.H_Others==='Y') foundHaz.push(`Others: ${d.H_Others_Detail}`);
        doc.text(`Identified Hazards: ${foundHaz.join(', ') || 'None'}`, 35, doc.y + 5, {width: 525});
        const ppeKeys = ["Helmet","Safety Shoes","Hand gloves","Boiler suit","Face Shield","Apron","Goggles","Dust Respirator","Fresh Air Mask","Lifeline","Safety Harness","Airline","Earmuff"];
        const foundPPE = ppeKeys.filter(k => d[`P_${k.replace(/ /g,'')}`] === 'Y'); doc.text(`PPE Required: ${foundPPE.join(', ') || 'Standard Only'}`, 35, doc.y + 25, {width: 525}); doc.y += 70;

        doc.font('Helvetica-Bold').fontSize(10).text("DIGITAL SIGNATURES (ISSUANCE)", 30, doc.y); doc.y += 15; const sigY = doc.y;
        doc.rect(30, sigY, 178, 50).stroke().text(`REQUESTER\n${d.RequesterName}\n${formatDate(p.ValidFrom)}`, 35, sigY + 5); doc.rect(208, sigY, 178, 50).stroke().text(`SAFETY OFFICER\n${d.Reviewer_Sig||'Pending'}`, 213, sigY + 5); doc.rect(386, sigY, 179, 50).stroke().text(`ISSUING AUTHORITY\n${d.Approver_Sig||'Pending'}`, 391, sigY + 5); doc.y = sigY + 60;

        doc.font('Helvetica-Bold').fontSize(10).text("CLEARANCE RENEWAL", 30, doc.y); doc.y += 15;
        doc.rect(30, doc.y, 100, 20).stroke().text("Date/Time", 35, doc.y+5); doc.rect(130, doc.y, 150, 20).stroke().text("Readings (HC/Tox/O2)", 135, doc.y+5); doc.rect(280, doc.y, 285, 20).stroke().text("Signatures (Req / Safety / Issuer)", 285, doc.y+5); doc.y += 20;
        const renewals = JSON.parse(p.RenewalsJSON || "[]"); doc.font('Helvetica').fontSize(8);
        renewals.forEach(r => { doc.rect(30, doc.y, 100, 30).stroke().text(`${formatDate(r.valid_from)}\n${formatDate(r.valid_till)}`, 35, doc.y+5); doc.rect(130, doc.y, 150, 30).stroke().text(`HC:${r.hc} Tox:${r.toxic} O2:${r.oxygen}`, 135, doc.y+10); doc.rect(280, doc.y, 285, 30).stroke().text(`${r.req_name} | ${r.rev_name||'-'} | ${r.app_name||'-'}`, 285, doc.y+10); doc.y += 30; }); doc.y += 20;

        doc.font('Helvetica-Bold').fontSize(10).text("CLOSURE OF WORK PERMIT", 30, doc.y); doc.y += 15; doc.rect(30, doc.y, 535, 70).stroke(); doc.fontSize(8);
        doc.text("1. RECEIVER: Work stopped/completed & area cleared.", 35, doc.y + 10); doc.font('Helvetica').text(`${d.Closure_Requestor_Remarks || '-'} (${d.Closure_Requestor_Date || ''})`, 300, doc.y + 10);
        doc.font('Helvetica-Bold').text("2. SAFETY: Verified area is safe.", 35, doc.y + 30); doc.font('Helvetica').text(`${d.Closure_Reviewer_Remarks || '-'} (${d.Closure_Reviewer_Date || ''})`, 300, doc.y + 30);
        doc.font('Helvetica-Bold').text("3. ISSUER: Permit Closed.", 35, doc.y + 50); doc.font('Helvetica').text(`${d.Closure_Approver_Remarks || '-'} (${d.Closure_Approver_Date || ''})`, 300, doc.y + 50);
        
        doc.addPage(); drawHeader(doc); doc.y = 135; doc.font('Helvetica-Bold').fontSize(10).text("GENERAL INSTRUCTIONS", 30, doc.y); doc.y += 15; doc.font('Helvetica').fontSize(8);
        const instructions = ["1. The work permit shall be filled up carefully.", "2. Appropriate safeguards and PPEs shall be determined.", "3. Requirement of standby personnel shall be mentioned.", "4. Means of communication must be available.", "5. Shift-wise communication to Main Control Room.", "6. Only certified vehicles and electrical equipment allowed.", "7. Welding machines shall be placed in ventilated areas.", "8. No hot work unless explosive meter reading is Zero.", "9. Standby person mandatory for confined space.", "10. Compressed gas cylinders not allowed inside.", "11. While filling trench, men/equipment must be outside.", "12. For renewal, issuer must ensure conditions are satisfactory.", "13. Max renewal up to 7 calendar days.", "14. Permit must be available at site.", "15. On completion, permit must be closed.", "16. Follow latest SOP for Trenching.", "17. CCTV and gas monitoring should be utilized.", "18. Refer to PLHO guidelines for details."];
        instructions.forEach(ins => { doc.text(ins, 30, doc.y); doc.y += 12; });

        const wm = p.Status.includes('Closed') ? 'CLOSED' : 'ACTIVE'; const color = p.Status.includes('Closed') ? '#ff0000' : '#00ff00';
        const range = doc.bufferedPageRange(); for(let i=0; i<range.count; i++) { doc.switchToPage(i); doc.save(); doc.rotate(-45, {origin:[300,400]}); doc.fontSize(80).fillColor(color).opacity(0.15).text(wm, 100, 350, {align:'center'}); doc.restore(); }
        doc.end();
    } catch (e) { res.status(500).send(e.message); }
});

app.listen(8080, () => console.log('Server Ready'));
