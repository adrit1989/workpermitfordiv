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
let containerClient;
if (AZURE_CONN_STR) {
    try {
        const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN_STR);
        containerClient = blobServiceClient.getContainerClient("permit-attachments");
        (async () => { try { await containerClient.createIfNotExists(); } catch(e) {} })();
    } catch (err) { console.error("Blob Storage Error:", err.message); }
}
const upload = multer({ storage: multer.memoryStorage() });

// --- HELPERS ---
function getNowIST() { return new Date().toLocaleString("en-GB", { timeZone: "Asia/Kolkata", day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).replace(',', ''); }
function formatDate(dateStr) { if (!dateStr) return '-'; const d = new Date(dateStr); if (isNaN(d.getTime())) return dateStr; return d.toLocaleString("en-GB", { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).replace(',', ''); }

// --- CHECKLIST DATA (EXACTLY AS PER OISD-105) ---
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

// --- PDF DRAWING HELPERS ---
function drawHeader(doc) {
    const startX = 30; const startY = 30; const fullW = 535;
    doc.lineWidth(1);

    // Main Box
    doc.rect(startX, startY, fullW, 95).stroke();
    
    // Logo Area (Left)
    doc.rect(startX, startY, 80, 95).stroke();
    // doc.image('iocl_logo.png', startX + 15, startY + 25, {width: 50}); // Uncomment if logo exists

    // Title Area (Center)
    doc.rect(startX + 80, startY, 320, 95).stroke();
    doc.font('Helvetica-Bold').fontSize(12).text('INDIAN OIL CORPORATION LIMITED', startX + 80, startY + 15, {width: 320, align: 'center'});
    doc.fontSize(10).text('EASTERN REGION PIPELINES', startX + 80, startY + 30, {width: 320, align: 'center'});
    doc.text('HSE DEPT.', startX + 80, startY + 45, {width: 320, align: 'center'});
    doc.fontSize(9).text('COMPOSITE WORK PERMIT (OISD-105)', startX + 80, startY + 65, {width: 320, align: 'center'});

    // Doc Control Area (Right)
    const rightX = startX + 400;
    doc.rect(rightX, startY, 135, 95).stroke();
    doc.fontSize(8).font('Helvetica');
    doc.text('Doc No: ERPL/HS&E/25-26', rightX + 5, startY + 20);
    doc.text('Issue No: 01', rightX + 5, startY + 35);
    doc.text('Date: 01.09.2025', rightX + 5, startY + 50);
    doc.text('Rev No: 00', rightX + 5, startY + 65);
}

// --- API ROUTES ---

// LOGIN & USERS (Standard - No Change)
app.post('/api/login', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().input('r', sql.NVarChar, req.body.role).input('e', sql.NVarChar, req.body.name).input('p', sql.NVarChar, req.body.password).query('SELECT * FROM Users WHERE Role=@r AND Email=@e AND Password=@p'); if(r.recordset.length) res.json({success:true, user:r.recordset[0]}); else res.json({success:false}); } catch(e){res.status(500).json({error:e.message})} });
app.get('/api/users', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query('SELECT Name, Role, Email FROM Users'); res.json({ Requesters: r.recordset.filter(u=>u.Role==='Requester').map(u=>({name:u.Name,email:u.Email})), Reviewers: r.recordset.filter(u=>u.Role==='Reviewer').map(u=>({name:u.Name,email:u.Email})), Approvers: r.recordset.filter(u=>u.Role==='Approver').map(u=>({name:u.Name,email:u.Email})) }); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/dashboard', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON FROM Permits"); const p = r.recordset.map(x=>({...JSON.parse(x.FullDataJSON), PermitID:x.PermitID, Status:x.Status})); const f = p.filter(x => (req.body.role==='Requester'?x.RequesterEmail===req.body.email : (req.body.role==='Reviewer'?(x.ReviewerEmail===req.body.email && (x.Status.includes('Pending Review')||x.Status.includes('Closure')||x.Status.includes('Renewal'))) : (x.ApproverEmail===req.body.email)))); res.json(f.sort((a,b)=>b.PermitID.localeCompare(a.PermitID))); } catch(e){res.status(500).json({error:e.message})} });

// SAVE PERMIT (With ALL new fields)
app.post('/api/save-permit', upload.single('file'), async (req, res) => {
    try {
        const pool = await getConnection();
        let pid = req.body.PermitID && req.body.PermitID !== 'null' ? req.body.PermitID : null;
        let isUpdate = false;

        if (pid) {
            const c = await pool.request().input('p', sql.NVarChar, pid).query("SELECT Status FROM Permits WHERE PermitID=@p");
            if (c.recordset.length > 0 && (c.recordset[0].Status === 'Pending Review' || c.recordset[0].Status === 'New')) isUpdate = true;
            else if (c.recordset.length > 0) return res.status(400).json({error: "Cannot edit processed permit"});
            else pid = null;
        }

        if (!pid) {
            const idRes = await pool.request().query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
            pid = `WP-${parseInt(idRes.recordset.length > 0 ? idRes.recordset[0].PermitID.split('-')[1] : 1000) + 1}`;
        }

        const data = { ...req.body, PermitID: pid };
        const q = pool.request().input('p', sql.NVarChar, pid).input('s', sql.NVarChar, 'Pending Review').input('w', sql.NVarChar, req.body.WorkType)
            .input('re', sql.NVarChar, req.body.RequesterEmail).input('rv', sql.NVarChar, req.body.ReviewerEmail).input('ap', sql.NVarChar, req.body.ApproverEmail)
            .input('vf', sql.DateTime, new Date(req.body.ValidFrom)).input('vt', sql.DateTime, new Date(req.body.ValidTo))
            .input('j', sql.NVarChar, JSON.stringify(data));

        if (isUpdate) await q.query("UPDATE Permits SET FullDataJSON=@j, WorkType=@w, ReviewerEmail=@rv, ApproverEmail=@ap, ValidFrom=@vf, ValidTo=@vt WHERE PermitID=@p");
        else await q.query("INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, FullDataJSON, RenewalsJSON) VALUES (@p, @s, @w, @re, @rv, @ap, @vf, @vt, @j, '[]')");
        
        res.json({ success: true, permitId: pid });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// STATUS UPDATE & RENEWAL (Standard logic preserved)
app.post('/api/update-status', async (req, res) => { try { const pool = await getConnection(); const cur = await pool.request().input('p', sql.NVarChar, req.body.PermitID).query("SELECT * FROM Permits WHERE PermitID=@p"); if(!cur.recordset.length) return; let d = JSON.parse(cur.recordset[0].FullDataJSON); Object.assign(d, req.body); let st = cur.recordset[0].Status; const now = getNowIST(); 
    if(req.body.role==='Reviewer' && req.body.action==='review') { st='Pending Approval'; d.Reviewer_Sig=`${req.body.user} on ${now}`; }
    if(req.body.role==='Approver' && req.body.action==='approve') { st=st.includes('Closure')?'Closed':'Active'; if(!st.includes('Closed')) d.Approver_Sig=`${req.body.user} on ${now}`; else d.Closure_Issuer_Sig=`${req.body.user} on ${now}`; }
    if(req.body.action==='reject') { st='Rejected'; }
    if(req.body.action==='initiate_closure') { st='Closure Pending Review'; d.Closure_Requestor_Date=now; }
    await pool.request().input('p', req.body.PermitID).input('s', st).input('j', JSON.stringify(d)).query("UPDATE Permits SET Status=@s, FullDataJSON=@j WHERE PermitID=@p"); res.json({success:true}); } catch(e){res.status(500).json({error:e.message})} });

app.post('/api/renewal', async (req, res) => { try { const pool = await getConnection(); const cur = await pool.request().input('p', sql.NVarChar, req.body.PermitID).query("SELECT * FROM Permits WHERE PermitID=@p"); let r = JSON.parse(cur.recordset[0].RenewalsJSON||"[]"); 
    if(req.body.userRole==='Requester') { r.push({status:'pending_review', ...req.body, req_at: getNowIST()}); }
    else if(req.body.action==='reject') { r[r.length-1].status='rejected'; } 
    else { r[r.length-1].status = req.body.userRole==='Reviewer'?'pending_approval':'approved'; }
    await pool.request().input('p', req.body.PermitID).input('r', JSON.stringify(r)).input('s', r[r.length-1].status==='approved'?'Active':(r[r.length-1].status==='rejected'?'Active':(req.body.userRole==='Requester'?'Renewal Pending Review':'Renewal Pending Approval'))).query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p"); res.json({success:true}); } catch(e){res.status(500).json({error:e.message})} });

// PERMIT DATA
app.post('/api/permit-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().input('p', sql.NVarChar, req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p"); if(r.recordset.length) res.json({...JSON.parse(r.recordset[0].FullDataJSON), Status:r.recordset[0].Status, RenewalsJSON:r.recordset[0].RenewalsJSON}); else res.json({error:"404"}); } catch(e){res.status(500).json({error:e.message})} });


// ==========================================
// PDF GENERATION (EXACTLY AS PER FORMAT)
// ==========================================
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('pid', sql.NVarChar, req.params.id).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if(result.recordset.length === 0) return res.status(404).send('Not Found');
        
        const p = result.recordset[0];
        const d = JSON.parse(p.FullDataJSON);
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`);
        doc.pipe(res);

        // 1. PAGE 1 - INFO & CHECKLISTS
        drawHeader(doc);
        doc.y = 135; // Start below header
        
        doc.fontSize(9).font('Helvetica');
        
        // Info Table Logic
        const infoY = doc.y;
        const col1 = 40, col2 = 300;
        doc.text(`Permit No: ${p.PermitID}`, col1, infoY);
        doc.text(`Valid From: ${formatDate(p.ValidFrom)} To: ${formatDate(p.ValidTo)}`, col2, infoY);
        
        doc.text(`Issued To: ${d.IssuedToDept} (${d.Vendor || 'Self'})`, col1, infoY + 15);
        doc.text(`Location: ${d.ExactLocation} (${d.LocationUnit})`, col2, infoY + 15);
        
        doc.text(`Description: ${d.Desc}`, col1, infoY + 30, {width: 500});
        
        doc.text(`Site Person: ${d.RequesterName}`, col1, infoY + 60);
        doc.text(`Security/Patrol: ${d.SecurityGuard || '-'}`, col2, infoY + 60);
        
        doc.text(`Emergency Contact: ${d.EmergencyContact || '-'}`, col1, infoY + 75);
        doc.text(`Fire Stn/Hospital: ${d.FireStation || '-'}`, col2, infoY + 75);

        doc.rect(30, infoY - 5, 535, 95).stroke(); // Box around info
        doc.y = infoY + 100;

        // CHECKLIST TABLES
        const drawChecklistTable = (title, items, idPrefix) => {
            if(doc.y > 650) { doc.addPage(); drawHeader(doc); doc.y = 135; }
            
            doc.font('Helvetica-Bold').fontSize(10).text(title, 30, doc.y + 10);
            doc.y += 25;
            
            // Table Header
            let y = doc.y;
            doc.rect(30, y, 30, 20).stroke().text("SN", 35, y+5);
            doc.rect(60, y, 350, 20).stroke().text("Item / Condition", 65, y+5);
            doc.rect(410, y, 60, 20).stroke().text("Status", 415, y+5);
            doc.rect(470, y, 95, 20).stroke().text("Remarks", 475, y+5);
            y += 20;

            doc.font('Helvetica').fontSize(8);
            items.forEach((itemText, i) => {
                if(y > 750) { doc.addPage(); drawHeader(doc); doc.y = 135; y = 135; }
                
                const qId = `${idPrefix}_Q${i+1}`;
                const status = d[qId] === 'Yes' ? 'YES' : (d[qId] === 'NA' ? 'NA' : 'NO');
                // Special handling for Gas Test Q12 in Section A
                let remarks = d[`${idPrefix}_Q${i+1}_Detail`] || '';
                if(idPrefix === 'A' && i === 11) { // Index 11 is Q12
                    remarks = `HC:${d.GP_Q12_HC||0}% Tox:${d.GP_Q12_ToxicGas||0} O2:${d.GP_Q12_Oxygen||21}%`;
                }

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

        // HAZARDS & SIGNATURES PAGE
        doc.addPage(); drawHeader(doc); doc.y = 135;

        doc.font('Helvetica-Bold').fontSize(10).text("HAZARDS & PRECAUTIONS", 30, doc.y);
        doc.y += 15;
        doc.rect(30, doc.y, 535, 60).stroke();
        doc.fontSize(8).font('Helvetica');
        
        const hazKeys = ["H_H2S", "H_LackOxygen", "H_Corrosive", "H_ToxicGas", "H_Combustible", "H_Steam", "H_PyroIron", "H_N2Gas", "H_Height", "H_LooseEarth", "H_HighNoise", "H_Radiation"];
        const foundHazards = hazKeys.filter(k => d[k] === 'Y').map(k => k.replace('H_', ''));
        if(d.H_Other === 'Y') foundHazards.push(`Other: ${d.H_Other_Detail}`);
        
        doc.text(`Identified Hazards: ${foundHazards.join(', ') || 'None'}`, 35, doc.y + 5, {width: 525});
        doc.text(`Additional Precautions: ${d.AdditionalPrecautions || 'None'}`, 35, doc.y + 35, {width: 525});
        doc.y += 70;

        doc.font('Helvetica-Bold').fontSize(10).text("DIGITAL SIGNATURES (ISSUANCE)", 30, doc.y);
        doc.y += 15;
        const sigY = doc.y;
        doc.rect(30, sigY, 178, 50).stroke();
        doc.text("REQUESTER", 35, sigY + 5);
        doc.font('Helvetica').text(`${d.RequesterName}\n${formatDate(p.ValidFrom)}`, 35, sigY + 20);

        doc.rect(208, sigY, 178, 50).stroke();
        doc.font('Helvetica-Bold').text("SAFETY OFFICER (REVIEWER)", 213, sigY + 5);
        doc.font('Helvetica').text(d.Reviewer_Sig || 'Pending', 213, sigY + 20);

        doc.rect(386, sigY, 179, 50).stroke();
        doc.font('Helvetica-Bold').text("ISSUING AUTHORITY", 391, sigY + 5);
        doc.font('Helvetica').text(d.Approver_Sig || 'Pending', 391, sigY + 20);
        doc.y = sigY + 60;

        // RENEWALS
        doc.font('Helvetica-Bold').fontSize(10).text("CLEARANCE RENEWAL", 30, doc.y);
        doc.y += 15;
        // Header
        doc.rect(30, doc.y, 100, 20).stroke().text("Date/Time", 35, doc.y+5);
        doc.rect(130, doc.y, 150, 20).stroke().text("Readings (HC/Tox/O2)", 135, doc.y+5);
        doc.rect(280, doc.y, 285, 20).stroke().text("Signatures (Req / Safety / Issuer)", 285, doc.y+5);
        doc.y += 20;
        
        const renewals = JSON.parse(p.RenewalsJSON || "[]");
        doc.font('Helvetica').fontSize(8);
        renewals.forEach(r => {
             doc.rect(30, doc.y, 100, 30).stroke().text(`${formatDate(r.valid_from)}\nto\n${formatDate(r.valid_till)}`, 35, doc.y+5);
             doc.rect(130, doc.y, 150, 30).stroke().text(`HC:${r.hc} Tox:${r.toxic} O2:${r.oxygen}`, 135, doc.y+10);
             doc.rect(280, doc.y, 285, 30).stroke().text(`${r.req_name} | ${r.rev_name||'-'} | ${r.app_name||'-'}`, 285, doc.y+10);
             doc.y += 30;
        });
        doc.y += 20;

        // CLOSURE
        doc.font('Helvetica-Bold').fontSize(10).text("CLOSURE OF WORK PERMIT", 30, doc.y);
        doc.y += 15;
        doc.rect(30, doc.y, 535, 70).stroke();
        doc.fontSize(8);
        doc.text("1. RECEIVER: Certified that work is completed & area cleared.", 35, doc.y + 10);
        doc.font('Helvetica').text(`${d.Closure_Requestor_Remarks || '-'} (${d.Closure_Requestor_Date || ''})`, 300, doc.y + 10);
        
        doc.font('Helvetica-Bold').text("2. SAFETY: Verified area is safe.", 35, doc.y + 30);
        doc.font('Helvetica').text(`${d.Closure_Reviewer_Remarks || '-'} (${d.Closure_Reviewer_Date || ''})`, 300, doc.y + 30);
        
        doc.font('Helvetica-Bold').text("3. ISSUER: Permit Closed.", 35, doc.y + 50);
        doc.font('Helvetica').text(`${d.Closure_Approver_Remarks || '-'} (${d.Closure_Approver_Date || ''})`, 300, doc.y + 50);

        // GENERAL INSTRUCTIONS
        doc.addPage(); drawHeader(doc); doc.y = 135;
        doc.font('Helvetica-Bold').fontSize(10).text("GENERAL INSTRUCTIONS", 30, doc.y);
        doc.y += 15;
        doc.font('Helvetica').fontSize(8);
        const instructions = [
            "1. The work permit shall be filled up carefully and accurately.",
            "2. Appropriate safeguards and PPEs shall be determined prior to work.",
            "3. Requirement of standby personnel shall be mentioned.",
            "4. Means of communication must be available at site.",
            "5. Shift-wise communication to Main Control Room is mandatory.",
            "6. Only certified vehicles and electrical equipment allowed.",
            "7. Welding machines shall be placed in ventilated areas.",
            "8. No hot work permitted unless explosive meter reading is Zero.",
            "9. Standby person mandatory for confined space entry.",
            "10. Compressed gas cylinders not allowed inside confined spaces.",
            "11. While filling trench, men/equipment must be outside.",
            "12. For renewal, issuer must ensure conditions are satisfactory.",
            "13. Max renewal up to 7 calendar days.",
            "14. Permit must be available at site (Hard/Soft copy).",
            "15. On completion, permit must be closed and kept as record.",
            "16. Follow latest SOP for Trenching & Excavation.",
            "17. CCTV and gas monitoring devices should be utilized.",
            "18. Refer to PLHO guidelines for additional instructions."
        ];
        instructions.forEach(ins => {
            doc.text(ins, 30, doc.y);
            doc.y += 12;
        });

        // Watermark
        const wm = p.Status.includes('Closed') ? 'CLOSED' : 'ACTIVE';
        const color = p.Status.includes('Closed') ? '#ff0000' : '#00ff00';
        const range = doc.bufferedPageRange();
        for(let i=0; i<range.count; i++) {
            doc.switchToPage(i); doc.save(); 
            doc.rotate(-45, {origin:[300,400]}); 
            doc.fontSize(80).fillColor(color).opacity(0.15).text(wm, 100, 350, {align:'center'}); 
            doc.restore();
        }

        doc.end();
    } catch (e) { res.status(500).send(e.message); }
});

app.listen(8080, () => console.log('Server Ready on 8080'));
