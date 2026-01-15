require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
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
function getNowIST() {
    return new Date().toLocaleString("en-GB", {
        timeZone: "Asia/Kolkata",
        day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
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

// --- CHECKLIST DATA ---
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
        "8. Attendant Trained Provided With Rescue Equipment/SCABA.",
        "9. Space Adequately Cooled for Safe Entry Of Person.",
        "10. Continuous Inert Gas Flow Arranged.",
        "11. Check For Earthing/ELCB of all Temporary Electrical Connections being used for welding.",
        "12. Gas Cylinders are kept outside the confined Space.",
        "13. Spark arrestor Checked on mobile Equipments.",
        "14. Welding Machine Checked for Safe Location.",
        "15. Permit taken for working at height Vide Permit No."
    ],
    C: ["1. PESO approved spark elimination system provided on the mobile equipment/ vehicle provided."],
    D: [
        "1. For excavated trench/ pit proper slop/ shoring/ shuttering provided to prevent soil collapse.",
        "2. Excavated soil kept at safe distance from trench/pit edge (min. pit depth).",
        "3. Safe means of access provided inside trench/pit.",
        "4. Movement of heavy vehicle prohibited."
    ]
};

// --- PDF DRAWING ---
function drawHeader(doc, bgColor, permitNoStr) {
    if(bgColor && bgColor !== 'Auto' && bgColor !== 'White') {
        const colorMap = { 'Red': '#fee2e2', 'Green': '#dcfce7', 'Yellow': '#fef9c3' };
        doc.save();
        doc.fillColor(colorMap[bgColor] || 'white');
        doc.rect(0, 0, doc.page.width, doc.page.height).fill();
        doc.restore();
    }
    const startX=30, startY=30;
    doc.lineWidth(1);
    doc.rect(startX,startY,535,95).stroke();
    // Logo Box (Left)
    doc.rect(startX,startY,80,95).stroke();
    if (fs.existsSync('logo.png')) {
        try {
            doc.image('logo.png', startX, startY, { fit: [80, 95], align: 'center', valign: 'center' });
        } catch (err) {
            console.error("Error loading logo:", err.message);
        }
    }

    doc.rect(startX+80,startY,320,95).stroke();
    doc.font('Helvetica-Bold').fontSize(11).fillColor('black').text('INDIAN OIL CORPORATION LIMITED', startX+80, startY+15, {width:320, align:'center'});
    doc.fontSize(9).text('EASTERN REGION PIPELINES', startX+80, startY+30, {width:320, align:'center'});
    doc.text('HSE DEPT.', startX+80, startY+45, {width:320, align:'center'});
    doc.fontSize(8).text('COMPOSITE WORK/ COLD WORK/HOT WORK/ENTRY TO CONFINED SPACE/VEHICLE ENTRY / EXCAVATION WORK AT MAINLINE/RCP/SV', startX+80, startY+65, {width:320, align:'center'});
    
    // Right Box
    doc.rect(startX+400,startY,135,95).stroke();
    doc.fontSize(8).font('Helvetica');
    doc.text('Doc No: ERPL/HS&E/25-26', startX+405, startY+60);
    doc.text('Issue No: 01', startX+405, startY+70);
    doc.text('Date: 01.09.2025', startX+405, startY+80);

    // (A) Permit No on All Pages
    if(permitNoStr) {
        doc.font('Helvetica-Bold').fontSize(10).fillColor('red');
        doc.text(`Permit No: ${permitNoStr}`, startX+405, startY+15, {width:130, align:'left'});
        doc.fillColor('black');
    }
}

// --- API ROUTES ---

app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().input('r', sql.NVarChar, req.body.role).input('e', sql.NVarChar, req.body.name).input('p', sql.NVarChar, req.body.password).query('SELECT * FROM Users WHERE Role=@r AND Email=@e AND Password=@p');
        if(r.recordset.length) res.json({success:true, user:{Name: r.recordset[0].Name, Email: r.recordset[0].Email, Role: r.recordset[0].Role}}); 
        else res.json({success:false});
    } catch(e){res.status(500).json({error:e.message})} 
});

app.get('/api/users', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().query('SELECT Name, Email, Role FROM Users');
        const mapU = u => ({name: u.Name, email: u.Email, role: u.Role});
        res.json({
            Requesters: r.recordset.filter(u=>u.Role==='Requester').map(mapU),
            Reviewers: r.recordset.filter(u=>u.Role==='Reviewer').map(mapU),
            Approvers: r.recordset.filter(u=>u.Role==='Approver').map(mapU)
        });
    } catch(e){res.status(500).json({error:e.message})} 
});

app.post('/api/add-user', async (req, res) => {
    try {
        const pool = await getConnection();
        const check = await pool.request().input('e', req.body.email).query("SELECT * FROM Users WHERE Email=@e");
        if(check.recordset.length) return res.status(400).json({error:"User Exists"});
        await pool.request().input('n', req.body.name).input('e', req.body.email).input('r', req.body.role).input('p', req.body.password).query("INSERT INTO Users (Name,Email,Role,Password) VALUES (@n,@e,@r,@p)");
        res.json({success:true});
    } catch(e){res.status(500).json({error:e.message})} 
});

// WORKER MANAGEMENT
app.post('/api/save-worker', async (req, res) => {
    try {
        const { WorkerID, Action, Role, Details, RequestorEmail, RequestorName, ApproverName } = req.body;
        const pool = await getConnection();
        if ((Action === 'create' || Action === 'edit_request') && Details && parseInt(Details.Age) < 18) return res.status(400).json({error: "Worker must be 18+"});

        if (Action === 'create') {
            const idRes = await pool.request().query("SELECT TOP 1 WorkerID FROM Workers ORDER BY WorkerID DESC");
            const wid = `W-${parseInt(idRes.recordset.length > 0 ? idRes.recordset[0].WorkerID.split('-')[1] : 1000) + 1}`;
            const dataObj = { Current: {}, Pending: { ...Details, RequestorName: RequestorName } }; 
            
            await pool.request()
                .input('w', wid).input('s', 'Pending Review').input('r', RequestorEmail)
                .input('j', JSON.stringify(dataObj))
                .input('idt', sql.NVarChar, Details.IDType) 
                .query("INSERT INTO Workers (WorkerID, Status, RequestorEmail, DataJSON, IDType) VALUES (@w, @s, @r, @j, @idt)");
            res.json({success:true});
        } 
        else if (Action === 'edit_request') {
            const cur = await pool.request().input('w', WorkerID).query("SELECT DataJSON FROM Workers WHERE WorkerID=@w");
            if(cur.recordset.length === 0) return res.status(404).json({error:"Worker not found"});
            let dataObj = JSON.parse(cur.recordset[0].DataJSON);
            dataObj.Pending = { ...dataObj.Current, ...Details, RequestorName: RequestorName || dataObj.Current.RequestorName };
            
            await pool.request()
                .input('w', WorkerID).input('s', 'Edit Pending Review').input('j', JSON.stringify(dataObj))
                .input('idt', sql.NVarChar, Details.IDType)
                .query("UPDATE Workers SET Status=@s, DataJSON=@j, IDType=@idt WHERE WorkerID=@w");
            res.json({success:true});
        }
        else if (Action === 'delete') {
            await pool.request().input('w', WorkerID).query("DELETE FROM Workers WHERE WorkerID=@w");
            res.json({success:true});
        }
        else {
            const cur = await pool.request().input('w', WorkerID).query("SELECT Status, DataJSON FROM Workers WHERE WorkerID=@w");
            if(cur.recordset.length === 0) return res.status(404).json({error:"Worker not found"});
            let st = cur.recordset[0].Status;
            let dataObj = JSON.parse(cur.recordset[0].DataJSON);

            let appBy = null; let appOn = null;

            if (Action === 'approve') {
                if (st.includes('Pending Review')) st = st.replace('Review', 'Approval');
                else if (st.includes('Pending Approval')) { 
                    st = 'Approved'; 
                    appBy = ApproverName;
                    appOn = getNowIST();
                    dataObj.Current = { ...dataObj.Pending, ApprovedBy: appBy, ApprovedAt: appOn };
                    dataObj.Pending = null; 
                }
            } else if (Action === 'reject') { st = 'Rejected'; dataObj.Pending = null; }
            
            await pool.request()
                .input('w', WorkerID).input('s', st).input('j', JSON.stringify(dataObj))
                .input('aby', sql.NVarChar, appBy).input('aon', sql.NVarChar, appOn)
                .query("UPDATE Workers SET Status=@s, DataJSON=@j, ApprovedBy=@aby, ApprovedOn=@aon WHERE WorkerID=@w");
            res.json({success:true});
        }
    } catch(e) { res.status(500).json({error: e.message}); }
});

app.post('/api/get-workers', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().query("SELECT * FROM Workers");
        const list = r.recordset.map(w => {
            const d = JSON.parse(w.DataJSON);
            const details = d.Pending || d.Current || {};
            details.IDType = w.IDType || details.IDType;
            details.ApprovedBy = w.ApprovedBy || details.ApprovedBy;
            details.ApprovedAt = w.ApprovedOn || details.ApprovedAt;
            return { ...details, WorkerID: w.WorkerID, Status: w.Status, RequestorEmail: w.RequestorEmail, IsEdit: w.Status.includes('Edit') };
        });
        if(req.body.context === 'permit_dropdown') res.json(list.filter(w => w.Status === 'Approved'));
        else {
            if(req.body.role === 'Requester') res.json(list.filter(w => w.RequestorEmail === req.body.email || w.Status === 'Approved'));
            else res.json(list);
        }
    } catch(e) { res.status(500).json({error: e.message}); }
});

app.post('/api/dashboard', async (req, res) => {
    try {
        const { role, email } = req.body;
        const pool = await getConnection();
        const r = await pool.request().query("SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON FROM Permits");
        const p = r.recordset.map(x=>({...JSON.parse(x.FullDataJSON), PermitID:x.PermitID, Status:x.Status, ValidFrom:x.ValidFrom}));
        const f = p.filter(x => (role==='Requester'?x.RequesterEmail===email : true));
        res.json(f.sort((a,b)=>b.PermitID.localeCompare(a.PermitID)));
    } catch(e){res.status(500).json({error:e.message})} 
});

// --- SAVE PERMIT (Corrected & Robust) ---
app.post('/api/save-permit', upload.none(), async (req, res) => {
    try {
        console.log("Received Permit Submit Request:", req.body.PermitID); // Debug Log

        // 1. Validate Dates robustly
        let vf, vt;
        try {
            vf = req.body.ValidFrom ? new Date(req.body.ValidFrom) : null;
            vt = req.body.ValidTo ? new Date(req.body.ValidTo) : null;
        } catch (err) {
            return res.status(400).json({ error: "Invalid Date Format" });
        }

        if (!vf || !vt) return res.status(400).json({ error: "Start and End dates are required" });
        if (vt <= vf) return res.status(400).json({ error: "End date must be after Start date" });
        if ((vt - vf) / (1000 * 60 * 60 * 24) > 7) return res.status(400).json({ error: "Max 7 days allowed" });
        
        const pool = await getConnection();
        
        // 2. ID Generation Logic
        let pid = req.body.PermitID;
        if (!pid || pid === 'undefined' || pid === 'null' || pid === '') {
            const idRes = await pool.request().query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
            // Check if table is empty
            const lastId = idRes.recordset.length > 0 ? idRes.recordset[0].PermitID : 'WP-1000';
            const numPart = parseInt(lastId.split('-')[1] || 1000);
            pid = `WP-${numPart + 1}`;
        }
        
        // 3. Status Check
        const chk = await pool.request().input('p', sql.NVarChar, pid).query("SELECT Status FROM Permits WHERE PermitID=@p");
        if(chk.recordset.length > 0) {
            const status = chk.recordset[0].Status;
            if (status === 'Closed' || status.includes('Closed')) return res.status(400).json({error: "Permit is CLOSED. Editing denied."});
            // Allow editing if New or Pending Review
        }
        
        // 4. Parse Workers
        let workers = req.body.SelectedWorkers;
        if (typeof workers === 'string') { try { workers = JSON.parse(workers); } catch (e) { workers = []; } }
        if (!Array.isArray(workers)) workers = [];

        // 5. Build Renewals Array (If requested)
        let renewalsArr = [];
        if(req.body.InitRen === 'Y') {
            renewalsArr.push({
                status: 'pending_review',
                valid_from: req.body.InitRenFrom || '',
                valid_till: req.body.InitRenTo || '',
                hc: req.body.InitRenHC || '', 
                toxic: req.body.InitRenTox || '', 
                oxygen: req.body.InitRenO2 || '',
                precautions: req.body.InitRenPrec || 'As per Permit',
                req_name: req.body.RequesterName || '',
                req_at: getNowIST(),
                worker_list: workers.map(w => w.Name) 
            });
        }
        const renewalsJsonStr = JSON.stringify(renewalsArr);

        // 6. Data Assembly
        const data = { ...req.body, SelectedWorkers: workers, PermitID: pid, CreatedDate: getNowIST(), GSR_Accepted: req.body.GSR_Accepted || 'Y' }; 
        
        // 7. Clean Geo Data (Prevent SQL errors on empty strings)
        let lat = req.body.Latitude; let lng = req.body.Longitude;
        const cleanGeo = (val) => (!val || val === 'undefined' || val === 'null' || String(val).trim() === '') ? null : String(val);
        
        const q = pool.request()
            .input('p', sql.NVarChar(50), pid)
            .input('s', sql.NVarChar(50), 'Pending Review')
            .input('w', sql.NVarChar(50), req.body.WorkType || '')
            .input('re', sql.NVarChar(100), req.body.RequesterEmail || '')
            .input('rv', sql.NVarChar(100), req.body.ReviewerEmail || '')
            .input('ap', sql.NVarChar(100), req.body.ApproverEmail || '')
            .input('vf', sql.DateTime, vf)
            .input('vt', sql.DateTime, vt)
            .input('lat', sql.NVarChar(50), cleanGeo(lat))
            .input('lng', sql.NVarChar(50), cleanGeo(lng))
            .input('j', sql.NVarChar(sql.MAX), JSON.stringify(data))
            .input('ren', sql.NVarChar(sql.MAX), renewalsJsonStr);

        if (chk.recordset.length > 0) {
            // Update Existing
            await q.query("UPDATE Permits SET FullDataJSON=@j, WorkType=@w, ValidFrom=@vf, ValidTo=@vt, Latitude=@lat, Longitude=@lng WHERE PermitID=@p");
        } else {
            // Insert New
            await q.query("INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, FullDataJSON, RenewalsJSON) VALUES (@p, @s, @w, @re, @rv, @ap, @vf, @vt, @lat, @lng, @j, @ren)");
        }
        
        console.log("Save Success:", pid);
        res.json({ success: true, permitId: pid });

    } catch (e) { 
        console.error("SERVER SAVE ERROR:", e); // THIS will show in your Azure Logs
        res.status(500).json({ error: e.message, stack: e.stack }); 
    }
});
app.post('/api/update-status', async (req, res) => {
    try {
        const { PermitID, action, role, user, comment, bgColor, IOCLSupervisors, FirstRenewalAction, ...extras } = req.body;
        const pool = await getConnection();
        const cur = await pool.request().input('p', PermitID).query("SELECT * FROM Permits WHERE PermitID=@p");
        if(cur.recordset.length === 0) return res.json({error: "Not found"});
        
        let st = cur.recordset[0].Status;
        if (st === 'Closed') {
            return res.status(400).json({error: "Permit is strictly CLOSED. No further actions allowed."});
        }

        let d = JSON.parse(cur.recordset[0].FullDataJSON);
        let renewals = JSON.parse(cur.recordset[0].RenewalsJSON || "[]");
        const now = getNowIST();

        // --- MERGE EXTRAS ---
        Object.assign(d, extras);
        if(bgColor) d.PdfBgColor = bgColor;
        if (IOCLSupervisors) d.IOCLSupervisors = IOCLSupervisors;
        if(req.body.Site_Restored_Check) d.Site_Restored_Check = req.body.Site_Restored_Check;

        if(comment) {
            if(role === 'Reviewer') d.Reviewer_Remarks = comment;
            if(role === 'Approver') d.Approver_Remarks = comment;
        }
        if(req.body.Closure_Requestor_Remarks) d.Closure_Requestor_Remarks = req.body.Closure_Requestor_Remarks;
        if(req.body.Closure_Reviewer_Remarks) d.Closure_Reviewer_Remarks = req.body.Closure_Reviewer_Remarks;
        if(req.body.Closure_Approver_Remarks) d.Closure_Approver_Remarks = req.body.Closure_Approver_Remarks;

        // --- 1ST RENEWAL LOGIC (Simultaneous Processing) ---
        // Only applies if there is exactly 1 renewal (the initial one) and we are in the main workflow
        if (renewals.length === 1 && FirstRenewalAction) {
            const ren = renewals[0];
            
            // If Reviewer is submitting a review (Permit Approved, Renewal Decision split)
            if (role === 'Reviewer' && action === 'review') {
                if (FirstRenewalAction === 'accept') {
                    ren.status = 'pending_approval'; // Move renewal to next stage
                    ren.rev_name = user;
                    ren.rev_at = now;
                } else if (FirstRenewalAction === 'reject') {
                    ren.status = 'rejected';
                    ren.rej_by = user;
                    ren.rej_at = now;
                    ren.rej_reason = "Rejected during 1st Review";
                    ren.rej_role = 'Reviewer';
                }
            }
            // If Approver is approving (Permit Approved, Renewal Decision split)
            else if (role === 'Approver' && action === 'approve') {
                if (ren.status !== 'rejected') { // Only act if reviewer didn't already reject it
                    if (FirstRenewalAction === 'accept') {
                        ren.status = 'approved';
                        ren.app_name = user;
                        ren.app_at = now;
                    } else if (FirstRenewalAction === 'reject') {
                        ren.status = 'rejected';
                        ren.rej_by = user;
                        ren.rej_at = now;
                        ren.rej_reason = "Rejected during 1st Approval";
                        ren.rej_role = 'Approver';
                    }
                }
            }
        }

        // --- MAIN PERMIT STATUS LOGIC ---
        if(action === 'reject_closure') {
            st = 'Active'; 
        }
        else if(action === 'approve_closure' && role === 'Reviewer') {
            st = 'Closure Pending Approval'; 
            d.Closure_Reviewer_Sig = `${user} on ${now}`;
            d.Closure_Reviewer_Date = now;
        }
        else if(action === 'approve' && role === 'Approver') {
            if(st.includes('Closure Pending Approval')) {
                st = 'Closed';
                d.Closure_Issuer_Sig = `${user} on ${now}`;
                d.Closure_Approver_Date = now;
            } else {
                st = 'Active';
                d.Approver_Sig = `${user} on ${now}`;
            }
        }
        else if(action === 'initiate_closure') {
            st = 'Closure Pending Review';
            d.Closure_Requestor_Date = now;
            d.Closure_Receiver_Sig = `${user} on ${now}`;
        }
        else if(action === 'reject') {
            st = 'Rejected';
            // If permit is rejected, reject any pending renewals too
            if(renewals.length > 0) {
                const last = renewals[renewals.length-1];
                if(last.status.includes('pending')) {
                    last.status = 'rejected';
                    last.rej_reason = "Parent Permit Rejected";
                }
            }
        }
        else if(role === 'Reviewer' && action === 'review') {
            st = 'Pending Approval';
            d.Reviewer_Sig = `${user} on ${now}`;
        }
        
        await pool.request()
            .input('p', PermitID)
            .input('s', st)
            .input('j', JSON.stringify(d))
            .input('r', JSON.stringify(renewals)) // Save updated renewals
            .query("UPDATE Permits SET Status=@s, FullDataJSON=@j, RenewalsJSON=@r WHERE PermitID=@p");
            
        res.json({success:true});
    } catch(e){
        res.status(500).json({error:e.message});
    } 
});
app.post('/api/renewal', async (req, res) => {
    try {
        const { PermitID, userRole, userName, action, rejectionReason, renewalWorkers, ...data } = req.body;
        const pool = await getConnection();
        const cur = await pool.request().input('p', PermitID).query("SELECT RenewalsJSON, Status, ValidFrom, ValidTo FROM Permits WHERE PermitID=@p");
        if (cur.recordset[0].Status === 'Closed') {
            return res.status(400).json({error: "Permit is CLOSED. Renewals are disabled."});
        }
        let r = JSON.parse(cur.recordset[0].RenewalsJSON||"[]"); 
        const now = getNowIST();

        if (userRole === 'Requester') {
            const rs = new Date(data.RenewalValidFrom); const re = new Date(data.RenewalValidTo);
            const pS = new Date(cur.recordset[0].ValidFrom); const pE = new Date(cur.recordset[0].ValidTo);
            
            if (re <= rs) return res.status(400).json({error: "Renewal End time must be later than Start time"});
            if (rs < pS || re > pE) return res.status(400).json({error: "Renewal must be within permit validity"});
            if ((re - rs) / 36e5 > 8) return res.status(400).json({error: "Max 8 hours per clearance"});
            
            if(r.length > 0) {
                const last = r[r.length-1];
                if(last.status !== 'rejected' && last.status !== 'approved') return res.status(400).json({error: "Previous renewal pending"});
                if(last.status !== 'rejected' && rs < new Date(last.valid_till)) return res.status(400).json({error: "Overlap detected"});
            }
            r.push({ 
                status: 'pending_review', 
                valid_from: data.RenewalValidFrom, 
                valid_till: data.RenewalValidTo, 
                hc: data.hc, toxic: data.toxic, oxygen: data.oxygen, precautions: data.precautions,
                req_name: userName, 
                req_at: now,
                worker_list: renewalWorkers || [] 
            });
        } else {
            const last = r[r.length-1];
            if (action === 'reject') { 
                last.status = 'rejected'; 
                last.rej_by = userName; 
                last.rej_at = now; 
                last.rej_reason = rejectionReason; 
                last.rej_role = userRole; 
            }
            else { 
                last.status = userRole==='Reviewer'?'pending_approval':'approved'; 
                if(userRole==='Reviewer') { last.rev_name = userName; last.rev_at = now; last.rev_rem = rejectionReason; }
                if(userRole==='Approver') { last.app_name = userName; last.app_at = now; last.app_rem = rejectionReason; }
            }
        }
        let newStatus = r[r.length-1].status==='approved'?'Active':(r[r.length-1].status==='rejected'?'Active':'Renewal Pending ' + (userRole==='Requester'?'Review':'Approval'));
        await pool.request().input('p', PermitID).input('r', JSON.stringify(r)).input('s', newStatus).query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/permit-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().input('p', sql.NVarChar, req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p"); if(r.recordset.length) res.json({...JSON.parse(r.recordset[0].FullDataJSON), Status:r.recordset[0].Status, RenewalsJSON:r.recordset[0].RenewalsJSON, FullDataJSON:null}); else res.json({error:"404"}); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/map-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status='Active'"); res.json(r.recordset.map(x=>({PermitID:x.PermitID, lat:parseFloat(x.Latitude), lng:parseFloat(x.Longitude), ...JSON.parse(x.FullDataJSON)}))); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/stats', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT Status, WorkType FROM Permits"); const s={}, t={}; r.recordset.forEach(x=>{s[x.Status]=(s[x.Status]||0)+1; t[x.WorkType]=(t[x.WorkType]||0)+1;}); res.json({success:true, statusCounts:s, typeCounts:t}); } catch(e){res.status(500).json({error:e.message})} });
app.get('/api/download-excel', async (req, res) => { try { const pool = await getConnection(); const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC"); const workbook = new ExcelJS.Workbook(); const sheet = workbook.addWorksheet('Permits'); sheet.columns = [{header:'Permit ID',key:'id',width:15},{header:'Status',key:'status',width:20},{header:'Work',key:'wt',width:25},{header:'Requester',key:'req',width:25},{header:'Location',key:'loc',width:30},{header:'Vendor',key:'ven',width:20},{header:'Valid From',key:'vf',width:20},{header:'Valid To',key:'vt',width:20}]; sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 }; sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFED7D31' } }; result.recordset.forEach(r => { const d = JSON.parse(r.FullDataJSON || "{}"); sheet.addRow({ id: r.PermitID, status: r.Status, wt: d.WorkType, req: d.RequesterName, loc: d.ExactLocation, ven: d.Vendor, vf: formatDate(r.ValidFrom), vt: formatDate(r.ValidTo) }); }); res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'); res.setHeader('Content-Disposition', 'attachment; filename=IndianOil_Permits.xlsx'); await workbook.xlsx.write(res); res.end(); } catch (e) { res.status(500).send(e.message); } });

// --- PDF GENERATION ROUTE ---
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('p', req.params.id).query("SELECT * FROM Permits WHERE PermitID = @p");
        if(!result.recordset.length) return res.status(404).send('Not Found');
        const p = result.recordset[0]; const d = JSON.parse(p.FullDataJSON);
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`);
        doc.pipe(res);

        const bgColor = d.PdfBgColor || 'White';
        // (A) Composite Permit No
        const compositePermitNo = `${d.IssuedToDept || 'DEPT'}/${p.PermitID}`;

        const drawHeaderOnAll = () => {
            drawHeader(doc, bgColor, compositePermitNo);
            doc.y = 135; 
            doc.fontSize(9).font('Helvetica');
        };

        drawHeaderOnAll();

        // Banner (Top of Page 1)
        if (fs.existsSync('safety_banner.png')) {
            try {
                doc.image('safety_banner.png', 30, doc.y, { width: 535, height: 100 });
                doc.y += 110; 
            } catch(err) { console.log("Error loading banner image:", err); }
        }

        // GSR Acceptance
        if(d.GSR_Accepted === 'Y') {
             doc.rect(30, doc.y, 535, 20).fillColor('#e6fffa').fill(); 
             doc.fillColor('black').stroke(); 
             doc.rect(30, doc.y, 535, 20).stroke(); 
             doc.font('Helvetica-Bold').fontSize(9).fillColor('#047857')
                .text("✓ I have read, understood and accepted the IOCL Golden Safety Rules terms and penalties.", 35, doc.y + 5);
             doc.y += 25;
             doc.fillColor('black');
        }

        doc.font('Helvetica-Bold').fontSize(10).text(`Permit No: ${compositePermitNo}`, 30, doc.y);
        doc.fontSize(9).font('Helvetica');
        doc.y += 15;
        const startY = doc.y;

        const dateFrom = formatDate(p.ValidFrom);
        const dateTo = formatDate(p.ValidTo);
        doc.text(`(i) Work clearance from: ${dateFrom}    To    ${dateTo} (Valid for the shift unless renewed).`, 30, doc.y);
        doc.y += 15;

        doc.text(`(ii) Issued to (Dept/Section/Contractor): ${d.IssuedToDept || '-'} / ${d.Vendor || '-'}`, 30, doc.y);
        doc.y += 15;

        const coords = d.ExactLocation || 'No GPS Data';
        const locDetail = d.WorkLocationDetail || '-';
        doc.text(`(iii) Exact Location of work (Area/RCP/SV/Chainage): ${locDetail} [GPS: ${coords}]`, 30, doc.y);
        doc.y += 15;

        doc.text(`(iv) Description of work: ${d.Desc || '-'}`, 30, doc.y, {width: 535});
        doc.y += 20;

        const siteContact = d.EmergencyContact || 'Not Provided';
        doc.text(`(v) Person from Contractor / Dept. at site (Name & Contact): ${d.RequesterName} / ${siteContact}`, 30, doc.y);
        doc.y += 15;

        doc.text(`(vi) Patrolling/ security Guard at site (Name & Contact): ${d.SecurityGuard || '-'}`, 30, doc.y);
        doc.y += 15;

        const jsa = d.JsaNo || '-';
        const wo = d.WorkOrder || '-';
        doc.text(`(vii) JSA Ref. No: ${jsa} | Cross-Reference/WO: ${wo}`, 30, doc.y);
        doc.y += 15;

        doc.text(`(viii) Name & contact no. of person in case of emergency: ${d.EmergencyContact || '-'}`, 30, doc.y);
        doc.y += 15;

        doc.text(`(ix) Nearest Fire station and Hospital: ${d.FireStation || '-'}`, 30, doc.y);
        doc.y += 20;

        doc.rect(25, startY - 5, 545, doc.y - startY + 5).stroke();
        doc.y += 10;
        
        // Checklists
        const drawChecklist = (t,i,pr) => { 
            if(doc.y>650){doc.addPage(); drawHeaderOnAll(); doc.y=135;} 
            doc.font('Helvetica-Bold').fillColor('black').fontSize(9).text(t,30,doc.y+10); doc.y+=25; 
            let y=doc.y;
            doc.rect(30,y,350,20).stroke().text("Item",35,y+5); doc.rect(380,y,60,20).stroke().text("Sts",385,y+5); doc.rect(440,y,125,20).stroke().text("Rem",445,y+5); y+=20;
            doc.font('Helvetica').fontSize(8);
            i.forEach((x,k)=>{
                let rowH = 20;
                if(pr === 'A' && k === 11) rowH = 45; 

                if(y + rowH > 750){doc.addPage(); drawHeaderOnAll(); doc.y=135; y=135;}
                const st = d[`${pr}_Q${k+1}`]||'NA';
                if(d[`${pr}_Q${k+1}`]) {
                    doc.rect(30,y,350,rowH).stroke().text(x,35,y+5,{width:340});
                    doc.rect(380,y,60,rowH).stroke().text(st,385,y+5); 
                    
                    let detailTxt = d[`${pr}_Q${k+1}_Detail`]||'';
                    if(pr === 'A' && k === 11) { 
                         const hc = d.GP_Q12_HC || '_';
                         const tox = d.GP_Q12_ToxicGas || '_';
                         const o2 = d.GP_Q12_Oxygen || '_';
                         detailTxt = `HC: ${hc}% LEL\nTox: ${tox} PPM\nO2: ${o2}%`;
                    }
                    doc.rect(440,y,125,rowH).stroke().text(detailTxt,445,y+5);
                    y+=rowH; 
                }
            }); doc.y=y;
        };
        drawChecklist("SECTION A: GENERAL", CHECKLIST_DATA.A,'A');
        drawChecklist("SECTION B : For Hot work / Entry to confined Space", CHECKLIST_DATA.B,'B');
        drawChecklist("SECTION C: For vehicle Entry in Hazardous area", CHECKLIST_DATA.C,'C'); drawChecklist("SECTION D: EXCAVATION", CHECKLIST_DATA.D,'D');

        if(doc.y>600){doc.addPage(); drawHeaderOnAll(); doc.y=135;}
        doc.font('Helvetica-Bold').fontSize(9).text("Annexure III: ATTACHMENT TO MAINLINE WORK PERMIT", 30, doc.y); doc.y+=15;
        
        // (E) Annexure III Table
        const annexData = [
            ["Approved SOP/SWP/SMP No", d.SopNo || '-'],
            ["Approved Site Specific JSA No", d.JsaNo || '-'],
            ["IOCL Equipment", d.IoclEquip || '-'],
            ["Contractor Equipment", d.ContEquip || '-'],
            ["Work Order", d.WorkOrder || '-'],
            ["Tool Box Talk", d.ToolBoxTalk || '-']
        ];

        let axY = doc.y;
        doc.font('Helvetica').fontSize(9);
        doc.fillColor('#eee');
        doc.rect(30, axY, 200, 20).fill().stroke();
        doc.rect(230, axY, 335, 20).fill().stroke();
        doc.fillColor('black');
        doc.font('Helvetica-Bold').text("Parameter", 35, axY+5);
        doc.text("Details", 235, axY+5);
        axY += 20;

        doc.font('Helvetica');
        annexData.forEach(row => {
            doc.rect(30, axY, 200, 20).stroke();
            doc.text(row[0], 35, axY+5);
            doc.rect(230, axY, 335, 20).stroke();
            doc.text(row[1], 235, axY+5);
            axY += 20;
        });
        doc.y = axY + 20;

        const drawSupTable = (title, headers, dataRows) => {
            if(doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y=135; }
             doc.font('Helvetica-Bold').text(title, 30, doc.y);
            doc.y += 15; 
            const headerHeight = 20; 
             let currentY = doc.y;
            let currentX = 30;
            headers.forEach(h => {
                doc.rect(currentX, currentY, h.w, headerHeight).stroke();
                doc.text(h.t, currentX + 2, currentY + 6, { width: h.w - 4, align: 'left' });
                currentX += h.w;
            });
            currentY += headerHeight;
            doc.font('Helvetica');
            dataRows.forEach(row => {
                let maxRowHeight = 20; 
                row.forEach((cell, idx) => {
                    const cellWidth = headers[idx].w - 4;
                    const textHeight = doc.heightOfString(cell, { width: cellWidth, align: 'left' });
                    if (textHeight + 10 > maxRowHeight) maxRowHeight = textHeight + 10;
                });
                if(currentY + maxRowHeight > 750) { 
                     doc.addPage(); drawHeaderOnAll(); currentY = 135; 
                 }
                let rowX = 30;
                row.forEach((cell, idx) => {
                    doc.rect(rowX, currentY, headers[idx].w, maxRowHeight).stroke();
                    doc.text(cell, rowX + 2, currentY + 5, { width: headers[idx].w - 4, align: 'left' });
                    rowX += headers[idx].w;
                });
                currentY += maxRowHeight;
            });
            doc.y = currentY + 15;
        };

        const ioclSups = d.IOCLSupervisors || [];
        let ioclRows = ioclSups.map(s => {
            let auditText = `Add: ${s.added_by||'-'} (${s.added_at||'-'})`;
            if(s.is_deleted) auditText += `\nDel: ${s.deleted_by} (${s.deleted_at})`;
            return [s.name, s.desig, s.contact, auditText];
        });
        if(ioclRows.length === 0) ioclRows.push(["-", "-", "-", "-"]);
        
        drawSupTable("Authorized Work Supervisor (IOCL)", [{t:"Name", w:130}, {t:"Designation", w:130}, {t:"Contact", w:100}, {t:"Audit Trail", w:175}], ioclRows);
        
        const contRows = [[d.RequesterName || '-', "Site In-Charge / Requester", d.EmergencyContact || '-']];
        drawSupTable("Authorized Work Supervisor (Contractor)", [{t:"Name", w:180}, {t:"Designation", w:180}, {t:"Contact", w:175}], contRows);

        if(doc.y>650){doc.addPage(); drawHeaderOnAll(); doc.y=135;}
        doc.font('Helvetica-Bold').text("HAZARDS & PRECAUTIONS",30,doc.y); doc.y+=15; doc.rect(30,doc.y,535,60).stroke();
        const hazKeys = ["Lack of Oxygen", "H2S", "Toxic Gases", "Combustible gases", "Pyrophoric Iron", "Corrosive Chemicals", "cave in formation"];
        const foundHaz = hazKeys.filter(k => d[`H_${k.replace(/ /g,'')}`] === 'Y');
        if(d.H_Others==='Y') foundHaz.push(`Others: ${d.H_Others_Detail}`);
        doc.text(`1.The activity has the following expected residual hazards: ${foundHaz.join(', ')}`,35,doc.y+5); 
        // (C) PPE Update
        const ppeKeys = ["Helmet","Safety Shoes","Hand gloves","Boiler suit","Face Shield","Apron","Goggles","Dust Respirator","Fresh Air Mask","Lifeline","Safety Harness","Airline","Earmuff","IFR"];
        const foundPPE = ppeKeys.filter(k => d[`P_${k.replace(/ /g,'')}`] === 'Y');
        if(d.AdditionalPrecautions && d.AdditionalPrecautions.trim() !== '') { foundPPE.push(`(Other: ${d.AdditionalPrecautions})`); }
        doc.text(`2.Following additional PPE to be used in addition to standards PPE: ${foundPPE.join(', ')}`,35,doc.y+25); doc.y+=70;

        // Workers Table (Updated)
        if(doc.y>650){doc.addPage(); drawHeaderOnAll(); doc.y=135;}
        doc.font('Helvetica-Bold').text("WORKERS DEPLOYED",30,doc.y); doc.y+=15; 
        let wy = doc.y;
        // (F) Adjusted columns for Gender
        doc.rect(30,wy,80,20).stroke().text("Name",35,wy+5); 
        doc.rect(110,wy,40,20).stroke().text("Gender",112,wy+5);
        doc.rect(150,wy,30,20).stroke().text("Age",152,wy+5); 
        doc.rect(180,wy,90,20).stroke().text("ID Details",182,wy+5); 
        doc.rect(270,wy,80,20).stroke().text("Requestor",272,wy+5);
        doc.rect(350,wy,215,20).stroke().text("Approved On / By",352,wy+5); 
        wy+=20;
        let workers = d.SelectedWorkers || [];
        if (typeof workers === 'string') { try { workers = JSON.parse(workers); } catch (e) { workers = []; } }
        doc.font('Helvetica').fontSize(8);
        workers.forEach(w => {
            if(wy>750){doc.addPage(); drawHeaderOnAll(); doc.y=135; wy=135;}
            doc.rect(30,wy,80,35).stroke().text(w.Name,35,wy+5); 
            doc.rect(110,wy,40,35).stroke().text(w.Gender||'-',112,wy+5); 
            doc.rect(150,wy,30,35).stroke().text(w.Age,152,wy+5); 
            doc.rect(180,wy,90,35).stroke().text(`${w.IDType || ''}: ${w.ID || '-'}`,182,wy+5); 
            doc.rect(270,wy,80,35).stroke().text(w.RequestorName || '-', 272,wy+5);
            doc.rect(350,wy,215,35).stroke().text(`${w.ApprovedAt || '-'} by ${w.ApprovedBy || 'Admin'}`, 352,wy+5); 
            wy+=35;
        });
        doc.y = wy+20;

        if(doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
        doc.font('Helvetica-Bold').text("SIGNATURES",30,doc.y); 
        doc.y+=15; const sY=doc.y;
        doc.rect(30,sY,178,40).stroke().text(`REQ: ${d.RequesterName} on ${d.CreatedDate||'-'}`,35,sY+5);
        doc.rect(208,sY,178,40).stroke().text(`REV: ${d.Reviewer_Sig||'-'}\nRem: ${d.Reviewer_Remarks||'-'}`, 213, sY+5, {width:168});
        doc.rect(386,sY,179,40).stroke().text(`APP: ${d.Approver_Sig||'-'}\nRem: ${d.Approver_Remarks||'-'}`, 391, sY+5, {width:169}); 
        doc.y=sY+50;

        if(doc.y>650){doc.addPage(); drawHeaderOnAll(); doc.y=135;}
        doc.font('Helvetica-Bold').text("CLEARANCE RENEWAL",30,doc.y); doc.y+=15;
        let ry = doc.y;
        doc.rect(30,ry,50,25).stroke().text("From",32,ry+5); doc.rect(80,ry,50,25).stroke().text("To",82,ry+5);
        doc.rect(130,ry,60,25).stroke().text("Gas",132,ry+5); doc.rect(190,ry,70,25).stroke().text("Precautions",192,ry+5);
        doc.rect(260,ry,70,25).stroke().text("Workers",262,ry+5);
        doc.rect(330,ry,75,25).stroke().text("Req",332,ry+5); doc.rect(405,ry,75,25).stroke().text("Rev",407,ry+5);
        doc.rect(480,ry,75,25).stroke().text("App",482,ry+5);
        ry+=25;
        const renewals = JSON.parse(p.RenewalsJSON || "[]");
        doc.font('Helvetica').fontSize(8);
        renewals.forEach(r => {
             if(ry>700){doc.addPage(); drawHeaderOnAll(); doc.y=135; ry=135;}
             const reqText = `${r.req_name}\n${r.req_at}`;
     
     let revText = r.rev_name ? `${r.rev_name}\n${r.rev_at}` : '-';
     if(r.rev_rem) revText += `\nRem: ${r.rev_rem}`; // Add Remark
     
     let appText = r.app_name ? `${r.app_name}\n${r.app_at}` : '-';
     if(r.app_rem) appText += `\nRem: ${r.app_rem}`; // Add Remark

     // Handle Rejection logic
     if (r.status === 'rejected') {
         const rejText = `REJECTED BY:\n${r.rej_by}\n${r.rej_at}\nReason: ${r.rej_reason}`;
         if (r.rej_role === 'Reviewer') revText = rejText; else appText = rejText;
     }
             doc.rect(30,ry,50,55).stroke().text(r.valid_from.replace('T','\n'), 32, ry+5, {width:48});
             doc.rect(80,ry,50,55).stroke().text(r.valid_till.replace('T','\n'), 82, ry+5, {width:48});
             doc.rect(130,ry,60,55).stroke().text(`HC: ${r.hc}\nTox: ${r.toxic}\nO2: ${r.oxygen}`, 132, ry+5, {width:58});
             doc.rect(190,ry,70,55).stroke().text(r.precautions||'-', 192, ry+5, {width:68});
             const wList = r.worker_list ? r.worker_list.join(', ') : 'All';
             doc.rect(260,ry,70,55).stroke().text(wList, 262, ry+5, {width:68});
             doc.rect(330,ry,75,55).stroke().text(`${r.req_name}\n${r.req_at}`, 332, ry+5, {width:73});
             let revText = `${r.rev_name||'-'}\n${r.rev_at||'-'}\nRem: ${r.rev_rem||'-'}`;
             let appText = `${r.app_name||'-'}\n${r.app_at||'-'}\nRem: ${r.app_rem||'-'}`;
             if (r.status === 'rejected') {
                 const rejText = `REJECTED BY:\n${r.rej_by}\n${r.rej_at}\nReason: ${r.rej_reason}`;
                 if (r.rej_role === 'Reviewer') revText = rejText; else appText = rejText;
             }
             doc.rect(405,ry,75,55).stroke().text(revText, 407, ry+5, {width:73});
             doc.rect(480,ry,75,55).stroke().text(appText, 482, ry+5, {width:73});
             ry += 55;
        });
        doc.y = ry + 20;

        if(doc.y>650){doc.addPage(); drawHeaderOnAll(); doc.y=135;}
        doc.font('Helvetica-Bold').text("CLOSURE OF WORK PERMIT",30,doc.y); doc.y+=15;
        let cy = doc.y;
        doc.rect(30,cy,80,20).stroke().text("Stage",35,cy+5); doc.rect(110,cy,120,20).stroke().text("Name/Sig",115,cy+5);
        doc.rect(230,cy,100,20).stroke().text("Date/Time",235,cy+5); doc.rect(330,cy,235,20).stroke().text("Remarks",335,cy+5);
        cy+=20;
        const closureSteps = [
            {role:'Requestor', name: d.Closure_Requestor_Sig || d.RequesterName, date:d.Closure_Requestor_Date, rem:d.Closure_Requestor_Remarks},
            {role:'Reviewer', name: d.Closure_Reviewer_Sig, date:d.Closure_Reviewer_Date, rem:d.Closure_Reviewer_Remarks},
            {role:'Approver', name: d.Closure_Approver_Sig || d.Closure_Issuer_Sig, date:d.Closure_Approver_Date, rem:d.Closure_Approver_Remarks}
        ];
        doc.font('Helvetica').fontSize(8);
        closureSteps.forEach(s => {
            doc.rect(30,cy,80,30).stroke().text(s.role,35,cy+5); 
            doc.rect(110,cy,120,30).stroke().text(s.name||'-',115,cy+5, {width:110}); 
            doc.rect(230,cy,100,30).stroke().text(s.date||'-',235,cy+5, {width:90}); 
            doc.rect(330,cy,235,30).stroke().text(s.rem||'-',335,cy+5, {width:225});
            cy+=30;
        });
        doc.y = cy + 20;

        if(doc.y>500){doc.addPage(); drawHeaderOnAll(); doc.y=135;} 
        doc.font('Helvetica-Bold').fontSize(10).text("GENERAL INSTRUCTIONS", 30, doc.y); 
        doc.y += 15; 
        doc.font('Helvetica').fontSize(8);
        const instructions = ["1. The work permit shall be filled up carefully.", "2. Appropriate safeguards and PPEs shall be determined.", "3. Requirement of standby personnel shall be mentioned.", "4. Means of communication must be available.", "5. Shift-wise communication to Main Control Room.", "6. Only certified vehicles and electrical equipment allowed.", "7. Welding machines shall be placed in ventilated areas.", "8. No hot work unless explosive meter reading is Zero.", "9. Standby person mandatory for confined space.", "10. Compressed gas cylinders not allowed inside.", "11. While filling trench, men/equipment must be outside.", "12. For renewal, issuer must ensure conditions are satisfactory.", "13. Max renewal up to 7 calendar days.", "14. Permit must be available at site.", "15. On completion, permit must be closed.", "16. Follow latest SOP for Trenching.", "17. CCTV and gas monitoring should be utilized.", "18. Refer to PLHO guidelines for details.", "19. This original permit must always be available with permit receiver.", "20. On completion of the work, the permit must be closed and the original copy of TBT, JSA, Permission etc. associated with permit to be handed over to Permit issuer", "21. A group shall be made for every work with SIC, EIC, permit issuer, Permit receiver, Mainline In charge and authorized contractor supervisor for digital platform", "22. The renewal of permits shall be done through confirmation by digital platform. However, the regularization on permits for renewal shall be done before closure of permit.", "23. No additional worker/supervisor to be engaged unless approved by Permit Receiver."]; 
        instructions.forEach(i => { doc.text(i, 30, doc.y); doc.y += 12; }); 

        // (G) Watermark (Status + Type)
        const wmStatus = p.Status.includes('Closed') ? 'CLOSED' : 'ACTIVE'; 
        const wmType = (p.WorkType || '').toUpperCase();
        const wm = `${wmStatus} - ${wmType}`; 
        const color = p.Status.includes('Closed') ? '#ef4444' : '#22c55e'; 
        const range = doc.bufferedPageRange(); 
        for(let i=0; i<range.count; i++) { doc.switchToPage(i); doc.save(); doc.rotate(-45, {origin:[300,400]}); doc.fontSize(60).fillColor(color).opacity(0.15).text(wm, 50, 350, {align:'center'}); doc.restore(); } 
        doc.end();
    } catch (e) { res.status(500).send(e.message); }
});

app.listen(8080, () => console.log('Server Ready'));
