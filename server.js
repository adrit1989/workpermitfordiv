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

// --- CHECKLIST DATA ---
const CHECKLIST_DATA = {
    A: ["1. Equipment / Work Area inspected.", "2. Surrounding area checked, cleaned. Oil/RAGS removed.", "3. Manholes, Sewers, CBD etc. covered.", "4. Hazards from other ops considered.", "5. Equipment blinded/isolated.", "6. Drained & Depressurized.", "7. Steamed/Purged.", "8. Water Flushed.", "9. Fire Tender Access.", "10. Iron Sulfide removed.", "11. Electrically Isolated.", "12. Gas Test: HC / Toxic / O2 checked.", "13. Fire Extinguisher / Water hose.", "14. Area cordoned off.", "15. CCTV Available.", "16. Ventilation/Lighting."],
    B: ["1. Means of Exit.", "2. Standby Personnel.", "3. Trapped Oil/Gas Check.", "4. Shield against spark.", "5. Portable equipment grounded.", "6. Confined Space Standby.", "7. Communication.", "8. Rescue Equip/SCBA.", "9. Space Cooled.", "10. Inert Gas Flow.", "11. Earthing/ELCB.", "12. Cylinders outside.", "13. Spark Arrestor.", "14. Welding Machine Loc.", "15. Height Permit."],
    C: ["1. PESO Approved Spark Arrestor on Vehicle."],
    D: ["1. Shoring/Sloping provided.", "2. Soil at safe distance.", "3. Safe Access.", "4. Heavy Vehicle Prohibited."]
};

// --- PDF HEADER ---
function drawHeader(doc) {
    const startX = 30, startY = 30, fullW = 535;
    doc.lineWidth(1);
    doc.rect(startX, startY, fullW, 95).stroke();
    doc.rect(startX, startY, 80, 95).stroke();
    doc.rect(startX + 80, startY, 320, 95).stroke();
    doc.font('Helvetica-Bold').fontSize(12).text('INDIAN OIL CORPORATION LIMITED', startX + 80, startY + 15, {width: 320, align: 'center'});
    doc.fontSize(10).text('EASTERN REGION PIPELINES', startX + 80, startY + 30, {width: 320, align: 'center'});
    doc.text('HSE DEPT.', startX + 80, startY + 45, {width: 320, align: 'center'});
    doc.fontSize(9).text('COMPOSITE WORK PERMIT (OISD-105)', startX + 80, startY + 65, {width: 320, align: 'center'});
    const rightX = startX + 400;
    doc.rect(rightX, startY, 135, 95).stroke();
    doc.fontSize(8).font('Helvetica');
    doc.text('Doc No: ERPL/HS&E/25-26', rightX + 5, startY + 60);
    doc.text('Date: 01.09.2025', rightX + 5, startY + 75);
}

// --- API ROUTES ---

app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().input('r', sql.NVarChar, req.body.role).input('e', sql.NVarChar, req.body.name).input('p', sql.NVarChar, req.body.password).query('SELECT * FROM Users WHERE Role=@r AND Email=@e AND Password=@p');
        if(r.recordset.length) {
             const u = r.recordset[0];
             res.json({success:true, user:{Name: u.Name||u.name, Email: u.Email||u.email, Role: u.Role||u.role}});
        } else res.json({success:false});
    } catch(e){res.status(500).json({error:e.message})} 
});

app.get('/api/users', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().query('SELECT Name, Email, Role FROM Users');
        const mapU = u => ({name: u.Name, email: u.Email});
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

app.post('/api/dashboard', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().query("SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON FROM Permits");
        const p = r.recordset.map(x=>({...JSON.parse(x.FullDataJSON), PermitID:x.PermitID, Status:x.Status, ValidFrom:x.ValidFrom, ValidTo:x.ValidTo}));
        
        const f = p.filter(x => {
            const st = (x.Status || "").toLowerCase();
            if (req.body.role==='Requester') return x.RequesterEmail === req.body.email;
            if (req.body.role==='Reviewer') return x.ReviewerEmail === req.body.email && (st.includes('pending review') || st.includes('closure') || st === 'closed' || st.includes('renewal'));
            if (req.body.role==='Approver') return x.ApproverEmail === req.body.email || st === 'active' || st === 'closed' || st.includes('renewal') || st.includes('closure');
            return false;
        });
        res.json(f.sort((a,b)=>b.PermitID.localeCompare(a.PermitID)));
    } catch(e){res.status(500).json({error:e.message})} 
});

app.post('/api/save-permit', upload.single('file'), async (req, res) => {
    try {
        const vf = new Date(req.body.ValidFrom); const vt = new Date(req.body.ValidTo);
        if ((vt-vf)/(1000*60*60*24) > 7) return res.status(400).json({ error: "Max 7 days allowed" });
        
        const pool = await getConnection();
        let pid = req.body.PermitID;
        if (!pid || pid === 'undefined' || pid === 'null' || pid === '') {
            const idRes = await pool.request().query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
            pid = `WP-${parseInt(idRes.recordset.length > 0 ? idRes.recordset[0].PermitID.split('-')[1] : 1000) + 1}`;
        }
        
        const chk = await pool.request().input('p', pid).query("SELECT Status FROM Permits WHERE PermitID=@p");
        if(chk.recordset.length > 0 && chk.recordset[0].Status !== 'Pending Review' && chk.recordset[0].Status !== 'New') {
            return res.status(400).json({error:"Cannot edit active permit"});
        }

        const data = { ...req.body, PermitID: pid };
        const q = pool.request().input('p', pid).input('s', 'Pending Review').input('w', req.body.WorkType).input('re', req.body.RequesterEmail).input('rv', req.body.ReviewerEmail).input('ap', req.body.ApproverEmail).input('vf', vf).input('vt', vt).input('j', JSON.stringify(data));
        
        if (chk.recordset.length > 0) await q.query("UPDATE Permits SET FullDataJSON=@j, WorkType=@w, ValidFrom=@vf, ValidTo=@vt WHERE PermitID=@p");
        else await q.query("INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, FullDataJSON, RenewalsJSON) VALUES (@p, @s, @w, @re, @rv, @ap, @vf, @vt, @j, '[]')");
        
        res.json({ success: true, permitId: pid });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

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
             if (rs < pStart || re > pEnd) return res.status(400).json({error: "Renewal must be within permit validity"});
             if ((re - rs) / 36e5 > 8) return res.status(400).json({error: "Max 8 hours per clearance"});
             
             if(r.length > 0) {
                 const last = r[r.length-1];
                 if(last.status === 'pending_review' || last.status === 'pending_approval') return res.status(400).json({error: "Previous renewal is pending."});
                 if(last.status !== 'rejected' && rs < new Date(last.valid_till)) return res.status(400).json({error: "Overlapping renewal."});
             }
             
             r.push({ 
                 status: 'pending_review', 
                 valid_from: data.RenewalValidFrom, valid_till: data.RenewalValidTo, 
                 hc: data.hc, toxic: data.toxic, oxygen: data.oxygen, 
                 precautions: data.precautions, 
                 req_name: userName, req_at: now 
             });
        } 
        else {
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

app.post('/api/update-status', async (req, res) => {
    try {
        const pool = await getConnection();
        const cur = await pool.request().input('p', req.body.PermitID).query("SELECT * FROM Permits WHERE PermitID=@p");
        let d = JSON.parse(cur.recordset[0].FullDataJSON);
        Object.assign(d, req.body);
        let st = cur.recordset[0].Status;
        const now = getNowIST();

        if(req.body.action==='reject') { st='Rejected'; }
        else if(req.body.role==='Reviewer' && req.body.action==='review') { st='Pending Approval'; d.Reviewer_Sig=`${req.body.user} on ${now}`; }
        else if(req.body.role==='Approver' && req.body.action==='approve') { 
            st = st.includes('Closure') ? 'Closed' : 'Active'; 
            if(st==='Closed') d.Closure_Issuer_Sig=`${req.body.user} on ${now}`; else d.Approver_Sig=`${req.body.user} on ${now}`;
        }
        else if(req.body.action==='initiate_closure') { st='Closure Pending Review'; d.Closure_Requestor_Date=now; }
        
        await pool.request().input('p', req.body.PermitID).input('s', st).input('j', JSON.stringify(d)).query("UPDATE Permits SET Status=@s, FullDataJSON=@j WHERE PermitID=@p");
        res.json({success:true});
    } catch(e){res.status(500).json({error:e.message})} 
});

app.post('/api/permit-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().input('p', req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p"); if(r.recordset.length) res.json({...JSON.parse(r.recordset[0].FullDataJSON), Status:r.recordset[0].Status, RenewalsJSON:r.recordset[0].RenewalsJSON, FullDataJSON:null}); else res.json({error:"404"}); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/map-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status='Active'"); res.json(r.recordset.map(x=>({PermitID:x.PermitID, lat:parseFloat(x.Latitude), lng:parseFloat(x.Longitude), ...JSON.parse(x.FullDataJSON)}))); } catch(e){res.status(500).json({error:e.message})} });
app.post('/api/stats', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT Status, WorkType FROM Permits"); const s={}, t={}; r.recordset.forEach(x=>{s[x.Status]=(s[x.Status]||0)+1; t[x.WorkType]=(t[x.WorkType]||0)+1;}); res.json({success:true, statusCounts:s, typeCounts:t}); } catch(e){res.status(500).json({error:e.message})} });
app.get('/api/download-excel', async (req, res) => { try { const pool = await getConnection(); const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC"); const workbook = new ExcelJS.Workbook(); const sheet = workbook.addWorksheet('Permits Summary'); sheet.columns = [{header:'Permit ID',key:'id',width:15},{header:'Status',key:'status',width:20},{header:'Work Type',key:'wt',width:25},{header:'Requester',key:'req',width:25},{header:'Location',key:'loc',width:30},{header:'Vendor',key:'ven',width:20},{header:'Valid From',key:'vf',width:20},{header:'Valid To',key:'vt',width:20}]; sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 }; sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFED7D31' } }; result.recordset.forEach(r => { const d = JSON.parse(r.FullDataJSON || "{}"); sheet.addRow({ id: r.PermitID, status: r.Status, wt: d.WorkType, req: d.RequesterName, loc: d.ExactLocation, ven: d.Vendor, vf: formatDate(r.ValidFrom), vt: formatDate(r.ValidTo) }); }); res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'); res.setHeader('Content-Disposition', 'attachment; filename=IndianOil_Permits.xlsx'); await workbook.xlsx.write(res); res.end(); } catch (e) { res.status(500).send(e.message); } });

// PDF
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('p', req.params.id).query("SELECT * FROM Permits WHERE PermitID = @p");
        if(!result.recordset.length) return res.status(404).send('Not Found');
        const p = result.recordset[0]; const d = JSON.parse(p.FullDataJSON);
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`); doc.pipe(res);

        // ... (Header and Checklists same as previous to maintain format) ...
        const drawHeader = () => {
             const startX=30, startY=30;
             doc.rect(startX,startY,535,95).stroke(); doc.rect(startX,startY,80,95).stroke(); doc.rect(startX+80,startY,320,95).stroke(); doc.rect(startX+400,startY,135,95).stroke();
             doc.font('Helvetica-Bold').fontSize(12).text('INDIAN OIL CORPORATION LIMITED', startX+80,startY+15,{width:320,align:'center'}); doc.fontSize(10).text('EASTERN REGION PIPELINES', startX+80,startY+30,{width:320,align:'center'}); doc.text('HSE DEPT.', startX+80,startY+45,{width:320,align:'center'}); doc.fontSize(9).text('COMPOSITE WORK PERMIT (OISD-105)', startX+80,startY+65,{width:320,align:'center'});
             doc.fontSize(8).font('Helvetica').text('Doc No: ERPL/HS&E/25-26',startX+405,startY+20).text('Date: 01.09.2025',startX+405,startY+50);
        };
        drawHeader(); doc.y=135; doc.fontSize(9).font('Helvetica');
        const infoY=doc.y; const c1=40, c2=300;
        doc.text(`Permit No: ${p.PermitID}`, c1, infoY).text(`Validity: ${formatDate(p.ValidFrom)} - ${formatDate(p.ValidTo)}`, c2, infoY);
        doc.text(`Issued To: ${d.IssuedToDept}`, c1, infoY+15).text(`Location: ${d.ExactLocation}`, c2, infoY+15);
        doc.text(`Desc: ${d.Desc}`, c1, infoY+30,{width:500}).text(`Site Person: ${d.RequesterName}`, c1, infoY+60).text(`Security: ${d.SecurityGuard}`, c2, infoY+60);
        doc.rect(30,infoY-5,535,95).stroke(); doc.y=infoY+100;

        const drawChecklist = (t,i,p) => { 
            if(doc.y>650){doc.addPage(); drawHeader(); doc.y=135;} 
            doc.font('Helvetica-Bold').text(t,30,doc.y+10); doc.y+=25; 
            let y=doc.y; doc.rect(30,y,350,20).stroke().text("Item",35,y+5); doc.rect(380,y,60,20).stroke().text("Sts",385,y+5); doc.rect(440,y,125,20).stroke().text("Rem",445,y+5); y+=20;
            doc.font('Helvetica').fontSize(8);
            i.forEach((x,k)=>{
                if(y>750){doc.addPage(); drawHeader(); doc.y=135; y=135;}
                doc.rect(30,y,350,20).stroke().text(x,35,y+5,{width:340});
                doc.rect(380,y,60,20).stroke().text(d[`${p}_Q${k+1}`]||'NA',385,y+5);
                doc.rect(440,y,125,20).stroke().text(d[`${p}_Q${k+1}_Detail`]||'',445,y+5); y+=20;
            }); doc.y=y;
        };
        drawChecklist("SECTION A", CHECKLIST_DATA.A,'A'); drawChecklist("SECTION B", CHECKLIST_DATA.B,'B'); drawChecklist("SECTION C", CHECKLIST_DATA.C,'C'); drawChecklist("SECTION D", CHECKLIST_DATA.D,'D');

        doc.addPage(); drawHeader(); doc.y=135;
        doc.font('Helvetica-Bold').text("HAZARDS & PRECAUTIONS",30,doc.y); doc.y+=15; doc.rect(30,doc.y,535,60).stroke();
        doc.text(`Hazards: ${d.H_Others_Detail||'None'}`,35,doc.y+5); doc.text(`PPE: Standard`,35,doc.y+25); doc.y+=70;

        doc.font('Helvetica-Bold').text("SIGNATURES",30,doc.y); doc.y+=15; const sY=doc.y;
        doc.rect(30,sY,178,40).stroke().text(`REQ: ${d.RequesterName}`,35,sY+5);
        doc.rect(208,sY,178,40).stroke().text(`REV: ${d.Reviewer_Sig||'-'}`,213,sY+5);
        doc.rect(386,sY,179,40).stroke().text(`APP: ${d.Approver_Sig||'-'}`,391,sY+5); doc.y=sY+50;

        // UPDATED RENEWAL TABLE (Format C)
        doc.font('Helvetica-Bold').text("CLEARANCE RENEWAL",30,doc.y); doc.y+=15;
        let ry = doc.y;
        // Header
        doc.rect(30,ry,60,25).stroke().text("From",32,ry+5);
        doc.rect(90,ry,60,25).stroke().text("To",92,ry+5);
        doc.rect(150,ry,100,25).stroke().text("Gas (HC/Tox/O2)",152,ry+5);
        doc.rect(250,ry,100,25).stroke().text("Precautions",252,ry+5);
        doc.rect(350,ry,70,25).stroke().text("Req (Name/Dt)",352,ry+5);
        doc.rect(420,ry,70,25).stroke().text("Rev (Name/Dt)",422,ry+5);
        doc.rect(490,ry,75,25).stroke().text("App (Name/Dt)",492,ry+5);
        ry += 25;
        
        const renewals = JSON.parse(p.RenewalsJSON || "[]");
        doc.font('Helvetica').fontSize(8);
        renewals.forEach(r => {
             doc.rect(30,ry,60,35).stroke().text(r.valid_from.replace('T','\n'), 32, ry+5);
             doc.rect(90,ry,60,35).stroke().text(r.valid_till.replace('T','\n'), 92, ry+5);
             doc.rect(150,ry,100,35).stroke().text(`${r.hc} / ${r.toxic} / ${r.oxygen}`, 152, ry+5);
             doc.rect(250,ry,100,35).stroke().text(r.precautions||'-', 252, ry+5);
             doc.rect(350,ry,70,35).stroke().text(`${r.req_name}\n${r.req_at}`, 352, ry+5);
             doc.rect(420,ry,70,35).stroke().text(`${r.rev_name||'-'}\n${r.rev_at||'-'}`, 422, ry+5);
             doc.rect(490,ry,75,35).stroke().text(`${r.app_name||'-'}\n${r.app_at||'-'}`, 492, ry+5);
             ry += 35;
        });
        doc.y = ry + 20;

        doc.font('Helvetica-Bold').text("CLOSURE",30,doc.y); doc.y+=15; doc.rect(30,doc.y,535,60).stroke();
        doc.text(`Receiver: ${d.Closure_Requestor_Remarks||'-'}`,35,doc.y+5);
        doc.text(`Safety: ${d.Closure_Reviewer_Remarks||'-'}`,35,doc.y+20);
        doc.text(`Issuer: ${d.Closure_Approver_Remarks||'-'}`,35,doc.y+35);
        
        const wm = p.Status.includes('Closed')?'CLOSED':'ACTIVE';
        const range = doc.bufferedPageRange(); for(let i=0; i<range.count; i++) { doc.switchToPage(i); doc.save(); doc.rotate(-45, {origin:[300,400]}); doc.fontSize(80).fillColor(p.Status.includes('Closed')?'#ef4444':'#22c55e').opacity(0.15).text(wm, 100, 350, {align:'center'}); doc.restore(); }
        doc.end();
    } catch (e) { res.status(500).send(e.message); }
});

app.listen(8080, () => console.log('Server Ready'));
