require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const { BlobServiceClient } = require('@azure/storage-blob');
const { getConnection, sql } = require('./db');

// SECURITY PACKAGES
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); 
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// APP SETUP
const app = express();
app.set('trust proxy', 1); 
app.use(cookieParser());

// CONFIG
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET || (process.env.JWT_SECRET + "_refresh");
const AZURE_CONN_STR = process.env.AZURE_STORAGE_CONNECTION_STRING;

// ENV VALIDATION
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET missing.");
  process.exit(1);
}

// MIDDLEWARE
app.use((req, res, next) => { 
  res.locals.nonce = crypto.randomBytes(16).toString('base64'); 
  next(); 
});

app.use(helmet({ contentSecurityPolicy: false })); 

const allowedOrigins = [
  "https://workpermitdivision-dwcahkbpbnc4fyah.centralindia-01.azurewebsites.net",
  "http://localhost:3000"
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!allowedOrigins.includes(origin)) return cb(null, true); 
    cb(null, true);
  },
  credentials: true
}));

app.use(bodyParser.json({ limit: '50mb' }));
app.use('/public', express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 10 * 1000, max: 200 });
app.use('/api/', limiter);

const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: 10 * 1024 * 1024 } 
});

let containerClient = null;
if (AZURE_CONN_STR) {
    try {
        const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN_STR);
        containerClient = blobServiceClient.getContainerClient("permit-attachments");
        (async () => { try { await containerClient.createIfNotExists(); } catch (e) {} })();
    } catch (err) { console.log("Blob Error:", err.message); }
}

/* =====================================================
   HELPER FUNCTIONS
===================================================== */
function getNowIST() { 
  return new Date().toLocaleString("en-GB", { 
    timeZone: "Asia/Kolkata", 
    day: '2-digit', month: '2-digit', year: 'numeric', 
    hour: '2-digit', minute: '2-digit', second: '2-digit', 
    hour12: false 
  }).replace(',', ''); 
}

function formatDate(d) { 
  if(!d) return '-'; 
  const dateObj = new Date(d);
  if (isNaN(dateObj.getTime())) return d;
  return dateObj.toLocaleString("en-GB", {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).replace(',', '');
}

async function uploadToAzure(buffer, blobName, mimeType = null) {
  if (!containerClient) return null;
  try {
      // Lazy load file-type to prevent crash if not installed immediately
      let type = null;
      try {
          const { fileTypeFromBuffer } = await import('file-type');
          type = await fileTypeFromBuffer(buffer);
      } catch (e) {
          console.warn("file-type not installed, skipping strict check");
          type = { mime: mimeType || 'image/jpeg' }; // Fallback
      }

      const blockBlobClient = containerClient.getBlockBlobClient(blobName);
      const options = type ? { blobHTTPHeaders: { blobContentType: type.mime } } : undefined;
      await blockBlobClient.uploadData(buffer, options);
      return blockBlobClient.url;
  } catch (err) {
      console.log("Azure upload error: " + err.message);
      return null;
  }
}

/* =====================================================
   AUTHENTICATION
===================================================== */
function createAccessToken(user) {
  const pwdTime = user.lastPwd || Math.floor(Date.now() / 1000);
  return jwt.sign({
    name: user.Name,
    email: user.Email,
    role: user.Role,
    region: user.Region,
    unit: user.Unit,
    location: user.Location,
    lastPwd: pwdTime
  }, JWT_SECRET, { expiresIn: "15m" }); 
}

function createRefreshToken(user) {
  return jwt.sign({ email: user.Email }, REFRESH_SECRET, { expiresIn: "30d" }); 
}

async function saveRefreshToken(email, token) {
  const pool = await getConnection();
  await pool.request()
    .input('e', email).input('t', token).input('exp', new Date(Date.now() + 30 * 24 * 3600 * 1000))
    .query("INSERT INTO UserRefreshTokens (Email, RefreshToken, ExpiresAt) VALUES (@e, @t, @exp)");
}

async function authenticateAccess(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ error: "No token" });

    jwt.verify(token, JWT_SECRET, async (err, decodedUser) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });

        const pool = await getConnection();
        const r = await pool.request()
            .input('e', sql.NVarChar, decodedUser.email)
            .query('SELECT LastPasswordChange FROM Users WHERE Email=@e');

        if (r.recordset.length === 0) return res.status(401).json({ error: "Unknown user" });

        const dbTimeRaw = r.recordset[0].LastPasswordChange;
        const dbLast = dbTimeRaw ? Math.floor(new Date(dbTimeRaw).getTime() / 1000) : 0;
        const tokenLast = decodedUser.lastPwd || 0;

        if (dbLast > (tokenLast + 120)) { 
            return res.status(401).json({ error: "Session expired due to password change" });
        }

        req.user = decodedUser;
        next();
    });
}

// LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request()
            .input('e', sql.NVarChar, req.body.email)
            .query('SELECT * FROM Users WHERE Email=@e');

        if (!r.recordset.length) return res.json({ success: false, msg: "User not found" });
        
        const user = r.recordset[0];
        const valid = await bcrypt.compare(req.body.password, user.Password);
        
        if (!valid) return res.json({ success: false, msg: "Invalid credentials" });
        
        if (user.ForcePwdChange === 'Y') {
            return res.json({ success: false, forceChange: true, email: user.Email });
        }

        const lastPwdTime = user.LastPasswordChange ? Math.floor(new Date(user.LastPasswordChange).getTime() / 1000) : 0;
        user.lastPwd = lastPwdTime;

        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);
        await saveRefreshToken(user.Email, refreshToken);

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            path: "/api/refresh"
        });

        res.json({ 
            success: true, 
            token: accessToken, 
            user: { 
                Name: user.Name, Email: user.Email, Role: user.Role, 
                Region: user.Region, Unit: user.Unit, Location: user.Location 
            } 
        });
    } catch (e) { 
        res.status(500).json({error: e.message}); 
    }
});

app.post('/api/force-password-change', async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        const pool = await getConnection();
        const hashed = await bcrypt.hash(newPassword, 10);
        await pool.request().input('e', email).input('p', hashed)
            .query("UPDATE Users SET Password=@p, ForcePwdChange='N', LastPasswordChange=GETDATE() WHERE Email=@e");
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: "Update failed" }); }
});

app.post('/api/admin/reset-password', authenticateAccess, async (req, res) => {
    try {
        const { targetEmail, newTempPass } = req.body;
        const pool = await getConnection();
        
        const target = await pool.request().input('e', targetEmail).query("SELECT CreatedBy FROM Users WHERE Email=@e");
        if(!target.recordset.length) return res.status(404).json({error: "User not found"});
        
        const tUser = target.recordset[0];
        let allow = false;
        if (req.user.role === 'MasterAdmin') allow = true;
        else if (req.user.role === 'Approver' && tUser.CreatedBy === req.user.email) allow = true;

        if (!allow) return res.status(403).json({ error: "Unauthorized" });

        const hashed = await bcrypt.hash(newTempPass, 10);
        await pool.request().input('e', targetEmail).input('p', hashed)
            .query("UPDATE Users SET Password=@p, ForcePwdChange='Y' WHERE Email=@e");

        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

/* =====================================================
   CRASH-PROOF PDF GENERATOR (UPDATED)
===================================================== */
async function drawPermitPDF(doc, p, d, renewalsList) {
    const workType = (d.WorkType || "PERMIT").toUpperCase();
    const status = p.Status || "Active";
    
    // Safety Helper
    const safeText = (t) => (t === null || t === undefined) ? '-' : String(t);

    let watermarkText = (status === 'Closed' || status.includes('Closure')) ? `CLOSED - ${workType}` : `ACTIVE - ${workType}`;

    const drawWatermark = () => {
        doc.save();
        doc.translate(doc.page.width / 2, doc.page.height / 2);
        doc.rotate(-45);
        doc.font('Helvetica-Bold').fontSize(60).fillColor('#ff0000').opacity(0.15);
        doc.text(watermarkText, -300, -30, { align: 'center', width: 600 });
        doc.restore();
        doc.opacity(1);
    };

    const bgColor = d.PdfBgColor || 'White';
    const permitPrefix = safeText(d.LocationUnit || 'LOC'); 
    const compositePermitNo = `${permitPrefix}/${p.PermitID}`;

    const drawHeader = (doc, bgColor, permitNoStr) => {
        if (bgColor && bgColor !== 'Auto' && bgColor !== 'White') {
            const colorMap = { 'Red': '#fee2e2', 'Green': '#dcfce7', 'Yellow': '#fef9c3' };
            doc.save();
            doc.fillColor(colorMap[bgColor] || 'white');
            doc.rect(0, 0, doc.page.width, doc.page.height).fill();
            doc.restore();
        }

        drawWatermark();

        const startX = 30, startY = 30;
        doc.lineWidth(1);
        doc.strokeColor('black');

        doc.rect(startX, startY, 535, 95).stroke();
        doc.rect(startX, startY, 80, 95).stroke();
        
        const logoPath = path.join(__dirname, 'public', 'logo.png');
        if (fs.existsSync(logoPath)) {
            try { 
                doc.image(logoPath, startX + 5, startY + 10, { fit: [70, 75], align: 'center', valign: 'center' }); 
            } catch (err) { }
        }

        doc.rect(startX + 80, startY, 320, 95).stroke();
        doc.font('Helvetica-Bold').fontSize(11).fillColor('black').text('INDIAN OIL CORPORATION LIMITED', startX + 80, startY + 15, { width: 320, align: 'center' });
        doc.fontSize(9).text('EASTERN REGION PIPELINES', startX + 80, startY + 30, { width: 320, align: 'center' });
        doc.text('HSE DEPT.', startX + 80, startY + 45, { width: 320, align: 'center' });
        doc.fontSize(8).text('COMPOSITE WORK/ COLD WORK/HOT WORK/ENTRY TO CONFINED SPACE/\nVEHICLE ENTRY / EXCAVATION WORK AT MAINLINE/RCP/SV', startX + 85, startY + 60, { width: 310, align: 'center' });

        doc.rect(startX + 400, startY, 135, 95).stroke();
        doc.fontSize(8).font('Helvetica-Bold');
        
        if (permitNoStr) {
            doc.fillColor('red');
            doc.text(`Permit No: ${permitNoStr}`, startX + 405, startY + 15, { width: 130, align: 'left' });
            doc.fillColor('black');
        }

        doc.font('Helvetica').fontSize(8);
        doc.text('Doc No: ERPL/HS&E/25-26', startX + 405, startY + 55);
        doc.text('Issue No: 01', startX + 405, startY + 70);
        doc.text(`Date: ${getNowIST().split(' ')[0]}`, startX + 405, startY + 85);
    };

    const drawHeaderOnAll = () => {
        drawHeader(doc, bgColor, compositePermitNo);
        doc.y = 135;
        doc.fontSize(9).font('Helvetica');
    };

    drawHeaderOnAll();

    // SAFETY BANNER
    const bannerPath = path.join(__dirname, 'public', 'safety_banner.png');
    if (fs.existsSync(bannerPath)) {
        try {
            doc.image(bannerPath, 30, doc.y, { width: 535, height: 120 });
            doc.y += 125;
        } catch (err) { }
    } else {
        doc.rect(30, doc.y, 535, 60).stroke();
        doc.font('Helvetica-Bold').fontSize(10).text("MANDATORY PPE & GOLDEN SAFETY RULES", 35, doc.y + 10, {align:'center'});
        doc.fontSize(8).font('Helvetica').text("1. Safety Helmet, Shoes, Coverall required. 2. No Mobile Phones. 3. Safe Driving.", 35, doc.y + 25, {align:'center'});
        doc.y += 65;
    }

    if (d.GSR_Accepted === 'Y') {
        doc.rect(30, doc.y, 535, 20).fillColor('#e6fffa').fill(); 
        doc.fillColor('black').stroke(); 
        doc.rect(30, doc.y, 535, 20).stroke(); 
        doc.font('Helvetica-Bold').fontSize(9).fillColor('#047857') 
           .text("I have read, understood and accepted the IOCL Golden Safety Rules terms and penalties.", 35, doc.y + 6);
        doc.y += 25;
        doc.fillColor('black');
    }

    doc.font('Helvetica-Bold').fontSize(10).text(`Permit No: ${compositePermitNo}`, 30, doc.y);
    doc.fontSize(9).font('Helvetica');
    doc.y += 5;
    
    const startY = doc.y;
    doc.text(`(i) Work clearance from: ${formatDate(p.ValidFrom)}    To    ${formatDate(p.ValidTo)}`, 35, doc.y);
    doc.y += 12;
    doc.text(`(ii) Issued to: ${safeText(d.IssuedToDept)} / ${safeText(d.Vendor)}`, 35, doc.y);
    doc.y += 12;
    doc.text(`(iii) Location: ${safeText(d.WorkLocationDetail)} [GPS: ${safeText(d.ExactLocation)}]`, 35, doc.y);
    doc.y += 12;
    doc.text(`(iv) Description: ${safeText(d.Desc)}`, 35, doc.y, { width: 525 });
    doc.y += 12;
    doc.text(`(v) Site Contact: ${safeText(d.RequesterName)} / ${safeText(d.EmergencyContact)}`, 35, doc.y);
    doc.y += 12;
    doc.text(`(vi) Security Guard: ${safeText(d.SecurityGuard)}`, 35, doc.y);
    doc.y += 12;
    doc.text(`(vii) JSA Ref: ${safeText(d.JsaNo)} | WO: ${safeText(d.WorkOrder)}`, 35, doc.y);
    doc.y += 12;
    doc.text(`(viii) Emergency: ${safeText(d.EmergencyContact)}`, 35, doc.y);
    doc.y += 12;
    doc.text(`(ix) Nearest Fire/Hospital: ${safeText(d.FireStation)}`, 35, doc.y);
    doc.y += 15;

    doc.rect(30, startY - 5, 535, doc.y - startY).stroke();
    doc.y += 10;

    // CHECKLISTS
    const CHECKLIST_DATA = {
        A: [ "1. Equipment/Work Area inspected.", "2. Surrounding area checked.", "3. Manholes covered.", "4. Hazards considered.", "5. Equipment blinded.", "6. Drained.", "7. Steamed.", "8. Flushed.", "9. Fire Access.", "10. Iron Sulfide.", "11. Electrical Isolation.", "12. Gas Test: HC / Toxic / O2 checked.", "13. Firefighting system.", "14. Cordoned off.", "15. CCTV.", "16. Ventilation." ],
        B: [ "1. Exit/Escape.", "2. Standby.", "3. Gas Check.", "4. Spark Shield.", "5. Grounding.", "6. Confined Standby.", "7. Communication.", "8. Rescue.", "9. Cooling.", "10. Inert Gas.", "11. ELCB.", "12. Cylinders.", "13. Spark arrestor.", "14. Welding Location.", "15. Height Permit." ],
        C: ["1. PESO approved spark elimination."],
        D: [ "1. Shoring/Sloping.", "2. Soil distance.", "3. Access.", "4. Vehicle ban." ]
    };

    const drawChecklistSection = (title, items, prefix) => {
        if (doc.y > 680) { doc.addPage(); drawHeaderOnAll(); }
        doc.font('Helvetica-Bold').fillColor('black').fontSize(9).text(title, 30, doc.y + 10); 
        doc.y += 25;
        let y = doc.y;
        doc.rect(30, y, 350, 20).stroke().text("Item", 35, y + 6); 
        doc.rect(380, y, 60, 20).stroke().text("Sts", 385, y + 6); 
        doc.rect(440, y, 125, 20).stroke().text("Rem", 445, y + 6); 
        y += 20;
        doc.font('Helvetica').fontSize(8);
        items.forEach((text, idx) => {
            const key = `${prefix}_Q${idx + 1}`;
            const statusVal = d[key] || 'NA';
            let rowHeight = 20;
            if (prefix === 'A' && idx === 11) rowHeight = 55;
            if (y + rowHeight > 760) { doc.addPage(); drawHeaderOnAll(); y = 135; }

            doc.rect(30, y, 350, rowHeight).stroke().text(text, 35, y + 6, { width: 340 });
            doc.rect(380, y, 60, rowHeight).stroke().text(safeText(statusVal), 385, y + 6);
            
            let remarkVal = d[`${key}_Rem`] || '';
            if (prefix === 'A' && idx === 11) {
                remarkVal = `HC: ${d.GP_Q12_HC || '0'}% LEL\nTox: ${d.GP_Q12_ToxicGas || '0'} PPM\nO2: ${d.GP_Q12_Oxygen || '20.9'}%`;
            }
            doc.rect(440, y, 125, rowHeight).stroke().text(safeText(remarkVal), 445, y + 6);
            y += rowHeight;
        });
        doc.y = y;
    };

    drawChecklistSection("SECTION A: GENERAL", CHECKLIST_DATA.A, 'A');
    drawChecklistSection("SECTION B: HOT / CONFINED", CHECKLIST_DATA.B, 'B');
    drawChecklistSection("SECTION C: VEHICLE", CHECKLIST_DATA.C, 'C'); 
    drawChecklistSection("SECTION D: EXCAVATION", CHECKLIST_DATA.D, 'D');

    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
    doc.y += 10;
    doc.font('Helvetica-Bold').fontSize(9).text("Annexure III: REFERENCES", 30, doc.y); 
    doc.y += 15;

    const annexData = [
        ["SOP / SWP No", d.SopNo],
        ["JSA No", d.JsaNo],
        ["IOCL Equipment", d.IoclEquip],
        ["Contractor Equipment", d.ContEquip],
        ["Work Order", d.WorkOrder],
        ["Tool Box Talk", d.ToolBoxTalk]
    ];

    let axY = doc.y;
    doc.font('Helvetica-Bold').fontSize(9);
    doc.fillColor('#eee');
    doc.rect(30, axY, 200, 20).fillAndStroke('black');
    doc.fillColor('black').text("Parameter", 35, axY + 6);
    doc.fillColor('#eee');
    doc.rect(230, axY, 335, 20).fillAndStroke('black');
    doc.fillColor('black').text("Details", 235, axY + 6);
    axY += 20;

    doc.font('Helvetica');
    annexData.forEach(row => {
        doc.rect(30, axY, 200, 20).stroke().text(safeText(row[0]), 35, axY + 6);
        doc.rect(230, axY, 335, 20).stroke().text(safeText(row[1]), 235, axY + 6);
        axY += 20;
    });
    doc.y = axY + 15;

    // 7. SUPERVISORS
    const drawSupTable = (title, headers, rows) => {
        if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
        doc.font('Helvetica-Bold').text(title, 30, doc.y);
        doc.y += 15;
        
        let y = doc.y;
        let x = 30;
        headers.forEach(h => {
            doc.rect(x, y, h.w, 20).stroke().text(h.t, x + 2, y + 6);
            x += h.w;
        });
        y += 20;

        doc.font('Helvetica');
        rows.forEach(row => {
            x = 30;
            let h = 25; 
            // Dynamic height adjustment for audit column if text is long
            if (row[3] && row[3].length > 40) h = 45; 
            if (y + h > 750) { doc.addPage(); drawHeaderOnAll(); y = 135; }
            
            row.forEach((cell, idx) => {
                doc.rect(x, y, headers[idx].w, h).stroke().text(safeText(cell), x + 2, y + 6, { width: headers[idx].w - 4 });
                x += headers[idx].w;
            });
            y += h;
        });
        doc.y = y + 15;
    };

    let ioclSups = [];
    if(d.IOCLSupervisors) {
        if(Array.isArray(d.IOCLSupervisors)) ioclSups = d.IOCLSupervisors;
        else if(typeof d.IOCLSupervisors === 'string') try { ioclSups = JSON.parse(d.IOCLSupervisors); } catch(e){}
    }

    // [MODIFICATION A] Enhanced Audit Trail
    let ioclRows = ioclSups.map(s => {
        let audit = `Added: ${s.added_by || 'Admin'} (${s.added_at || '-'})`;
        if (s.is_deleted) audit += `\nDel: ${s.deleted_by || 'Admin'} (${s.deleted_at || '-'})`;
        return [s.name, s.desig, s.contact, audit];
    });
    if(ioclRows.length === 0) ioclRows.push(["-", "-", "-", "-"]);
    drawSupTable("IOCL Supervisors", [{t:"Name",w:120}, {t:"Designation",w:120}, {t:"Contact",w:100}, {t:"Audit (Added/Deleted)",w:195}], ioclRows);

    const contRows = [[d.RequesterName, "Requester", d.EmergencyContact]];
    drawSupTable("Contractor Supervisors", [{t:"Name",w:180}, {t:"Designation",w:180}, {t:"Contact",w:175}], contRows);

    // 8. HAZARDS & PPE
    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
    doc.font('Helvetica-Bold').text("HAZARDS & PRECAUTIONS", 30, doc.y);
    doc.y += 15;
    doc.rect(30, doc.y, 535, 60).stroke();
    
    const hazKeys = ["Lack of Oxygen", "H2S", "Toxic Gases", "Combustible gases", "Pyrophoric Iron", "Corrosive Chemicals", "cave in formation"];
    let foundHaz = hazKeys.filter(k => d[`H_${k.replace(/ /g, '')}`] === 'Y');
    if (d.H_Others === 'Y') foundHaz.push(`Others: ${safeText(d.H_Others_Detail)}`);
    doc.font('Helvetica').fontSize(9).text(`1. Hazards: ${foundHaz.join(', ')}`, 35, doc.y + 6, {width: 520});
    
    const ppeKeys = ["Helmet", "Safety Shoes", "Hand gloves", "Boiler suit", "Face Shield", "Apron", "Goggles", "Dust Respirator", "Fresh Air Mask", "Lifeline", "Safety Harness", "Airline", "Earmuff", "IFR"];
    let foundPPE = ppeKeys.filter(k => d[`P_${k.replace(/ /g, '')}`] === 'Y');
    if (d.AdditionalPrecautions) foundPPE.push(`Other: ${safeText(d.AdditionalPrecautions)}`);
    doc.text(`2. PPE: ${foundPPE.join(', ')}`, 35, doc.y + 25, {width: 520});
    doc.y += 70;

    // 9. WORKERS
    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
    doc.font('Helvetica-Bold').text("WORKERS DEPLOYED", 30, doc.y);
    doc.y += 15;
    let wy = doc.y;
    const wHeaders = [
        {t:"Name", w:100}, {t:"Gender", w:50}, {t:"Age", w:40}, 
        {t:"ID Details", w:100}, {t:"Requestor", w:80}, {t:"Approved By", w:165}
    ];
    let wx = 30;
    wHeaders.forEach(h => { doc.rect(wx, wy, h.w, 20).stroke().text(h.t, wx+2, wy+6); wx += h.w; });
    wy += 20;

    let workers = [];
    if(d.SelectedWorkers) {
        if(Array.isArray(d.SelectedWorkers)) workers = d.SelectedWorkers;
        else if(typeof d.SelectedWorkers === 'string') try { workers = JSON.parse(d.SelectedWorkers); } catch(e){}
    }

    doc.font('Helvetica').fontSize(8);
    workers.forEach(w => {
        if (wy > 750) { doc.addPage(); drawHeaderOnAll(); wy = 135; }
        // [MODIFICATION B] Added Approved timestamp
        const approvedAudit = `${safeText(w.ApprovedBy)}\n${safeText(w.ApprovedOn || w.ApprovedAt || '')}`;

        doc.rect(30, wy, 100, 30).stroke().text(safeText(w.Name), 32, wy+5);
        doc.rect(130, wy, 50, 30).stroke().text(safeText(w.Gender), 132, wy+5);
        doc.rect(180, wy, 40, 30).stroke().text(safeText(w.Age), 182, wy+5);
        doc.rect(220, wy, 100, 30).stroke().text(`${safeText(w.IDType)}: ${safeText(w.ID)}`, 222, wy+5);
        doc.rect(320, wy, 80, 30).stroke().text(safeText(w.RequestorName), 322, wy+5);
        doc.rect(400, wy, 165, 30).stroke().text(approvedAudit, 402, wy+5);
        wy += 30;
    });
    doc.y = wy + 20;

    // 10. SIGNATURES / APPROVALS
    // [MODIFICATION C] Renamed Title & Added Explicit Fields
    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
    doc.font('Helvetica-Bold').fontSize(10).text("PERMIT APPROVAL", 30, doc.y);
    doc.y += 15;
    const sY = doc.y;

    // Format helpers
    const reqText = `REQ: ${safeText(d.RequesterName)}\nDate: ${safeText(d.CreatedDate)}`;
    const revText = `REV: ${safeText(d.Reviewer_Sig)}\nRem: ${safeText(d.Reviewer_Remarks)}`;
    const appText = `APP: ${safeText(d.Approver_Sig)}\nRem: ${safeText(d.Approver_Remarks)}`;

    doc.rect(30, sY, 178, 45).stroke().text(reqText, 35, sY+5);
    doc.rect(208, sY, 178, 45).stroke().text(revText, 213, sY+5);
    doc.rect(386, sY, 179, 45).stroke().text(appText, 391, sY+5);
    doc.y += 60;

    // 11. RENEWALS
    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
    doc.font('Helvetica-Bold').text("CLEARANCE RENEWAL", 30, doc.y);
    doc.y += 15;
    let ry = doc.y;
    // [MODIFICATION D] Updated Headers
    const rCols = [ {t:"From", w:50}, {t:"To", w:50}, {t:"Gas", w:80}, {t:"Workers", w:80}, {t:"Photo", w:60}, {t:"Req", w:70}, {t:"Rev", w:70}, {t:"App", w:75} ];
    let rx = 30;
    rCols.forEach(h => { doc.rect(rx, ry, h.w, 20).stroke().text(h.t, rx+2, ry+6); rx += h.w; });
    ry += 20;

    const finalRenewals = renewalsList || [];
    doc.font('Helvetica').fontSize(8);

    for (const r of finalRenewals) {
        if (ry > 700) { doc.addPage(); drawHeaderOnAll(); ry = 135; }
        const rH = 65; // Increased height for stacked data
        
        let rawFrom = r.valid_from || r.ValidFrom;
        let rawTo = r.valid_till || r.valid_to || r.ValidTo;
        
        let startT = safeText(rawFrom).replace('T', '\n');
        let endT = safeText(rawTo).replace('T', '\n'); 
        
        if (r.odd_hour_req) { doc.fillColor('purple'); endT += '\n(Night)'; } else doc.fillColor('black');

        doc.rect(30, ry, 50, rH).stroke().text(startT, 32, ry+5, {width:48});
        doc.rect(80, ry, 50, rH).stroke().text(endT, 82, ry+5, {width:48});
        doc.fillColor('black');
        doc.rect(130, ry, 80, rH).stroke().text(`HC:${safeText(r.hc)}/Tox:${safeText(r.toxic)}/O2:${safeText(r.oxygen)}\n${safeText(r.precautions)}`, 132, ry+5, {width:78});
        
        let wNames = 'All';
        if(r.worker_list && Array.isArray(r.worker_list)) wNames = r.worker_list.join(', ');
        doc.rect(210, ry, 80, rH).stroke().text(wNames, 212, ry+5, {width:78}); // Wrapped text

        doc.rect(290, ry, 60, rH).stroke();
        if (r.photoUrl && containerClient) {
            try {
                const blobName = r.photoUrl.split('/').pop();
                const blockBlob = containerClient.getBlockBlobClient(blobName);
                const downloadPromise = blockBlob.download(0);
                const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 2500));
                const response = await Promise.race([downloadPromise, timeoutPromise]);
                const chunks = [];
                for await (const chunk of response.readableStreamBody) { chunks.push(chunk); }
                const imgBuff = Buffer.concat(chunks);
                doc.image(imgBuff, 292, ry+2, {fit: [56, 56], align:'center', valign:'center'});
            } catch (e) { doc.text("Img Err", 290, ry+25, {width: 60, align:'center'}); }
        } else { 
            // [MODIFICATION D] Fixed Photo Text Alignment
            doc.text("No Photo", 290, ry+25, {width: 60, align:'center'}); 
        }

        // [MODIFICATION D] Stacked Name / Date / Rem
        // Req Column
        const reqStack = `${safeText(r.req_name)}\n${safeText(r.req_at)}\n${safeText(r.req_rem || '')}`;
        doc.rect(350, ry, 70, rH).stroke().text(reqStack, 352, ry+5, {width:68});

        // Rev Column
        const revStack = `${safeText(r.rev_name)}\n${safeText(r.rev_at || '')}\n${safeText(r.rev_rem || '')}`;
        doc.rect(420, ry, 70, rH).stroke().text(revStack, 422, ry+5, {width:68});

        // App Column
        const appStack = `${safeText(r.app_name)}\n${safeText(r.app_at || '')}\n${safeText(r.app_rem || '')}`;
        doc.rect(490, ry, 75, rH).stroke().text(appStack, 492, ry+5, {width:73});

        ry += rH;
    }
    doc.y = ry + 20;

    if (p.Status === 'Closed' || p.Status.includes('Closure') || d.Closure_Issuer_Sig) {
        if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
        doc.font('Helvetica-Bold').fontSize(10).text("WORK COMPLETION & CLOSURE", 30, doc.y);
        doc.y += 15;
        const cY = doc.y;
        const boxColor = d.Site_Restored_Check === 'Y' ? '#dcfce7' : '#fee2e2';
        const checkMark = d.Site_Restored_Check === 'Y' ? 'YES' : 'NO';
        
        doc.rect(30, cY, 535, 25).fillColor(boxColor).fill().stroke();
        doc.fillColor('black').text(`Site Restored? [ ${checkMark} ]`, 35, cY + 8);
        doc.y += 35;

        const closureY = doc.y;
        if (closureY > 700) { doc.addPage(); drawHeaderOnAll(); }
        doc.rect(30, closureY, 178, 50).stroke().text(`REQUESTOR:\n${d.Closure_Receiver_Sig || '-'}\nDate: ${d.Closure_Requestor_Date || '-'}\nRem: ${d.Closure_Requestor_Remarks || '-'}`, 35, closureY+5, {width:168});
        doc.rect(208, closureY, 178, 50).stroke().text(`REVIEWER:\n${d.Closure_Reviewer_Sig || '-'}\nDate: ${d.Closure_Reviewer_Date || '-'}\nRem: ${d.Closure_Reviewer_Remarks || '-'}`, 213, closureY+5, {width:168});
        doc.rect(386, closureY, 179, 50).stroke().text(`APPROVER:\n${d.Closure_Issuer_Sig || '-'}\nDate: ${d.Closure_Approver_Date || '-'}\nRem: ${d.Closure_Approver_Remarks || '-'}`, 391, closureY+5, {width:169});
    }
}

// DROPDOWN
app.post('/api/get-hierarchy', async (req, res) => {
    try {
        const { region, unit } = req.body;
        const pool = await getConnection();
        let query = "", param = "";
        if (!region) query = "SELECT DISTINCT Region FROM Users WHERE Region IS NOT NULL";
        else if (region && !unit) { query = "SELECT DISTINCT Unit FROM Users WHERE Region = @p"; param = region; }
        else query = "SELECT DISTINCT Location FROM Users WHERE Region = @p AND Unit = @u";

        const reqSql = pool.request();
        if(region) reqSql.input('p', sql.NVarChar, region);
        if(unit) reqSql.input('u', sql.NVarChar, unit);
        const r = await reqSql.query(query);
        let results = r.recordset.map(x => x[(!region ? 'Region' : (!unit ? 'Unit' : 'Location'))]);
        if(results.length === 0 && !region) results = ['ALL'];
        res.json(results);
    } catch (e) { res.status(500).json({error: e.message}); }
});

// FILTER USERS
app.post('/api/get-users-by-loc', async (req, res) => {
    try {
        const { region, unit, location, role } = req.body;
        const pool = await getConnection();
        if (role === 'MasterAdmin') {
             const r = await pool.request().query("SELECT Name, Email FROM Users WHERE Role='MasterAdmin'");
             return res.json(r.recordset);
        }
        const r = await pool.request()
            .input('r', region).input('u', unit).input('l', location).input('role', role)
            .query("SELECT Name, Email FROM Users WHERE Region=@r AND Unit=@u AND Location=@l AND Role=@role");
        res.json(r.recordset);
    } catch(e) { res.status(500).json({error:e.message}); }
});

// ADD USER
app.post('/api/add-user', authenticateAccess, async (req, res) => {
    if(req.user.role !== 'Approver' && req.user.role !== 'MasterAdmin') return res.sendStatus(403);
    try {
        const pool = await getConnection();
        const check = await pool.request().input('e', req.body.email).query("SELECT * FROM Users WHERE Email=@e");
        if(check.recordset.length) return res.status(400).json({error: "User Exists"});
        const hashed = await bcrypt.hash(req.body.password, 10);
        const reg = req.user.role === 'MasterAdmin' ? req.body.region : req.user.region;
        const unit = req.user.role === 'MasterAdmin' ? req.body.unit : req.user.unit;
        const loc = req.user.role === 'MasterAdmin' ? req.body.location : req.user.location;
        await pool.request().input('n', req.body.name).input('e', req.body.email).input('r', req.body.role).input('p', hashed)
            .input('reg', reg).input('u', unit).input('l', loc).input('cb', req.user.email)
            .query("INSERT INTO Users (Name,Email,Role,Password,Region,Unit,Location,CreatedBy,ForcePwdChange) VALUES (@n,@e,@r,@p,@reg,@u,@l,@cb,'Y')");
        res.json({success: true});
    } catch(e) { res.status(500).json({error: "Error Adding User"}); }
});

// DELETE USER
app.post('/api/delete-user', authenticateAccess, async (req, res) => {
    try {
        const targetEmail = req.body.email;
        const pool = await getConnection();
        const target = await pool.request().input('e', targetEmail).query("SELECT CreatedBy FROM Users WHERE Email=@e");
        if(!target.recordset.length) return res.status(404).json({error: "User not found"});
        const tUser = target.recordset[0];
        let allow = false;
        if (req.user.role === 'MasterAdmin') allow = true;
        else if (req.user.role === 'Approver' && tUser.CreatedBy === req.user.email) allow = true;
        if (!allow) return res.status(403).json({ error: "Unauthorized deletion" });
        await pool.request().input('e', targetEmail).query("DELETE FROM Users WHERE Email=@e");
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: "Delete failed" }); }
});

// BULK UPLOAD
app.post('/api/admin/bulk-upload', authenticateAccess, upload.single('excelFile'), async (req, res) => {
    if (req.user.role !== 'MasterAdmin') return res.status(403).json({ error: "Access Denied" });
    try {
        if (!req.file) return res.status(400).json({ error: "No file uploaded" });
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(req.file.buffer);
        const worksheet = workbook.getWorksheet(1);
        const pool = await getConnection();
        const usersToInsert = [];
        const existingUsersRes = await pool.request().query("SELECT Email FROM Users");
        const existingEmails = new Set(existingUsersRes.recordset.map(u => u.Email.toLowerCase().trim()));
        worksheet.eachRow((row, rowNumber) => {
            if (rowNumber === 1) return; 
            const getVal = (c) => (c.value && c.value.text ? c.value.text : (c.value ? c.value.toString() : null));
            const name = getVal(row.getCell(1));
            const emailRaw = getVal(row.getCell(2));
            const role = getVal(row.getCell(3));
            const rawPass = getVal(row.getCell(4)) || "Pass@123";
            const region = getVal(row.getCell(5));
            const unit = getVal(row.getCell(6));
            const loc = getVal(row.getCell(7));
            if (emailRaw && role && !existingEmails.has(emailRaw.toLowerCase().trim())) {
                usersToInsert.push({ name, email: emailRaw.trim(), role, rawPass, region, unit, loc });
                existingEmails.add(emailRaw.toLowerCase().trim());
            }
        });
        const promises = usersToInsert.map(async (u) => {
            const hashed = await bcrypt.hash(u.rawPass, 10);
            return pool.request().input('n', u.name).input('e', u.email).input('r', u.role).input('p', hashed)
                .input('reg', u.region).input('u', u.unit).input('l', u.loc).input('cb', req.user.email)
                .query(`INSERT INTO Users (Name, Email, Role, Password, Region, Unit, Location, CreatedBy, ForcePwdChange) VALUES (@n, @e, @r, @p, @reg, @u, @l, @cb, 'Y')`);
        });
        await Promise.all(promises);
        res.json({ success: true, count: usersToInsert.length });
    } catch (e) { res.status(500).json({ error: "Bulk Upload Failed: " + e.message }); }
});

// GET WORKERS
app.post('/api/get-workers', authenticateAccess, async(req, res) => {
    const { role, email } = req.user;
    const pool = await getConnection();
    const r = await pool.request().query("SELECT * FROM Workers");
    let workers = r.recordset.map(w => {
        let d = {}; 
        try { d = JSON.parse(w.DataJSON).Current || JSON.parse(w.DataJSON).Pending || {}; } catch(e){}
        return { ...d, WorkerID: w.WorkerID, Status: w.Status, RequestorEmail: w.RequestorEmail, ApprovedBy: w.ApprovedBy, ApprovedAt: w.ApprovedOn };
    });
    if (role === 'Requester') { workers = workers.filter(w => w.RequestorEmail === email); } 
    res.json(workers);
});

// SAVE WORKER
app.post('/api/save-worker', authenticateAccess, async (req, res) => {
    const { WorkerID, Action, Details, RequestorEmail } = req.body;
    const pool = await getConnection();
    try {
        if(Action === 'create') {
            if (Details && parseInt(Details.Age) < 18) return res.status(400).json({ error: "Worker must be 18+" });
            const idRes = await pool.request().query("SELECT TOP 1 WorkerID FROM Workers ORDER BY WorkerID DESC");
            const nextNum = parseInt(idRes.recordset.length ? idRes.recordset[0].WorkerID.split('-')[1] : 1000) + 1;
            const wid = `W-${nextNum}`; 
            const data = { Pending: { ...Details } };
            await pool.request().input('w', wid).input('s', 'Pending Review').input('r', RequestorEmail)
                .input('j', JSON.stringify(data)).input('idt', sql.NVarChar, Details.IDType)
                .query("INSERT INTO Workers (WorkerID, Status, RequestorEmail, DataJSON, IDType) VALUES (@w, @s, @r, @j, @idt)");
        } else if (Action === 'edit_request') {
            const cur = await pool.request().input('w', WorkerID).query("SELECT DataJSON FROM Workers WHERE WorkerID=@w");
            let d = JSON.parse(cur.recordset[0].DataJSON);
            d.Pending = { ...d.Current, ...Details }; 
            await pool.request().input('w', WorkerID).input('j', JSON.stringify(d)).input('s', 'Pending Review')
                .query("UPDATE Workers SET DataJSON=@j, Status=@s WHERE WorkerID=@w");
        } else if (Action === 'delete') {
            await pool.request().input('w', WorkerID).query("DELETE FROM Workers WHERE WorkerID=@w");
        } else if (Action === 'approve') {
            const cur = await pool.request().input('w', WorkerID).query("SELECT DataJSON FROM Workers WHERE WorkerID=@w");
            let d = JSON.parse(cur.recordset[0].DataJSON);
            d.Current = d.Pending; d.Pending = null;
            await pool.request().input('w', WorkerID).input('j', JSON.stringify(d)).input('s', 'Approved')
                .input('by', req.user.name).input('at', getNowIST())
                .query("UPDATE Workers SET DataJSON=@j, Status=@s, ApprovedBy=@by, ApprovedOn=@at WHERE WorkerID=@w");
        }
        res.json({ success: true });
    } catch(e) { res.status(500).json({error: e.message}); }
});

// DASHBOARD
app.post('/api/dashboard', authenticateAccess, async (req, res) => {
    const { role, email } = req.user;
    const pool = await getConnection();
    const r = await pool.request().query("SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON, FinalPdfUrl FROM Permits");
    const data = r.recordset.map(x => {
        let parsed = {};
        try { parsed = JSON.parse(x.FullDataJSON || "{}"); } catch (e) {}
        return { ...parsed, ...x, FinalPdfUrl: x.FinalPdfUrl };
    });
    const filtered = data.filter(p => {
        if(role === 'MasterAdmin') return true; 
        if(role === 'Requester') return p.RequesterEmail === email;
        if(role === 'Reviewer') return p.ReviewerEmail === email;
        if(role === 'Approver') return p.ApproverEmail === email;
        return true;
    });
    res.json(filtered.sort((a,b) => {
         const numA = parseInt(a.PermitID.split('-')[1] || 0);
         const numB = parseInt(b.PermitID.split('-')[1] || 0);
         return numB - numA; 
    }));
});

// SAVE PERMIT
app.post('/api/save-permit', authenticateAccess, upload.any(), async(req, res) => {
    const pool = await getConnection();
    const fd = req.body;
    if(!fd.WorkType || !fd.ValidFrom) return res.status(400).json({error: "Missing Data"});
    let pid = fd.PermitID;
    if (!pid || pid === 'undefined' || pid === '' || pid === 'null') {
        const idRes = await pool.request().query("SELECT MAX(CAST(SUBSTRING(PermitID, 4, 10) AS INT)) as MaxVal FROM Permits WHERE PermitID LIKE 'WP-%'");
        let nextNum = 1000;
        if (idRes.recordset[0].MaxVal) nextNum = idRes.recordset[0].MaxVal + 1;
        pid = `WP-${nextNum}`;
    }
    /* --- NEW JSA LOGIC START --- */
    let jsaUrl = null;
    if (req.files) {
        const jsaFile = req.files.find(f => f.fieldname === 'JsaFile');
        if(jsaFile) {
            jsaUrl = await uploadToAzure(jsaFile.buffer, `permit-jsa/${pid}-${Date.now()}.pdf`, 'application/pdf');
        }
    }
    const jsaLinkedId = fd.JsaLinkedId || null;
    /* --- NEW JSA LOGIC END --- */
    let rens = [];
    if(fd.InitRen === 'Y') {
        rens.push({ status: 'pending_review', valid_from: fd.InitRenFrom, valid_to: fd.InitRenTo, hc: fd.InitRenHC, toxic: fd.InitRenTox, oxygen: fd.InitRenO2, req_name: req.user.name, req_at: getNowIST() });
    }
    const q = pool.request().input('p', pid).input('s', 'Pending Review').input('w', fd.WorkType)
        .input('re', req.user.email).input('rv', fd.ReviewerEmail).input('ap', fd.ApproverEmail)
        .input('vf', new Date(fd.ValidFrom)).input('vt', new Date(fd.ValidTo))
        .input('j', JSON.stringify(fd)).input('ren', JSON.stringify(rens))
        /* NEW INPUTS */
        .input('jsaUrl', jsaUrl)
        .input('jsaId', jsaLinkedId);

    await q.query(`
        MERGE Permits AS target USING (SELECT @p as PermitID) AS source ON (target.PermitID = source.PermitID) 
        WHEN MATCHED THEN 
            UPDATE SET FullDataJSON=@j, Status=@s, RenewalsJSON=@ren,
            JsaFileUrl = COALESCE(@jsaUrl, JsaFileUrl), -- Update only if new file
            JsaLinkedId = @jsaId
        WHEN NOT MATCHED THEN 
            INSERT (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, FullDataJSON, RenewalsJSON, JsaFileUrl, JsaLinkedId) 
            VALUES (@p, @s, @w, @re, @rv, @ap, @vf, @vt, @j, @ren, @jsaUrl, @jsaId);
    `);

    res.json({success: true, permitId: pid});
});
app.post('/api/update-status', authenticateAccess, async(req, res) => {
    const { PermitID, action, ...extras } = req.body;
    const pool = await getConnection();
    const cur = await pool.request().input('p', PermitID).query("SELECT * FROM Permits WHERE PermitID=@p");
    if(!cur.recordset.length) return res.status(404).json({error: "Permit Not Found"});
    let p = cur.recordset[0];
    let d = JSON.parse(p.FullDataJSON);
    let rens = JSON.parse(p.RenewalsJSON || "[]");
    let st = p.Status;
    const now = getNowIST(); 
    const usr = req.user.name;
    Object.assign(d, extras);

    if (action === 'reject') st = 'Rejected';
    else if (action === 'review') { st = 'Pending Approval'; d.Reviewer_Sig = `${usr} on ${now}`; }
    else if (action === 'approve' && st.includes('Closure')) { st = 'Closed'; d.Closure_Approver_Date = now; d.Closure_Issuer_Sig = `${usr} on ${now}`; }
    else if (action === 'approve') { st = 'Active'; d.Approver_Sig = `${usr} on ${now}`; }
    else if (action === 'initiate_closure') { st = 'Closure Pending Review'; d.Closure_Requestor_Date = now; d.Closure_Receiver_Sig = `${usr} on ${now}`; }
    else if (action === 'reject_closure') { st = 'Active'; } 
    else if (action === 'approve_closure') { st = 'Closure Pending Approval'; d.Closure_Reviewer_Date = now; d.Closure_Reviewer_Sig = `${usr} on ${now}`; }

    if(action === 'approve_1st_ren' || action === 'approve' || action === 'review') {
        if(rens.length > 0 && rens[rens.length-1].status.includes('pending')) {
             let last = rens[rens.length-1];
             if(req.body.FirstRenewalAction === 'reject') { last.status = 'rejected'; if(st.includes('Renewal')) st = 'Active'; }
             else if(req.user.role === 'Reviewer') { last.status = 'pending_approval'; last.rev_name = usr; st = 'Pending Approval'; }
             else if(req.user.role === 'Approver') { last.status = 'approved'; last.app_name = usr; st = 'Active'; }
        }
    }

    // ARCHIVAL
    if (st === 'Closed') {
        try {
            const pdfRecord = { ...p, Status: 'Closed', PermitID: PermitID, ValidFrom: p.ValidFrom, ValidTo: p.ValidTo };
            const pdfBuffer = await new Promise((resolve, reject) => {
                const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
                const chunks = [];
                doc.on('data', chunks.push.bind(chunks));
                doc.on('end', () => resolve(Buffer.concat(chunks)));
                doc.on('error', reject);
                drawPermitPDF(doc, pdfRecord, d, rens).then(() => doc.end()).catch(reject);
            });
            const blobName = `closed-permits/${PermitID}_FINAL.pdf`;
            const finalPdfUrl = await uploadToAzure(pdfBuffer, blobName, "application/pdf");
            if (finalPdfUrl) {
                await pool.request().input('p', PermitID).input('url', finalPdfUrl).query("UPDATE Permits SET Status='Closed', FinalPdfUrl=@url, FullDataJSON=NULL, RenewalsJSON=NULL WHERE PermitID=@p");
                return res.json({ success: true, archived: true, pdfUrl: finalPdfUrl });
            }
        } catch(e) { console.error("PDF Fail", e); }
    }

    await pool.request().input('p', PermitID).input('s', st).input('j', JSON.stringify(d)).input('r', JSON.stringify(rens))
        .query("UPDATE Permits SET Status=@s, FullDataJSON=@j, RenewalsJSON=@r WHERE PermitID=@p");
    res.json({success: true});
});

// RENEWAL
app.post('/api/renewal', authenticateAccess, upload.single('RenewalImage'), async(req,res) => {
    const { PermitID, action, comment } = req.body; 
    const userRole = req.user.role; 
    const pool = await getConnection();
    const cur = await pool.request().input('p', PermitID).query("SELECT RenewalsJSON, ValidTo, Status FROM Permits WHERE PermitID=@p");
    if (!cur.recordset.length) return res.status(404).json({error: "Permit not found"});
    let rens = JSON.parse(cur.recordset[0].RenewalsJSON || "[]");
    let newStatus = cur.recordset[0].Status;
    
    if(action === 'initiate') {
        let url = null;
        if(req.file) url = await uploadToAzure(req.file.buffer, `${PermitID}-REN-${Date.now()}.jpg`);
        let workerList = [];
        try { workerList = JSON.parse(req.body.renewalWorkers || "[]"); } catch(e){}
        rens.push({ status: 'pending_review', valid_from: req.body.RenewalValidFrom, valid_to: req.body.RenewalValidTo, hc: req.body.hc, toxic: req.body.toxic, oxygen: req.body.oxygen, precautions: req.body.precautions, workers: workerList, req_name: req.user.name, req_at: getNowIST(), photoUrl: url, oddHourReq: req.body.oddHourReq || 'N' });
        newStatus = 'Renewal Pending Review';
    } else {
        if(rens.length === 0) return res.status(400).json({error: "No renewals found"});
        let last = rens[rens.length - 1]; 
        if (action === 'reject') { last.status = 'rejected'; last.rejection_reason = req.body.rejectionReason || comment || '-'; last.rejected_by = req.user.name; newStatus = 'Active'; }
        else if (action === 'approve' || action === 'forward_to_approver') {
            if (userRole === 'Reviewer') { last.status = 'pending_approval'; last.rev_name = req.user.name; last.rev_at = getNowIST(); last.rev_rem = comment || ''; if(last.oddHourReq === 'Y') last.rev_odd_hour_accepted = 'Y'; newStatus = 'Renewal Pending Approval'; } 
            else if (userRole === 'Approver') { last.status = 'approved'; last.app_name = req.user.name; last.app_at = getNowIST(); last.app_rem = comment || ''; newStatus = 'Active'; await pool.request().input('p', PermitID).input('vt', new Date(last.valid_to)).query("UPDATE Permits SET ValidTo=@vt WHERE PermitID=@p"); }
        }
    }
    await pool.request().input('p', PermitID).input('r', JSON.stringify(rens)).input('s', newStatus).query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p");
    res.json({success: true});
});

// EXCEL
app.get('/api/download-excel', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC");
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Permits');
    sheet.columns = [ { header:'ID', key:'id' }, { header:'Status', key:'status' }, { header:'Work', key:'wt' }, { header:'Requester', key:'req' }, { header:'Location', key:'loc' }, { header:'From', key:'vf' }, { header:'To', key:'vt' } ];
    result.recordset.forEach(r=>{ const d = r.FullDataJSON ? JSON.parse(r.FullDataJSON) : {}; sheet.addRow({ id:r.PermitID, status:r.Status, wt:d.WorkType, req:d.RequesterName, loc:d.ExactLocation, vf:formatDate(r.ValidFrom), vt:formatDate(r.ValidTo) }); });
    res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition','attachment; filename=Permits.xlsx');
    await workbook.xlsx.write(res); res.end();
  } catch (err) { res.status(500).send("Export Error"); }
});

// DOWNLOAD PDF
app.get('/api/download-pdf/:id', authenticateAccess, async(req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().input('p', req.params.id).query("SELECT * FROM Permits WHERE PermitID=@p");
        if(!r.recordset.length) return res.status(404).send("Not Found");
        const p = r.recordset[0];
        
        if ((p.Status==='Closed' || p.Status.includes('Closure')) && p.FinalPdfUrl && containerClient) {
            try {
                const blobName = `closed-permits/${p.PermitID}_FINAL.pdf`;
                const blockBlob = containerClient.getBlockBlobClient(blobName);
                if (await blockBlob.exists()) {
                    const download = await blockBlob.download(0);
                    res.setHeader('Content-Type','application/pdf');
                    res.setHeader('Content-Disposition',`attachment; filename=${p.PermitID}.pdf`);
                    return download.readableStreamBody.pipe(res);
                }
            } catch (err) { console.log("Archival fetch error, generating dynamic fallback."); }
        }

        const doc = new PDFDocument({ margin: 30, size: 'A4' });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`);
        doc.pipe(res);
        
        // SAFE PARSING
        const d = p.FullDataJSON ? JSON.parse(p.FullDataJSON) : {};
        const rens = p.RenewalsJSON ? JSON.parse(p.RenewalsJSON) : [];
        
        await drawPermitPDF(doc, p, d, rens);
        doc.end();
    } catch(err) {
        console.error("PDF Gen Error:", err);
        if(!res.headersSent) res.status(500).send("PDF Generation Failed");
    }
});

app.post('/api/permit-data', authenticateAccess, async(req, res) => {
    const pool = await getConnection();
    const r = await pool.request().input('p', req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p");
    if(!r.recordset.length) return res.json({error:"404"});
    const p = r.recordset[0];
    res.json({ ...JSON.parse(p.FullDataJSON), Status: p.Status, RenewalsJSON: p.RenewalsJSON, IOCLSupervisors: JSON.parse(p.FullDataJSON).IOCLSupervisors || [] });
});

app.post('/api/map-data', async(req,res) => {
    const pool = await getConnection();
    const r = await pool.request().query("SELECT PermitID, FullDataJSON, Status, Latitude, Longitude FROM Permits WHERE Status='Active' OR Status LIKE '%Renewal%'");
    res.json(r.recordset.map(x => ({ PermitID: x.PermitID, Status: x.Status, lat: x.Latitude, lng: x.Longitude, ...JSON.parse(x.FullDataJSON) })));
});
/* =====================================================
   JSA PORTAL ROUTES
===================================================== */

// 1. List JSAs for Dashboard
app.post('/api/jsa/list-my', authenticateAccess, async(req, res) => {
    const { role, email } = req.body;
    const pool = await getConnection();
    let q = "SELECT JSAID, RefNumber, JobTitle, Location, Status, RequesterName FROM JSAs ";
    
    // Filter logic
    if (role === 'Requester') q += "WHERE RequesterEmail = @e";
    else if (role === 'Reviewer') q += "WHERE ReviewerEmail = @e OR Status = 'Pending Review' OR Status = 'Approved'";
    else if (role === 'Approver') q += "WHERE ApproverEmail = @e OR Status = 'Pending Approval' OR Status = 'Approved'";
    else if (role !== 'MasterAdmin') q += "WHERE 1=0"; // Safety fallback
    
    const r = await pool.request().input('e', email).query(q + " ORDER BY JSAID DESC");
    res.json(r.recordset);
});

// 2. List Approved JSAs for Linking in Permit
app.post('/api/jsa/list-approved', authenticateAccess, async(req, res) => {
    const pool = await getConnection();
    const r = await pool.request()
        .input('r', req.body.region).input('u', req.body.unit)
        .query("SELECT RefNumber, JobTitle FROM JSAs WHERE Status='Approved' AND Region=@r AND Unit=@u ORDER BY JSAID DESC");
    res.json(r.recordset);
});

// 3. Get Single JSA Data
app.post('/api/jsa/get', authenticateAccess, async(req, res) => {
    const pool = await getConnection();
    const r = await pool.request().input('id', req.body.id).query("SELECT * FROM JSAs WHERE JSAID=@id");
    res.json(r.recordset[0]);
});

// 4. Save JSA (Create or Edit Draft)
app.post('/api/jsa/save', authenticateAccess, async(req, res) => {
    try { // <--- ADDED TRY BLOCK
        const { JSAID, DataJSON, ...fields } = req.body;
        const pool = await getConnection();
        
        let targetID = JSAID;
        if (!targetID) {
            const idRes = await pool.request().query("SELECT MAX(JSAID) as maxId FROM JSAs");
            const nextId = (idRes.recordset[0].maxId || 1000) + 1;
            
            await pool.request().input('id', nextId).input('reqE', fields.RequesterEmail)
                .query("INSERT INTO JSAs (JSAID, Status, RequesterEmail, CreatedAt) VALUES (@id, 'Draft', @reqE, GETDATE())");
            targetID = nextId;
        }

        const status = 'Pending Review'; 
        
        await pool.request()
            .input('id', targetID)
            .input('jt', fields.JobTitle).input('ex', fields.ExecutedBy)
            .input('re', fields.ReviewerEmail).input('ae', fields.ApproverEmail)
            .input('reqE', fields.RequesterEmail).input('reqN', fields.RequesterName)
            .input('reg', fields.Region).input('u', fields.Unit).input('l', fields.Location)
            .input('d', DataJSON).input('s', status)
            .query(`UPDATE JSAs SET JobTitle=@jt, ExecutedBy=@ex, ReviewerEmail=@re, ApproverEmail=@ae, 
                    RequesterEmail=@reqE, RequesterName=@reqN, Region=@reg, Unit=@u, Location=@l, 
                    DataJSON=@d, Status=@s WHERE JSAID=@id`);
                    
        res.json({ success: true });
    } catch (e) {
        console.error("JSA Save Error:", e); // <--- LOGS ERROR TO CONSOLE
        res.status(500).json({ error: "Database Error: " + e.message }); // <--- SENDS ERROR TO FRONTEND INSTEAD OF CRASHING
    }
});
// 5. Action (Review/Approve/Reject)
app.post('/api/jsa/action', authenticateAccess, async(req, res) => {
    const { id, action, remarks, updatedData } = req.body;
    const pool = await getConnection();
    
    let newStatus = '';
    let extraSql = ''; 
    const now = getNowIST();

    if (action === 'reject') newStatus = 'Rejected';
    else if (action === 'approve' && req.user.role === 'Reviewer') newStatus = 'Pending Approval';
    else if (action === 'approve' && req.user.role === 'Approver') newStatus = 'Approved';

    if (newStatus === 'Approved') {
        const ref = `JSA-${req.user.unit}-${id}`;
        
        // Generate PDF
        const r = await pool.request().input('id', id).query("SELECT * FROM JSAs WHERE JSAID=@id");
        const jsaData = r.recordset[0];
        jsaData.DataJSON = updatedData; 
        
        const pdfBuffer = await generateJsaPdfBuffer(jsaData, ref, req.user.name, now);
        const url = await uploadToAzure(pdfBuffer, `jsa/${ref}.pdf`, 'application/pdf');
        
        extraSql = `, RefNumber='${ref}', FinalPdfUrl='${url}', ApprovedBy='${req.user.name}', ApprovedAt='${now}'`;
    } else if (req.user.role === 'Reviewer' && action === 'approve') {
        extraSql = `, ReviewedBy='${req.user.name}', ReviewedAt='${now}'`;
    }

    await pool.request()
        .input('id', id).input('s', newStatus).input('d', updatedData) 
        .query(`UPDATE JSAs SET Status=@s, DataJSON=@d ${extraSql} WHERE JSAID=@id`);
        
    res.json({ success: true });
});

// 6. Download JSA PDF
app.get('/api/jsa/download/:id', authenticateAccess, async(req, res) => {
    const pool = await getConnection();
    const r = await pool.request().input('id', req.params.id).query("SELECT FinalPdfUrl FROM JSAs WHERE JSAID=@id");
    if(r.recordset[0] && r.recordset[0].FinalPdfUrl) {
         // Assuming you have a function to fetch from Azure, or just redirect
         // Ideally use the same logic as download-pdf permit to stream securely
         const blobName = r.recordset[0].FinalPdfUrl.split('/').pop();
         // ... (Insert Blob Download Stream Logic Here) ...
         // For now, if public access allowed: res.redirect(r.recordset[0].FinalPdfUrl);
         res.json({url: r.recordset[0].FinalPdfUrl}); // Simplified
    } else {
        res.status(404).send("PDF not found");
    }
});

async function generateJsaPdfBuffer(jsa, refNo, approverName, approvedDate) {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: 30, size: 'A4' });
        const chunks = [];
        doc.on('data', chunks.push.bind(chunks));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        const data = JSON.parse(jsa.DataJSON);
        const team = data.team || [];
        const steps = data.steps || [];

        // Header
        doc.font('Helvetica-Bold').fontSize(14).text('JOB SAFETY ANALYSIS', { align: 'center' });
        doc.fontSize(10).text('IndianOil Corporation Limited', { align: 'center' });
        doc.moveDown();
        
        // Info Box
        const startY = doc.y;
        doc.rect(30, startY, 535, 70).stroke();
        doc.fontSize(9).text(`Ref: ${refNo}`, 35, startY+10);
        doc.text(`Date: ${approvedDate}`, 400, startY+10);
        doc.text(`Job: ${jsa.JobTitle}`, 35, startY+25);
        doc.text(`Loc: ${jsa.Location}`, 35, startY+40);
        doc.text(`Executed By: ${jsa.ExecutedBy}`, 35, startY+55);

        // Team
        doc.y = startY + 80;
        doc.font('Helvetica-Bold').text('JSA DONE BY:', 30, doc.y);
        doc.y += 15;
        team.forEach(p => doc.font('Helvetica').text(`- ${p.name} (${p.desig}, ${p.dept})`));

        // Table
        doc.moveDown();
        doc.font('Helvetica-Bold').text('RISK ASSESSMENT:', 30, doc.y);
        doc.moveDown();
        
        // Risk Steps
        steps.forEach((s, i) => {
            if(doc.y > 700) doc.addPage();
            doc.font('Helvetica-Bold').text(`Step ${i+1}: ${s.activity}`);
            doc.font('Helvetica').fillColor('red').text(`   Hazard: ${s.hazard}`);
            doc.fillColor('green').text(`   Control: ${s.control}`);
            doc.fillColor('black').moveDown(0.5);
        });

        // Signatures
        doc.moveDown();
        doc.font('Helvetica-Bold').text(`Approved By: ${approverName} on ${approvedDate}`);
        
        doc.end();
    });
}

app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'index.html');
    fs.readFile(indexPath, 'utf8', (err, html) => {
        if (err) { console.error("HTML File missing!", err); return res.status(500).send('Error loading System UI.'); }
        const finalHtml = html.replace(/NONCE_PLACEHOLDER/g, res.locals.nonce);
        res.send(finalHtml);
    });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log("Server Started on Port " + PORT));
