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

// Using simplified CSP (Code B style) to prevent UI breakage, but keeping security tools
app.use(helmet({ contentSecurityPolicy: false })); 

const allowedOrigins = [
  "https://workpermitdivision-dwcahkbpbnc4fyah.centralindia-01.azurewebsites.net/",
  "http://localhost:3000"
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!allowedOrigins.includes(origin)) return cb(null, true); // Permissive for dev
    cb(null, true);
  },
  credentials: true
}));

app.use(bodyParser.json({ limit: '50mb' }));
app.use('/public', express.static(path.join(__dirname, 'public')));

// RATE LIMIT
const limiter = rateLimit({ windowMs: 10 * 1000, max: 200 });
app.use('/api/', limiter);

// STORAGE
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
      const blockBlobClient = containerClient.getBlockBlobClient(blobName);
      const options = mimeType ? { blobHTTPHeaders: { blobContentType: mimeType } } : undefined;
      await blockBlobClient.uploadData(buffer, options);
      return blockBlobClient.url;
  } catch (err) {
      console.log("Azure upload error: " + err.message);
      return null;
  }
}

const log = (msg, type = 'INFO') => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${type}] ${msg}`);
};

/* =====================================================
   ADVANCED AUTHENTICATION (Restored from Code A)
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
  }, JWT_SECRET, { expiresIn: "15m" }); // Short lived
}

function createRefreshToken(user) {
  return jwt.sign({ email: user.Email }, REFRESH_SECRET, { expiresIn: "30d" }); // Long lived
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

        // Security: Check if password changed since token issue
        const pool = await getConnection();
        const r = await pool.request()
            .input('e', sql.NVarChar, decodedUser.email)
            .query('SELECT LastPasswordChange FROM Users WHERE Email=@e');

        if (r.recordset.length === 0) return res.status(401).json({ error: "Unknown user" });

        const dbTimeRaw = r.recordset[0].LastPasswordChange;
        const dbLast = dbTimeRaw ? Math.floor(new Date(dbTimeRaw).getTime() / 1000) : 0;
        const tokenLast = decodedUser.lastPwd || 0;

        if (dbLast > (tokenLast + 120)) { // 2 min buffer
            return res.status(401).json({ error: "Session expired due to password change" });
        }

        req.user = decodedUser;
        next();
    });
}

// 1. ROBUST LOGIN ROUTE
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
        
        // CHECK: Force Password Change
        if (user.ForcePwdChange === 'Y') {
            return res.json({ success: false, forceChange: true, email: user.Email });
        }

        const lastPwdTime = user.LastPasswordChange ? Math.floor(new Date(user.LastPasswordChange).getTime() / 1000) : 0;
        user.lastPwd = lastPwdTime;

        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);
        await saveRefreshToken(user.Email, refreshToken);

        // Send Refresh Token as HttpOnly Cookie
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

// 2. FORCE PASSWORD CHANGE
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

// 3. ADMIN RESET PASSWORD
app.post('/api/admin/reset-password', authenticateAccess, async (req, res) => {
    try {
        const { targetEmail, newTempPass } = req.body;
        const pool = await getConnection();
        
        // Check permissions
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
   COMPLIANCE PDF GENERATOR (Restored High-End Logic from Code A)
   Includes: Watermarks, Legal Tables, Annexure III
===================================================== */
async function drawPermitPDF(doc, p, d, renewalsList) {
    const workType = (d.WorkType || "PERMIT").toUpperCase();
    const status = p.Status || "Active";
    
    // 1. DYNAMIC WATERMARK (Visual Status Indicator)
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

    const compositePermitNo = `${d.IssuedToDept || 'DEPT'}/${p.PermitID}`;

    const drawHeader = (doc) => {
        drawWatermark();
        const startX = 30, startY = 30;
        doc.lineWidth(1);
        
        // Logo Box
        doc.rect(startX, startY, 80, 95).stroke();
        const logoPath = path.join(__dirname, 'public', 'logo.png');
        if (fs.existsSync(logoPath)) {
            try { doc.image(logoPath, startX, startY, { fit: [80, 95], align: 'center', valign: 'center' }); } catch (err) { }
        }

        // Title Box
        doc.rect(startX + 80, startY, 320, 95).stroke();
        doc.font('Helvetica-Bold').fontSize(11).fillColor('black').text('INDIAN OIL CORPORATION LIMITED', startX + 80, startY + 15, { width: 320, align: 'center' });
        doc.fontSize(9).text('EASTERN REGION PIPELINES', startX + 80, startY + 30, { width: 320, align: 'center' });
        doc.text('HSE DEPT.', startX + 80, startY + 45, { width: 320, align: 'center' });
        doc.fontSize(8).text('COMPOSITE WORK PERMIT SYSTEM', startX + 80, startY + 65, { width: 320, align: 'center' });

        // Meta Box
        doc.rect(startX + 400, startY, 135, 95).stroke();
        doc.text(`Doc No: ERPL/HS&E/25-26`, startX + 405, startY + 60);
        doc.text(`Date: ${getNowIST().split(' ')[0]}`, startX + 405, startY + 80);
        
        doc.font('Helvetica-Bold').fontSize(10).fillColor('red');
        doc.text(`Permit No: ${compositePermitNo}`, startX + 405, startY + 15, { width: 130, align: 'left' });
        doc.fillColor('black');
    };

    const drawHeaderOnAll = () => {
        drawHeader(doc);
        doc.y = 135;
        doc.fontSize(9).font('Helvetica');
    };

    drawHeaderOnAll();

    // 2. LEGAL DISCLAIMER (Golden Safety Rules)
    if (d.GSR_Accepted === 'Y') {
        doc.rect(30, doc.y, 535, 20).fillColor('#e6fffa').fill();
        doc.fillColor('black').stroke();
        doc.rect(30, doc.y, 535, 20).stroke();
        doc.font('Helvetica-Bold').fontSize(9).fillColor('#047857')
           .text("✓ I have read, understood and accepted the IOCL Golden Safety Rules terms and penalties.", 35, doc.y + 5);
        doc.y += 25;
        doc.fillColor('black');
    }

    // 3. MAIN DETAILS
    const startY = doc.y;
    doc.text(`(i) Work clearance from: ${formatDate(p.ValidFrom)}    To    ${formatDate(p.ValidTo)}`, 30, doc.y);
    doc.y += 15;
    doc.text(`(ii) Issued to: ${d.IssuedToDept || '-'} / ${d.Vendor || '-'}`, 30, doc.y);
    doc.y += 15;
    doc.text(`(iii) Location: ${d.WorkLocationDetail || '-'} [GPS: ${d.ExactLocation || 'No GPS'}]`, 30, doc.y);
    doc.y += 15;
    doc.text(`(iv) Description: ${d.Desc || '-'}`, 30, doc.y, { width: 535 });
    doc.y += 20;
    doc.rect(25, startY - 5, 545, doc.y - startY + 5).stroke();
    doc.y += 10;

    // 4. CATEGORIZED CHECKLISTS (Restored A/B/C/D Sections)
    // Map simplified keys (A_0) to questions if needed, or use stored text
    const CHECKLIST_SECTIONS = {
        'A': 'SECTION A: GENERAL SAFETY CHECKS',
        'B': 'SECTION B: HOT WORK / CONFINED SPACE',
        'C': 'SECTION C: VEHICLE ENTRY',
        'D': 'SECTION D: EXCAVATION'
    };

    Object.keys(CHECKLIST_SECTIONS).forEach(prefix => {
        // Find keys starting with this prefix (e.g. A_Q1, A_Q2)
        const relevantKeys = Object.keys(d).filter(k => k.startsWith(`${prefix}_Q`) && !k.includes('Detail'));
        
        if (relevantKeys.length > 0 && relevantKeys.some(k => d[k] !== 'NA')) {
            if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
            
            doc.font('Helvetica-Bold').fillColor('black').fontSize(9).text(CHECKLIST_SECTIONS[prefix], 30, doc.y + 10); 
            doc.y += 25;
            
            let y = doc.y;
            doc.rect(30, y, 350, 20).stroke().text("Checklist Item", 35, y + 5); 
            doc.rect(380, y, 60, 20).stroke().text("Status", 385, y + 5); 
            doc.rect(440, y, 125, 20).stroke().text("Remarks", 445, y + 5); 
            y += 20;
            
            doc.font('Helvetica').fontSize(8);
            
            relevantKeys.forEach(key => {
                if (d[key] && d[key] !== 'NA') {
                    if (y > 750) { doc.addPage(); drawHeaderOnAll(); y = 135; }
                    
                    // Specific logic for Gas Tests (A_Q12 usually)
                    let detailTxt = d[`${key}_Detail`] || d[`${key}_Rem`] || '';
                    if (prefix === 'A' && key.includes('12')) {
                        detailTxt = `HC:${d.GP_Q12_HC||'-'} / Tox:${d.GP_Q12_ToxicGas||'-'} / O2:${d.GP_Q12_Oxygen||'-'}`;
                    }

                    doc.rect(30, y, 350, 20).stroke().text(key, 35, y + 5); // Using key code as label for brevity in merge
                    doc.rect(380, y, 60, 20).stroke().text(d[key], 385, y + 5);
                    doc.rect(440, y, 125, 20).stroke().text(detailTxt, 445, y + 5);
                    y += 20;
                }
            });
            doc.y = y;
        }
    });

    // 5. ANNEXURE III TABLE
    if (doc.y > 600) { doc.addPage(); drawHeaderOnAll(); }
    doc.y += 10;
    doc.font('Helvetica-Bold').fontSize(9).text("Annexure III: REFERENCES", 30, doc.y); doc.y += 15;

    const annexData = [
        ["SOP / SWP No", d.SopNo || '-'],
        ["JSA No", d.JsaNo || '-'],
        ["Work Order", d.WorkOrder || '-'],
        ["Tool Box Talk", d.ToolBoxTalk || '-']
    ];

    let axY = doc.y;
    doc.font('Helvetica').fontSize(9);
    annexData.forEach(row => {
        doc.rect(30, axY, 200, 20).stroke().text(row[0], 35, axY + 5);
        doc.rect(230, axY, 335, 20).stroke().text(row[1], 235, axY + 5);
        axY += 20;
    });
    doc.y = axY + 20;

    // 6. WORKERS & SUPERVISORS (Using Helper)
    const drawTable = (title, headers, rows) => {
        if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
        doc.font('Helvetica-Bold').text(title, 30, doc.y); doc.y += 15;
        let y = doc.y;
        
        // Header
        let x = 30;
        headers.forEach(h => {
            doc.rect(x, y, h.w, 20).stroke().text(h.t, x+2, y+5);
            x += h.w;
        });
        y += 20;
        
        // Rows
        doc.font('Helvetica');
        rows.forEach(r => {
             if (y > 750) { doc.addPage(); drawHeaderOnAll(); y = 135; }
             x = 30;
             r.forEach((cell, i) => {
                 doc.rect(x, y, headers[i].w, 20).stroke().text(cell, x+2, y+5, {width: headers[i].w-4});
                 x += headers[i].w;
             });
             y += 20;
        });
        doc.y = y + 15;
    };

    // Workers
    let workers = []; try { workers = JSON.parse(d.SelectedWorkers || p.SelectedWorkers || "[]"); } catch(e){}
    let workerRows = workers.map(w => [w.Name, w.ID || '-', w.ApprovedBy || '-']);
    if(workerRows.length > 0) drawTable("WORKERS DEPLOYED", [{t:"Name",w:200}, {t:"ID",w:100}, {t:"Approved By",w:235}], workerRows);

    // IOCL Supervisors
    let ioclSups = d.IOCLSupervisors || [];
    let ioclRows = ioclSups.map(s => [s.name, s.desig, s.contact]);
    if(ioclRows.length > 0) drawTable("IOCL SUPERVISORS", [{t:"Name",w:200}, {t:"Designation",w:200}, {t:"Contact",w:135}], ioclRows);

    // 7. RENEWALS (With Images)
    const finalRenewals = renewalsList || JSON.parse(p.RenewalsJSON || "[]");
    if(finalRenewals.length > 0) {
        if (doc.y > 600) { doc.addPage(); drawHeaderOnAll(); }
        doc.font('Helvetica-Bold').text("CLEARANCE RENEWALS", 30, doc.y); doc.y += 15;
        
        // Table Header
        let ry = doc.y;
        const rHeaders = [
            {t:"Time", w:90}, {t:"Gas", w:90}, {t:"Req", w:70}, 
            {t:"Rev", w:70}, {t:"App", w:70}, {t:"Photo", w:145}
        ];
        let rx = 30;
        rHeaders.forEach(h => { doc.rect(rx, ry, h.w, 20).stroke().text(h.t, rx+2, ry+5); rx += h.w; });
        ry += 20;

        for (const r of finalRenewals) {
            if (ry > 700) { doc.addPage(); drawHeaderOnAll(); ry = 135; }
            const h = 60;
            
            doc.rect(30, ry, 90, h).stroke().text(`${r.valid_from}\nTo\n${r.valid_to}`, 32, ry+5, {width:85});
            doc.rect(120, ry, 90, h).stroke().text(`HC:${r.hc}\nTox:${r.toxic}\nO2:${r.oxygen}`, 122, ry+5, {width:85});
            doc.rect(210, ry, 70, h).stroke().text(r.req_name, 212, ry+5, {width:65});
            doc.rect(280, ry, 70, h).stroke().text(r.rev_name||'-', 282, ry+5, {width:65});
            doc.rect(350, ry, 70, h).stroke().text(r.app_name||'-', 352, ry+5, {width:65});
            
            // Photo Logic
            doc.rect(420, ry, 145, h).stroke();
            if(r.photoUrl && containerClient) {
                try {
                    const blobName = r.photoUrl.split('/').pop();
                    const blockBlob = containerClient.getBlockBlobClient(blobName);
                    // Timeout protection
                    const downloadPromise = blockBlob.download(0);
                    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 3000));
                    
                    const response = await Promise.race([downloadPromise, timeoutPromise]);
                    const chunks = [];
                    for await (const chunk of response.readableStreamBody) { chunks.push(chunk); }
                    const imgBuffer = Buffer.concat(chunks);
                    doc.image(imgBuffer, 425, ry+2, {fit: [135, 56], align:'center'});
                } catch(e) { doc.text("Image Unavailable", 425, ry+25); }
            } else { doc.text("No Photo", 425, ry+25); }
            ry += h;
        }
        doc.y = ry + 20;
    }

    // 8. CLOSURE SECTION
    if (p.Status === 'Closed' || p.Status.includes('Closure') || d.Closure_Issuer_Sig) {
        if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
        doc.font('Helvetica-Bold').fontSize(10).text("WORK COMPLETION & CLOSURE", 30, doc.y);
        doc.y += 15;
        const cY = doc.y;

        const boxColor = d.Site_Restored_Check === 'Y' ? '#dcfce7' : '#fee2e2';
        doc.rect(30, cY, 535, 25).fillColor(boxColor).fill().stroke();
        doc.fillColor('black').text(`Site Restored & Housekeeping Done?  [ ${d.Site_Restored_Check === 'Y' ? 'YES' : 'NO'} ]`, 35, cY + 8);
        doc.y += 35;

        const closureY = doc.y;
        if (closureY > 700) { doc.addPage(); drawHeaderOnAll(); }
        doc.rect(30, closureY, 178, 60).stroke().text(`REQUESTOR:\n${d.Closure_Receiver_Sig || '-'}\nDate: ${d.Closure_Requestor_Date || '-'}\nRem: ${d.Closure_Requestor_Remarks || '-'}`, 35, closureY + 5, { width: 168 });
        doc.rect(208, closureY, 178, 60).stroke().text(`REVIEWER:\n${d.Closure_Reviewer_Sig || '-'}\nDate: ${d.Closure_Reviewer_Date || '-'}\nRem: ${d.Closure_Reviewer_Remarks || '-'}`, 213, closureY + 5, { width: 168 });
        doc.rect(386, closureY, 179, 60).stroke().text(`APPROVER:\n${d.Closure_Issuer_Sig || '-'}\nDate: ${d.Closure_Approver_Date || '-'}\nRem: ${d.Closure_Approver_Remarks || '-'}`, 391, closureY + 5, { width: 169 });
    }
}

/* =====================================================
   ADMINISTRATION & HIERARCHY (Restored from Code A)
===================================================== */

// 1. Get Dropdown Hierarchy
app.post('/api/get-hierarchy', async (req, res) => {
    try {
        const { region, unit } = req.body;
        const pool = await getConnection();
        let query = "", param = "";

        if (!region) {
            query = "SELECT DISTINCT Region FROM Users WHERE Region IS NOT NULL";
        } else if (region && !unit) {
            query = "SELECT DISTINCT Unit FROM Users WHERE Region = @p";
            param = region;
        } else {
            query = "SELECT DISTINCT Location FROM Users WHERE Region = @p AND Unit = @u";
        }

        const reqSql = pool.request();
        if(region) reqSql.input('p', sql.NVarChar, region);
        if(unit) reqSql.input('u', sql.NVarChar, unit);
        
        const r = await reqSql.query(query);
        let results = r.recordset.map(x => x[(!region ? 'Region' : (!unit ? 'Unit' : 'Location'))]);
        if(results.length === 0 && !region) results = ['ALL'];
        res.json(results);
    } catch (e) { res.status(500).json({error: e.message}); }
});

// 2. Filter Users
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

// 3. Add User (Admin/Approver)
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

        await pool.request()
            .input('n', req.body.name).input('e', req.body.email).input('r', req.body.role).input('p', hashed)
            .input('reg', reg).input('u', unit).input('l', loc).input('cb', req.user.email)
            .query("INSERT INTO Users (Name,Email,Role,Password,Region,Unit,Location,CreatedBy,ForcePwdChange) VALUES (@n,@e,@r,@p,@reg,@u,@l,@cb,'Y')");
        
        res.json({success: true});
    } catch(e) { res.status(500).json({error: "Error Adding User"}); }
});

// 4. Delete User
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

// 5. Bulk Upload (Master Admin Only)
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
            return pool.request()
                .input('n', u.name).input('e', u.email).input('r', u.role).input('p', hashed)
                .input('reg', u.region).input('u', u.unit).input('l', u.loc).input('cb', req.user.email)
                .query(`INSERT INTO Users (Name, Email, Role, Password, Region, Unit, Location, CreatedBy, ForcePwdChange) VALUES (@n, @e, @r, @p, @reg, @u, @l, @cb, 'Y')`);
        });

        await Promise.all(promises);
        res.json({ success: true, count: usersToInsert.length });
    } catch (e) { res.status(500).json({ error: "Bulk Upload Failed: " + e.message }); }
});
/* =====================================================
   CORE PERMIT ROUTES (Stable Logic + Compliance Features)
===================================================== */

// 1. Get Workers (Code B Logic: Strict Filtering)
app.post('/api/get-workers', authenticateAccess, async(req, res) => {
    const { role, email } = req.user;
    const pool = await getConnection();
    const r = await pool.request().query("SELECT * FROM Workers");
    
    let workers = r.recordset.map(w => {
        let d = {}; 
        try { 
            // Handle both Pending and Current structures
            d = JSON.parse(w.DataJSON).Current || JSON.parse(w.DataJSON).Pending || {}; 
        } catch(e){}
        
        return { 
            ...d, 
            WorkerID: w.WorkerID, 
            Status: w.Status, 
            RequestorEmail: w.RequestorEmail, 
            ApprovedBy: w.ApprovedBy, 
            ApprovedAt: w.ApprovedOn 
        };
    });

    if (role === 'Requester') {
        workers = workers.filter(w => w.RequestorEmail === email);
    } 
    res.json(workers);
});

// 2. Save Worker (Edit/Create/Approve/Delete)
app.post('/api/save-worker', authenticateAccess, async (req, res) => {
    const { WorkerID, Action, Details, RequestorEmail } = req.body;
    const pool = await getConnection();
    
    try {
        if(Action === 'create') {
            // Restore Code A Check: Age < 18
            if (Details && parseInt(Details.Age) < 18) {
                return res.status(400).json({ error: "Worker must be 18+" });
            }

            const idRes = await pool.request().query("SELECT TOP 1 WorkerID FROM Workers ORDER BY WorkerID DESC");
            const nextNum = parseInt(idRes.recordset.length ? idRes.recordset[0].WorkerID.split('-')[1] : 1000) + 1;
            const wid = `W-${nextNum}`; // Sequential ID restored
            
            const data = { Pending: { ...Details } };
            await pool.request()
                .input('w', wid).input('s', 'Pending Review').input('r', RequestorEmail)
                .input('j', JSON.stringify(data)).input('idt', sql.NVarChar, Details.IDType)
                .query("INSERT INTO Workers (WorkerID, Status, RequestorEmail, DataJSON, IDType) VALUES (@w, @s, @r, @j, @idt)");
        
        } else if (Action === 'edit_request') {
            const cur = await pool.request().input('w', WorkerID).query("SELECT DataJSON FROM Workers WHERE WorkerID=@w");
            let d = JSON.parse(cur.recordset[0].DataJSON);
            d.Pending = { ...d.Current, ...Details }; // Merge updates into Pending
            await pool.request()
                .input('w', WorkerID).input('j', JSON.stringify(d)).input('s', 'Pending Review')
                .query("UPDATE Workers SET DataJSON=@j, Status=@s WHERE WorkerID=@w");
        
        } else if (Action === 'delete') {
            await pool.request().input('w', WorkerID).query("DELETE FROM Workers WHERE WorkerID=@w");
        
        } else if (Action === 'approve') {
            const cur = await pool.request().input('w', WorkerID).query("SELECT DataJSON FROM Workers WHERE WorkerID=@w");
            let d = JSON.parse(cur.recordset[0].DataJSON);
            d.Current = d.Pending; // Promote Pending to Current
            d.Pending = null;
            
            await pool.request()
                .input('w', WorkerID).input('j', JSON.stringify(d)).input('s', 'Approved')
                .input('by', req.user.name).input('at', getNowIST())
                .query("UPDATE Workers SET DataJSON=@j, Status=@s, ApprovedBy=@by, ApprovedOn=@at WHERE WorkerID=@w");
        }
        res.json({ success: true });
    } catch(e) { res.status(500).json({error: e.message}); }
});

// 3. Dashboard
app.post('/api/dashboard', authenticateAccess, async (req, res) => {
    const { role, email } = req.user;
    const pool = await getConnection();
    const r = await pool.request().query("SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON, FinalPdfUrl FROM Permits");
    
const data = r.recordset.map(x => {
    let parsed = {};
    try {
        parsed = JSON.parse(x.FullDataJSON || "{}");
    } catch (e) {
        // If JSON is invalid, keep parsed as empty object and log for debugging
        console.warn("Invalid FullDataJSON for PermitID", x.PermitID);
        parsed = {};
    }
    // Spread parsed first (client-supplied), then DB columns override them so DB is authoritative.
    return {
        ...parsed,
        ...x,
        FinalPdfUrl: x.FinalPdfUrl // Include archival link
    };
});
    
    // Filter based on Role
    const filtered = data.filter(p => {
        if(role === 'MasterAdmin') return true; 
        if(role === 'Requester') return p.RequesterEmail === email;
        if(role === 'Reviewer') return p.ReviewerEmail === email;
        if(role === 'Approver') return p.ApproverEmail === email;
        return true;
    });
    
    res.json(filtered.sort((a,b) => {
         // Sort by Sequential ID (WP-1002 > WP-1001)
         const numA = parseInt(a.PermitID.split('-')[1] || 0);
         const numB = parseInt(b.PermitID.split('-')[1] || 0);
         return numB - numA; 
    }));
});

// 4. Save Permit (Sequential ID Restored)
app.post('/api/save-permit', authenticateAccess, upload.any(), async(req, res) => {
    const pool = await getConnection();
    const fd = req.body;
    
    if(!fd.WorkType || !fd.ValidFrom) return res.status(400).json({error: "Missing Data"});
    
    let pid = fd.PermitID;
    
    // SEQUENTIAL ID GENERATION (Code A Logic)
    if (!pid || pid === 'undefined' || pid === '' || pid === 'null') {
        const idRes = await pool.request().query("SELECT MAX(CAST(SUBSTRING(PermitID, 4, 10) AS INT)) as MaxVal FROM Permits WHERE PermitID LIKE 'WP-%'");
        let nextNum = 1000;
        if (idRes.recordset[0].MaxVal) nextNum = idRes.recordset[0].MaxVal + 1;
        pid = `WP-${nextNum}`;
    }
    
    let rens = [];
    if(fd.InitRen === 'Y') {
        rens.push({ 
            status: 'pending_review', 
            valid_from: fd.InitRenFrom, 
            valid_to: fd.InitRenTo, 
            hc: fd.InitRenHC, 
            toxic: fd.InitRenTox, 
            oxygen: fd.InitRenO2, 
            req_name: req.user.name, 
            req_at: getNowIST() 
        });
    }

    // Merge Logic (Insert or Update)
    const q = pool.request()
        .input('p', pid).input('s', 'Pending Review').input('w', fd.WorkType)
        .input('re', req.user.email).input('rv', fd.ReviewerEmail).input('ap', fd.ApproverEmail)
        .input('vf', new Date(fd.ValidFrom)).input('vt', new Date(fd.ValidTo))
        .input('j', JSON.stringify(fd)).input('ren', JSON.stringify(rens));

    await q.query(`
        MERGE Permits AS target 
        USING (SELECT @p as PermitID) AS source 
        ON (target.PermitID = source.PermitID) 
        WHEN MATCHED THEN 
            UPDATE SET FullDataJSON=@j, Status=@s, RenewalsJSON=@ren 
        WHEN NOT MATCHED THEN 
            INSERT (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, FullDataJSON, RenewalsJSON) 
            VALUES (@p, @s, @w, @re, @rv, @ap, @vf, @vt, @j, @ren);
    `);
    
    res.json({success: true, permitId: pid});
});

// 5. Update Status & ARCHIVAL (Code A Logic Restored)
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

    // STATUS TRANSITIONS
    if (action === 'reject') st = 'Rejected';
    else if (action === 'review') { st = 'Pending Approval'; d.Reviewer_Sig = `${usr} on ${now}`; }
    else if (action === 'approve') { st = 'Active'; d.Approver_Sig = `${usr} on ${now}`; }

    // CLOSURE WORKFLOW
    else if (action === 'initiate_closure') { st = 'Closure Pending Review'; d.Closure_Requestor_Date = now; d.Closure_Receiver_Sig = `${usr} on ${now}`; }
    else if (action === 'reject_closure') { st = 'Active'; } 
    else if (action === 'approve_closure') { st = 'Closure Pending Approval'; d.Closure_Reviewer_Date = now; d.Closure_Reviewer_Sig = `${usr} on ${now}`; }
    else if (action === 'approve' && st.includes('Closure')) { 
        st = 'Closed'; 
        d.Closure_Approver_Date = now; 
        d.Closure_Issuer_Sig = `${usr} on ${now}`;
    }

    // RENEWAL WORKFLOW
    if(action === 'approve_1st_ren' || action === 'approve' || action === 'review') {
        if(rens.length > 0 && rens[rens.length-1].status.includes('pending')) {
             let last = rens[rens.length-1];
             if(req.body.FirstRenewalAction === 'reject') { 
                 last.status = 'rejected'; 
                 if(st.includes('Renewal')) st = 'Active'; 
             }
             else if(req.user.role === 'Reviewer') { 
                 last.status = 'pending_approval'; last.rev_name = usr; st = 'Pending Approval'; 
             }
             else if(req.user.role === 'Approver') { 
                 last.status = 'approved'; last.app_name = usr; st = 'Active'; 
             }
        }
    }

    // *** CRITICAL ARCHIVAL STEP (From Code A) ***
    // If Status becomes Closed, generate Final PDF and freeze record
    if (st === 'Closed') {
        const pdfRecord = { ...p, Status: 'Closed', PermitID: PermitID, ValidFrom: p.ValidFrom, ValidTo: p.ValidTo };
        
        const pdfBuffer = await new Promise((resolve, reject) => {
            const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
            const chunks = [];
            doc.on('data', chunks.push.bind(chunks));
            doc.on('end', () => resolve(Buffer.concat(chunks)));
            drawPermitPDF(doc, pdfRecord, d, rens).then(() => doc.end()).catch(reject);
        });

        const blobName = `closed-permits/${PermitID}_FINAL.pdf`;
        const finalPdfUrl = await uploadToAzure(pdfBuffer, blobName, "application/pdf");

        if (finalPdfUrl) {
            await pool.request().input('p', PermitID).input('url', finalPdfUrl).query("UPDATE Permits SET Status='Closed', FinalPdfUrl=@url, FullDataJSON=NULL, RenewalsJSON=NULL WHERE PermitID=@p");
            return res.json({ success: true, archived: true, pdfUrl: finalPdfUrl });
        }
    }

    await pool.request()
        .input('p', PermitID).input('s', st)
        .input('j', JSON.stringify(d)).input('r', JSON.stringify(rens))
        .query("UPDATE Permits SET Status=@s, FullDataJSON=@j, RenewalsJSON=@r WHERE PermitID=@p");
    
    res.json({success: true});
});

// 6. Renewal (Code B Logic - UPDATED FOR ODD HOUR TRACKING)
app.post('/api/renewal', authenticateAccess, upload.single('RenewalImage'), async(req,res) => {
    const { PermitID, action, comment } = req.body; 
    const userRole = req.user.role; 
    const pool = await getConnection();
    
    const cur = await pool.request().input('p', PermitID).query("SELECT RenewalsJSON, ValidTo, Status FROM Permits WHERE PermitID=@p");
    if (!cur.recordset.length) return res.status(404).json({error: "Permit not found"});

    let rens = JSON.parse(cur.recordset[0].RenewalsJSON || "[]");
    let currentStatus = cur.recordset[0].Status;
    let newStatus = currentStatus;
    
    if(action === 'initiate') {
        let url = null;
        if(req.file) url = await uploadToAzure(req.file.buffer, `${PermitID}-REN-${Date.now()}.jpg`);
        
        let workerList = [];
        try { workerList = JSON.parse(req.body.renewalWorkers || "[]"); } catch(e){}

        rens.push({
            status: 'pending_review',
            valid_from: req.body.RenewalValidFrom,
            valid_to: req.body.RenewalValidTo,
            hc: req.body.hc, toxic: req.body.toxic, oxygen: req.body.oxygen,
            precautions: req.body.precautions,
            workers: workerList,
            req_name: req.user.name, req_at: getNowIST(),
            photoUrl: url,
            oddHourReq: req.body.oddHourReq || 'N'
        });
        newStatus = 'Renewal Pending Review';
    } 
    else {
        if(rens.length === 0) return res.status(400).json({error: "No renewals found"});
        let last = rens[rens.length - 1]; 
        
        if (action === 'reject') {
            last.status = 'rejected';
            last.rejection_reason = req.body.rejectionReason || comment || '-'; 
            last.rejected_by = req.user.name;
            newStatus = 'Active'; 
        }
        else if (action === 'approve' || action === 'forward_to_approver') {
            
            if (userRole === 'Reviewer') {
                last.status = 'pending_approval';
                last.rev_name = req.user.name;
                last.rev_at = getNowIST();
                last.rev_rem = comment || '';
                // NEW: Explicitly save that Reviewer accepted Odd Hours
                if(last.oddHourReq === 'Y') last.rev_odd_hour_accepted = 'Y';
                newStatus = 'Renewal Pending Approval';
            } 
            else if (userRole === 'Approver') {
                last.status = 'approved';
                last.app_name = req.user.name;
                last.app_at = getNowIST();
                last.app_rem = comment || '';
                newStatus = 'Active';

                await pool.request()
                    .input('p', PermitID)
                    .input('vt', new Date(last.valid_to)) 
                    .query("UPDATE Permits SET ValidTo=@vt WHERE PermitID=@p");
            }
        }
    }

    await pool.request()
        .input('p', PermitID).input('r', JSON.stringify(rens)).input('s', newStatus)
        .query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p");

    res.json({success: true});
});
// 7. EXCEL EXPORT (Restored from Code A)
app.get('/api/download-excel', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC");
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Permits');
    sheet.columns = [
      { header:'Permit ID', key:'id', width:15 },
      { header:'Status', key:'status', width:20 },
      { header:'Work', key:'wt', width:25 },
      { header:'Requester', key:'req', width:25 },
      { header:'Location', key:'loc', width:30 },
      { header:'Vendor', key:'ven', width:20 },
      { header:'Valid From', key:'vf', width:20 },
      { header:'Valid To', key:'vt', width:20 }
    ];
    result.recordset.forEach(r=>{
      const d = r.FullDataJSON ? JSON.parse(r.FullDataJSON) : {};
      sheet.addRow({
        id:r.PermitID, status:r.Status, wt:d.WorkType || '-',
        req:d.RequesterName || '-', loc:d.ExactLocation || '-',
        ven:d.Vendor || '-', vf:formatDate(r.ValidFrom), vt:formatDate(r.ValidTo)
      });
    });
    res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition','attachment; filename=Permits.xlsx');
    await workbook.xlsx.write(res);
    res.end();
  } catch (err) { res.status(500).send("Export Error"); }
});

// 8. PDF Download (Supports Final Archival)
app.get('/api/download-pdf/:id', authenticateAccess, async(req, res) => {
    const pool = await getConnection();
    const r = await pool.request().input('p', req.params.id).query("SELECT * FROM Permits WHERE PermitID=@p");
    if(!r.recordset.length) return res.status(404).send("Not Found");
    
    const p = r.recordset[0];
    
    // Check if archived in Cloud
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
    await drawPermitPDF(doc, p, JSON.parse(p.FullDataJSON), JSON.parse(p.RenewalsJSON||"[]"));
    doc.end();
});

app.post('/api/permit-data', authenticateAccess, async(req, res) => {
    const pool = await getConnection();
    const r = await pool.request().input('p', req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p");
    if(!r.recordset.length) return res.json({error:"404"});
    
    const p = r.recordset[0];
    res.json({ 
        ...JSON.parse(p.FullDataJSON), 
        Status: p.Status, 
        RenewalsJSON: p.RenewalsJSON, 
        IOCLSupervisors: JSON.parse(p.FullDataJSON).IOCLSupervisors || [] 
    });
});

app.post('/api/map-data', async(req,res) => {
    const pool = await getConnection();
    const r = await pool.request().query("SELECT PermitID, FullDataJSON, Status, Latitude, Longitude FROM Permits WHERE Status='Active' OR Status LIKE '%Renewal%'");
    res.json(r.recordset.map(x => ({
        PermitID: x.PermitID, 
        Status: x.Status, 
        lat: x.Latitude, 
        lng: x.Longitude, 
        ...JSON.parse(x.FullDataJSON)
    })));
});
app.get('/', (req, res) => {
    // Ensure you save your HTML code as 'index.html' in the same folder
    const indexPath = path.join(__dirname, 'index.html');
    
    fs.readFile(indexPath, 'utf8', (err, html) => {
        if (err) {
            console.error("HTML File missing!", err);
            return res.status(500).send('Error loading System UI. Is index.html present?');
        }
        // This replaces the NONCE_PLACEHOLDER in your HTML with a secure random key
        const finalHtml = html.replace(/NONCE_PLACEHOLDER/g, res.locals.nonce);
        res.send(finalHtml);
    });
});
// SERVER START
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log("Server Started on Port " + PORT));
