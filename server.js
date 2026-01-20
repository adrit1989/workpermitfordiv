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

/* =====================================================
   SECURITY CONFIGURATION (CSP & CORS)
===================================================== */

/* --- NONCE CSP --- */
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        // Script still uses Nonce for security
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, "https://cdn.jsdelivr.net", "https://maps.googleapis.com", "https://cdn.tailwindcss.com"],
        // Style MUST allow unsafe-inline for Tailwind CDN to work
        styleSrc: ["'self'", "https:", "'unsafe-inline'"], 
        imgSrc: ["'self'", "data:", "blob:", "https://maps.gstatic.com", "https://maps.googleapis.com", "https://*.googleapis.com"],
        fontSrc: ["'self'", "https:", "data:"],
        connectSrc: ["'self'", "https://maps.googleapis.com", "https://cdn.jsdelivr.net"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [] // Optional: Helps with mixed content on some Azure setups
      }
    }
  })
);
/* --- CORS --- */
const allowedOrigins = [
  "https://workpermit-a8hueufcdzc0ftcd.centralindia-01.azurewebsites.net",
  "http://localhost:3000"
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!allowedOrigins.includes(origin)) return cb(new Error("CORS Blocked"), false);
    cb(null, true);
  },
  credentials: true
}));

app.use(bodyParser.json({ limit: '50mb' }));
app.use('/public', express.static(path.join(__dirname, 'public')));

// ENV VALIDATION
if (!process.env.JWT_SECRET) {
  console.error("FATAL: JWT_SECRET missing.");
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET || (process.env.JWT_SECRET + "_refresh");
const AZURE_CONN_STR = process.env.AZURE_STORAGE_CONNECTION_STRING;

// RATE LIMITER (Safe IP Logic)
const safeKeyGenerator = (req) => {
    return req.ip ? req.ip.replace(/:\d+$/, '') : req.ip;
};

app.use('/api/', rateLimit({ 
    windowMs: 10 * 1000, 
    max: 50,
    keyGenerator: safeKeyGenerator,
    validate: { trustProxy: false }
}));
const loginLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 100,
    keyGenerator: safeKeyGenerator,
    validate: { trustProxy: false }
});

/* --- MULTER SETUP --- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

/* --- AZURE BLOBS --- */
let containerClient = null;
if (AZURE_CONN_STR) {
  try {
    const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN_STR);
    containerClient = blobServiceClient.getContainerClient("permit-attachments");
    (async () => { try { await containerClient.createIfNotExists(); } catch (e) {} })();
  } catch (err) {
    console.error("Blob Error:", err.message);
  }
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

function formatDate(dateStr) {
  if (!dateStr) return '-';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  return d.toLocaleString("en-GB", {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
    hour12: false
  }).replace(',', '');
}

function getOrdinal(n) {
  const s = ["th", "st", "nd", "rd"], v = n % 100;
  return n + (s[(v - 20) % 10] || s[v] || s[0]);
}

// --- SECURE UPLOAD HELPER (FILE-TYPE) ---
async function uploadToAzure(buffer, blobName, isSystemPdf = false) {
  if (!containerClient) return null;
  try {
    // 1. Dynamic Import (ESM fix for CommonJS environment)
    const { fileTypeFromBuffer } = await import('file-type');
    
    // 2. Inspect Buffer Magic Numbers
    const type = await fileTypeFromBuffer(buffer);

    // 3. Define Allowed Types
    // Default: Images only (User Uploads)
    let allowedTypes = ['image/jpeg', 'image/png'];

    // Exception: Allow PDF ONLY if System explicitly requests it (Archiving)
    if (isSystemPdf === 'application/pdf' || isSystemPdf === true) {
        allowedTypes.push('application/pdf');
    }

    // 4. Security Check
    // If type is undefined (unknown binary) or not in allowed list -> Block
    if (!type || !allowedTypes.includes(type.mime)) {
        console.error(`[SECURITY ALERT] Blocked upload for ${blobName}. Detected: ${type ? type.mime : 'Unknown'}. Allowed: ${allowedTypes.join(', ')}`);
        return null;
    }

    // 5. Upload with Verified Mime
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
    await blockBlobClient.uploadData(buffer, {
      blobHTTPHeaders: { blobContentType: type.mime }
    });
    
    return blockBlobClient.url;

  } catch (err) {
    console.error("Azure upload error:", err.message);
    return null;
  }
}

/* =====================================================
   TOKEN & AUTH FUNCTIONS
===================================================== */

function createAccessToken(user) {
  return jwt.sign({
    name: user.Name,
    email: user.Email,
    role: user.Role,
    region: user.Region,
    lastPwd: user.lastPwd
  }, JWT_SECRET, { expiresIn: "15m" });
}

function createRefreshToken(user) {
  return jwt.sign({ email: user.Email }, REFRESH_SECRET, { expiresIn: "30d" });
}

async function saveRefreshToken(email, token) {
  const pool = await getConnection();
  await pool.request()
    .input('e', email)
    .input('t', token)
    .input('exp', new Date(Date.now() + 30 * 24 * 3600 * 1000))
    .query("INSERT INTO UserRefreshTokens (Email, RefreshToken, ExpiresAt) VALUES (@e, @t, @exp)");
}

async function deleteRefreshToken(token) {
  const pool = await getConnection();
  await pool.request().input('t', token).query("DELETE FROM UserRefreshTokens WHERE RefreshToken=@t");
}

async function isRefreshValid(token) {
  const pool = await getConnection();
  const r = await pool.request().input('t', token).query("SELECT * FROM UserRefreshTokens WHERE RefreshToken=@t");
  if (r.recordset.length === 0) return false;
  return new Date(r.recordset[0].ExpiresAt) > new Date();
}

// --- AUTH MIDDLEWARE ---
async function authenticateAccess(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid Token" });

    const pool = await getConnection();
    const r = await pool.request()
      .input('e', sql.NVarChar, user.email)
      .query('SELECT LastPasswordChange FROM Users WHERE Email=@e');

    if (r.recordset.length === 0) return res.status(401).json({ error: "Unknown user" });

    const dbLast = r.recordset[0].LastPasswordChange ?
      Math.floor(new Date(r.recordset[0].LastPasswordChange).getTime() / 1000) : 0;

    if (dbLast > (user.lastPwd || 0)) {
      return res.status(401).json({ error: "Session expired" });
    }

    req.user = user;
    next();
  });
}

/* =====================================================
   FULL PDF GENERATOR LOGIC
===================================================== */

async function drawPermitPDF(doc, p, d, renewalsList) {
    const workType = (d.WorkType || "PERMIT").toUpperCase();
    const status = p.Status || "Active";
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
    const compositePermitNo = `${d.IssuedToDept || 'DEPT'}/${p.PermitID}`;

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
        doc.rect(startX, startY, 535, 95).stroke();
        doc.rect(startX, startY, 80, 95).stroke();
        
        const logoPath = path.join(__dirname, 'public', 'logo.png');
        if (fs.existsSync(logoPath)) {
            try { 
                doc.image(logoPath, startX, startY, { fit: [80, 95], align: 'center', valign: 'center' }); 
            } catch (err) { }
        }

        doc.rect(startX + 80, startY, 320, 95).stroke();
        doc.font('Helvetica-Bold').fontSize(11).fillColor('black').text('INDIAN OIL CORPORATION LIMITED', startX + 80, startY + 15, { width: 320, align: 'center' });
        doc.fontSize(9).text('EASTERN REGION PIPELINES', startX + 80, startY + 30, { width: 320, align: 'center' });
        doc.text('HSE DEPT.', startX + 80, startY + 45, { width: 320, align: 'center' });
        doc.fontSize(8).text('COMPOSITE WORK/ COLD WORK/HOT WORK/ENTRY TO CONFINED SPACE/VEHICLE ENTRY / EXCAVATION WORK AT MAINLINE/RCP/SV', startX + 80, startY + 65, { width: 320, align: 'center' });

        doc.rect(startX + 400, startY, 135, 95).stroke();
        doc.fontSize(8).font('Helvetica');
        doc.text('Doc No: ERPL/HS&E/25-26', startX + 405, startY + 60);
        doc.text('Issue No: 01', startX + 405, startY + 70);
        doc.text('Date: 01.09.2025', startX + 405, startY + 80);

        if (permitNoStr) {
            doc.font('Helvetica-Bold').fontSize(10).fillColor('red');
            doc.text(`Permit No: ${permitNoStr}`, startX + 405, startY + 15, { width: 130, align: 'left' });
            doc.fillColor('black');
        }
    };

    const drawHeaderOnAll = () => {
        drawHeader(doc, bgColor, compositePermitNo);
        doc.y = 135;
        doc.fontSize(9).font('Helvetica');
    };

    drawHeaderOnAll();

    // Safety Banner
    const bannerPath = path.join(__dirname, 'public', 'safety_banner.png');
    if (fs.existsSync(bannerPath)) {
        try {
            doc.image(bannerPath, 30, doc.y, { width: 535, height: 100 });
            doc.y += 110;
        } catch (err) { }
    }

    if (d.GSR_Accepted === 'Y') {
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

    doc.text(`(i) Work clearance from: ${formatDate(p.ValidFrom)}    To    ${formatDate(p.ValidTo)} (Valid for the shift unless renewed).`, 30, doc.y);
    doc.y += 15;
    doc.text(`(ii) Issued to (Dept/Section/Contractor): ${d.IssuedToDept || '-'} / ${d.Vendor || '-'}`, 30, doc.y);
    doc.y += 15;
    doc.text(`(iii) Exact Location: ${d.WorkLocationDetail || '-'} [GPS: ${d.ExactLocation || 'No GPS'}]`, 30, doc.y);
    doc.y += 15;
    doc.text(`(iv) Description: ${d.Desc || '-'}`, 30, doc.y, { width: 535 });
    doc.y += 20;
    doc.text(`(v) Site Contact: ${d.RequesterName} / ${d.EmergencyContact || 'Not Provided'}`, 30, doc.y);
    doc.y += 15;
    doc.text(`(vi) Security Guard: ${d.SecurityGuard || '-'}`, 30, doc.y);
    doc.y += 15;
    doc.text(`(vii) JSA Ref: ${d.JsaNo || '-'} | WO: ${d.WorkOrder || '-'}`, 30, doc.y);
    doc.y += 15;
    doc.text(`(viii) Emergency Contact: ${d.EmergencyContact || '-'}`, 30, doc.y);
    doc.y += 15;
    doc.text(`(ix) Nearest Fire/Hospital: ${d.FireStation || '-'}`, 30, doc.y);
    doc.y += 20;
    doc.rect(25, startY - 5, 545, doc.y - startY + 5).stroke();
    doc.y += 10;

    // CHECKLISTS
    const CHECKLIST_DATA = {
        A: [ "1. Equipment / Work Area inspected.", "2. Surrounding area checked, cleaned and covered. Oil/RAGS/Grass Etc removed.", "3. Manholes, Sewers, CBD etc. and hot nearby surface covered.", "4. Considered hazards from other routine, non-routine operations and concerned person alerted.", "5. Equipment blinded/ disconnected/ closed/ isolated/ wedge opened.", "6. Equipment properly drained and depressurized.", "7. Equipment properly steamed/purged.", "8. Equipment water flushed.", "9. Access for Free approach of Fire Tender.", "10. Iron Sulfide removed/ Kept wet.", "11. Equipment electrically isolated and tagged vide Permit no.", "12. Gas Test: HC / Toxic / O2 checked.", "13. Running water hose / Fire extinguisher provided. Fire water system available.", "14. Area cordoned off and Precautionary tag/Board provided.", "15. CCTV monitoring facility available at site.", "16. Proper ventilation and Lighting provided." ],
        B: [ "1. Proper means of exit / escape provided.", "2. Standby personnel provided from Mainline/ Maint. / Contractor/HSE.", "3. Checked for oil and Gas trapped behind the lining in equipment.", "4. Shield provided against spark.", "5. Portable equipment / nozzle properly grounded.", "6. Standby persons provided for entry to confined space.", "7. Adequate Communication Provided to Stand by Person.", "8. Attendant Trained Provided With Rescue Equipment/SCABA.", "9. Space Adequately Cooled for Safe Entry Of Person.", "10. Continuous Inert Gas Flow Arranged.", "11. Check For Earthing/ELCB of all Temporary Electrical Connections being used for welding.", "12. Gas Cylinders are kept outside the confined Space.", "13. Spark arrestor Checked on mobile Equipments.", "14. Welding Machine Checked for Safe Location.", "15. Permit taken for working at height Vide Permit No." ],
        C: ["1. PESO approved spark elimination system provided on the mobile equipment/ vehicle provided."],
        D: [ "1. For excavated trench/ pit proper slop/ shoring/ shuttering provided to prevent soil collapse.", "2. Excavated soil kept at safe distance from trench/pit edge (min. pit depth).", "3. Safe means of access provided inside trench/pit.", "4. Movement of heavy vehicle prohibited." ]
    };

    const drawChecklist = (t, i, pr) => {
        if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
        doc.font('Helvetica-Bold').fillColor('black').fontSize(9).text(t, 30, doc.y + 10); doc.y += 25;
        let y = doc.y;
        doc.rect(30, y, 350, 20).stroke().text("Item", 35, y + 5); doc.rect(380, y, 60, 20).stroke().text("Sts", 385, y + 5); doc.rect(440, y, 125, 20).stroke().text("Rem", 445, y + 5); y += 20;
        doc.font('Helvetica').fontSize(8);
        i.forEach((x, k) => {
            let rowH = 20;
            if (pr === 'A' && k === 11) rowH = 45;
            if (y + rowH > 750) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; y = 135; }
            const st = d[`${pr}_Q${k + 1}`] || 'NA';
            if (d[`${pr}_Q${k + 1}`]) {
                doc.rect(30, y, 350, rowH).stroke().text(x, 35, y + 5, { width: 340 });
                doc.rect(380, y, 60, rowH).stroke().text(st, 385, y + 5);
                let detailTxt = d[`${pr}_Q${k + 1}_Detail`] || '';
                if (pr === 'A' && k === 11) {
                    const hc = d.GP_Q12_HC || '_';
                    const tox = d.GP_Q12_ToxicGas || '_';
                    const o2 = d.GP_Q12_Oxygen || '_';
                    detailTxt = `HC: ${hc}% LEL\nTox: ${tox} PPM\nO2: ${o2}%`;
                }
                doc.rect(440, y, 125, rowH).stroke().text(detailTxt, 445, y + 5);
                y += rowH;
            }
        }); doc.y = y;
    };
    drawChecklist("SECTION A: GENERAL", CHECKLIST_DATA.A, 'A');
    drawChecklist("SECTION B : For Hot work / Entry to confined Space", CHECKLIST_DATA.B, 'B');
    drawChecklist("SECTION C: For vehicle Entry in Hazardous area", CHECKLIST_DATA.C, 'C'); 
    drawChecklist("SECTION D: EXCAVATION", CHECKLIST_DATA.D, 'D');

    if (doc.y > 600) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
    doc.font('Helvetica-Bold').fontSize(9).text("Annexure III: ATTACHMENT TO MAINLINE WORK PERMIT", 30, doc.y); doc.y += 15;

    // Annexure III Table
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
    doc.font('Helvetica-Bold').text("Parameter", 35, axY + 5);
    doc.text("Details", 235, axY + 5);
    axY += 20;

    doc.font('Helvetica');
    annexData.forEach(row => {
        doc.rect(30, axY, 200, 20).stroke();
        doc.text(row[0], 35, axY + 5);
        doc.rect(230, axY, 335, 20).stroke();
        doc.text(row[1], 235, axY + 5);
        axY += 20;
    });
    doc.y = axY + 20;

    // Helper for Supervisor tables
    const drawSupTable = (title, headers, dataRows) => {
        if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
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
            if (currentY + maxRowHeight > 750) { doc.addPage(); drawHeaderOnAll(); currentY = 135; }
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
        let auditText = `Add: ${s.added_by || '-'} (${s.added_at || '-'})`;
        if (s.is_deleted) auditText += `\nDel: ${s.deleted_by} (${s.deleted_at})`;
        return [s.name, s.desig, s.contact, auditText];
    });
    if (ioclRows.length === 0) ioclRows.push(["-", "-", "-", "-"]);
    drawSupTable("Authorized Work Supervisor (IOCL)", [{ t: "Name", w: 130 }, { t: "Designation", w: 130 }, { t: "Contact", w: 100 }, { t: "Audit Trail", w: 175 }], ioclRows);

    const contRows = [[d.RequesterName || '-', "Site In-Charge / Requester", d.EmergencyContact || '-']];
    drawSupTable("Authorized Work Supervisor (Contractor)", [{ t: "Name", w: 180 }, { t: "Designation", w: 180 }, { t: "Contact", w: 175 }], contRows);

    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
    doc.font('Helvetica-Bold').text("HAZARDS & PRECAUTIONS", 30, doc.y); doc.y += 15; doc.rect(30, doc.y, 535, 60).stroke();
    const hazKeys = ["Lack of Oxygen", "H2S", "Toxic Gases", "Combustible gases", "Pyrophoric Iron", "Corrosive Chemicals", "cave in formation"];
    const foundHaz = hazKeys.filter(k => d[`H_${k.replace(/ /g, '')}`] === 'Y');
    if (d.H_Others === 'Y') foundHaz.push(`Others: ${d.H_Others_Detail}`);
    doc.text(`1.The activity has the following expected residual hazards: ${foundHaz.join(', ')}`, 35, doc.y + 5);
    
    const ppeKeys = ["Helmet", "Safety Shoes", "Hand gloves", "Boiler suit", "Face Shield", "Apron", "Goggles", "Dust Respirator", "Fresh Air Mask", "Lifeline", "Safety Harness", "Airline", "Earmuff", "IFR"];
    const foundPPE = ppeKeys.filter(k => d[`P_${k.replace(/ /g, '')}`] === 'Y');
    if (d.AdditionalPrecautions && d.AdditionalPrecautions.trim() !== '') { foundPPE.push(`(Other: ${d.AdditionalPrecautions})`); }
    doc.text(`2.Following additional PPE to be used in addition to standards PPE: ${foundPPE.join(', ')}`, 35, doc.y + 25);
    doc.y += 70;

    // Workers Table
    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
    doc.font('Helvetica-Bold').text("WORKERS DEPLOYED", 30, doc.y); doc.y += 15;
    let wy = doc.y;
    doc.rect(30, wy, 80, 20).stroke().text("Name", 35, wy + 5);
    doc.rect(110, wy, 40, 20).stroke().text("Gender", 112, wy + 5);
    doc.rect(150, wy, 30, 20).stroke().text("Age", 152, wy + 5);
    doc.rect(180, wy, 90, 20).stroke().text("ID Details", 182, wy + 5);
    doc.rect(270, wy, 80, 20).stroke().text("Requestor", 272, wy + 5);
    doc.rect(350, wy, 215, 20).stroke().text("Approved On / By", 352, wy + 5);
    wy += 20;
    let workers = d.SelectedWorkers || [];
    if (typeof workers === 'string') { try { workers = JSON.parse(workers); } catch (e) { workers = []; } }
    doc.font('Helvetica').fontSize(8);
    workers.forEach(w => {
        if (wy > 750) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; wy = 135; }
        doc.rect(30, wy, 80, 35).stroke().text(w.Name, 35, wy + 5);
        doc.rect(110, wy, 40, 35).stroke().text(w.Gender || '-', 112, wy + 5);
        doc.rect(150, wy, 30, 35).stroke().text(w.Age, 152, wy + 5);
        doc.rect(180, wy, 90, 35).stroke().text(`${w.IDType || ''}: ${w.ID || '-'}`, 182, wy + 5);
        doc.rect(270, wy, 80, 35).stroke().text(w.RequestorName || '-', 272, wy + 5);
        doc.rect(350, wy, 215, 35).stroke().text(`${w.ApprovedAt || '-'} by ${w.ApprovedBy || 'Admin'}`, 352, wy + 5);
        wy += 35;
    });
    doc.y = wy + 20;

    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
    doc.font('Helvetica-Bold').text("SIGNATURES", 30, doc.y);
    doc.y += 15; const sY = doc.y;
    doc.rect(30, sY, 178, 40).stroke().text(`REQ: ${d.RequesterName} on ${d.CreatedDate || '-'}`, 35, sY + 5);
    doc.rect(208, sY, 178, 40).stroke().text(`REV: ${d.Reviewer_Sig || '-'}\nRem: ${d.Reviewer_Remarks || '-'}`, 213, sY + 5, { width: 168 });
    doc.rect(386, sY, 179, 40).stroke().text(`APP: ${d.Approver_Sig || '-'}\nRem: ${d.Approver_Remarks || '-'}`, 391, sY + 5, { width: 169 });
    doc.y = sY + 50;

    // --- RENEWAL TABLE ---
    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
    doc.font('Helvetica-Bold').text("CLEARANCE RENEWAL", 30, doc.y); doc.y += 15;
    let ry = doc.y;

    doc.rect(30, ry, 45, 25).stroke().text("From", 32, ry + 5);
    doc.rect(75, ry, 45, 25).stroke().text("To", 77, ry + 5);
    doc.rect(120, ry, 55, 25).stroke().text("Gas/Prec", 122, ry + 5);
    doc.rect(175, ry, 60, 25).stroke().text("Workers", 177, ry + 5);
    doc.rect(235, ry, 50, 25).stroke().text("Photo", 237, ry + 5);
    doc.rect(285, ry, 70, 25).stroke().text("Req", 287, ry + 5);
    doc.rect(355, ry, 70, 25).stroke().text("Rev", 357, ry + 5);
    doc.rect(425, ry, 70, 25).stroke().text("App", 427, ry + 5);
    doc.rect(495, ry, 70, 25).stroke().text("Reason", 497, ry + 5);

    ry += 25;
    const finalRenewals = renewalsList || JSON.parse(p.RenewalsJSON || "[]");
    doc.font('Helvetica').fontSize(8);

    for (const r of finalRenewals) {
        const rowHeight = 60;
        if (ry > 680) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; ry = 135; }

        let startTxt = r.valid_from.replace('T', '\n');
        let endTxt = r.valid_till.replace('T', '\n');
        if (r.odd_hour_req === true) {
            endTxt += "\n(Night Shift)";
            doc.font('Helvetica-Bold').fillColor('purple');
        }

        doc.rect(30, ry, 45, rowHeight).stroke().text(startTxt, 32, ry + 5, { width: 43 });
        doc.rect(75, ry, 45, rowHeight).stroke().text(endTxt, 77, ry + 5, { width: 43 });
        doc.fillColor('black').font('Helvetica');

        doc.rect(120, ry, 55, rowHeight).stroke().text(`HC: ${r.hc}\nTox: ${r.toxic}\nO2: ${r.oxygen}\nPrec: ${r.precautions || '-'}`, 122, ry + 5, { width: 53 });
        const wList = r.worker_list ? r.worker_list.join(', ') : 'All';
        doc.rect(175, ry, 60, rowHeight).stroke().text(wList, 177, ry + 5, { width: 58 });

        // --- PHOTO: ASYNC DOWNLOAD with TIMEOUT ---
        doc.rect(235, ry, 50, rowHeight).stroke();
        if (r.photoUrl && containerClient) {
            try {
                const blobName = r.photoUrl.split('/').pop();
                const blockBlobClient = containerClient.getBlockBlobClient(blobName);
                
                // Add Timeout to prevent hanging
                const downloadPromise = blockBlobClient.download(0);
                const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 3000));
                
                const downloadBlockBlobResponse = await Promise.race([downloadPromise, timeoutPromise]);
                const chunks = [];
                for await (const chunk of downloadBlockBlobResponse.readableStreamBody) {
                    chunks.push(chunk);
                }
                const imageBuffer = Buffer.concat(chunks);
                try {
                    doc.image(imageBuffer, 237, ry + 2, { fit: [46, rowHeight - 4], align: 'center', valign: 'center' });
                } catch (imgErr) { console.log("Img draw err", imgErr); }
            } catch (err) { console.log("Blob err/Timeout", err.message); }
        } else {
            doc.text("No Photo", 237, ry + 25, { width: 46, align: 'center' });
        }

        doc.rect(285, ry, 70, rowHeight).stroke().text(`${r.req_name}\n${r.req_at}`, 287, ry + 5, { width: 66 });
        doc.rect(355, ry, 70, rowHeight).stroke().text(`${r.rev_name || '-'}\n${r.rev_at || ''}`, 357, ry + 5, { width: 66 });
        doc.rect(425, ry, 70, rowHeight).stroke().text(`${r.app_name || '-'}\n${r.app_at || ''}`, 427, ry + 5, { width: 66 });
        doc.rect(495, ry, 70, rowHeight).stroke().text(r.status === 'rejected' ? (r.rej_reason || 'Rejected') : '-', 497, ry + 5, { width: 66 });

        ry += rowHeight;
    }
    doc.y = ry + 20;

    // --- CLOSURE SECTION ---
    if (p.Status === 'Closed' || p.Status.includes('Closure') || d.Closure_Issuer_Sig) {
        if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
        doc.font('Helvetica-Bold').fontSize(10).text("WORK COMPLETION & CLOSURE", 30, doc.y);
        doc.y += 15;
        const cY = doc.y;

        const boxColor = d.Site_Restored_Check === 'Y' ? '#dcfce7' : '#fee2e2';
        const checkMark = d.Site_Restored_Check === 'Y' ? 'YES' : 'NO';

        doc.rect(30, cY, 535, 25).fillColor(boxColor).fill().stroke();
        doc.fillColor('black');
        doc.text(`Site Restored, Materials Removed & Housekeeping Done?  [ ${checkMark} ]`, 35, cY + 8);
        doc.y += 35;

        const closureY = doc.y;
        if (closureY > 700) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; }
        doc.rect(30, closureY, 178, 60).stroke().text(`REQUESTOR:\n${d.Closure_Receiver_Sig || '-'}\nDate: ${d.Closure_Requestor_Date || '-'}\nRem: ${d.Closure_Requestor_Remarks || '-'}`, 35, closureY + 5, { width: 168 });
        doc.rect(208, closureY, 178, 60).stroke().text(`REVIEWER:\n${d.Closure_Reviewer_Sig || '-'}\nDate: ${d.Closure_Reviewer_Date || '-'}\nRem: ${d.Closure_Reviewer_Remarks || '-'}`, 213, closureY + 5, { width: 168 });
        doc.rect(386, closureY, 179, 60).stroke().text(`ISSUING AUTHORITY (APPROVER):\n${d.Closure_Issuer_Sig || '-'}\nDate: ${d.Closure_Approver_Date || '-'}\nRem: ${d.Closure_Approver_Remarks || '-'}`, 391, closureY + 5, { width: 169 });
    }
}

/* =====================================================
   HIERARCHY & ADMIN ROUTES
===================================================== */

// 1. Get Dropdown Hierarchy for Login Page
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
        const key = !region ? 'Region' : (!unit ? 'Unit' : 'Location');
        res.json(r.recordset.map(x => x[key]));
    } catch (e) { res.status(500).json({error: e.message}); }
});

// 2. Filter Users based on Hierarchy
app.post('/api/get-users-by-loc', async (req, res) => {
    try {
        const { region, unit, location, role } = req.body;
        const pool = await getConnection();
        const r = await pool.request()
            .input('r', region).input('u', unit).input('l', location).input('role', role)
            .query("SELECT Name, Email FROM Users WHERE Region=@r AND Unit=@u AND Location=@l AND Role=@role");
        res.json(r.recordset);
    } catch(e) { res.status(500).json({error:e.message}); }
});

// 3. Login with Force Password Change Check
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const pool = await getConnection();
    const r = await pool.request()
      .input('e', sql.NVarChar, req.body.email) 
      .query('SELECT * FROM Users WHERE Email=@e');

    if (!r.recordset.length) return res.json({ success: false, msg: "User not found" });

    const user = r.recordset[0];
    const valid = await bcrypt.compare(req.body.password, user.Password);
    if (!valid) return res.json({ success: false, msg: "Invalid credentials" });

    // REQ I: Mandatory Password Change
    if (user.ForcePwdChange === 'Y') {
        return res.json({ success: false, forceChange: true, email: user.Email });
    }

    // Token Logic
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
        success: true, token: accessToken, 
        user: { Name: user.Name, Email: user.Email, Role: user.Role, Region: user.Region, Unit: user.Unit, Location: user.Location } 
    });

  } catch (err) { res.status(500).json({ error: "Login Error" }); }
});

// 4. Force Password Change (First Login)
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

// 5. Reset Password (Admin/Approver)
app.post('/api/admin/reset-password', authenticateAccess, async (req, res) => {
    try {
        const { targetEmail, newTempPass } = req.body;
        const pool = await getConnection();
        
        // Security Check
        const target = await pool.request().input('e', targetEmail).query("SELECT CreatedBy, Region FROM Users WHERE Email=@e");
        if(!target.recordset.length) return res.status(404).json({error: "User not found"});
        
        const tUser = target.recordset[0];

        // REQ G & H: Permission Logic
        let allow = false;
        if (req.user.role === 'MasterAdmin') allow = true;
        else if (req.user.role === 'Approver' && tUser.CreatedBy === req.user.email) allow = true;

        if (!allow) return res.status(403).json({ error: "Unauthorized to reset this user" });

        const hashed = await bcrypt.hash(newTempPass, 10);
        await pool.request().input('e', targetEmail).input('p', hashed)
            .query("UPDATE Users SET Password=@p, ForcePwdChange='Y' WHERE Email=@e"); // REQ I: Force change next time

        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// 6. Bulk Upload Users (Master Admin Only)
app.post('/api/admin/bulk-upload', authenticateAccess, upload.single('excelFile'), async (req, res) => {
    if(req.user.role !== 'MasterAdmin') return res.status(403).json({error: "Master Admin only"});
    
    try {
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(req.file.buffer);
        const worksheet = workbook.getWorksheet(1);
        const pool = await getConnection();
        
        const promises = [];
        
        worksheet.eachRow((row, rowNumber) => {
            if(rowNumber === 1) return; // Skip Header
            // Columns: A=Name, B=Email, C=Role, D=Password, E=Region, F=Unit, G=Location
            const name = row.getCell(1).value;
            const email = row.getCell(2).value;
            const role = row.getCell(3).value;
            const pass = row.getCell(4).value.toString(); // Temp Pass
            const region = row.getCell(5).value;
            const unit = row.getCell(6).value;
            const loc = row.getCell(7).value;

            promises.push((async () => {
                const hashed = await bcrypt.hash(pass, 10);
                await pool.request()
                    .input('n', name).input('e', email).input('r', role).input('p', hashed)
                    .input('reg', region).input('u', unit).input('l', loc).input('cb', req.user.email)
                    .query(`
                        IF NOT EXISTS (SELECT * FROM Users WHERE Email=@e)
                        INSERT INTO Users (Name, Email, Role, Password, Region, Unit, Location, CreatedBy, ForcePwdChange)
                        VALUES (@n, @e, @r, @p, @reg, @u, @l, @cb, 'Y')
                    `);
            })());
        });

        await Promise.all(promises);
        res.json({ success: true, count: promises.length });

    } catch(e) { res.status(500).json({error: "Bulk Upload Failed: " + e.message}); }
});

// 7. Add User (Single)
app.post('/api/add-user', authenticateAccess, async (req, res) => {
    if(req.user.role !== 'Approver' && req.user.role !== 'MasterAdmin') return res.sendStatus(403);
    try {
        const pool = await getConnection();
        const check = await pool.request().input('e', req.body.email).query("SELECT * FROM Users WHERE Email=@e");
        if(check.recordset.length) return res.status(400).json({error: "User Exists"});

        const hashed = await bcrypt.hash(req.body.password, 10);
        
        // Approver can only add to their location
        const reg = req.user.role === 'MasterAdmin' ? req.body.region : req.user.region;
        const unit = req.user.role === 'MasterAdmin' ? req.body.unit : req.user.unit; // Assuming stored in token/user obj
        const loc = req.user.role === 'MasterAdmin' ? req.body.location : req.user.location;

        await pool.request()
            .input('n', req.body.name).input('e', req.body.email).input('r', req.body.role).input('p', hashed)
            .input('reg', reg).input('u', unit).input('l', loc).input('cb', req.user.email)
            .query("INSERT INTO Users (Name,Email,Role,Password,Region,Unit,Location,CreatedBy,ForcePwdChange) VALUES (@n,@e,@r,@p,@reg,@u,@l,@cb,'Y')");
        
        res.json({success: true});
    } catch(e) { res.status(500).json({error: "Error Adding User"}); }
});

// 8. Delete User (Approver/Admin)
app.post('/api/delete-user', authenticateAccess, async (req, res) => {
    try {
        const targetEmail = req.body.email;
        const pool = await getConnection();
        
        // Security Check
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

/* =====================================================
   CORE PERMIT ROUTES
===================================================== */

app.post('/api/save-worker', authenticateAccess, async (req, res) => {
  try {
    const { WorkerID, Action, Role, Details, RequestorEmail, RequestorName } = req.body;
    const pool = await getConnection();

    if ((Action === 'create' || Action === 'edit_request') && Details && parseInt(Details.Age) < 18) {
      return res.status(400).json({ error: "Worker must be 18+" });
    }

    if (Action === 'create') {
      const idRes = await pool.request().query("SELECT TOP 1 WorkerID FROM Workers ORDER BY WorkerID DESC");
      const wid = `W-${parseInt(idRes.recordset.length ? idRes.recordset[0].WorkerID.split('-')[1] : 1000) + 1}`;
      const dataObj = { Current: {}, Pending: { ...Details, RequestorName } };
      await pool.request()
        .input('w', wid)
        .input('s', 'Pending Review')
        .input('r', RequestorEmail)
        .input('j', JSON.stringify(dataObj))
        .input('idt', sql.NVarChar, Details.IDType)
        .query("INSERT INTO Workers (WorkerID, Status, RequestorEmail, DataJSON, IDType) VALUES (@w,@s,@r,@j,@idt)");

      return res.json({ success: true });
    }

    if (Action === 'edit_request') {
      const cur = await pool.request().input('w', WorkerID).query("SELECT DataJSON FROM Workers WHERE WorkerID=@w");
      if (!cur.recordset.length) return res.status(404).json({ error: "Worker not found" });
      let dataObj = JSON.parse(cur.recordset[0].DataJSON);
      dataObj.Pending = { ...dataObj.Current, ...Details, RequestorName };
      await pool.request()
        .input('w', WorkerID)
        .input('s', 'Edit Pending Review')
        .input('j', JSON.stringify(dataObj))
        .input('idt', sql.NVarChar, Details.IDType)
        .query("UPDATE Workers SET Status=@s, DataJSON=@j, IDType=@idt WHERE WorkerID=@w");

      return res.json({ success: true });
    }

    if (Action === 'delete') {
      if (req.user.role === 'Requester') {
        const check = await pool.request().input('w', WorkerID).query("SELECT RequestorEmail FROM Workers WHERE WorkerID=@w");
        if (!check.recordset.length) return res.status(404).json({ error: "Not found" });
        if (check.recordset[0].RequestorEmail !== req.user.email) {
          return res.status(403).json({ error: "Unauthorized" });
        }
      }
      await pool.request().input('w', WorkerID).query("DELETE FROM Workers WHERE WorkerID=@w");
      return res.json({ success: true });
    }

    const cur = await pool.request().input('w', WorkerID).query("SELECT Status, DataJSON FROM Workers WHERE WorkerID=@w");
    if (!cur.recordset.length) return res.status(404).json({ error: "Worker not found" });

    let st = cur.recordset[0].Status;
    let dataObj = JSON.parse(cur.recordset[0].DataJSON);
    let appBy = null, appOn = null;

    if (Action === 'approve') {
      if (req.user.role === 'Requester') return res.status(403).json({ error: "Unauthorized" });
      if (st.includes('Pending Review')) st = st.replace('Review', 'Approval');
      else if (st.includes('Pending Approval')) {
        st = 'Approved';
        appBy = req.user.name;
        appOn = getNowIST();
        dataObj.Current = { ...dataObj.Pending, ApprovedBy: appBy, ApprovedAt: appOn };
        dataObj.Pending = null;
      }
    } else if (Action === 'reject') {
      st = 'Rejected';
      dataObj.Pending = null;
    }

    await pool.request()
      .input('w', WorkerID)
      .input('s', st)
      .input('j', JSON.stringify(dataObj))
      .input('aby', sql.NVarChar, appBy)
      .input('aon', sql.NVarChar, appOn)
      .query("UPDATE Workers SET Status=@s, DataJSON=@j, ApprovedBy=@aby, ApprovedOn=@aon WHERE WorkerID=@w");

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post('/api/get-workers', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const r = await pool.request().query("SELECT * FROM Workers");
    const list = r.recordset.map(w => {
      const d = JSON.parse(w.DataJSON);
      const details = d.Pending || d.Current || {};
      details.IDType = w.IDType || details.IDType;
      details.ApprovedBy = w.ApprovedBy || details.ApprovedBy;
      details.ApprovedAt = w.ApprovedOn || details.ApprovedAt;
      return {
        ...details,
        WorkerID: w.WorkerID,
        Status: w.Status,
        RequestorEmail: w.RequestorEmail,
        IsEdit: w.Status.includes('Edit')
      };
    });

    if (req.body.context === 'permit_dropdown') {
      return res.json(list.filter(w => w.Status === 'Approved'));
    }

    if (req.user.role === 'Requester') {
      return res.json(list.filter(w => w.RequestorEmail === req.user.email || w.Status === 'Approved'));
    }

    res.json(list);

  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post('/api/dashboard', authenticateAccess, async (req, res) => {
  try {
    const { role, email } = req.user;
    const pool = await getConnection();
    const r = await pool.request().query(
      "SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON, FinalPdfUrl FROM Permits"
    );
    const p = r.recordset.map(x => {
      let baseData = {};
      if (x.FullDataJSON) {
        try { baseData = JSON.parse(x.FullDataJSON); } catch {}
      }
      return {
        ...baseData,
        PermitID: x.PermitID,
        Status: x.Status,
        RequesterEmail: x.RequesterEmail,
        ReviewerEmail: x.ReviewerEmail,
        ApproverEmail: x.ApproverEmail,
        FinalPdfUrl: x.FinalPdfUrl
      }
    });
    
    // Strict Assignment
    const f = p.filter(x => {
        if (role === 'Requester') return x.RequesterEmail === email;
        if (role === 'Reviewer') return x.ReviewerEmail === email;
        if (role === 'Approver') return x.ApproverEmail === email;
        if (role === 'MasterAdmin') return true; // Admin sees all
        return false;
    });
    
    res.json(f.sort((a,b) => {
        const numA = parseInt(a.PermitID.split('-')[1] || 0);
        const numB = parseInt(b.PermitID.split('-')[1] || 0);
        return numB - numA; 
    }));

  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post('/api/save-permit', authenticateAccess, upload.any(), async (req, res) => {
  try {
    const requesterEmail = req.user.email;
    let vf, vt;
    try {
      vf = req.body.ValidFrom ? new Date(req.body.ValidFrom) : null;
      vt = req.body.ValidTo ? new Date(req.body.ValidTo) : null;
    } catch {
      return res.status(400).json({ error: "Invalid Date Format" });
    }

    if (!vf || !vt) return res.status(400).json({ error: "Start & End required" });
    if (vt <= vf) return res.status(400).json({ error: "End > Start required" });

    const pool = await getConnection();
    let pid = req.body.PermitID;

    // Mathematical ID
    if (!pid || pid === 'undefined' || pid === 'null' || pid === '') {
      const idRes = await pool.request().query("SELECT MAX(CAST(SUBSTRING(PermitID, 4, 10) AS INT)) as MaxVal FROM Permits WHERE PermitID LIKE 'WP-%'");
      let nextNum = 1000;
      if (idRes.recordset[0].MaxVal) {
        nextNum = idRes.recordset[0].MaxVal + 1;
      }
      pid = `WP-${nextNum}`;
    }

    const chk = await pool.request().input('p', sql.NVarChar, pid)
      .query("SELECT Status FROM Permits WHERE PermitID=@p");
    
    if (chk.recordset.length && chk.recordset[0].Status.includes('Closed')) {
      return res.status(400).json({ error: "Permit CLOSED" });
    }

    let workers = req.body.SelectedWorkers;
    if (typeof workers === 'string') { try { workers = JSON.parse(workers); } catch { workers = []; } }

    let renewalsArr = [];
    if (req.body.InitRen === 'Y') {
      let photoUrl = null;
      const renImg = req.files ? req.files.find(x => x.fieldname === 'InitRenImage') : null;
      if (renImg) {
        const blobName = `${pid}-1stRenewal.jpg`;
        // Use verified safe upload
        photoUrl = await uploadToAzure(renImg.buffer, blobName);
      }
      renewalsArr.push({
        status: 'pending_review',
        valid_from: req.body.InitRenFrom,
        valid_till: req.body.InitRenTo,
        hc: req.body.InitRenHC,
        toxic: req.body.InitRenTox,
        oxygen: req.body.InitRenO2,
        precautions: req.body.InitRenPrec,
        req_name: req.body.RequesterName,
        req_at: getNowIST(),
        worker_list: workers.map(w => w.Name),
        photoUrl
      });
    }

    const renewalsJsonStr = JSON.stringify(renewalsArr);
    const data = { ...req.body, SelectedWorkers: workers, PermitID: pid, CreatedDate: getNowIST(), GSR_Accepted: 'Y' };

    const safeLat = req.body.Latitude && req.body.Latitude !== 'undefined' ? String(req.body.Latitude) : null;
    const safeLng = req.body.Longitude && req.body.Longitude !== 'undefined' ? String(req.body.Longitude) : null;

    const q = pool.request()
      .input('p', sql.NVarChar, pid)
      .input('s', sql.NVarChar, 'Pending Review')
      .input('w', sql.NVarChar, req.body.WorkType)
      .input('re', sql.NVarChar, requesterEmail)
      .input('rv', sql.NVarChar, req.body.ReviewerEmail)
      .input('ap', sql.NVarChar, req.body.ApproverEmail)
      .input('vf', sql.DateTime, vf)
      .input('vt', sql.DateTime, vt)
      .input('lat', sql.NVarChar, safeLat)
      .input('lng', sql.NVarChar, safeLng)
      .input('j', sql.NVarChar(sql.MAX), JSON.stringify(data))
      .input('ren', sql.NVarChar(sql.MAX), renewalsJsonStr);

    if (chk.recordset.length) {
      await q.query("UPDATE Permits SET FullDataJSON=@j, WorkType=@w, ValidFrom=@vf, ValidTo=@vt, Latitude=@lat, Longitude=@lng, Status=@s, ReviewerEmail=@rv, ApproverEmail=@ap, RenewalsJSON=@ren WHERE PermitID=@p");
    } else {
      await q.query("INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, FullDataJSON, RenewalsJSON) VALUES (@p,@s,@w,@re,@rv,@ap,@vf,@vt,@lat,@lng,@j,@ren)");
    }

    res.json({ success: true, permitId: pid });

  } catch (err) {
    console.error("Save Error:", err.message);
    res.status(500).json({ error: "Database Save Failed" });
  }
});

app.post('/api/update-status', authenticateAccess, async (req, res) => {
  try {
    const { PermitID, action, ...extras } = req.body;
    const role = req.user.role;
    const user = req.user.name;

    const pool = await getConnection();
    const cur = await pool.request().input('p', PermitID).query("SELECT * FROM Permits WHERE PermitID=@p");
    if (!cur.recordset.length) return res.status(404).json({ error:"Not found" });

    let st = cur.recordset[0].Status;
    let d = JSON.parse(cur.recordset[0].FullDataJSON || "{}");
    let renewals = JSON.parse(cur.recordset[0].RenewalsJSON || "[]");
    const now = getNowIST();

    Object.assign(d, extras);

    if (renewals.length === 1) {
      const r1 = renewals[0];
      if (['pending_review','pending_approval'].includes(r1.status)) {
        if (action === 'reject') {
          r1.status = 'rejected'; r1.rej_by = user; r1.rej_reason = "Rejected with main permit";
        } else if (role === 'Reviewer' && action === 'review') {
          r1.status = 'pending_approval'; r1.rev_name = user; r1.rev_at = now;
        } else if (role === 'Approver' && action === 'approve') {
          r1.status = 'approved'; r1.app_name = user; r1.app_at = now;
        }
      }
    }

    if (action === 'reject_closure') st = 'Active';
    else if (action === 'approve_closure' && role === 'Reviewer') {
      st = 'Closure Pending Approval';
      d.Closure_Reviewer_Sig = `${user} on ${now}`;
      d.Closure_Reviewer_Date = now;
    }
    else if (action === 'approve' && role === 'Approver') {
      if (st.includes('Closure Pending Approval')) {
        st = 'Closed';
        d.Closure_Issuer_Sig = `${user} on ${now}`;
        d.Closure_Approver_Date = now;
        d.Closure_Approver_Sig = `${user} on ${now}`;
      } else {
        st = 'Active';
        d.Approver_Sig = `${user} on ${now}`;
      }
    }
    else if (action === 'initiate_closure') {
      st = 'Closure Pending Review';
      d.Closure_Requestor_Date = now;
      d.Closure_Receiver_Sig = `${user} on ${now}`;
    }
    else if (action === 'reject') st = 'Rejected';
    else if (role === 'Reviewer' && action === 'review') {
      st = 'Pending Approval';
      d.Reviewer_Sig = `${user} on ${now}`;
    }

    let finalPdfUrl = null;
    let finalJson = JSON.stringify(d);

    if (st === 'Closed') {
      const pdfRecord = { ...cur.recordset[0], Status:'Closed', PermitID, ValidFrom:cur.recordset[0].ValidFrom, ValidTo:cur.recordset[0].ValidTo };
      const pdfBuffer = await new Promise(async (resolve, reject)=>{
        const doc = new PDFDocument({ margin:30, size:'A4', bufferPages:true });
        const buffers=[];
        
        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', ()=> resolve(Buffer.concat(buffers)));
        doc.on('error', reject);

        try {
          await drawPermitPDF(doc, pdfRecord, d, renewals);
          doc.end();
        } catch(e) { 
            if(!doc.closed) doc.end(); 
            reject(e); 
        }
      });
      const blobName = `closed-permits/${PermitID}_FINAL.pdf`;
      // Allow PDF upload for System Archives
      finalPdfUrl = await uploadToAzure(pdfBuffer, blobName, true);
    }

    const q = pool.request().input('p', PermitID).input('s', st).input('r', JSON.stringify(renewals));
    if (finalPdfUrl) {
      await q.input('url', finalPdfUrl).query("UPDATE Permits SET Status=@s, FullDataJSON=NULL, RenewalsJSON=NULL, FinalPdfUrl=@url WHERE PermitID=@p");
    } else {
      await q.input('j', finalJson).query("UPDATE Permits SET Status=@s, FullDataJSON=@j, RenewalsJSON=@r WHERE PermitID=@p");
    }

    res.json({ success:true, archived:!!finalPdfUrl });

  } catch (err) {
    console.error("Status Update Error:", err);
    res.status(500).json({ error:"Internal Server Error" });
  }
});

app.post('/api/renewal', authenticateAccess, upload.any(), async (req, res) => {
  try {
    const { PermitID, action, rejectionReason, renewalWorkers, oddHourReq, ...data } = req.body;
    const role = req.user.role;
    const user = req.user.name;

    const pool = await getConnection();
    const cur = await pool.request().input('p', PermitID).query("SELECT RenewalsJSON, Status, ValidFrom, ValidTo FROM Permits WHERE PermitID=@p");
    if (cur.recordset[0].Status === 'Closed') return res.status(400).json({ error:"Permit CLOSED" });

    let r = JSON.parse(cur.recordset[0].RenewalsJSON || "[]");
    const now = getNowIST();

    if (role === 'Requester') {
      const rs = new Date(data.RenewalValidFrom);
      const re = new Date(data.RenewalValidTo);
      if (re <= rs) return res.status(400).json({ error:"End > Start required" });

      const pStart = new Date(cur.recordset[0].ValidFrom);
      const pEnd = new Date(cur.recordset[0].ValidTo);
      if (rs < pStart || re > pEnd) {
        return res.status(400).json({ error:"Renewal must be within main permit" });
      }

      const diffMs = re - rs;
      if (diffMs > 8*60*60*1000) {
        return res.status(400).json({ error:"Max 8 hours" });
      }

      if (r.length > 0) {
        const last = r[r.length-1];
        if (last.status !== 'rejected') {
          const lastEnd = new Date(last.valid_till);
          if (rs < lastEnd) {
            return res.status(400).json({ error:"Overlap not allowed" });
          }
        }
      }

      const file = req.files ? req.files.find(f => f.fieldname === 'RenewalImage') : null;
      let photoUrl=null;
      if (file) {
        const blobName = `${PermitID}-${getOrdinal(r.length+1)}Renewal.jpg`;
        photoUrl = await uploadToAzure(file.buffer, blobName);
      }

      r.push({
        status:'pending_review',
        valid_from:data.RenewalValidFrom,
        valid_till:data.RenewalValidTo,
        hc:data.hc,
        toxic:data.toxic,
        oxygen:data.oxygen,
        precautions:data.precautions,
        req_name:user,
        req_at:now,
        worker_list: JSON.parse(renewalWorkers || "[]"),
        photoUrl,
        odd_hour_req:(oddHourReq === 'Y')
      });
    } else {
      const last=r[r.length-1];
      if (action==='reject') {
        last.status='rejected';
        last.rej_by=user;
        last.rej_reason=rejectionReason;
      } else {
        if (role==='Reviewer') {
          last.status='pending_approval';
          last.rev_name=user;
          last.rev_at=now;
        } else if (role==='Approver') {
          last.status='approved';
          last.app_name=user;
          last.app_at=now;
        }
      }
    }

    const last=r[r.length-1];
    let newStatus;
    if (last.status==='approved' || last.status==='rejected') newStatus='Active';
    else newStatus = last.status==='pending_review' ? 'Renewal Pending Review' : 'Renewal Pending Approval';

    await pool.request()
      .input('p',PermitID)
      .input('r',JSON.stringify(r))
      .input('s',newStatus)
      .query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p");

    res.json({ success:true });

  } catch (err) {
    res.status(500).json({ error:"Internal Server Error" });
  }
});

app.post('/api/permit-data', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const r = await pool.request().input('p', sql.NVarChar, req.body.permitId)
      .query("SELECT * FROM Permits WHERE PermitID=@p");
    if (!r.recordset.length) return res.json({ error:"404" });

    const jsonStr = r.recordset[0].FullDataJSON;
    const data = jsonStr ? JSON.parse(jsonStr) : {};

    res.json({
      ...data,
      Status:r.recordset[0].Status,
      RenewalsJSON:r.recordset[0].RenewalsJSON,
      RequireRenewalPhotos:data.RequireRenewalPhotos || 'N',
      FullDataJSON:null
    });

  } catch (err) {
    res.status(500).json({ error:"Internal Server Error" });
  }
});

app.post('/api/map-data', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const r = await pool.request()
      .query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status='Active'");
    res.json(r.recordset.map(x => ({
      PermitID:x.PermitID,
      lat: parseFloat(x.Latitude),
      lng: parseFloat(x.Longitude),
      ...JSON.parse(x.FullDataJSON)
    })));
  } catch (err) {
    res.status(500).json({ error:"Internal Server Error" });
  }
});

app.post('/api/stats', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const r = await pool.request().query("SELECT Status, WorkType FROM Permits");
    const s={}, t={};
    r.recordset.forEach(x=>{
      s[x.Status]=(s[x.Status]||0)+1;
      t[x.WorkType]=(t[x.WorkType]||0)+1;
    });
    res.json({ success:true, statusCounts:s, typeCounts:t });
  } catch (err) {
    res.status(500).json({ error:"Internal Server Error" });
  }
});

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
    sheet.getRow(1).font = { bold:true };
    result.recordset.forEach(r=>{
      const d = r.FullDataJSON ? JSON.parse(r.FullDataJSON) : {};
      sheet.addRow({
        id:r.PermitID,
        status:r.Status,
        wt:d.WorkType || '-',
        req:d.RequesterName || '-',
        loc:d.ExactLocation || '-',
        ven:d.Vendor || '-',
        vf:formatDate(r.ValidFrom),
        vt:formatDate(r.ValidTo)
      });
    });
    res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition','attachment; filename=IndianOil_Permits.xlsx');
    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    res.status(500).send("Internal Server Error");
  }
});

app.get('/api/download-pdf/:id', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const result = await pool.request().input('p', req.params.id)
      .query("SELECT * FROM Permits WHERE PermitID=@p");
    if (!result.recordset.length) return res.status(404).send('Not Found');

    const p = result.recordset[0];

    // Strict Authorization
    if (req.user.role === 'Requester' && p.RequesterEmail !== req.user.email) return res.status(403).send("Unauthorized");
    if (req.user.role === 'Reviewer' && p.ReviewerEmail !== req.user.email) return res.status(403).send("Unauthorized");
    if (req.user.role === 'Approver' && p.ApproverEmail !== req.user.email) return res.status(403).send("Unauthorized");

    // Serve from Blob if closed
    if ((p.Status==='Closed' || p.Status.includes('Closure')) && p.FinalPdfUrl) {
      if (!containerClient) return res.status(500).send("Storage Error");
      try {
        const blobName = `closed-permits/${p.PermitID}_FINAL.pdf`;
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
        if (await blockBlobClient.exists()) {
            const download = await blockBlobClient.download(0);
            res.setHeader('Content-Type','application/pdf');
            res.setHeader('Content-Disposition',`attachment; filename=${p.PermitID}.pdf`);
            return download.readableStreamBody.pipe(res);
        }
      } catch (err) {
        console.error("Azure Download Error:", err.message);
      }
    }

    const d = p.FullDataJSON ? JSON.parse(p.FullDataJSON) : {};
    const renewals = p.RenewalsJSON ? JSON.parse(p.RenewalsJSON) : [];

    const doc = new PDFDocument({ margin:30, size:'A4', bufferPages:true });
    res.setHeader('Content-Type','application/pdf');
    res.setHeader('Content-Disposition',`attachment; filename=${p.PermitID}.pdf`);
    
    doc.on('error', (err) => {
        console.error('PDF Stream Error:', err);
        if (!res.headersSent) res.status(500).end();
    });

    doc.pipe(res);
    await drawPermitPDF(doc, p, d, renewals);
    doc.end();

  } catch (err) {
    console.error("Download Error:", err);
    if (!res.headersSent) res.status(500).send("Internal Server Error");
  }
});

app.get('/api/view-photo/:filename', authenticateAccess, async (req, res) => {
  try {
    const filename = req.params.filename;
    const permitId = filename.split('-')[0] + '-' + filename.split('-')[1];

    if (!containerClient) return res.status(500).send("Storage not configured");

    const pool = await getConnection();
    const r = await pool.request().input('p', sql.NVarChar, permitId).query("SELECT RequesterEmail, ReviewerEmail, ApproverEmail FROM Permits WHERE PermitID=@p");
    
    if (!r.recordset.length) return res.status(404).send("Permit Not Found");
    const p = r.recordset[0];

    // Strict Authorization
    if (req.user.role === 'Requester' && p.RequesterEmail !== req.user.email) return res.status(403).send("Unauthorized");
    if (req.user.role === 'Reviewer' && p.ReviewerEmail !== req.user.email) return res.status(403).send("Unauthorized");
    if (req.user.role === 'Approver' && p.ApproverEmail !== req.user.email) return res.status(403).send("Unauthorized");

    const blob = containerClient.getBlockBlobClient(filename);
    if (!await blob.exists()) return res.status(404).send("Photo not found");

    const download = await blob.download(0);
    res.setHeader('Content-Type', download.contentType || 'image/jpeg');
    download.readableStreamBody.pipe(res);

  } catch (err) {
    console.error("Photo error:", err.message);
    res.status(500).send("Photo retrieval error");
  }
});

app.get('/', (req,res)=>{
  const indexPath = path.join(__dirname,'index.html');
  fs.readFile(indexPath,'utf8',(err,html)=>{
    if(err) return res.status(500).send('Error loading page');
    const finalHtml = html.replace(/NONCE_PLACEHOLDER/g, res.locals.nonce);
    res.send(finalHtml);
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, ()=> console.log("Server running on port "+PORT));
