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

// SECURITY PACKAGE
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); 
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
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

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        
        // Scripts: Self + Nonce + Chart.js + Google Maps
        scriptSrc: [
            "'self'", 
            "'unsafe-inline'", // Needed for older browsers/fallback
            (req, res) => `'nonce-${res.locals.nonce}'`, 
            "https://cdn.jsdelivr.net",      
            "https://maps.googleapis.com"    
        ],
        scriptSrcAttr: ["'unsafe-inline'"],

        // Styles: Self + Nonce + Google Fonts
        // REMOVED: cdn.tailwindcss.com (Since you are now using local /public/app.css)
        styleSrc: [
            "'self'", 
            (req, res) => `'nonce-${res.locals.nonce}'`, 
            "https://fonts.googleapis.com"
        ],
        styleSrcAttr: ["'unsafe-inline'"],
        // Images: Self + Data + Blob + Maps + AZURE STORAGE
        imgSrc: [
            "'self'", 
            "data:", 
            "blob:", 
            "https://maps.gstatic.com", 
            "https://maps.googleapis.com", 
            "https://*.blob.core.windows.net" // CRITICAL: Allows permit photos
        ],

        fontSrc: ["'self'", "https://fonts.gstatic.com"],

        // Connections: Self + Maps + Azure
        connectSrc: [
            "'self'", 
            "https://maps.googleapis.com", 
            "https://cdn.jsdelivr.net",
            "https://*.blob.core.windows.net"
        ],

        frameAncestors: ["'none'"]
      }
    },
    // Required to allow cross-origin assets like Google Maps images
    crossOriginResourcePolicy: { policy: "cross-origin" }
  })
);

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

app.use(bodyParser.json({ limit: '5mb' }));
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
async function sendEmailNotification(toEmail, subject, text) {
    if (!toEmail || !process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
        console.log("Skipping email: Missing credentials or recipient.");
        return;
    }

    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASS
            }
        });

        const mailOptions = {
            from: `"ERPL Permit System" <${process.env.GMAIL_USER}>`,
            to: toEmail,
            subject: subject,
            text: text
        };

        await transporter.sendMail(mailOptions);
        console.log(`📧 Email sent to ${toEmail}`);
    } catch (error) {
        console.error("Email Error:", error.message);
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
   MERGED PDF GENERATOR (Crash Proof B + Features A)
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

    // --- FEATURE FROM A: CRITICAL WORK BANNER ---
    if (d.IsCritical === 'Y') {
       doc.rect(30, doc.y, 535, 25).fillColor('#fee2e2').fill().stroke();
       doc.fillColor('red').font('Helvetica-Bold').text(`CRITICAL WORK: ${d.CriticalActivityType || 'Specified Activity'}`, 35, doc.y + 8);
       doc.y += 30;
       doc.fillColor('black').font('Helvetica');
    }
    // --------------------------------------------

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
   if (d.TBT_Ref_No) {
        doc.text(`(vi) TBT Done and recorded via TBT No: ${d.TBT_Ref_No}`, 35, doc.y);
    } else {
        let tbtText = d.TBT_Permit === 'Y' ? 'YES' : 'NO';
        doc.text(`(vi) TBT Conducted: ${tbtText} | Security: ${safeText(d.SecurityGuard)}`, 35, doc.y);
    }
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
        // 1. FILTER: Only keep items where status is NOT 'NA'
        const activeItems = items.map((text, idx) => {
             const key = `${prefix}_Q${idx + 1}`;
             const val = d[key] || 'NA';
             return { text, key, val, idx };
        }).filter(item => item.val !== 'NA');

        // 2. SKIP: If section is empty after filtering, do not draw it
        if(activeItems.length === 0) return;

        if (doc.y > 680) { doc.addPage(); drawHeaderOnAll(); }
        doc.font('Helvetica-Bold').fillColor('black').fontSize(9).text(title, 30, doc.y + 10); 
        doc.y += 25;
        let y = doc.y;
        
        // Headers
        doc.rect(30, y, 350, 20).stroke().text("Item", 35, y + 6); 
        doc.rect(380, y, 60, 20).stroke().text("Sts", 385, y + 6); 
        doc.rect(440, y, 125, 20).stroke().text("Rem", 445, y + 6); 
        y += 20;

        doc.font('Helvetica').fontSize(8);
        
        // 3. LOOP: Iterate only active items
        activeItems.forEach(item => {
            const { text, key, val, idx } = item;
            let rowHeight = 20;
            if (prefix === 'A' && idx === 11) rowHeight = 55; // Gas Test Height

            if (y + rowHeight > 760) { doc.addPage(); drawHeaderOnAll(); y = 135; }

            doc.rect(30, y, 350, rowHeight).stroke().text(text, 35, y + 6, { width: 340 });
            doc.rect(380, y, 60, rowHeight).stroke().text(safeText(val), 385, y + 6);
            
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

    // Enhanced Audit Trail (From Code B)
   let ioclRows = ioclSups.map(s => {
        let audit = `Added: ${s.added_by || 'Admin'}\nDate: ${s.added_at || '-'}`;
        
        // FIX: Check for 'inactive' status explicitly used in your frontend
        if (s.status === 'inactive' || s.is_deleted) {
            audit += `\n\n[DELETED]\nBy: ${s.deleted_by || 'Admin'}\nOn: ${s.deleted_at || '-'}`;
        }
        
        return [safeText(s.name), safeText(s.desig), safeText(s.contact), audit];
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
    
    // --- FIX: Standard PDF Electrical Audit Trail ---
    if (d.A_Q11 === 'Y') {
        if (doc.y > 550) { doc.addPage(); drawHeaderOnAll(); }
        
        // 1. Title
        doc.font('Helvetica-Bold').fontSize(10).fillColor('#1e40af').text("ELECTRICAL ISOLATION & ENERGISATION AUDIT TRAIL", 30, doc.y);
        doc.y += 15;

        // 2. Setup Dimensions
        const width = 535; // Standard width
        const tableTop = doc.y;
        const cWidth = [100, 215, 220]; // Cols: Label | Req | Auth
        doc.font('Helvetica-Bold').fontSize(8).fillColor('black');

        // 3. Helper Function for Rows (Defined locally to avoid scope issues)
        const drawAuditRow = (label, reqVal, authVal, rowHeight = 25) => {
            if (doc.y + rowHeight > 750) { doc.addPage(); drawHeaderOnAll(); }
            const currentY = doc.y;
            // Draw Borders
            doc.rect(30, currentY, cWidth[0], rowHeight).stroke();
            doc.rect(30 + cWidth[0], currentY, cWidth[1], rowHeight).stroke();
            doc.rect(30 + cWidth[0] + cWidth[1], currentY, cWidth[2], rowHeight).stroke();
            
            // Draw Text
            doc.text(label, 30 + 5, currentY + 7, {width: cWidth[0]-10});
            doc.text(safeText(reqVal), 30 + cWidth[0] + 5, currentY + 7, {width: cWidth[1]-10});
            doc.text(safeText(authVal), 30 + cWidth[0] + cWidth[1] + 5, currentY + 7, {width: cWidth[2]-10});
            
            doc.y += rowHeight;
        };

        // 4. Header Row
        doc.fillColor('#f3f4f6').rect(30, tableTop, width, 20).fillAndStroke('black');
        doc.fillColor('black').text("Phase / Parameter", 35, tableTop + 6);
        doc.text("Requester Action", 30 + cWidth[0] + 5, tableTop + 6);
        doc.text("Electrical Authorized Action", 30 + cWidth[0] + cWidth[1] + 5, tableTop + 6);
        doc.y = tableTop + 20;

        // 5. Data Rows
        doc.font('Helvetica');
        
        // Row 1: Equipment & Assignment
        drawAuditRow("Equipment Details", 
            `No: ${d.Elec_EquipNo}\nName: ${d.Elec_EquipName}`, 
            `Assigned to: ${d.Elec_AuthEmail}`, 35);
            
        // Row 2: LOTO
        drawAuditRow("LOTO Tagging", 
            `Tag No: ${d.Elec_LotoTag_Req}`, 
            `Official LOTO: ${d.Elec_LotoTag_Auth}`);
        
        // Row 3: Isolation
        drawAuditRow("Isolation Status", 
            `Requested: ${d.CreatedDate}`, 
            `ISOLATED: ${formatDate(d.Elec_Iso_DateTime)}\nBy: ${d.Elec_Approved_By}`);

        // Row 4: De-Isolation (Energization)
        const energizeStatus = d.Elec_Energized_Final_Check === 'Y' ? "ENERGIZED & SAFE" : "Pending";
        drawAuditRow("De-Isolation Cycle", 
    `Restoration Confirmed: ${d.Closure_Requestor_Date || '-'}`, 
    `STATUS: ${energizeStatus}\nLOTO Removed: ${d.Elec_LotoTag_Auth || '-'}\nDate: ${formatDate(d.Elec_DeIso_DateTime_Final)}\nBy: ${d.Elec_DeIsolation_Sig ? d.Elec_DeIsolation_Sig.split(' on ')[0] : '-'}`);
        // 6. Reset
        doc.y += 20;
        doc.fillColor('black'); 
    }
    // 10. SIGNATURES / APPROVALS

    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
    doc.font('Helvetica-Bold').fontSize(10).text("PERMIT APPROVAL", 30, doc.y);
    doc.y += 15;
    const sY = doc.y;

    // Helper to separate Name and Timestamp from "Name on Date" string
    const parseSig = (sig) => {
        if (!sig || sig === '-' || typeof sig !== 'string') return { name: '-', date: '-' };
        const parts = sig.split(' on ');
        return { name: parts[0] || '-', date: parts[1] || '-' };
    };

    // Parse Data
    const reqData = { name: safeText(d.RequesterName), date: safeText(d.CreatedDate) };
    const revData = parseSig(d.Reviewer_Sig);
    const appData = parseSig(d.Approver_Sig);

    // Format Text
    const reqText = `REQ: ${reqData.name}\nDate: ${reqData.date}`;
    const revText = `REV: ${revData.name}\nDate: ${revData.date}\nRem: ${safeText(d.Reviewer_Remarks)}`;
    const appText = `APP: ${appData.name}\nDate: ${appData.date}\nRem: ${safeText(d.Approver_Remarks)}`;

    // Draw Boxes
    doc.fontSize(8).font('Helvetica');
    doc.rect(30, sY, 178, 45).stroke().text(reqText, 35, sY+5, { width: 168 });
    doc.rect(208, sY, 178, 45).stroke().text(revText, 213, sY+5, { width: 168 });
    doc.rect(386, sY, 179, 45).stroke().text(appText, 391, sY+5, { width: 169 });
    doc.y += 60;

    // 11. RENEWALS
   // 11. RENEWALS (Updated for Req A & B)
    if (doc.y > 650) { doc.addPage(); drawHeaderOnAll(); }
    doc.font('Helvetica-Bold').text("CLEARANCE RENEWAL", 30, doc.y);
    doc.y += 15;
    let ry = doc.y;
    
    // New Column Structure: Status(60), Time(75), Gas(50), TBT(25), Workers(75), Photo(30), Signatures(220)
    const rCols = [ 
        {t:"Status", w:60}, {t:"Validity", w:75}, {t:"Gas", w:50}, {t:"TBT", w:25}, 
        {t:"Workers", w:75}, {t:"Img", w:30}, 
        {t:"Req", w:73}, {t:"Rev", w:73}, {t:"App", w:74} 
    ];
    let rx = 30;
    rCols.forEach(h => { doc.rect(rx, ry, h.w, 20).stroke().text(h.t, rx+2, ry+6); rx += h.w; });
    ry += 20;

    const finalRenewals = renewalsList || [];
    doc.font('Helvetica').fontSize(7); // Smaller font to fit data

    for (const r of finalRenewals) {
        if (ry > 700) { doc.addPage(); drawHeaderOnAll(); ry = 135; }
        const rH = 75; // Increased height for worker list & status details
        
        let rawFrom = r.valid_from || r.ValidFrom;
        let rawTo = r.valid_till || r.valid_to || r.ValidTo;
        let timeTxt = `${safeText(rawFrom).replace('T', '\n')}\nTO\n${safeText(rawTo).replace('T', '\n')}`;
        
        if (r.odd_hour_req) { doc.fillColor('purple'); timeTxt += '\n(Night)'; } else doc.fillColor('black');

        // 1. Status Column (Req A)
        let statusTxt = "Pending";
        if(r.status === 'approved') statusTxt = "APPROVED";
        else if(r.status === 'rejected') statusTxt = `REJECTED\nBy: ${r.rejected_by}\nReason: ${r.rejection_reason}`;
        
        doc.rect(30, ry, 60, rH).stroke().text(statusTxt, 32, ry+5, {width:56});

        // 2. Validity
        doc.rect(90, ry, 75, rH).stroke().text(timeTxt, 92, ry+5, {width:71});
        doc.fillColor('black');

        // 3. Gas & Precautions
        doc.rect(165, ry, 50, rH).stroke().text(`HC:${safeText(r.hc)}\nTox:${safeText(r.toxic)}\nO2:${safeText(r.oxygen)}\n\n${safeText(r.precautions)}`, 167, ry+5, {width:46});
        
        // 4. TBT
        let tbtYN = r.tbt_done === 'Y' ? 'YES' : 'NO';
        doc.rect(215, ry, 25, rH).stroke().text(tbtYN, 217, ry+5);

        // 5. Workers (Req B)
        let wNames = '-';
        if(r.workers && Array.isArray(r.workers)) wNames = r.workers.join(', ');
        doc.rect(240, ry, 75, rH).stroke().text(wNames, 242, ry+5, {width:71}); 

        // 6. Photo
        doc.rect(315, ry, 30, rH).stroke();
        if (r.photoUrl && containerClient) {
            try {
                // (Existing Image Fetch Logic kept same, just adjusted coordinates)
                const blobName = r.photoUrl.split('/').pop();
                const blockBlob = containerClient.getBlockBlobClient(blobName);
                const downloadPromise = blockBlob.download(0);
                const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 2500));
                const response = await Promise.race([downloadPromise, timeoutPromise]);
                const chunks = [];
                for await (const chunk of response.readableStreamBody) { chunks.push(chunk); }
                const imgBuff = Buffer.concat(chunks);
                doc.image(imgBuff, 317, ry+2, {fit: [26, 56], align:'center', valign:'center'});
            } catch (e) { doc.text("Err", 315, ry+25, {width: 30, align:'center'}); }
        } else { 
            doc.text("-", 315, ry+25, {width: 30, align:'center'}); 
        }

        // 7. Signatures
        const reqStack = `${safeText(r.req_name)}\n${safeText(r.req_at)}\n${safeText(r.req_rem || '')}`;
        doc.rect(345, ry, 73, rH).stroke().text(reqStack, 347, ry+5, {width:69});

        const revStack = `${safeText(r.rev_name)}\n${safeText(r.rev_at || '')}\n${safeText(r.rev_rem || '')}`;
        doc.rect(418, ry, 73, rH).stroke().text(revStack, 420, ry+5, {width:69});

        const appStack = `${safeText(r.app_name)}\n${safeText(r.app_at || '')}\n${safeText(r.app_rem || '')}`;
        doc.rect(491, ry, 74, rH).stroke().text(appStack, 493, ry+5, {width:70});

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
        // --- ADD THIS BLOCK FOR CLOSURE SUMMARY IN PDF ---
        
        // 1. Define the checklist items
        const cChecks = [
            { k: 'Closure_WorkCompleted', l: 'Work Completed' },
            { k: 'Closure_SiteRestored', l: 'Site Restoration' },
            { k: 'Closure_Withdrawal', l: 'Withdrawal of Men/Material' },
            { k: 'Closure_Normalization', l: 'Normalization of Isolations' },
            { k: 'Closure_Housekeeping', l: 'Housekeeping' }
        ];

        // 2. Filter Complied vs Not Complied
        const complied = cChecks.filter(c => d[c.k] === 'Y').map(c => c.l);
        const notComplied = cChecks.filter(c => d[c.k] !== 'Y').map(c => c.l);

        // 3. Build the Sentence
        let sumText = `Closure Summary: ${safeText(d.RequesterName)} confirmed that: `;
        if (complied.length > 0) sumText += `${complied.join(', ')} have been complied. `;
        if (notComplied.length > 0) {
            sumText += `For ${notComplied.join(', ')}, the reason provided is: "${safeText(d.Closure_Deviation_Reason) || 'No Reason'}".`;
        }

        // 4. Print to PDF (Italic, slightly gray to look like a comment)
        doc.font('Helvetica-Oblique').fontSize(8).fillColor('#333333');
        doc.text(sumText, 35, doc.y, { width: 525, align: 'justify' });
        doc.y += 15; // Add space before signature boxes
        doc.font('Helvetica').fillColor('black'); // Reset font

        // --- END ADDITION ---

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

// GET WORKERS LIST (Updated: Converts UTC to IST)
app.post('/api/get-workers', authenticateAccess, async (req, res) => {
    try {
        const pool = await getConnection();
        const { role, email, context } = req.body;

        let query = `
            SELECT 
                WorkerID, Name, Age, FatherName, Address, Contact, 
                IDCardNo as ID, IDType, Gender, 
                Status, RequestorName, ApprovedBy, 
                
                -- FIX: Add 330 minutes (5.5 Hours) to convert UTC to IST
                FORMAT(DATEADD(MINUTE, 330, ApprovedAt), 'dd-MMM-yyyy HH:mm') as ApprovedAt

            FROM Workers 
        `;

        // Filter Logic
        if (role === 'Requester') {
            query += ` WHERE RequestorEmail = @email`;
        } 
        else if (role === 'Reviewer') {
            query += ` WHERE Status = 'Pending Review' OR Status = 'Approved'`;
        }
        else if (role === 'Approver') {
            query += ` WHERE Status IN ('Pending Review', 'Pending Approval', 'Approved')`;
        }

        query += ` ORDER BY CreatedAt DESC`;

        const result = await pool.request()
            .input('email', email)
            .query(query);

        res.json(result.recordset);

    } catch (e) {
        console.error("Get Workers Error:", e);
        res.status(500).json({ error: e.message });
    }
});

// WORKER MANAGEMENT (Create, Edit, Delete, Approve, Reject)
app.post('/api/save-worker', authenticateAccess, async (req, res) => {
    try {
        const pool = await getConnection();
        const { Action, WorkerID, Details, Role, RequestorName, ApproverName } = req.body;

        console.log(`👷 Worker Action: ${Action} | ID: ${WorkerID}`);

        // 1. CREATE NEW WORKER
        if (Action === 'create') {
            const newWorkerID = Math.floor(100000000 + Math.random() * 900000000).toString();

            // SAFETY: Ensure RequestorEmail is never NULL (DB Constraint)
            const safeEmail = req.user.email || "unknown@system.com"; 

            await pool.request()
                .input('wid_new', newWorkerID)
                .input('n', Details.Name)
                .input('a', Details.Age)
                .input('f', Details.Father)
                .input('addr', Details.Address)
                .input('c', Details.Contact)
                .input('id', Details.ID)
                .input('idt', Details.IDType)
                .input('g', Details.Gender)
                .input('req', RequestorName)
                .input('req_e', safeEmail) // <--- Fixed potential crash
                .query(`INSERT INTO Workers (WorkerID, Name, Age, FatherName, Address, Contact, IDCardNo, IDType, Gender, Status, RequestorName, RequestorEmail, DataJSON, CreatedAt) 
                        VALUES (@wid_new, @n, @a, @f, @addr, @c, @id, @idt, @g, 'Pending Review', @req, @req_e, '{}', GETDATE())`);
            
            return res.json({ success: true, message: "Worker created" });
        }

        // 2. EDIT WORKER
       // 2. EDIT WORKER (Updated for Requirement D)
        else if (Action === 'edit') {
            const result = await pool.request()
                .input('wid', WorkerID)
                .input('n', Details.Name)
                .input('a', Details.Age)
                .input('f', Details.Father)
                .input('addr', Details.Address)
                .input('c', Details.Contact)
                .input('id', Details.ID)
                .input('idt', Details.IDType)
                .input('g', Details.Gender)
                .query(`UPDATE Workers 
                        SET Name=@n, Age=@a, FatherName=@f, Address=@addr, Contact=@c, 
                            IDCardNo=@id, IDType=@idt, Gender=@g, 
                            
                            -- FORCE RESET TO PENDING REVIEW ON EDIT
                            Status='Pending Review', 
                            ApprovedBy=NULL, ApprovedAt=NULL 
                        WHERE WorkerID=@wid`);

            if (result.rowsAffected[0] === 0) {
                return res.json({ success: false, error: "Worker ID not found. Edit failed." });
            }
            
            return res.json({ success: true, message: "Worker updated and sent for review" });
        }
        // 3. DELETE WORKER
        else if (Action === 'delete') {
            await pool.request()
                .input('wid', WorkerID)
                .query(`DELETE FROM Workers WHERE WorkerID=@wid`);
            
            return res.json({ success: true, message: "Worker deleted" });
        }

        // 4. APPROVE / REJECT
        else if (Action === 'approve' || Action === 'reject') {
            const newStatus = (Action === 'approve') ? 'Approved' : 'Rejected';
            await pool.request()
                .input('wid', WorkerID)
                .input('app', ApproverName || req.user.name)
                .input('st', newStatus)
                .query(`UPDATE Workers 
                        SET Status=@st, ApprovedBy=@app, ApprovedAt=GETDATE() 
                        WHERE WorkerID=@wid`);
            
            return res.json({ success: true, message: `Worker ${newStatus}` });
        }

        res.json({ success: false, error: "Invalid Action" });

    } catch (e) {
        console.error("Save Worker Error:", e);
        res.json({ success: false, error: e.message });
    }
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
        // 1. Master Admins see everything
        if(role === 'MasterAdmin') return true; 
        
        // 2. Requesters see only their own permits
        if(role === 'Requester') return p.RequesterEmail === email;
        
        // 3. NEW: Electrical Authorized Persons logic
        if(role === 'ElectricalAuth') {
            // They see permits waiting for isolation OR waiting for de-isolation
            return p.Status === 'Pending Electrical Isolation' || p.Status === 'Pending Electrical De-Isolation';
        }

        // 4. Reviewers see permits assigned to them or waiting for review
        if(role === 'Reviewer') return p.ReviewerEmail === email || p.Status === 'Pending Review' || p.Status === 'Closure Pending Review';
        
        // 5. Approvers see permits assigned to them or waiting for approval
        if(role === 'Approver') return p.ApproverEmail === email || p.Status === 'Pending Approval' || p.Status === 'Closure Pending Approval';
        
        return true;
    });
    res.json(filtered.sort((a,b) => {
         const numA = parseInt(a.PermitID.split('-')[1] || 0);
         const numB = parseInt(b.PermitID.split('-')[1] || 0);
         return numB - numA; 
    }));
});

// SAVE PERMIT (Merged Validation from A)
// SAVE PERMIT - Enforces Rules D (7 Days) and E (Time Order)
app.post('/api/save-permit', authenticateAccess, upload.any(), async(req, res) => {
    const pool = await getConnection();
    const fd = req.body;
    
    if(!fd.WorkType || !fd.ValidFrom || !fd.ValidTo) return res.status(400).json({error: "Missing Data"});
    if (!fd.CreatedDate) {
        fd.CreatedDate = getNowIST();
    }
    // --- SAFETY VALIDATION START ---
    const vFrom = new Date(fd.ValidFrom); 
    const vTo = new Date(fd.ValidTo);
    
    // Rule E: End > Start
    if (vTo <= vFrom) return res.status(400).json({error: "Invalid Time: End time must be after Start time"});
    
    // Rule D: Max 7 Days
    const diffTime = Math.abs(vTo - vFrom);
    const diffDays = diffTime / (1000 * 60 * 60 * 24); // Floating point days
    if(diffDays > 7) return res.status(400).json({error: "Safety Violation: Permit duration cannot exceed 7 days"});
    
    if(fd.TBT_Permit !== 'Y') return res.status(400).json({error: "Tool Box Talk must be confirmed"});
    // --- SAFETY VALIDATION END ---

    let pid = fd.PermitID;
    if (!pid || pid === 'undefined' || pid === '' || pid === 'null') {
        const idRes = await pool.request().query("SELECT MAX(CAST(SUBSTRING(PermitID, 4, 10) AS INT)) as MaxVal FROM Permits WHERE PermitID LIKE 'WP-%'");
        let nextNum = 1000;
        if (idRes.recordset[0].MaxVal) nextNum = idRes.recordset[0].MaxVal + 1;
        pid = `WP-${nextNum}`;
    }
    let initialStatus = 'Pending Review';
    if (fd.A_Q11 === 'Y') {
        initialStatus = 'Pending Electrical Isolation';
    }
    let jsaUrl = null;
    if (req.files) {
        const jsaFile = req.files.find(f => f.fieldname === 'JsaFile');
        if(jsaFile) {
            jsaUrl = await uploadToAzure(jsaFile.buffer, `permit-jsa/${pid}-${Date.now()}.pdf`, 'application/pdf');
        }
    }
    const jsaLinkedId = fd.JsaLinkedId || null;
    
    let rens = [];
    if(fd.InitRen === 'Y') {
        // Note: Initial Renewal is typically 8 hours, logic handles this in renewal route mostly, 
        // but user creates this manually here. You might want to enforce 8h here too if strict.
        rens.push({ status: 'pending_review', valid_from: fd.InitRenFrom, valid_to: fd.InitRenTo, hc: fd.InitRenHC, toxic: fd.InitRenTox, oxygen: fd.InitRenO2, req_name: req.user.name, req_at: getNowIST(), tbt_done: 'Y' });
    }

    const q = pool.request()
    .input('p', pid)
    .input('s', initialStatus) // Removed single quotes around initialStatus
    .input('w', fd.WorkType)
        .input('re', req.user.email).input('rv', fd.ReviewerEmail).input('ap', fd.ApproverEmail)
        .input('vf', new Date(fd.ValidFrom)).input('vt', new Date(fd.ValidTo))
        .input('j', JSON.stringify(fd)).input('ren', JSON.stringify(rens))
        .input('jsaUrl', jsaUrl).input('jsaId', jsaLinkedId);

    await q.query(`
        MERGE Permits AS target USING (SELECT @p as PermitID) AS source ON (target.PermitID = source.PermitID) 
        WHEN MATCHED THEN 
            UPDATE SET FullDataJSON=@j, Status=@s, RenewalsJSON=@ren,
            JsaFileUrl = COALESCE(@jsaUrl, JsaFileUrl), 
            JsaLinkedId = @jsaId
        WHEN NOT MATCHED THEN 
            INSERT (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, FullDataJSON, RenewalsJSON, JsaFileUrl, JsaLinkedId) 
            VALUES (@p, @s, @w, @re, @rv, @ap, @vf, @vt, @j, @ren, @jsaUrl, @jsaId);
    `);

    res.json({success: true, permitId: pid});
});

app.post('/api/update-status', authenticateAccess, upload.any(), async(req, res) => {
    const { PermitID, action, ...extras } = req.body;
    const pool = await getConnection();
    const cur = await pool.request().input('p', PermitID).query("SELECT * FROM Permits WHERE PermitID=@p");
    if(!cur.recordset.length) return res.status(404).json({error: "Permit Not Found"});
    
    let p = cur.recordset[0];
    // --- SECURITY FIX: OWNERSHIP CHECK START ---
    const userEmail = req.user.email;
    const userRole = req.user.role;

    if (userRole !== 'MasterAdmin') {
        // Prevent unauthorized Review/Reject
        if (action === 'review' || action === 'reject') {
            if (p.ReviewerEmail !== userEmail && !p.Status.includes('Closure')) {
                 return res.status(403).json({ error: "Security: You are not the assigned Reviewer." });
            }
        }
        // Prevent unauthorized Approval
        if (action === 'approve') {
            if (p.ApproverEmail !== userEmail && !p.Status.includes('Closure')) {
                 return res.status(403).json({ error: "Security: You are not the assigned Approver." });
            }
        }
    }
    // --- SECURITY FIX END ---
    let d = JSON.parse(p.FullDataJSON);
    let rens = JSON.parse(p.RenewalsJSON || "[]");
    let st = p.Status;
    const now = getNowIST(); 
    const usr = req.user.name;
    Object.assign(d, extras);

    // Initialize variables used later in the query
    let newJsaUrl = null;
    let sqlSetJsa = ""; 

    // 1. ELECTRICAL LOGIC
    if (action === 'elec_approve') {
        const elecAuthNum = `ELEC-${PermitID}-${Date.now().toString().slice(-4)}`;
        st = 'Pending Review'; 
        d.ElectricalAuthNum = elecAuthNum;
        d.Elec_Approved_By = usr;
        d.Elec_Approval_Statement = `${usr} has approved the electrical isolation request no ${elecAuthNum} and submitted for further approval.`;
    } 
    else if (action === 'elec_reject') {
        st = 'Rejected';
    }
if (action === 'elec_closure_approve') {
         st = 'Closure Pending Review';
         d.Elec_DeIsolation_Sig = `${usr} on ${now}`;
         
         // Capture the data sent from Frontend
         const deIsoTime = extras.Elec_DeIso_DateTime_Final || now;
         d.Elec_DeIso_DateTime_Final = deIsoTime; // Ensure this is saved explicitly
         d.Elec_Energized_Final_Check = 'Y';

         // Generate the Statement for the Green Box
         const equip = d.Elec_EquipNo || "Equipment";
         const tag = d.Elec_LotoTag_Auth || "N/A";
         d.Elec_Energization_Msg = `${usr} (Electrical Auth) has successfully energised the ${equip} (LOTO Tag: ${tag}) at ${deIsoTime}.`;
    }
    else if (action === 'initiate_closure') {
        if (d.A_Q11 === 'Y') {
            if (extras.Elec_Energize_Check !== 'Y') {
                return res.status(400).json({ error: "Electrical re-energize confirmation required" });
            }
            st = 'Pending Electrical De-Isolation'; 
        } else {
            st = 'Closure Pending Review'; 
        }
        d.Closure_Requestor_Date = now;
        d.Closure_Receiver_Sig = `${usr} on ${now}`;
    }
    else if (action === 'elec_closure_approve') {
        st = 'Closure Pending Review'; 
        d.Elec_DeIsolation_Sig = `${usr} on ${now}`;
    }
    else if (action === 'elec_reject_closure') {
        st = 'Active'; 
    }
    
    // 2. GENERAL ACTIONS
    else if (action === 'reject') {
        st = 'Rejected';
      const subject = `❌ Permit Rejected: ${PermitID}`;
        const msg = `Dear Requester,\n\nYour permit ${PermitID} has been REJECTED by ${usr}.\n\nReason: ${req.body.comment || 'No remarks provided'}.\n\nPlease login to check details.`;
        sendEmailNotification(d.RequesterEmail, subject, msg);
    }
    else if (action === 'review' || action === 'approve_1st_ren') { 
        // --- File Handling for Review ---
        if (req.files) {
            const jsaFile = req.files.find(f => f.fieldname === 'JsaFile');
            if(jsaFile) {
                newJsaUrl = await uploadToAzure(jsaFile.buffer, `permit-jsa/${PermitID}-${Date.now()}.pdf`, 'application/pdf');
                sqlSetJsa += ", JsaFileUrl=@jsaUrl, JsaLinkedId=NULL"; 
            }
        }
        const newJsaId = req.body.JsaLinkedId || null;
        if (newJsaId && !newJsaUrl) {
             sqlSetJsa += ", JsaLinkedId=@jsaId, JsaFileUrl=NULL";
        }
        if (req.files) {
            const tbt = req.files.find(f => f.fieldname === 'TBT_PDF_File');
            if (tbt) {
                const url = await uploadToAzure(tbt.buffer, `tbt/${PermitID}_${Date.now()}.pdf`, 'application/pdf');
                d.TBT_File_Url = url;
            }
        }
        if(req.body.TBT_Ref_No) d.TBT_Ref_No = req.body.TBT_Ref_No;
        // -------------------------------

        st = 'Pending Approval'; 
        d.Reviewer_Sig = `${usr} on ${now}`; 
      if (d.ApproverEmail) {
            const subject = `⚠️ Action Required: Approve Permit ${PermitID}`;
            const msg = `Dear Approver,\n\nA permit (${PermitID}) has been reviewed by ${usr} and is waiting for your final approval.\n\nWork Type: ${d.WorkType}\nLocation: ${d.LocationUnit}\n\nPlease login to the dashboard to approve/reject.`;
            sendEmailNotification(d.ApproverEmail, subject, msg);
        }
    }
    else if (action === 'approve' && st.includes('Closure')) { 
        st = 'Closed'; 
        d.Closure_Approver_Date = now; 
        d.Closure_Issuer_Sig = `${usr} on ${now}`; 
      if (d.RequesterEmail) {
            sendEmailNotification(d.RequesterEmail, `✅ Permit Closed: ${PermitID}`, `Your permit ${PermitID} has been successfully closed by ${usr}.`);
        }
    }
    else if (action === 'approve') { 
        st = 'Active'; 
        d.Approver_Sig = `${usr} on ${now}`; 

        // --- FIX: Handle TBT Upload for Approver ---
        if (req.files) {
            const tbt = req.files.find(f => f.fieldname === 'TBT_PDF_File');
            if (tbt) {
                // Upload to Azure
                const url = await uploadToAzure(tbt.buffer, `tbt/${PermitID}_${Date.now()}.pdf`, 'application/pdf');
                d.TBT_File_Url = url; // Save URL to JSON
            }
        }
        // Save the Reference Number
        if (req.body.TBT_Ref_No) d.TBT_Ref_No = req.body.TBT_Ref_No;
        // -------------------------------------------
      if (d.RequesterEmail) {
            const subject = `✅ Permit Approved & Active: ${PermitID}`;
            const msg = `Dear Requester,\n\nYour permit ${PermitID} has been APPROVED by ${usr} and is now ACTIVE.\n\nValid From: ${formatDate(p.ValidFrom)}\nValid To: ${formatDate(p.ValidTo)}\n\nPlease ensure safety compliance at site.`;
            sendEmailNotification(d.RequesterEmail, subject, msg);
       }
    }
    else if (action === 'reject_closure') { st = 'Active'; } 
    else if (action === 'approve_closure') { 
        st = 'Closure Pending Approval'; 
        d.Closure_Reviewer_Date = now; 
        d.Closure_Reviewer_Sig = `${usr} on ${now}`; 
    }
    
    // --- RENEWAL ARRAY LOGIC ---
    if(action === 'approve_1st_ren' || action === 'approve' || action === 'review') {
        if(rens.length > 0 && rens[rens.length-1].status.includes('pending')) {
             let last = rens[rens.length-1];
             if(req.body.FirstRenewalAction === 'reject') { 
                 last.status = 'rejected'; 
             }
             else if(req.user.role === 'Reviewer') { 
                 last.status = 'pending_approval'; 
                 last.rev_name = usr; 
             }
             else if(req.user.role === 'Approver') { 
                 last.status = 'approved'; 
                 last.app_name = usr; 
             }
        }
    }

 // ... previous logic for st and d ...

   /* =====================================================
   CORRECTED CLOSURE LOGIC: PERSIST DATA UNTIL PDF IS SAFE
===================================================== */
if (st === 'Closed') {
    try {
        // Create a record object for the PDF generators
        const pdfRecord = { ...p, Status: 'Closed', PermitID: PermitID, ValidFrom: p.ValidFrom, ValidTo: p.ValidTo };
        
        // 1. GENERATE STANDARD PDF BUFFER
        const standardPdfBuffer = await new Promise((resolve, reject) => {
            const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
            const chunks = [];
            doc.on('data', chunks.push.bind(chunks));
            doc.on('end', () => resolve(Buffer.concat(chunks)));
            // d still contains IOCLSupervisors here
            drawPermitPDF(doc, pdfRecord, d, rens).then(() => doc.end()).catch(reject);
        });

        // 2. GENERATE MAINLINE PDF BUFFER
        const mainlinePdfBuffer = await new Promise((resolve, reject) => {
            const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
            const chunks = [];
            doc.on('data', chunks.push.bind(chunks));
            doc.on('end', () => resolve(Buffer.concat(chunks)));
            // Ensuring the detailed mainline format captures the supervisors
            drawMainlinePermitPDF(doc, pdfRecord, d, rens).then(() => doc.end()).catch(reject);
        });

        // 3. UPLOAD BOTH TO AZURE BLOB STORAGE
        const standardBlobName = `closed-permits/${PermitID}_FINAL.pdf`;
        const mainlineBlobName = `closed-permits/${PermitID}_MAINLINE_FINAL.pdf`;
        
        const finalPdfUrl = await uploadToAzure(standardPdfBuffer, standardBlobName, "application/pdf");
        const finalMainlineUrl = await uploadToAzure(mainlinePdfBuffer, mainlineBlobName, "application/pdf");

        if (finalPdfUrl && finalMainlineUrl) {
            // 4. DATABASE UPDATE: Only wipe JSON after both uploads are confirmed
            await pool.request()
                .input('p', PermitID)
                .input('url', finalPdfUrl)
                .query(`
                    UPDATE Permits 
                    SET Status='Closed', 
                        FinalPdfUrl=@url, 
                        FullDataJSON=NULL, 
                        RenewalsJSON=NULL 
                    WHERE PermitID=@p
                `);
            
            console.log(`✅ Archival Complete for ${PermitID}. Mainline & Standard saved.`);
            return res.json({ success: true, archived: true, pdfUrl: finalPdfUrl });
        } else {
            throw new Error("Azure Upload Failed");
        }
    } catch (e) {
        console.error("🚨 Archival Critical Failure:", e);
        // Do NOT wipe JSON if PDF generation/upload fails
        return res.status(500).json({ error: "Archival failed. Data preserved in system." });
    }
} else {
    /* =====================================================
       STANDARD UPDATE (Runs ONLY if status is NOT 'Closed')
    ===================================================== */
    const q = pool.request()
        .input('p', PermitID).input('s', st)
        .input('j', JSON.stringify(d)).input('r', JSON.stringify(rens))
        .input('jsaUrl', newJsaUrl)
        .input('jsaId', req.body.JsaLinkedId || null);

    await q.query(`UPDATE Permits SET Status=@s, FullDataJSON=@j, RenewalsJSON=@r ${sqlSetJsa} WHERE PermitID=@p`);
    
    return res.json({success: true});
    }
    });
// RENEWAL (Merged Validation from A)
// RENEWAL - Enforces Rules A (8h), B (Bounds), C (Chronological), E (Time Order)
app.post('/api/renewal', authenticateAccess, upload.single('RenewalImage'), async(req,res) => {
    const { PermitID, action, comment } = req.body; 
    const userRole = req.user.role; 
    const pool = await getConnection();
    
    // Fetch Permit data to check bounds (Rule B)
    const cur = await pool.request().input('p', PermitID).query("SELECT RenewalsJSON, ValidTo, Status, ValidFrom FROM Permits WHERE PermitID=@p");
    if (!cur.recordset.length) return res.status(404).json({error: "Permit not found"});
    
    const p = cur.recordset[0];
    let rens = JSON.parse(p.RenewalsJSON || "[]");
    let newStatus = p.Status;
    
    if(action === 'initiate') {
        const rStart = new Date(req.body.RenewalValidFrom);
        const rEnd = new Date(req.body.RenewalValidTo);
        const pStart = new Date(p.ValidFrom);
        const pEnd = new Date(p.ValidTo);

        // Rule E: End > Start
        if(rEnd <= rStart) return res.status(400).json({error: "Invalid Time: Renewal End time must be after Start time"});

        // Rule A: Max 8 Hours
        const durationMs = rEnd - rStart;
        const durationHrs = durationMs / (1000 * 60 * 60);
        if(durationHrs > 8.01) return res.status(400).json({error: "Safety Violation: Renewal cannot exceed 8 hours"}); // 8.01 allows slight buffer for seconds

        // Rule B: Must be within Original Permit Validity
        if(rStart < pStart || rEnd > pEnd) return res.status(400).json({error: "Violation: Renewal time is outside the Main Permit validity period"});

        // Rule C: Chronological & Non-Overlapping
        if(rens.length > 0) {
            const lastRen = rens[rens.length-1];
            // We ignore rejected renewals, they don't block the timeline
            if(lastRen.status !== 'rejected') {
                const lastEnd = new Date(lastRen.valid_to);
                // The new start time must be >= the last approved end time
                if(rStart < lastEnd) {
                     return res.status(400).json({error: `Overlap Detected: Previous renewal ends at ${lastRen.valid_to}. You cannot start before that.`});
                }
            }
        }

        // TBT Check
        if(req.body.TBT_Renewal !== 'Y') return res.status(400).json({error: "Tool Box Talk mandatory"}); 

        let url = null;
        if(req.file) url = await uploadToAzure(req.file.buffer, `${PermitID}-REN-${Date.now()}.jpg`);
        
        let workerList = [];
        try { workerList = JSON.parse(req.body.renewalWorkers || "[]"); } catch(e){}
        
        rens.push({ 
            status: 'pending_review', valid_from: req.body.RenewalValidFrom, valid_to: req.body.RenewalValidTo, 
            hc: req.body.hc, toxic: req.body.toxic, oxygen: req.body.oxygen, precautions: req.body.precautions, 
            workers: workerList, req_name: req.user.name, req_at: getNowIST(), photoUrl: url, 
            oddHourReq: req.body.oddHourReq || 'N',
            tbt_done: 'Y'
        });
        newStatus = 'Renewal Pending Review';

    } else {
        // Handle Approve/Reject Logic
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
                if(last.oddHourReq === 'Y') last.rev_odd_hour_accepted = 'Y'; 
                newStatus = 'Renewal Pending Approval'; 
              last.rev_tbt = req.body.tbt_check || 'N';
            } 
            else if (userRole === 'Approver') { 
                last.status = 'approved'; 
                last.app_name = req.user.name; 
                last.app_at = getNowIST(); 
                last.app_rem = comment || ''; 
                newStatus = 'Active'; 
                last.app_tbt = req.body.tbt_check || 'N';
            }
        }
    }
    
    await pool.request().input('p', PermitID).input('r', JSON.stringify(rens)).input('s', newStatus).query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p");
    res.json({success: true});
});

// EXCEL EXPORT (Enhanced & Interactive)
app.get('/api/download-excel', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC");
    
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'ERPL Permit System';
    workbook.created = new Date();
    
    // ==========================================
    // SHEET 1: DASHBOARD SUMMARY
    // ==========================================
    const summarySheet = workbook.addWorksheet('Dashboard Summary', { views: [{ showGridLines: false }] });
    
    // 1. Calculate Statistics
    const stats = { status: {}, type: {} };
    result.recordset.forEach(r => {
        const d = r.FullDataJSON ? JSON.parse(r.FullDataJSON) : {};
        stats.status[r.Status] = (stats.status[r.Status] || 0) + 1;
        const wType = d.WorkType || 'Unspecified';
        stats.type[wType] = (stats.type[wType] || 0) + 1;
    });

    // 2. Define Styles
    const titleStyle = { font: { bold: true, size: 14, color: { argb: 'FFEA580C' } } }; // Orange Text
    const headerStyleOrange = {
        font: { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 },
        fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEA580C' } }, // Orange Bg
        alignment: { horizontal: 'center', vertical: 'middle' },
        border: { top: {style:'thin'}, left: {style:'thin'}, bottom: {style:'thin'}, right: {style:'thin'} }
    };
    const headerStyleBlue = { ...headerStyleOrange, fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E40AF' } } }; // Blue Bg
    const cellBorder = { top: {style:'thin'}, left: {style:'thin'}, bottom: {style:'thin'}, right: {style:'thin'} };

    // 3. Draw Status Table (Starts at B2)
    summarySheet.getCell('B2').value = "PERMIT STATUS SUMMARY";
    summarySheet.getCell('B2').font = titleStyle;
    
    summarySheet.getCell('B4').value = "Status";
    summarySheet.getCell('C4').value = "Count";
    summarySheet.getCell('B4').style = headerStyleOrange;
    summarySheet.getCell('C4').style = headerStyleOrange;
    
    let rIdx = 5;
    Object.keys(stats.status).forEach(k => {
        summarySheet.getCell(`B${rIdx}`).value = k;
        summarySheet.getCell(`C${rIdx}`).value = stats.status[k];
        summarySheet.getCell(`B${rIdx}`).border = cellBorder;
        summarySheet.getCell(`C${rIdx}`).border = cellBorder;
        rIdx++;
    });

    // 4. Draw Work Type Table (Starts at E2)
    summarySheet.getCell('E2').value = "WORK TYPE DISTRIBUTION";
    summarySheet.getCell('E2').font = { ...titleStyle, color: { argb: 'FF1E40AF' } }; // Blue Title
    
    summarySheet.getCell('E4').value = "Work Type";
    summarySheet.getCell('F4').value = "Count";
    summarySheet.getCell('E4').style = headerStyleBlue;
    summarySheet.getCell('F4').style = headerStyleBlue;
    
    rIdx = 5;
    Object.keys(stats.type).forEach(k => {
        summarySheet.getCell(`E${rIdx}`).value = k;
        summarySheet.getCell(`F${rIdx}`).value = stats.type[k];
        summarySheet.getCell(`E${rIdx}`).border = cellBorder;
        summarySheet.getCell(`F${rIdx}`).border = cellBorder;
        rIdx++;
    });
    
    // Adjust Summary Column Widths
    summarySheet.getColumn('B').width = 30;
    summarySheet.getColumn('C').width = 15;
    summarySheet.getColumn('D').width = 5; // Spacer
    summarySheet.getColumn('E').width = 30;
    summarySheet.getColumn('F').width = 15;

    // ==========================================
    // SHEET 2: DETAILED REGISTER
    // ==========================================
    const sheet = workbook.addWorksheet('Permit Register', { views: [{ state: 'frozen', xSplit: 1, ySplit: 1 }] });
    
    sheet.columns = [ 
        { header:'Permit ID', key:'id', width: 18 }, 
        { header:'Current Status', key:'status', width: 22 }, 
        { header:'Work Type', key:'wt', width: 18 }, 
        { header:'Description', key:'desc', width: 45 }, 
        { header:'Requester', key:'req', width: 25 }, 
        { header:'Location', key:'loc', width: 35 }, 
        { header:'Valid From', key:'vf', width: 18 }, 
        { header:'Valid To', key:'vt', width: 18 },
        { header:'Reviewer', key:'rev', width: 30 },
        { header:'Approver', key:'app', width: 30 }
    ];
    
    // Apply Header Styling & Auto Filter
    sheet.getRow(1).height = 25;
    sheet.getRow(1).eachCell((cell) => {
        cell.style = headerStyleOrange;
    });
    sheet.autoFilter = 'A1:J1'; // Enable AutoFilter for interactivity

   // --- SECURITY FIX: EXCEL FORMULA INJECTION HELPER ---
    const sanitize = (val) => {
        if (!val) return '';
        const str = String(val);
        // If it starts with =, +, -, @, prepend a quote to force text format
        return /^[=+\-@]/.test(str) ? "'" + str : str;
    };

    // Add Data rows
    result.recordset.forEach(r => { 
        const d = r.FullDataJSON ? JSON.parse(r.FullDataJSON) : {}; 
        const row = sheet.addRow({ 
            id: sanitize(r.PermitID), 
            status: r.Status, 
            wt: sanitize(d.WorkType), 
            desc: sanitize(d.Desc || d.WorkTypeOther || '-'),
            req: sanitize(d.RequesterName), 
            loc: sanitize(d.LocationUnit || d.ExactLocation), 
            vf: formatDate(r.ValidFrom), 
            vt: formatDate(r.ValidTo),
            rev: r.ReviewerEmail,
            app: r.ApproverEmail
        });
        
        // ... (Keep your existing color styling logic below this) ...
        
        // Interactive: Color code status text
        const statusCell = row.getCell('status');
        if(r.Status === 'Active' || r.Status === 'Approved') statusCell.font = { color: { argb: 'FF008000' }, bold: true }; // Green
        else if(r.Status === 'Rejected') statusCell.font = { color: { argb: 'FFFF0000' }, bold: true }; // Red
        else if(r.Status.includes('Pending')) statusCell.font = { color: { argb: 'FFFFA500' }, bold: true }; // Orange
        else if(r.Status === 'Closed') statusCell.font = { color: { argb: 'FF808080' }, italic: true }; // Gray
        
        // Add subtle border to all cells for readability
        row.eachCell({ includeEmpty: true }, (cell) => {
            cell.border = { bottom: {style:'dotted', color: {argb:'FFCCCCCC'}} };
            cell.alignment = { vertical: 'middle', wrapText: true };
        });
    });

    // Finalize Response
    res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition',`attachment; filename=Permits_Register_${getNowIST().replace(/[\/, :]/g, '-')}.xlsx`);
    
    await workbook.xlsx.write(res); 
    res.end();
    
  } catch (err) { 
      console.error("Excel Export Error:", err);
      if(!res.headersSent) res.status(500).send("Export Error"); 
  }
});
// DOWNLOAD PDF (Updated to support Closed Mainline blobs)
app.get('/api/download-pdf/:id', authenticateAccess, async(req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().input('p', req.params.id).query("SELECT * FROM Permits WHERE PermitID=@p");
        if(!r.recordset.length) return res.status(404).send("Not Found");
        const p = r.recordset[0];

        // --- SECURITY CHECK (Existing) ---
        const { role, email } = req.user;
        let isAuthorized = false;
        if (role === 'MasterAdmin' || role === 'ElectricalAuth') isAuthorized = true;
        else if (role === 'Requester' && p.RequesterEmail === email) isAuthorized = true;
        else if (role === 'Reviewer' && (p.ReviewerEmail === email || p.Status.includes('Review'))) isAuthorized = true;
        else if (role === 'Approver' && (p.ApproverEmail === email || p.Status.includes('Approval'))) isAuthorized = true;

        if (!isAuthorized) return res.status(403).send("⛔ Unauthorized Access");
        
        const format = req.query.format; // Detect if ?format=mainline was used

        /* =====================================================
           ARCHIVAL FETCH LOGIC (For Closed Permits)
        ===================================================== */
        if (p.Status === 'Closed' && containerClient) {
            // Determine which archived file to grab
            let blobName = `closed-permits/${p.PermitID}_FINAL.pdf`;
            if (format === 'mainline') {
                blobName = `closed-permits/${p.PermitID}_MAINLINE_FINAL.pdf`;
            }

            try {
                const blockBlob = containerClient.getBlockBlobClient(blobName);
                if (await blockBlob.exists()) {
                    const download = await blockBlob.download(0);
                    res.setHeader('Content-Type', 'application/pdf');
                    res.setHeader('Content-Disposition', `attachment; filename=${blobName.split('/').pop()}`);
                    return download.readableStreamBody.pipe(res);
                }
            } catch (err) { 
                console.log("Archived blob not found, falling back to dynamic generation."); 
            }
        }

        /* =====================================================
           DYNAMIC GENERATION (For Active Permits or Fallback)
        ===================================================== */
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        res.setHeader('Content-Type', 'application/pdf');
        const filename = format === 'mainline' ? `${p.PermitID}_Mainline.pdf` : `${p.PermitID}.pdf`;
        res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
        
        doc.pipe(res);
        
        const d = p.FullDataJSON ? JSON.parse(p.FullDataJSON) : {};
        const rens = p.RenewalsJSON ? JSON.parse(p.RenewalsJSON) : [];
        
        if (format === 'mainline') {
            await drawMainlinePermitPDF(doc, p, d, rens);
        } else {
            await drawPermitPDF(doc, p, d, rens);
        }
        
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
    const { role, email } = req.user;
    let isAuthorized = false;

    if (role === 'MasterAdmin' || role === 'ElectricalAuth') isAuthorized = true;
    else if (role === 'Requester' && p.RequesterEmail === email) isAuthorized = true;
    else if (role === 'Reviewer' && (p.ReviewerEmail === email || p.Status.includes('Review'))) isAuthorized = true;
    else if (role === 'Approver' && (p.ApproverEmail === email || p.Status.includes('Approval'))) isAuthorized = true;

    if (!isAuthorized) {
        return res.status(403).json({ error: "Unauthorized Access" });
    }
    
    // MERGE JSON DATA WITH SQL COLUMNS
    res.json({ 
        ...JSON.parse(p.FullDataJSON), 
        Status: p.Status, 
        RenewalsJSON: p.RenewalsJSON, 
        IOCLSupervisors: JSON.parse(p.FullDataJSON).IOCLSupervisors || [],
        JsaFileUrl: p.JsaFileUrl, 
        JsaLinkedId: p.JsaLinkedId 
    });
});

/* =====================================================
   HELPER: Format Comma Separated Strings to Numbered Lists
===================================================== */
function formatToList(str) {
    if (!str) return 'N/A';
    return str.split(',')
        .map((item, index) => `${index + 1}. ${item.trim()}`)
        .join('\n');
}

/* =====================================================
   NEW FORMAT: MAINLINE PERMIT PDF GENERATOR
   (Triggered via ?format=mainline)
===================================================== */
async function drawMainlinePermitPDF(doc, p, d, renewalsList) {
    const safeText = (t) => (t === null || t === undefined) ? '-' : String(t);

    // --- PAGE 1: HEADER & DATA ---
    const startX = 30;
    let currentY = 30;

    // Logos
    const logoPath = path.join(__dirname, 'public', 'logo.png');
    if (fs.existsSync(logoPath)) {
        try { doc.image(logoPath, startX, currentY, { fit: [50, 50] }); } catch (e) {}
    }
    
// Titles
    doc.font('Helvetica-Bold').fontSize(12).text('Indian Oil Corporation Limited', 0, currentY, { align: 'center' });
    doc.fontSize(10).text('PIPELINES DIVISION', { align: 'center' });
    currentY += 45;
    
    doc.fontSize(11).text('GUIDELINES ON WORK PERMIT SYSTEM (WPS) FOR', { align: 'center' });
    doc.text('MAINLINE WORK of PIPELINES DIVISION', { align: 'center' });
    currentY += 25;

    // --- RESTORED TOP HEADER (Annexure & Sr No) ---
    // 1. Annexure III (Top Right)
    doc.font('Helvetica-Bold').fontSize(10);
    doc.text('Annexure III', 0, currentY, { align: 'right', width: 565 });
    currentY += 15;

    // 2. Attachment Title (Center)
    doc.fontSize(11).text('ATTACHMENT TO MAINLINE WORK PERMIT', 0, currentY, { align: 'center', width: 595 }); // Full page width for center
    currentY += 15;

    // 3. Sr No (Right, below Annexure)
    doc.fontSize(10).text(`Sr No- ${p.PermitID}`, 0, currentY, { align: 'right', width: 565 });
    currentY += 25;

    // --- MAIN DATA TABLES ---
    doc.lineWidth(0.5);
    const col1 = 30;  // Label Col 1
    const col2 = 180; // Data Col 1
    const col3 = 350; // Label Col 2
    const col4 = 450; // Data Col 2
    const rightEdge = 565;
    const rowH = 25;  // Base row height
    
    doc.font('Helvetica').fontSize(9);

    // Row 1: Permit No | Type
    doc.rect(col1, currentY, col2 - col1, rowH).stroke().text('Permit No:', col1 + 5, currentY + 8);
    doc.rect(col2, currentY, col3 - col2, rowH).stroke().text(p.PermitID, col2 + 5, currentY + 8);
    doc.rect(col3, currentY, col4 - col3, rowH).stroke().text('Type of Permit:', col3 + 5, currentY + 8);
    doc.rect(col4, currentY, rightEdge - col4, rowH).stroke().text(safeText(d.WorkType), col4 + 5, currentY + 8);
    currentY += rowH;

    // Row 2: Work Order | Contractor Name (Requestor)
    doc.rect(col1, currentY, col2 - col1, rowH).stroke().text('Work Order No:', col1 + 5, currentY + 8);
    doc.rect(col2, currentY, col3 - col2, rowH).stroke().text(safeText(d.WorkOrder), col2 + 5, currentY + 8);
    doc.rect(col3, currentY, col4 - col3, rowH).stroke().text('Contractor Names:', col3 + 5, currentY + 8);
    doc.rect(col4, currentY, rightEdge - col4, rowH).stroke().text(safeText(d.RequesterName), col4 + 5, currentY + 8);
    currentY += rowH;

    // Row 3: Prior Consent (Yes/No & By Whom)
    const consentTaken = d.Approver_Sig ? "Yes" : "No";
    const consentBy = d.Approver_Sig ? d.Approver_Sig : "Pending Approval";

    doc.rect(col1, currentY, col2 - col1, rowH * 2).stroke().text('Prior Information/consent taken for work (Yes/No):', col1 + 5, currentY + 8, {width: 140});
    doc.rect(col2, currentY, col3 - col2, rowH * 2).stroke().text(consentTaken, col2 + 5, currentY + 20);
    doc.rect(col3, currentY, col4 - col3, rowH * 2).stroke().text('Prior Information/consent given by:', col3 + 5, currentY + 8, {width: 90});
    doc.rect(col4, currentY, rightEdge - col4, rowH * 2).stroke().text(consentBy, col4 + 5, currentY + 8, {width: 110});
    currentY += (rowH * 2);

    // Row 4: SOP No
    doc.rect(col1, currentY, col2 - col1, rowH).stroke().text('Approved SOP/SWP/SMP no:', col1 + 5, currentY + 8);
    doc.rect(col2, currentY, rightEdge - col2, rowH).stroke().text(safeText(d.SopNo), col2 + 5, currentY + 8);
    currentY += rowH;

    // Row 5: JSA No
    doc.rect(col1, currentY, col2 - col1, rowH).stroke().text('Approved site specific JSA no:', col1 + 5, currentY + 8);
    doc.rect(col2, currentY, rightEdge - col2, rowH).stroke().text(safeText(d.JsaNo), col2 + 5, currentY + 8);
    currentY += rowH;

    // Row 6: IOCL Equipment (Numbered List)
    const ioclEquipList = formatToList(d.IoclEquip);
    const ioclH = Math.max(rowH, ioclEquipList.split('\n').length * 12 + 10);

    doc.rect(col1, currentY, col2 - col1, ioclH).stroke().text('IOCL Equipment / Machinery deployed at Site:', col1 + 5, currentY + 8, {width: 140});
    doc.rect(col2, currentY, rightEdge - col2, ioclH).stroke().text(ioclEquipList, col2 + 5, currentY + 8);
    currentY += ioclH;

    // Row 7: Contractor Equipment (Numbered List)
    const contEquipList = formatToList(d.ContEquip);
    const contH = Math.max(rowH, contEquipList.split('\n').length * 12 + 10);

    doc.rect(col1, currentY, col2 - col1, contH).stroke().text('Contractor Equipment / Machinery deployed at Site:', col1 + 5, currentY + 8, {width: 140});
    doc.rect(col2, currentY, rightEdge - col2, contH).stroke().text(contEquipList, col2 + 5, currentY + 8);
    currentY += contH;

    // --- SUPERVISOR TABLES ---
    
    // IOCL Supervisors
    currentY += 10;
    if(currentY > 650) { doc.addPage(); currentY = 30; }
    doc.font('Helvetica-Bold').text('Authorized work supervisor from IOCL side:', col1, currentY);
    currentY += 15;

    // Headers
    doc.rect(col1, currentY, 40, 20).stroke().text('Sr No', col1 + 5, currentY + 5);
    doc.rect(col1 + 40, currentY, 250, 20).stroke().text('Name', col1 + 45, currentY + 5);
    doc.rect(col1 + 290, currentY, 245, 20).stroke().text('Contact No', col1 + 295, currentY + 5);
    currentY += 20;

    let ioclSups = [];
    if(d.IOCLSupervisors) {
        if(Array.isArray(d.IOCLSupervisors)) ioclSups = d.IOCLSupervisors;
        else if(typeof d.IOCLSupervisors === 'string') try { ioclSups = JSON.parse(d.IOCLSupervisors); } catch(e){}
    }
    
   doc.font('Helvetica');
    if(ioclSups.length === 0) {
        doc.rect(col1, currentY, 535, 20).stroke().text('No IOCL Supervisors assigned', col1 + 5, currentY + 5);
        currentY += 20;
    } else {
        ioclSups.forEach((sup, idx) => {
             // START FIX: Visualize Deleted Status
             const isDel = (sup.status === 'inactive' || sup.is_deleted);
             let nameTxt = safeText(sup.name);
             let contactTxt = safeText(sup.contact);
             
             if(isDel) {
                 nameTxt += ` (DEL: ${sup.deleted_by || 'Admin'})`; // Added safe fallback
                 doc.fillColor('red'); // Draw deleted rows in red
             } else {
                 doc.fillColor('black');
             }
             // END FIX

             doc.rect(col1, currentY, 40, 20).stroke().text((idx + 1).toString(), col1 + 5, currentY + 5);
             doc.rect(col1 + 40, currentY, 250, 20).stroke().text(nameTxt, col1 + 45, currentY + 5);
             doc.rect(col1 + 290, currentY, 245, 20).stroke().text(contactTxt, col1 + 295, currentY + 5);
             currentY += 20;
        });
        doc.fillColor('black'); // Reset color
    }

    // Contractor Supervisors
    currentY += 10;
    doc.font('Helvetica-Bold').text('Authorized work supervisor from Contractor side:', col1, currentY);
    currentY += 15;
    
    doc.rect(col1, currentY, 40, 20).stroke().text('Sr No', col1 + 5, currentY + 5);
    doc.rect(col1 + 40, currentY, 250, 20).stroke().text('Name', col1 + 45, currentY + 5);
    doc.rect(col1 + 290, currentY, 245, 20).stroke().text('Contact No', col1 + 295, currentY + 5);
    currentY += 20;

    doc.font('Helvetica');
    doc.rect(col1, currentY, 40, 20).stroke().text('1', col1 + 5, currentY + 5);
    doc.rect(col1 + 40, currentY, 250, 20).stroke().text(safeText(d.RequesterName), col1 + 45, currentY + 5);
    doc.rect(col1 + 290, currentY, 245, 20).stroke().text(safeText(d.EmergencyContact), col1 + 295, currentY + 5);
    currentY += 20;

    // --- PAGE 2: ATTACHMENT B (WORKERS) ---
    if (currentY > 600) { doc.addPage(); currentY = 30; } else { currentY += 30; }

    doc.font('Helvetica-Bold').fontSize(11).text('ATTACHMENT TO MAINLINE WORK PERMIT', col1, currentY, {underline: true});
    currentY += 20;
    doc.fontSize(10).text('B) Detail of associated workers', col1, currentY);
    currentY += 20;

    // Worker Headers
    doc.fontSize(9);
    const wx1 = 30; const wx2 = 70; const wx3 = 220; const wx4 = 280; const wx5 = 320; const wx6 = 565;

    doc.rect(wx1, currentY, wx2-wx1, 25).stroke().text('Sr No', wx1+2, currentY+8);
    doc.rect(wx2, currentY, wx3-wx2, 25).stroke().text('Worker Name', wx2+2, currentY+8);
    doc.rect(wx3, currentY, wx4-wx3, 25).stroke().text('Gender', wx3+2, currentY+8);
    doc.rect(wx4, currentY, wx5-wx4, 25).stroke().text('Age', wx4+2, currentY+8);
    doc.rect(wx5, currentY, wx6-wx5, 25).stroke().text('Name of Contractor', wx5+2, currentY+8);
    currentY += 25;

    // Worker Data
    let workers = [];
    if(d.SelectedWorkers) {
        if(Array.isArray(d.SelectedWorkers)) workers = d.SelectedWorkers;
        else if(typeof d.SelectedWorkers === 'string') try { workers = JSON.parse(d.SelectedWorkers); } catch(e){}
    }

    doc.font('Helvetica');
    const contractorName = safeText(d.Vendor) || safeText(d.RequesterName);

    workers.forEach((w, index) => {
        if (currentY > 750) { doc.addPage(); currentY = 30; }
        doc.rect(wx1, currentY, wx2-wx1, 20).stroke().text((index + 1).toString(), wx1+2, currentY+5);
        doc.rect(wx2, currentY, wx3-wx2, 20).stroke().text(safeText(w.Name), wx2+2, currentY+5);
        doc.rect(wx3, currentY, wx4-wx3, 20).stroke().text(safeText(w.Gender), wx3+2, currentY+5);
        doc.rect(wx4, currentY, wx5-wx4, 20).stroke().text(safeText(w.Age), wx4+2, currentY+5);
        doc.rect(wx5, currentY, wx6-wx5, 20).stroke().text(contractorName, wx5+2, currentY+5);
        currentY += 20;
    });
    
    // --- FOOTER ---
    const bottomY = doc.page.height - 50;
    doc.font('Helvetica').fontSize(8);
    // Removed 'Annexure III' from here as it is now at the top
    doc.text('DOCUMENT NUMBER PL/HO/HSE/18/2025-26/01, Rev 0', 30, bottomY + 10);
    doc.text('Effective from: 01.07.2025', 30, bottomY + 20);
    
    // Page Numbers
    let pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
        doc.switchToPage(i);
        doc.text(`Page ${i + 1} of ${pages.count}`, 500, doc.page.height - 30);
    }
}
/* =====================================================
   JSA PORTAL ROUTES (Crash Proofed from B)
===================================================== */

// 1. List JSAs for Dashboard
app.post('/api/jsa/list-my', authenticateAccess, async(req, res) => {
    const { role, email } = req.body;
    const pool = await getConnection();
    let q = "SELECT JSAID, RefNumber, JobTitle, Location, Status, RequesterName FROM JSAs ";
    
    if (role === 'Requester') q += "WHERE RequesterEmail = @e";
    else if (role === 'Reviewer') q += "WHERE ReviewerEmail = @e OR Status = 'Pending Review' OR Status = 'Approved'";
    else if (role === 'Approver') q += "WHERE ApproverEmail = @e OR Status = 'Pending Approval' OR Status = 'Approved'";
    else if (role !== 'MasterAdmin') q += "WHERE 1=0"; 
    
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

// 3. Get Single JSA Data (Updated to support RefNumber lookup)
app.post('/api/jsa/get', authenticateAccess, async(req, res) => {
    const pool = await getConnection();
    const reqSql = pool.request();
    let query = "SELECT * FROM JSAs WHERE ";
    
    if (req.body.id) {
        query += "JSAID=@id";
        reqSql.input('id', req.body.id);
    } else if (req.body.ref) {
        query += "RefNumber=@ref";
        reqSql.input('ref', req.body.ref);
    } else {
        return res.status(400).json({error: "No ID or Ref provided"});
    }
    
    const r = await reqSql.query(query);
    res.json(r.recordset[0]);
});

// 4. Save JSA (Create or Edit Draft) - CRASH PROOFED
app.post('/api/jsa/save', authenticateAccess, async(req, res) => {
    try { 
        const { JSAID, DataJSON, ...fields } = req.body;
        const pool = await getConnection();
        
        let targetID = JSAID;
        if (!targetID) {
            const r = await pool.request().input('reqE', fields.RequesterEmail)
                .query("INSERT INTO JSAs (Status, RequesterEmail, CreatedAt) OUTPUT INSERTED.JSAID VALUES ('Draft', @reqE, GETDATE())");
            
            targetID = r.recordset[0].JSAID;
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
        console.error("JSA Save Error:", e);
        res.status(500).json({ error: "Database Error: " + e.message }); 
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
         res.json({url: r.recordset[0].FinalPdfUrl}); 
    } else {
        res.status(404).send("PDF not found");
    }
});

async function generateJsaPdfBuffer(jsa, refNo, approverName, approvedDate) {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        const chunks = [];
        doc.on('data', chunks.push.bind(chunks));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        const data = JSON.parse(jsa.DataJSON);
        const team = data.team || [];
        const steps = data.steps || [];

        // Layout Constants
        const startX = 30;
        const width = 535;
        let y = 30;
        const col1 = 30;
        const col2 = 180;
        const col3 = 350;
        const col4 = 450;

        // --- 1. HEADER ---
        const logoPath = path.join(__dirname, 'public', 'logo.png');
        if (fs.existsSync(logoPath)) {
            try { doc.image(logoPath, 265, y, { fit: [60, 60], align: 'center' }); } catch (e) {}
        }
        y += 70;

        doc.font('Helvetica-Bold').fontSize(14).text('INDIAN OIL CORPORATION LIMITED', startX, y, { align: 'center', width: width });
        y += 20;
        doc.fontSize(10).text('Pipelines Division', startX, y, { align: 'center', width: width });
        y += 15;
        // Region/Unit/Loc
        const locHeader = `${jsa.Region || 'Region'} / ${jsa.Unit || 'Unit'} / ${jsa.Location || 'Location'}`;
        doc.text(locHeader, startX, y, { align: 'center', width: width });
        y += 20;
        
        doc.fontSize(16).text('JOB SAFETY ANALYSIS', startX, y, { align: 'center', width: width, underline: true });
        y += 30;

        // --- 2. INFO BLOCK ---
        doc.fontSize(10).font('Helvetica-Bold');
        
        // Line 1: Ref | Date | Page
        doc.text(`JSA Ref: ${refNo}`, startX, y);
        doc.text(`Date: ${approvedDate}`, startX + 250, y);
        doc.text(`Page: 1 of 1`, startX + 450, y); // Placeholder for paging
        y += 20;

        // Line 2: Unit | Area | Location
        doc.text(`Unit: ${jsa.Unit || '-'}`, startX, y);
        doc.text(`Area: ${jsa.Location || '-'}`, startX + 180, y);
        doc.text(`Location: ${jsa.Location || '-'}`, startX + 360, y);
        y += 20;

        // Line 3: Job Title
        doc.text(`Job Title: ${jsa.JobTitle || '-'}`, startX, y);
        y += 25;

        // --- 3. TEAM & EXECUTION ---
        
        // Header Row
        doc.font('Helvetica-Bold').fontSize(10);
        // Column 1: JSA Done By
        doc.rect(startX, y, 350, 20).fillAndStroke('#f3f4f6', 'black');
        doc.fillColor('black').text('JSA Done By (Name, Designation, Department)', startX + 5, y + 6);
        
        // Column 2: Signature
        doc.rect(startX + 350, y, 185, 20).fillAndStroke('#f3f4f6', 'black');
        doc.fillColor('black').text('Signature', startX + 355, y + 6);
        y += 20;

        // Data Rows
        doc.font('Helvetica').fontSize(9);
        
        if (team.length === 0) {
            // Draw one empty row if no team members defined
            doc.rect(startX, y, 350, 25).stroke();
            doc.rect(startX + 350, y, 185, 25).stroke();
            y += 25;
        } else {
            team.forEach(m => {
                // Format: Name, Designation, Department
                const details = `${m.name || '-'}, ${m.desig || '-'}, ${m.dept || '-'}`;
                
                // Col 1: Text
                doc.rect(startX, y, 350, 25).stroke();
                doc.text(details, startX + 5, y + 8, { width: 340, ellipsis: true });

                // Col 2: Blank for manual signature
                doc.rect(startX + 350, y, 185, 25).stroke();
                
                y += 25;
            });
        }
        y += 10; // Add some spacing after the table

        // Job Execution Line
        doc.font('Helvetica-Bold').text('Job to be Executed By (Dept/Contractor):', startX, y);
        doc.font('Helvetica').text(jsa.ExecutedBy || '-', startX + 220, y);
        y += 30;
        // --- 5. MAIN RISK TABLE ---
        const headers = [
    { t: "Sl. No.", w: 40 },
    { t: "Activities", w: 120 },
    { t: "Hazards", w: 120 },
    { t: "Recommended Actions /\nProcedures & Control Measures", w: 255 }
    ];

        // Header Row
        let tx = startX;
        doc.font('Helvetica-Bold').fontSize(9);
        // Header Background
        doc.rect(startX, y, width, 30).fillAndStroke('#f3f4f6', 'black');
        doc.fillColor('black');
        
        headers.forEach(h => {
            doc.text(h.t, tx + 5, y + 5, { width: h.w - 10, align: 'center' });
            tx += h.w;
        });
        y += 30;

        // Data Rows
        doc.font('Helvetica').fontSize(9);
        steps.forEach((s, i) => {
            // Calculate max height for the row
            const h1 = doc.heightOfString(s.activity, { width: 110 });
            const h2 = doc.heightOfString(s.hazard, { width: 110 });
            const h3 = doc.heightOfString(s.control, { width: 245 });
            const rowH = Math.max(h1, h2, h3, 20) + 10;
            
            // Page Break Check
            if (y + rowH > 750) {
                doc.addPage();
                y = 30;
                // Re-draw header on new page (optional but good)
                tx = startX;
                doc.font('Helvetica-Bold');
                doc.rect(startX, y, width, 30).fillAndStroke('#f3f4f6', 'black');
                doc.fillColor('black');
                headers.forEach(h => {
                    doc.text(h.t, tx + 5, y + 5, { width: h.w - 10, align: 'center' });
                    tx += h.w;
                });
                y += 30;
                doc.font('Helvetica');
            }

            tx = startX;
            
            // Draw Cell Boxes
            doc.rect(tx, y, 40, rowH).stroke();
            doc.text(String(i + 1), tx + 2, y + 5, { width: 36, align: 'center' });
            tx += 40;

            doc.rect(tx, y, 120, rowH).stroke();
            doc.text(s.activity || '-', tx + 5, y + 5, { width: 110 });
            tx += 120;

            doc.rect(tx, y, 120, rowH).stroke();
            doc.text(s.hazard || '-', tx + 5, y + 5, { width: 110 });
            tx += 120;

            doc.rect(tx, y, 255, rowH).stroke();
            doc.text(s.control || '-', tx + 5, y + 5, { width: 245 });
            
            y += rowH;
        });

       // --- 6. ADDITIONAL PRECAUTIONS ---
        y += 15;
        if (y > 700) { doc.addPage(); y = 30; }

        doc.font('Helvetica-Bold').text('Additional Precautions:', startX, y, { underline: true });
        y += 15;
        doc.font('Helvetica').fontSize(9);
        
        // Default List
        const defaultPrecs = [
            "Only qualified and experienced welder shall be engaged.",
            "Ensure availability of all tools, tackles, PPEs and preparedness at site as per JSA.",
            "Ensure availability of DCP & CO2 cylinders at site.",
            "Ensuring LEL level is within the acceptable limits by checking at regular intervals.",
            "Proper Hot / Cold work permit to be taken for each work.",
            "Walkie talkie to be used for communication during execution of job.",
            "Safety officer and site supervisor deployed by contractor shall be present at site.",
            "IOCL approved procedures to be followed to carry out all activities.",
            "Barricading to be done near pig launching barrel."
        ];

        let allPrecs = [...defaultPrecs];
        
        // Append user-entered precautions if present
        const userPrec = data.additionalPrecautions;
        if (userPrec && userPrec.trim() !== '' && userPrec !== 'None') {
            allPrecs.push(userPrec);
        }

        // Render List
        allPrecs.forEach((item, index) => {
            // Check for page break before printing each line
            const textHeight = doc.heightOfString(`${index + 1}. ${item}`, { width: width });
            if (y + textHeight > 750) { 
                doc.addPage(); 
                y = 30; 
            }
            
            doc.text(`${index + 1}. ${item}`, startX, y, { width: width });
            y += textHeight + 5; // Add dynamic spacing based on text height
        });

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
/* --- FILE VIEWING ROUTE --- */
app.get('/api/view-blob', authenticateAccess, async (req, res) => {
    try {
        const blobName = req.query.name;
        if (!blobName || !containerClient) return res.status(404).send("File not found");

        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
        const exists = await blockBlobClient.exists();
        if (!exists) return res.status(404).send("Blob missing");

        const props = await blockBlobClient.getProperties();
        res.setHeader('Content-Type', props.contentType);
        
        const downloadResponse = await blockBlobClient.download(0);
        downloadResponse.readableStreamBody.pipe(res);
    } catch (e) {
        console.error("View Blob Error:", e);
        res.status(500).send("Error loading file");
    }
});
// --- MISSING MAP ROUTE ---
app.post('/api/map-data', authenticateAccess, async (req, res) => {
    try {
        const pool = await getConnection();
        // Only fetch Active or Pending permits for the map
        const r = await pool.request().query("SELECT PermitID, Status, FullDataJSON FROM Permits WHERE Status NOT IN ('Closed', 'Rejected')");
        
        const points = r.recordset.map(p => {
            let d = {};
            try { d = JSON.parse(p.FullDataJSON); } catch (e) {}
            
            // Logic: Parse "26.1234, 85.5678" string into Lat/Lng numbers
            if (d.ExactLocation && d.ExactLocation.includes(',')) {
                const parts = d.ExactLocation.split(',');
                return {
                    PermitID: p.PermitID,
                    Status: p.Status,
                    lat: parseFloat(parts[0].trim()),
                    lng: parseFloat(parts[1].trim())
                };
            }
            return null;
        }).filter(x => x !== null); // Filter out permits with no GPS data

        res.json(points);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log("Server Started on Port " + PORT));
