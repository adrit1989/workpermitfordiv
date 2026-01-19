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

// SECURITY
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// APP
const app = express();
app.use(cookieParser());

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
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, "https://cdn.jsdelivr.net", "https://maps.googleapis.com"],
        styleSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:", "blob:", "https://maps.gstatic.com", "https://maps.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "https://maps.googleapis.com", "https://cdn.jsdelivr.net"],
        frameAncestors: ["'none'"]
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

// RATE LIMIT
app.use('/api/', rateLimit({ windowMs: 10 * 1000, max: 50 }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });

/* --- MULTER + FILE MIME VALIDATION --- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png"];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("INVALID_FILE_TYPE"), false);
    }
    cb(null, true);
  }
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
   TOKEN & AUTH FUNCTIONS (ACCESS + REFRESH)
===================================================== */

function createAccessToken(user) {
  return jwt.sign({
    name: user.Name,
    email: user.Email,
    role: user.Role,
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

/* --- MIDDLEWARE: AUTH ACCESS TOKEN --- */
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
   AUTH ROUTES: LOGIN / REFRESH / LOGOUT
===================================================== */

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const pool = await getConnection();
    const r = await pool.request()
      .input('e', sql.NVarChar, req.body.name)
      .query('SELECT * FROM Users WHERE Email=@e');

    if (!r.recordset.length) return res.json({ success: false });

    const user = r.recordset[0];
    const valid = await bcrypt.compare(req.body.password, user.Password);
    if (!valid || user.Role !== req.body.role) return res.json({ success: false });

    const lastPwdTime = user.LastPasswordChange ?
      Math.floor(new Date(user.LastPasswordChange).getTime() / 1000) : 0;

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

    return res.json({
      success: true,
      token: accessToken,
      user: { Name: user.Name, Email: user.Email, Role: user.Role }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Login Error" });
  }
});

app.post('/api/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(401).json({ error: "No refresh token" });

    if (!(await isRefreshValid(refreshToken))) {
      return res.status(403).json({ error: "Refresh token invalid" });
    }

    jwt.verify(refreshToken, REFRESH_SECRET, async (err, decoded) => {
      if (err) return res.status(403).json({ error: "Invalid refresh" });

      const pool = await getConnection();
      const r = await pool.request()
        .input('e', sql.NVarChar, decoded.email)
        .query('SELECT * FROM Users WHERE Email=@e');

      if (!r.recordset.length) return res.status(403).json({ error: "Unknown user" });

      const user = r.recordset[0];
      const lastPwdTime = user.LastPasswordChange ?
        Math.floor(new Date(user.LastPasswordChange).getTime() / 1000) : 0;
      user.lastPwd = lastPwdTime;

      const newAccess = createAccessToken(user);
      const newRefresh = createRefreshToken(user);

      await deleteRefreshToken(refreshToken);
      await saveRefreshToken(user.Email, newRefresh);

      res.cookie("refreshToken", newRefresh, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        path: "/api/refresh"
      });

      return res.json({ success: true, token: newAccess });
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Refresh Error" });
  }
});

app.post('/api/logout', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) await deleteRefreshToken(refreshToken);
    res.clearCookie("refreshToken", { path: "/api/refresh" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Logout Error" });
  }
});
/* =====================================================
   HELPER FUNCTIONS (unchanged from your original)
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

async function uploadToAzure(buffer, blobName, mimeType = "image/jpeg") {
  if (!containerClient) return null;
  try {
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
    await blockBlobClient.uploadData(buffer, {
      blobHTTPHeaders: { blobContentType: mimeType }
    });
    return blockBlobClient.url;
  } catch (err) {
    console.error("Azure upload error:", err.message);
    return null;
  }
}

/* =====================================================
   USERS & WORKERS
===================================================== */

app.get('/api/users', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const r = await pool.request().query("SELECT Name, Email, Role FROM Users");
    const fmt = u => ({ name: u.Name, email: u.Email, role: u.Role });
    res.json({
      Requesters: r.recordset.filter(u => u.Role === 'Requester').map(fmt),
      Reviewers: r.recordset.filter(u => u.Role === 'Reviewer').map(fmt),
      Approvers: r.recordset.filter(u => u.Role === 'Approver').map(fmt)
    });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post('/api/change-password', authenticateAccess, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const pool = await getConnection();
    const r = await pool.request()
      .input('e', req.user.email).query("SELECT * FROM Users WHERE Email=@e");
    if (!r.recordset.length) return res.status(404).json({ error: "User not found" });

    const user = r.recordset[0];
    const valid = await bcrypt.compare(currentPassword, user.Password);
    if (!valid) return res.status(400).json({ error: "Invalid current password" });

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.request()
      .input('p', hashed)
      .input('e', req.user.email)
      .query("UPDATE Users SET Password=@p, LastPasswordChange=GETDATE() WHERE Email=@e");

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post('/api/add-user', authenticateAccess, async (req, res) => {
  if (req.user.role !== 'Approver') return res.sendStatus(403);
  try {
    const pool = await getConnection();
    const check = await pool.request()
      .input('e', req.body.email)
      .query("SELECT * FROM Users WHERE Email=@e");
    if (check.recordset.length) return res.status(400).json({ error: "User Exists" });

    const hashed = await bcrypt.hash(req.body.password, 10);
    await pool.request()
      .input('n', req.body.name)
      .input('e', req.body.email)
      .input('r', req.body.role)
      .input('p', hashed)
      .query("INSERT INTO Users (Name,Email,Role,Password) VALUES (@n,@e,@r,@p)");

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

/* =====================================================
   WORKER MANAGEMENT (unchanged logic, new auth)
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
/* =====================================================
   DASHBOARD
===================================================== */

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
    const f = (role === 'Requester')
      ? p.filter(x => x.RequesterEmail === email)
      : p;
    res.json(f.sort((a,b)=> b.PermitID.localeCompare(a.PermitID)));
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

/* =====================================================
   SAVE PERMIT
===================================================== */

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

    if (!vf || !vt) return res.status(400).json({ error:"Start & End required" });
    if (vt <= vf) return res.status(400).json({ error:"End > Start required" });
    if (req.body.Desc && req.body.Desc.length > 500)
      return res.status(400).json({ error:"Description too long" });

    const pool = await getConnection();
    let pid = req.body.PermitID;

    if (!pid || pid === 'undefined' || pid === 'null' || pid === '') {
      const idRes = await pool.request().query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
      const lastId = idRes.recordset.length ? idRes.recordset[0].PermitID : 'WP-1000';
      const numPart = parseInt(lastId.split('-')[1] || 1000);
      pid = `WP-${numPart + 1}`;
    }

    const chk = await pool.request().input('p', sql.NVarChar, pid)
      .query("SELECT Status FROM Permits WHERE PermitID=@p");
    if (chk.recordset.length && chk.recordset[0].Status.includes('Closed'))
      return res.status(400).json({ error: "Permit CLOSED" });

    let workers = req.body.SelectedWorkers;
    if (typeof workers === 'string') {
      try { workers = JSON.parse(workers); } catch { workers = []; }
    }

    let renewalsArr = [];
    if (req.body.InitRen === 'Y') {
      let photoUrl = null;
      const renImg = req.files ? req.files.find(x => x.fieldname === 'InitRenImage') : null;
      if (renImg) {
        const blobName = `${pid}-1stRenewal.jpg`;
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
      await q.query("UPDATE Permits SET FullDataJSON=@j, WorkType=@w, ValidFrom=@vf, ValidTo=@vt, Latitude=@lat, Longitude=@lng WHERE PermitID=@p");
    } else {
      await q.query("INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, FullDataJSON, RenewalsJSON) VALUES (@p,@s,@w,@re,@rv,@ap,@vf,@vt,@lat,@lng,@j,@ren)");
    }

    res.json({ success: true, permitId: pid });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error:"Internal Server Error" });
  }
});

/* =====================================================
   UPDATE PERMIT STATUS
===================================================== */

app.post('/api/update-status', authenticateAccess, async (req, res) => {
  try {
    const { PermitID, action, ...extras } = req.body;
    const role = req.user.role;
    const user = req.user.name;

    const pool = await getConnection();
    const cur = await pool.request().input('p', PermitID).query("SELECT * FROM Permits WHERE PermitID=@p");
    if (!cur.recordset.length) return res.json({ error:"Not found" });

    let st = cur.recordset[0].Status;
    let d = JSON.parse(cur.recordset[0].FullDataJSON);
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
        } catch(e) { doc.end(); reject(e); }
      });
      const blobName = `closed-permits/${PermitID}_FINAL.pdf`;
      finalPdfUrl = await uploadToAzure(pdfBuffer, blobName, "application/pdf");
      if(finalPdfUrl) finalJson=null;
    }

    const q = pool.request().input('p', PermitID).input('s', st).input('r', JSON.stringify(renewals));
    if (finalPdfUrl) {
      await q.input('url', finalPdfUrl).query("UPDATE Permits SET Status=@s, FullDataJSON=NULL, RenewalsJSON=NULL, FinalPdfUrl=@url WHERE PermitID=@p");
    } else {
      await q.input('j', finalJson).query("UPDATE Permits SET Status=@s, FullDataJSON=@j, RenewalsJSON=@r WHERE PermitID=@p");
    }

    res.json({ success:true, archived:!!finalPdfUrl });

  } catch (err) {
    res.status(500).json({ error:"Internal Server Error" });
  }
});

/* =====================================================
   RENEWAL
===================================================== */

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

/* =====================================================
   PERMIT DATA & MAP & STATS
===================================================== */

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

/* =====================================================
   EXCEL EXPORT
===================================================== */

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

/* =====================================================
   PDF DOWNLOAD
===================================================== */

app.get('/api/download-pdf/:id', authenticateAccess, async (req, res) => {
  try {
    const pool = await getConnection();
    const result = await pool.request().input('p', req.params.id)
      .query("SELECT * FROM Permits WHERE PermitID=@p");
    if (!result.recordset.length) return res.status(404).send('Not Found');

    const p = result.recordset[0];

    if (req.user.role==='Requester' && p.RequesterEmail!==req.user.email)
      return res.status(403).send("Unauthorized");

    if ((p.Status==='Closed' || p.Status.includes('Closure')) && p.FinalPdfUrl) {
      if (!containerClient) return res.status(500).send("Storage Error");
      try {
        const blobName = `closed-permits/${p.PermitID}_FINAL.pdf`;
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
        if (!await blockBlobClient.exists()) return res.status(404).send("Archived PDF missing");

        const download = await blockBlobClient.download(0);
        res.setHeader('Content-Type','application/pdf');
        res.setHeader('Content-Disposition',`attachment; filename=${p.PermitID}.pdf`);
        return download.readableStreamBody.pipe(res);

      } catch (err) {
        console.error("Azure Download Error:", err.message);
        return res.status(500).send("Storage Error");
      }
    }

    const d = p.FullDataJSON ? JSON.parse(p.FullDataJSON) : {};
    const renewals = p.RenewalsJSON ? JSON.parse(p.RenewalsJSON) : [];

    const doc = new PDFDocument({ margin:30, size:'A4', bufferPages:true });
    res.setHeader('Content-Type','application/pdf');
    res.setHeader('Content-Disposition',`attachment; filename=${p.PermitID}.pdf`);
    doc.pipe(res);
    await drawPermitPDF(doc, p, d, renewals);
    doc.end();

  } catch (err) {
    res.status(500).send("Internal Server Error");
  }
});

/* =====================================================
   VIEW PHOTO
===================================================== */

app.get('/api/view-photo/:filename', authenticateAccess, async (req, res) => {
  try {
    const filename = req.params.filename;
    const permitId = filename.split('-')[0] + '-' + filename.split('-')[1];

    if (!containerClient) return res.status(500).send("Storage not configured");

    if (req.user.role==='Requester') {
      const pool = await getConnection();
      const r = await pool.request().input('p', sql.NVarChar, permitId)
        .query("SELECT RequesterEmail FROM Permits WHERE PermitID=@p");
      if (!r.recordset.length || r.recordset[0].RequesterEmail!==req.user.email) {
        return res.status(403).send("Unauthorized");
      }
    }

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

/* =====================================================
   FRONTEND + SERVER START
===================================================== */

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
