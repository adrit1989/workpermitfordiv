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

// ==========================================
// AZURE BLOB STORAGE SETUP
// ==========================================
const AZURE_CONN_STR = process.env.AZURE_STORAGE_CONNECTION_STRING;
let containerClient, kmlContainerClient;

if (AZURE_CONN_STR) {
    try {
        const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN_STR);
        containerClient = blobServiceClient.getContainerClient("permit-attachments");
        kmlContainerClient = blobServiceClient.getContainerClient("map-layers");
        (async () => {
            try { await containerClient.createIfNotExists(); } catch(e) { console.log("Attachments container exists"); }
            try { await kmlContainerClient.createIfNotExists({ access: 'blob' }); } catch(e) { console.log("KML container exists"); }
        })();
    } catch (err) { 
        console.error("Blob Storage Error:", err.message); 
    }
}

const upload = multer({ storage: multer.memoryStorage() });

// ==========================================
// HELPER FUNCTIONS
// ==========================================

// Get current time in IST (Indian Standard Time)
function getNowIST() { 
    return new Date().toLocaleString("en-GB", { 
        timeZone: "Asia/Kolkata", 
        day: '2-digit', 
        month: '2-digit', 
        year: 'numeric', 
        hour: '2-digit', 
        minute: '2-digit', 
        hour12: false 
    }).replace(',', ''); 
}

// Format Date string to DD-MM-YYYY HH:mm
function formatDate(dateStr) {
    if (!dateStr) return '-';
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr; // Return as-is if it's already a string
    return d.toLocaleString("en-GB", { 
        day: '2-digit', 
        month: '2-digit', 
        year: 'numeric', 
        hour: '2-digit', 
        minute: '2-digit', 
        hour12: false 
    }).replace(',', '');
}

// ==========================================
// API ROUTES
// ==========================================

// 1. LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request()
            .input('role', sql.NVarChar, req.body.role)
            .input('email', sql.NVarChar, req.body.name) 
            .input('pass', sql.NVarChar, req.body.password)
            .query('SELECT * FROM Users WHERE Role = @role AND Email = @email AND Password = @pass');
        
        if (result.recordset.length > 0) {
            res.json({ success: true, user: result.recordset[0] });
        } else {
            res.json({ success: false, message: "Invalid Credentials" });
        }
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

// 2. GET USERS LIST
app.get('/api/users', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query('SELECT Name, Role, Email FROM Users');
        res.json({
            Requesters: result.recordset.filter(u => u.Role === 'Requester').map(u => ({ name: u.Name, email: u.Email })),
            Reviewers: result.recordset.filter(u => u.Role === 'Reviewer').map(u => ({ name: u.Name, email: u.Email })),
            Approvers: result.recordset.filter(u => u.Role === 'Approver').map(u => ({ name: u.Name, email: u.Email }))
        });
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

// 2.5 ADD NEW USER
app.post('/api/add-user', async (req, res) => {
    try {
        const { name, email, role, password } = req.body;
        if (!name || !email || !role || !password) {
            return res.status(400).json({ error: "All fields required" });
        }

        const pool = await getConnection();
        // Check duplication
        const check = await pool.request()
            .input('e', sql.NVarChar, email)
            .query("SELECT * FROM Users WHERE Email = @e");
            
        if(check.recordset.length > 0) {
            return res.status(400).json({ error: "User with this email already exists." });
        }

        await pool.request()
            .input('n', sql.NVarChar, name)
            .input('e', sql.NVarChar, email)
            .input('r', sql.NVarChar, role)
            .input('p', sql.NVarChar, password)
            .query("INSERT INTO Users (Name, Email, Role, Password) VALUES (@n, @e, @r, @p)");
            
        res.json({ success: true });
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

// 3. DASHBOARD DATA
app.post('/api/dashboard', async (req, res) => {
    try {
        const { role, email } = req.body;
        const pool = await getConnection();
        const result = await pool.request().query('SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON FROM Permits');
        
        const permits = result.recordset.map(p => {
            const d = JSON.parse(p.FullDataJSON || "{}");
            return { 
                ...d, 
                PermitID: p.PermitID, 
                Status: p.Status, 
                ValidFrom: p.ValidFrom, 
                ValidTo: p.ValidTo 
            };
        });

        const filtered = permits.filter(p => {
            const st = (p.Status || "").toLowerCase();
            if (role === 'Requester') return p.RequesterEmail === email;
            
            if (role === 'Reviewer') {
                return (p.ReviewerEmail === email && (st.includes('pending review') || st.includes('closure') || st === 'closed' || st.includes('renewal')));
            }
            
            if (role === 'Approver') {
                return (p.ApproverEmail === email && (st.includes('pending approval') || st === 'active' || st === 'closed' || st.includes('renewal') || st.includes('closure')));
            }
            return false;
        });
        
        res.json(filtered.sort((a, b) => b.PermitID.localeCompare(a.PermitID)));
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

// 4. SAVE NEW PERMIT
app.post('/api/save-permit', upload.single('file'), async (req, res) => {
    try {
        const vf = new Date(req.body.ValidFrom);
        const vt = new Date(req.body.ValidTo);

        // Validation: End time > Start time
        if (vt <= vf) return res.status(400).json({ error: "End time must be greater than Start time." });
        
        // Validation: Max 7 Days
        const diffTime = Math.abs(vt - vf);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
        if (diffDays > 7) return res.status(400).json({ error: "Permit duration cannot exceed 7 days." });

        const pool = await getConnection();
        
        // Generate ID
        const idRes = await pool.request().query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
        const lastId = idRes.recordset.length > 0 ? idRes.recordset[0].PermitID : "WP-1000";
        const newId = `WP-${parseInt(lastId.split('-')[1]) + 1}`;

        const fullData = { ...req.body, PermitID: newId };
        
        await pool.request()
            .input('pid', sql.NVarChar, newId)
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
            .input('json', sql.NVarChar, JSON.stringify(fullData))
            .query(`INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, 
                    LocationPermitSno, RefIsolationCert, CrossRefPermits, JsaRef, MocRequired, MocRef, CctvAvailable, CctvDetail, Vendor, IssuedToDept, LocationUnit, ExactLocation, [Desc], OfficialName, RenewalsJSON, FullDataJSON) 
                    VALUES (@pid, @status, @wt, @req, @rev, @app, @vf, @vt, @lat, @lng, 
                    @locSno, @iso, @cross, @jsa, @mocReq, @mocRef, @cctv, @cctvDet, @vendor, @dept, @locUnit, @exactLoc, @desc, @offName, '[]', @json)`);

        res.json({ success: true, permitId: newId });
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

// 5. UPDATE STATUS (With Strict Logic & Locking)
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

        // STRICT LOCKING: Only update data fields if status is 'Pending Review' (Requestor Edit Mode)
        // Otherwise, ignore changes to core fields (checkboxes etc) from Requestor.
        if (status === 'Pending Review' || status === 'New') {
            Object.assign(data, extras); // Allow edits
        } else if (role === 'Reviewer' || role === 'Approver') {
            // Reviewer/Approver can add their specific fields (Hazards, PPE, Color) but not change Requestor data
            if(extras.ForceBackgroundColor) data.ForceBackgroundColor = extras.ForceBackgroundColor;
            // Hazards/PPE are handled in frontend logic to only send if Reviewer
            Object.assign(data, extras); 
        }

        // --- CLOSURE WORKFLOW LOGIC ---
        if (role === 'Requester' && action === 'initiate_closure') {
            status = 'Closure Pending Review'; 
            data.Closure_Receiver_Sig = sig; // Signature of Receiver/Requestor
            data.Site_Restored_Check = "Yes"; 
            
            // Save Requestor's specific remarks and date
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
                
                // Save Reviewer's specific closure remarks and date
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
                
                // Save Approver's specific closure remarks and date
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

        let q = pool.request()
            .input('pid', sql.NVarChar, PermitID)
            .input('status', sql.NVarChar, status)
            .input('json', sql.NVarChar, JSON.stringify(data));
            
        if(extras.WorkType) {
             q.input('wt', sql.NVarChar, extras.WorkType)
              .query("UPDATE Permits SET Status = @status, FullDataJSON = @json, WorkType = @wt WHERE PermitID = @pid");
        } else {
             q.query("UPDATE Permits SET Status = @status, FullDataJSON = @json WHERE PermitID = @pid");
        }

        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 6. PERMIT DATA
app.post('/api/permit-data', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('pid', sql.NVarChar, req.body.permitId).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if (result.recordset.length === 0) return res.json({ error: "Not found" });
        const p = result.recordset[0];
        res.json({ ...JSON.parse(p.FullDataJSON), PermitID: p.PermitID, Status: p.Status, RenewalsJSON: p.RenewalsJSON, Latitude: p.Latitude, Longitude: p.Longitude });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 7. RENEWALS
app.post('/api/renewal', async (req, res) => {
    try {
        const { PermitID, userRole, userName, action, rejectionReason, ...data } = req.body;
        const pool = await getConnection();
        const current = await pool.request().input('pid', sql.NVarChar, PermitID).query("SELECT RenewalsJSON, Status, ValidFrom, ValidTo FROM Permits WHERE PermitID = @pid");
        
        let renewals = JSON.parse(current.recordset[0].RenewalsJSON || "[]");
        let status = current.recordset[0].Status;
        const permitStart = new Date(current.recordset[0].ValidFrom);
        const permitEnd = new Date(current.recordset[0].ValidTo);
        const now = getNowIST();

        if (userRole === 'Requester') {
             const reqStart = new Date(data.RenewalValidFrom);
             const reqEnd = new Date(data.RenewalValidTill);

             if (reqStart < permitStart || reqEnd > permitEnd) return res.status(400).json({ error: "Renewal must be within original Permit Validity." });
             if (reqStart >= reqEnd) return res.status(400).json({ error: "Invalid Time Range." });
             
             const duration = (reqEnd - reqStart) / (1000 * 60 * 60);
             if (duration > 8) return res.status(400).json({ error: "Renewal cannot exceed 8 Hours." });

             if (renewals.length > 0) {
                 const lastRen = renewals[renewals.length - 1];
                 const lastEnd = new Date(lastRen.valid_till);
                 if (reqStart < lastEnd && lastRen.status !== 'rejected') return res.status(400).json({ error: "Renewal must start after the previous renewal ends." });
             }

             renewals.push({ 
                 status: 'pending_review', 
                 valid_from: data.RenewalValidFrom, 
                 valid_till: data.RenewalValidTill, 
                 hc: data.RenewalHC, 
                 toxic: data.RenewalToxic, 
                 oxygen: data.RenewalOxygen, 
                 precautions: data.RenewalPrecautions, 
                 req_name: userName,
                 req_at: now
             });
             status = "Renewal Pending Review";
        } 
        else if (userRole === 'Reviewer') {
            const last = renewals[renewals.length - 1];
            if (action === 'reject') { 
                last.status = 'rejected'; 
                last.rev_name = userName; 
                last.rev_at = now; 
                last.rejection_reason = rejectionReason; // Store rejection reason
                status = 'Active'; 
            } else { 
                last.status = 'pending_approval'; 
                last.rev_name = userName; 
                last.rev_at = now;
                Object.assign(last, { 
                    valid_from: data.RenewalValidFrom, 
                    valid_till: data.RenewalValidTill, 
                    hc: data.RenewalHC, 
                    toxic: data.RenewalToxic, 
                    oxygen: data.RenewalOxygen, 
                    precautions: data.RenewalPrecautions 
                });
                status = "Renewal Pending Approval"; 
            }
        }
        else if (userRole === 'Approver') {
            const last = renewals[renewals.length - 1];
            if (action === 'reject') { 
                last.status = 'rejected'; 
                last.app_name = userName; 
                last.app_at = now; 
                last.rejection_reason = rejectionReason; // Store rejection reason
                status = 'Active'; 
            } else { 
                last.status = 'approved'; 
                last.app_name = userName; 
                last.app_at = now; 
                status = "Active"; 
            }
        }

        await pool.request().input('pid', sql.NVarChar, PermitID).input('status', sql.NVarChar, status).input('ren', sql.NVarChar, JSON.stringify(renewals))
            .query("UPDATE Permits SET Status = @status, RenewalsJSON = @ren WHERE PermitID = @pid");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 8. MAP DATA
app.post('/api/map-data', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status = 'Active' AND Latitude IS NOT NULL");
        const mapPoints = result.recordset.map(row => {
            const d = JSON.parse(row.FullDataJSON);
            return { PermitID: row.PermitID, lat: parseFloat(row.Latitude), lng: parseFloat(row.Longitude), WorkType: d.WorkType, Desc: d.Desc, RequesterName: d.RequesterName, ValidFrom: d.ValidFrom, ValidTo: d.ValidTo };
        });
        res.json(mapPoints);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 9. KML ENDPOINTS
app.get('/api/kml', async (req, res) => { if(!kmlContainerClient) return res.json([]); let b=[]; for await(const x of kmlContainerClient.listBlobsFlat()) b.push({name:x.name,url:kmlContainerClient.getBlockBlobClient(x.name).url}); res.json(b); });
app.post('/api/kml', upload.single('file'), async (req, res) => { if(!kmlContainerClient) return; const b = kmlContainerClient.getBlockBlobClient(`${Date.now()}-${req.file.originalname}`); await b.uploadData(req.file.buffer, {blobHTTPHeaders:{blobContentType:"application/vnd.google-earth.kml+xml"}}); res.json({success:true, url:b.url}); });
app.delete('/api/kml/:name', async (req, res) => { if(!kmlContainerClient) return; await kmlContainerClient.getBlockBlobClient(req.params.name).delete(); res.json({success:true}); });

// 10. STATISTICS API
app.post('/api/stats', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT Status, WorkType FROM Permits");
        const statusCounts = {};
        const typeCounts = {};
        result.recordset.forEach(r => { statusCounts[r.Status] = (statusCounts[r.Status] || 0) + 1; typeCounts[r.WorkType] = (typeCounts[r.WorkType] || 0) + 1; });
        res.json({ success: true, statusCounts, typeCounts });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 11. EXCEL DOWNLOAD
app.get('/api/download-excel', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC");
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Permits Summary');
        
        // Define Columns
        worksheet.columns = [
            { header: 'Permit ID', key: 'id', width: 15 }, 
            { header: 'Status', key: 'status', width: 20 }, 
            { header: 'Work Type', key: 'wt', width: 20 }, 
            { header: 'Requester', key: 'req', width: 25 }, 
            { header: 'Department', key: 'dept', width: 20 }, 
            { header: 'Vendor', key: 'vendor', width: 20 }, 
            { header: 'Description', key: 'desc', width: 40 }, 
            { header: 'Location', key: 'loc', width: 30 }, 
            { header: 'Valid From', key: 'vf', width: 20 }, 
            { header: 'Valid To', key: 'vt', width: 20 }
        ];

        // Header Styling
        worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
        worksheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4F46E5' } };
        
        result.recordset.forEach(r => { 
            const d = JSON.parse(r.FullDataJSON || "{}"); 
            worksheet.addRow({ 
                id: r.PermitID, 
                status: r.Status, 
                wt: d.WorkType, 
                req: d.RequesterName, 
                dept: d.IssuedToDept, 
                vendor: d.Vendor, 
                desc: d.Desc, 
                loc: d.ExactLocation, 
                vf: formatDate(r.ValidFrom), 
                vt: formatDate(r.ValidTo) 
            }); 
        });
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=Permit_Summary.xlsx');
        await workbook.xlsx.write(res);
        res.end();
    } catch (e) { res.status(500).send(e.message); }
});

// 12. PDF DOWNLOAD (Fully Updated with Closure Remarks Table & Rejection Reasons)
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('pid', sql.NVarChar, req.params.id).query("SELECT * FROM Permits WHERE PermitID = @pid");
        if(result.recordset.length === 0) return res.status(404).send('Not Found');
        
        const p = result.recordset[0];
        const d = JSON.parse(p.FullDataJSON);
        
        // FIX: bufferPages: true IS CRITICAL FOR WATERMARKS
        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`);
        doc.pipe(res);

        // Helper: Split Signature
        const splitSig = (sigStr) => {
            if (!sigStr) return { name: 'Pending', date: '' };
            const parts = sigStr.split(' on ');
            return { name: parts[0], date: parts[1] || '' };
        };

        // Helper: Draw Grid Table
        function drawTable(startY, rows, colsWidth) {
            let currentY = startY;
            doc.fontSize(8).font('Helvetica');
            rows.forEach((row, i) => {
                let currentX = 40;
                let maxCellHeight = 0;
                // Calculate max height
                row.forEach((cell, j) => {
                    const height = doc.heightOfString(cell, { width: colsWidth[j] - 10 });
                    if(height > maxCellHeight) maxCellHeight = height;
                });
                maxCellHeight += 10;
                // Draw cells
                row.forEach((cell, j) => {
                    doc.rect(currentX, currentY, colsWidth[j], maxCellHeight).stroke();
                    doc.text(cell, currentX + 5, currentY + 5, { width: colsWidth[j] - 10 });
                    currentX += colsWidth[j];
                });
                currentY += maxCellHeight;
                // Page break check
                if(currentY > 750) { doc.addPage(); currentY = 40; }
            });
            return currentY;
        }

        // --- PAGE 1 CONTENT ---
        doc.rect(40, 40, 515, 60).stroke();
        doc.font('Helvetica-Bold').fontSize(14).text('INDIAN OIL CORPORATION LIMITED', 40, 55, { align: 'center', width: 515 });
        doc.fontSize(10).text('Pipeline Division', 40, 75, { align: 'center', width: 515 });
        
        doc.moveDown(4);
        doc.fontSize(12).text('COMPOSITE WORK PERMIT', { align: 'center', underline:true });
        doc.moveDown();

        doc.fontSize(9).font('Helvetica');
        const startY = doc.y;
        doc.text(`Permit No: ${p.PermitID}`, 40, startY);
        doc.text(`Work Type: ${d.WorkType}`, 300, startY);
        doc.text(`Valid From: ${formatDate(p.ValidFrom)}`, 40, startY + 15);
        doc.text(`Valid To: ${formatDate(p.ValidTo)}`, 300, startY + 15);
        doc.text(`Location: ${d.ExactLocation} (${d.LocationUnit})`, 40, startY + 30);
        
        doc.moveDown(4);
        doc.font('Helvetica-Bold').text('OTHER PERMIT DETAILS');
        const otherRows = [
            [`Vendor: ${d.Vendor||'-'}`, `Issued To: ${d.IssuedToDept}`],
            [`Isolation Cert: ${d.RefIsolationCert||'-'}`, `Cross Ref: ${d.CrossRefPermits||'-'}`],
            [`JSA Ref: ${d.JsaRef||'-'}`, `MOC Ref: ${d.MocRef||'NA'}`],
            [`CCTV Avail: ${d.CctvAvailable}`, `CCTV Detail: ${d.CctvDetail||'-'}`]
        ];
        let y = drawTable(doc.y, otherRows, [257, 258]);
        doc.y = y + 10;
        
        doc.font('Helvetica-Bold').text('GENERAL CHECKLIST');
        const gpQs = [{id:"GP_Q1", t:"Equipment/Work Area Inspected"}, {id:"GP_Q2", t:"Surrounding Area Cleaned"}, {id:"GP_Q3", t:"Sewer Manhole Covered"}, {id:"GP_Q4", t:"Hazards Considered"}, {id:"GP_Q5", t:"Equipment Blinded", d:"GP_Q5_Detail"}, {id:"GP_Q6", t:"Drained & Depressurized"}, {id:"GP_Q7", t:"Steamed/Purged"}, {id:"GP_Q8", t:"Water Flushed"}, {id:"GP_Q9", t:"Fire Tender Access"}, {id:"GP_Q10", t:"Iron Sulfide Removed"}, {id:"GP_Q11", t:"Electrically Isolated", d:"GP_Q11_Detail"}, {id:"GP_Q12", t:"Gas Test (Toxic/HC/O2)"}, {id:"GP_Q13", t:"Fire Extinguisher"}, {id:"GP_Q14", t:"Area Cordoned Off"}];
        const gpRows = gpQs.map((q, i) => {
            let ans = d[q.id] === 'Yes' ? 'YES' : 'NA';
            if(q.id === "GP_Q12") ans = `Tox:${d.GP_Q12_ToxicGas||'-'} HC:${d.GP_Q12_HC||'-'} O2:${d.GP_Q12_Oxygen||'-'}`;
            let desc = q.d ? (d[q.d] || '') : '';
            return [`${i+1}`, q.t, ans, desc];
        });
        drawTable(doc.y, [['No', 'Question', 'Status', 'Remarks'], ...gpRows], [30, 250, 80, 155]);

        // --- PAGE 2 CONTENT ---
        doc.addPage();
        doc.font('Helvetica-Bold').fontSize(10).text('SPECIFIC WORK CHECKLIST');
        const spQs = [{id:"HW_Q1", t:"Ventilation/Lighting"}, {id:"HW_Q2", t:"Means of Exit"}, {id:"HW_Q3", t:"Standby Person"}, {id:"HW_Q4", t:"Trapped Oil/Gas Check"}, {id:"HW_Q5", t:"Shield Against Spark"}, {id:"HW_Q6", t:"Equipment Grounded"}, {id:"HW_Q16", t:"Height Permit Taken", d:"HW_Q16_Detail"}, {id:"VE_Q1", t:"Spark Arrestor (Veh)"}, {id:"EX_Q1", t:"Excavation Clear"}];
        const spRows = spQs.map((q, i) => {
            let ans = d[q.id] === 'Yes' ? 'YES' : 'NA';
            let desc = q.d ? (d[q.d] || '') : '';
            return [`${i+1}`, q.t, ans, desc];
        });
        y = drawTable(doc.y, [['No', 'Question', 'Status', 'Remarks'], ...spRows], [30, 250, 80, 155]);
        doc.y = y + 10;

        const hazards = ["H_H2S", "H_LackOxygen", "H_Corrosive", "H_ToxicGas", "H_Combustible", "H_Steam", "H_PyroIron", "H_N2Gas", "H_Height", "H_LooseEarth", "H_HighNoise", "H_Radiation", "H_Other"];
        let hList = hazards.filter(h => d[h] === 'Y').map(h => h.replace('H_','')).join(', ');
        if(d.H_Other === 'Y' && d.H_Other_Detail) hList += ` (Other: ${d.H_Other_Detail})`;

        const ppe = ["P_FaceShield", "P_FreshAirMask", "P_CompressedBA", "P_Goggles", "P_DustRespirator", "P_Earmuff", "P_LifeLine", "P_Apron", "P_SafetyHarness", "P_SafetyNet", "P_Airline"];
        let pList = ppe.filter(p => d[p] === 'Y').map(p => p.replace('P_','')).join(', ');

        doc.rect(40, doc.y, 515, 60).stroke();
        doc.text(`HAZARDS IDENTIFIED: ${hList || 'None'}`, 45, doc.y + 5, {width: 505});
        doc.text(`PPE REQUIRED: ${pList || 'Standard'}`, 45, doc.y + 30, {width: 505});
        doc.y += 70;

        // SIGNATURES - Split Names and Dates
        doc.font('Helvetica-Bold').text('DIGITAL SIGNATURES');
        const reqSig = { name: d.RequesterName, date: formatDate(p.ValidFrom) };
        const revSig = splitSig(d.Reviewer_Sig);
        const appSig = splitSig(d.Approver_Sig);
        
        const sigRows = [
            ['Role', 'Name', 'Date/Time'],
            ['Requester', reqSig.name, reqSig.date],
            ['Reviewer', revSig.name, revSig.date],
            ['Approver', appSig.name, appSig.date]
        ];
        drawTable(doc.y, sigRows, [100, 250, 165]);

        // --- PAGE 3 CONTENT ---
        doc.addPage();
        doc.font('Helvetica-Bold').text('CLEARANCE RENEWAL HISTORY');
        const rens = JSON.parse(p.RenewalsJSON || "[]");
        const renRows = rens.map(r => [
            `${formatDate(r.valid_from)}\n${formatDate(r.valid_till)}`,
            `HC:${r.hc} Tox:${r.toxic} O2:${r.oxygen}`,
            r.status.toUpperCase() + (r.status === 'rejected' ? `\n(Reason: ${r.rejection_reason || 'N/A'})` : ''), // Add Rejection Reason
            `Req: ${r.req_name} (${r.req_at})\nRev: ${r.rev_name||'-'} (${r.rev_at||''})\nApp: ${r.app_name||'-'} (${r.app_at||''})`
        ]);
        if(renRows.length > 0) drawTable(doc.y, [['Period', 'Readings', 'Status', 'Signatures'], ...renRows], [100, 100, 80, 235]);
        else doc.text("No renewals recorded.");
        
        doc.moveDown(2);
        doc.font('Helvetica-Bold').text('CLOSURE DETAILS');
        doc.fontSize(9).font('Helvetica');
        doc.text(`Site Cleared & Restored: ${d.Site_Restored_Check || 'No'}`); 
        doc.moveDown();
        
        // CLOSURE REMARKS TABLE (NEW ADDITION)
        const closureRows = [
            ['Role', 'Remarks', 'Date/Time'],
            ['Requestor', d.Closure_Requestor_Remarks || '-', d.Closure_Requestor_Date || '-'],
            ['Reviewer', d.Closure_Reviewer_Remarks || '-', d.Closure_Reviewer_Date || '-'],
            ['Approver', d.Closure_Approver_Remarks || '-', d.Closure_Approver_Date || '-']
        ];
        drawTable(doc.y, closureRows, [80, 300, 135]);

        // WATERMARK LOOP
        const wmText = p.Status.includes('Closed') ? 'CLOSED' : 'ACTIVE';
        const wmColor = p.Status.includes('Closed') ? '#ef4444' : '#22c55e';
        const range = doc.bufferedPageRange(); // Get total pages
        for (let i = 0; i < range.count; i++) {
            doc.switchToPage(i);
            doc.save();
            doc.rotate(-45, { origin: [300, 400] });
            doc.fontSize(80).fillColor(wmColor).opacity(0.15).text(wmText, 100, 350, { align: 'center', width: 400 });
            doc.restore();
        }

        doc.end();
    } catch (e) { res.status(500).send(e.message); }
});

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`✅ SYSTEM LIVE ON PORT ${PORT}`));
