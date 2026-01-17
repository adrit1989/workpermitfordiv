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

// --- AZURE STORAGE SETUP ---
const AZURE_CONN_STR = process.env.AZURE_STORAGE_CONNECTION_STRING;
let containerClient;
if (AZURE_CONN_STR) {
    try {
        const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN_STR);
        containerClient = blobServiceClient.getContainerClient("permit-attachments");
        (async () => { try { await containerClient.createIfNotExists(); } catch (e) { console.log("Container info:", e.message); } })();
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

function getOrdinal(n) {
    const s = ["th", "st", "nd", "rd"];
    const v = n % 100;
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
    } catch (error) {
        console.error("Azure Upload Error:", error);
        return null;
    }
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

// --- CORE PDF GENERATOR (Refactored to support both Active & Closed) ---
async function drawPermitPDF(doc, p, d, renewalsList) {
    // Helper: Draw Header
    const bgColor = d.PdfBgColor || 'White';
    const compositePermitNo = `${d.IssuedToDept || 'DEPT'}/${p.PermitID}`;

    const drawWatermark = () => {
        if (p.Status === 'Closed') {
            doc.save();
            doc.rotate(-45, { origin: [297.5, 421] }); // Center of A4
            doc.font('Helvetica-Bold').fontSize(80).fillColor('red').opacity(0.15);
            doc.text('CLOSED PERMIT', 0, 300, { align: 'center', width: 595 });
            doc.restore();
            doc.opacity(1);
        }
    };

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
        // Logo Box (Left)
        doc.rect(startX, startY, 80, 95).stroke();
        if (fs.existsSync('logo.png')) {
            try { doc.image('logo.png', startX, startY, { fit: [80, 95], align: 'center', valign: 'center' }); } catch (err) { }
        }

        doc.rect(startX + 80, startY, 320, 95).stroke();
        doc.font('Helvetica-Bold').fontSize(11).fillColor('black').text('INDIAN OIL CORPORATION LIMITED', startX + 80, startY + 15, { width: 320, align: 'center' });
        doc.fontSize(9).text('EASTERN REGION PIPELINES', startX + 80, startY + 30, { width: 320, align: 'center' });
        doc.text('HSE DEPT.', startX + 80, startY + 45, { width: 320, align: 'center' });
        doc.fontSize(8).text('COMPOSITE WORK/ COLD WORK/HOT WORK/ENTRY TO CONFINED SPACE/VEHICLE ENTRY / EXCAVATION WORK AT MAINLINE/RCP/SV', startX + 80, startY + 65, { width: 320, align: 'center' });

        // Right Box
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

    // Banner
    if (fs.existsSync('safety_banner.png')) {
        try {
            doc.image('safety_banner.png', 30, doc.y, { width: 535, height: 100 });
            doc.y += 110;
        } catch (err) { }
    }

    // GSR Acceptance
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

    const dateFrom = formatDate(p.ValidFrom);
    const dateTo = formatDate(p.ValidTo);
    doc.text(`(i) Work clearance from: ${dateFrom}    To    ${dateTo} (Valid for the shift unless renewed).`, 30, doc.y);
    doc.y += 15;

    doc.text(`(ii) Issued to (Dept/Section/Contractor): ${d.IssuedToDept || '-'} / ${d.Vendor || '-'}`, 30, doc.y);
    doc.y += 15;

    const coords = d.ExactLocation || 'No GPS Data';
    const locDetail = d.WorkLocationDetail || '-';
    doc.text(`(iii) Exact Location of work (Area/RCP/SV/Chainage): ${locDetail} [GPS: ${coords}]`, 30, doc.y);
    doc.y += 15;

    doc.text(`(iv) Description of work: ${d.Desc || '-'}`, 30, doc.y, { width: 535 });
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
            if (currentY + maxRowHeight > 750) {
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
    // PPE Update
    const ppeKeys = ["Helmet", "Safety Shoes", "Hand gloves", "Boiler suit", "Face Shield", "Apron", "Goggles", "Dust Respirator", "Fresh Air Mask", "Lifeline", "Safety Harness", "Airline", "Earmuff", "IFR"];
    const foundPPE = ppeKeys.filter(k => d[`P_${k.replace(/ /g, '')}`] === 'Y');
    if (d.AdditionalPrecautions && d.AdditionalPrecautions.trim() !== '') { foundPPE.push(`(Other: ${d.AdditionalPrecautions})`); }
    doc.text(`2.Following additional PPE to be used in addition to standards PPE: ${foundPPE.join(', ')}`, 35, doc.y + 25); doc.y += 70;

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

    // --- RENEWAL TABLE WITH PHOTO (UPDATED & WATERMARK READY) ---
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
    
    // Ensure we iterate the PASSED renewals list, not just what's in 'p'
    const finalRenewals = renewalsList || JSON.parse(p.RenewalsJSON || "[]");
    doc.font('Helvetica').fontSize(8);

    for (const r of finalRenewals) {
        const rowHeight = 60; 
        if (ry > 680) { doc.addPage(); drawHeaderOnAll(); doc.y = 135; ry = 135; }

        let startTxt = r.valid_from.replace('T', '\n');
        let endTxt = r.valid_till.replace('T', '\n');
        
        // FEATURE B: Mark Odd Hours
        if (r.odd_hour_req === true) {
            endTxt += "\n(Night Shift)";
            doc.font('Helvetica-Bold').fillColor('purple');
        }

        doc.rect(30, ry, 45, rowHeight).stroke().text(startTxt, 32, ry + 5, { width: 43 });
        doc.rect(75, ry, 45, rowHeight).stroke().text(endTxt, 77, ry + 5, { width: 43 });
        doc.fillColor('black').font('Helvetica'); // Reset

        doc.rect(120, ry, 55, rowHeight).stroke().text(`HC: ${r.hc}\nTox: ${r.toxic}\nO2: ${r.oxygen}\nPrec: ${r.precautions || '-'}`, 122, ry + 5, { width: 53 });

        const wList = r.worker_list ? r.worker_list.join(', ') : 'All';
        doc.rect(175, ry, 60, rowHeight).stroke().text(wList, 177, ry + 5, { width: 58 });

        // --- PHOTO COLUMN ---
        doc.rect(235, ry, 50, rowHeight).stroke();
        if (r.photoUrl && containerClient) {
            try {
                const blobName = r.photoUrl.split('/').pop();
                const blockBlobClient = containerClient.getBlockBlobClient(blobName);
                const downloadBlockBlobResponse = await blockBlobClient.download(0);
                const chunks = [];
                for await (const chunk of downloadBlockBlobResponse.readableStreamBody) {
                    chunks.push(chunk);
                }
                const imageBuffer = Buffer.concat(chunks);
                try {
                    doc.image(imageBuffer, 237, ry + 2, { fit: [46, rowHeight - 4], align: 'center', valign: 'center' });
                } catch (imgErr) { console.log("Img draw err", imgErr); }
            } catch (err) { console.log("Blob err", err); }
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
    if (p.Status === 'Closed' || p.Status.includes('Closure')) {
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

// --- API ROUTES ---

// Login
app.post('/api/login', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().input('r', sql.NVarChar, req.body.role).input('e', sql.NVarChar, req.body.name).input('p', sql.NVarChar, req.body.password).query('SELECT * FROM Users WHERE Role=@r AND Email=@e AND Password=@p');
        if (r.recordset.length) res.json({ success: true, user: { Name: r.recordset[0].Name, Email: r.recordset[0].Email, Role: r.recordset[0].Role } });
        else res.json({ success: false });
    } catch (e) { res.status(500).json({ error: e.message }) }
});

// Users
app.get('/api/users', async (req, res) => {
    try {
        const pool = await getConnection();
        const r = await pool.request().query('SELECT Name, Email, Role FROM Users');
        const mapU = u => ({ name: u.Name, email: u.Email, role: u.Role });
        res.json({
            Requesters: r.recordset.filter(u => u.Role === 'Requester').map(mapU),
            Reviewers: r.recordset.filter(u => u.Role === 'Reviewer').map(mapU),
            Approvers: r.recordset.filter(u => u.Role === 'Approver').map(mapU)
        });
    } catch (e) { res.status(500).json({ error: e.message }) }
});

app.post('/api/add-user', async (req, res) => {
    try {
        const pool = await getConnection();
        const check = await pool.request().input('e', req.body.email).query("SELECT * FROM Users WHERE Email=@e");
        if (check.recordset.length) return res.status(400).json({ error: "User Exists" });
        await pool.request().input('n', req.body.name).input('e', req.body.email).input('r', req.body.role).input('p', req.body.password).query("INSERT INTO Users (Name,Email,Role,Password) VALUES (@n,@e,@r,@p)");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }) }
});

// WORKER MANAGEMENT
app.post('/api/save-worker', async (req, res) => {
    try {
        const { WorkerID, Action, Role, Details, RequestorEmail, RequestorName, ApproverName } = req.body;
        const pool = await getConnection();
        if ((Action === 'create' || Action === 'edit_request') && Details && parseInt(Details.Age) < 18) return res.status(400).json({ error: "Worker must be 18+" });

        if (Action === 'create') {
            const idRes = await pool.request().query("SELECT TOP 1 WorkerID FROM Workers ORDER BY WorkerID DESC");
            const wid = `W-${parseInt(idRes.recordset.length > 0 ? idRes.recordset[0].WorkerID.split('-')[1] : 1000) + 1}`;
            const dataObj = { Current: {}, Pending: { ...Details, RequestorName: RequestorName } };

            await pool.request()
                .input('w', wid).input('s', 'Pending Review').input('r', RequestorEmail)
                .input('j', JSON.stringify(dataObj))
                .input('idt', sql.NVarChar, Details.IDType)
                .query("INSERT INTO Workers (WorkerID, Status, RequestorEmail, DataJSON, IDType) VALUES (@w, @s, @r, @j, @idt)");
            res.json({ success: true });
        }
        else if (Action === 'edit_request') {
            const cur = await pool.request().input('w', WorkerID).query("SELECT DataJSON FROM Workers WHERE WorkerID=@w");
            if (cur.recordset.length === 0) return res.status(404).json({ error: "Worker not found" });
            let dataObj = JSON.parse(cur.recordset[0].DataJSON);
            dataObj.Pending = { ...dataObj.Current, ...Details, RequestorName: RequestorName || dataObj.Current.RequestorName };

            await pool.request()
                .input('w', WorkerID).input('s', 'Edit Pending Review').input('j', JSON.stringify(dataObj))
                .input('idt', sql.NVarChar, Details.IDType)
                .query("UPDATE Workers SET Status=@s, DataJSON=@j, IDType=@idt WHERE WorkerID=@w");
            res.json({ success: true });
        }
        else if (Action === 'delete') {
            await pool.request().input('w', WorkerID).query("DELETE FROM Workers WHERE WorkerID=@w");
            res.json({ success: true });
        }
        else {
            const cur = await pool.request().input('w', WorkerID).query("SELECT Status, DataJSON FROM Workers WHERE WorkerID=@w");
            if (cur.recordset.length === 0) return res.status(404).json({ error: "Worker not found" });
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
            res.json({ success: true });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
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
        if (req.body.context === 'permit_dropdown') res.json(list.filter(w => w.Status === 'Approved'));
        else {
            if (req.body.role === 'Requester') res.json(list.filter(w => w.RequestorEmail === req.body.email || w.Status === 'Approved'));
            else res.json(list);
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// DASHBOARD
app.post('/api/dashboard', async (req, res) => {
    try {
        const { role, email } = req.body;
        const pool = await getConnection();
        // UPDATED: Include FinalPdfUrl
        const r = await pool.request().query("SELECT PermitID, Status, ValidFrom, ValidTo, RequesterEmail, ReviewerEmail, ApproverEmail, FullDataJSON, FinalPdfUrl FROM Permits");
        
        const p = r.recordset.map(x => {
            let baseData = {};
            // Handle Closed Permits where JSON is null
            if (x.FullDataJSON) {
                try { baseData = JSON.parse(x.FullDataJSON); } catch(e) {}
            }
            return { 
                ...baseData, 
                PermitID: x.PermitID, 
                Status: x.Status, 
                ValidFrom: x.ValidFrom,
                RequesterEmail: x.RequesterEmail,
                ReviewerEmail: x.ReviewerEmail,
                ApproverEmail: x.ApproverEmail,
                FinalPdfUrl: x.FinalPdfUrl // Send PDF link to frontend
            };
        });
        
        const f = p.filter(x => (role === 'Requester' ? x.RequesterEmail === email : true));
        res.json(f.sort((a, b) => b.PermitID.localeCompare(a.PermitID)));
    } catch (e) { res.status(500).json({ error: e.message }) }
});

// --- SAVE PERMIT ---
app.post('/api/save-permit', upload.any(), async (req, res) => {
    try {
        console.log("Received Permit Submit Request:", req.body.PermitID);

        // 1. Validate Dates
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

        // 2. ID Generation
        let pid = req.body.PermitID;
        if (!pid || pid === 'undefined' || pid === 'null' || pid === '') {
            const idRes = await pool.request().query("SELECT TOP 1 PermitID FROM Permits ORDER BY Id DESC");
            const lastId = idRes.recordset.length > 0 ? idRes.recordset[0].PermitID : 'WP-1000';
            const numPart = parseInt(lastId.split('-')[1] || 1000);
            pid = `WP-${numPart + 1}`;
        }

        // 3. Status Check
        const chk = await pool.request().input('p', sql.NVarChar, pid).query("SELECT Status FROM Permits WHERE PermitID=@p");
        if (chk.recordset.length > 0) {
            const status = chk.recordset[0].Status;
            if (status === 'Closed' || status.includes('Closed')) return res.status(400).json({ error: "Permit is CLOSED. Editing denied." });
        }

        // 4. Parse Workers
        let workers = req.body.SelectedWorkers;
        if (typeof workers === 'string') { try { workers = JSON.parse(workers); } catch (e) { workers = []; } }
        if (!Array.isArray(workers)) workers = [];

        // 5. Build Renewals Array (If requested)
        let renewalsArr = [];
        if (req.body.InitRen === 'Y') {
            // Upload 1st Renewal Image
            let photoUrl = null;
            const renImageFile = req.files ? req.files.find(f => f.fieldname === 'InitRenImage') : null;
            if (renImageFile) {
                const blobName = `${pid}-1stRenewal.jpg`;
                photoUrl = await uploadToAzure(renImageFile.buffer, blobName);
            }

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
                worker_list: workers.map(w => w.Name),
                photoUrl: photoUrl
            });
        }
        const renewalsJsonStr = JSON.stringify(renewalsArr);

        // 6. Data Assembly
        const data = { ...req.body, SelectedWorkers: workers, PermitID: pid, CreatedDate: getNowIST(), GSR_Accepted: req.body.GSR_Accepted || 'Y' };

        // 7. Clean Geo Data
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
            await q.query("UPDATE Permits SET FullDataJSON=@j, WorkType=@w, ValidFrom=@vf, ValidTo=@vt, Latitude=@lat, Longitude=@lng WHERE PermitID=@p");
        } else {
            await q.query("INSERT INTO Permits (PermitID, Status, WorkType, RequesterEmail, ReviewerEmail, ApproverEmail, ValidFrom, ValidTo, Latitude, Longitude, FullDataJSON, RenewalsJSON) VALUES (@p, @s, @w, @re, @rv, @ap, @vf, @vt, @lat, @lng, @j, @ren)");
        }

        console.log("Save Success:", pid);
        res.json({ success: true, permitId: pid });

    } catch (e) {
        console.error("SERVER SAVE ERROR:", e);
        res.status(500).json({ error: e.message, stack: e.stack });
    }
});

// --- UPDATE STATUS & ARCHIVE ---
app.post('/api/update-status', async (req, res) => {
    try {
        const { PermitID, action, role, user, comment, bgColor, IOCLSupervisors, FirstRenewalAction, RequireRenewalPhotos, ...extras } = req.body;
        const pool = await getConnection();
        const cur = await pool.request().input('p', PermitID).query("SELECT * FROM Permits WHERE PermitID=@p");
        if (cur.recordset.length === 0) return res.json({ error: "Not found" });

        let st = cur.recordset[0].Status;
        if (st === 'Closed') {
            return res.status(400).json({ error: "Permit is strictly CLOSED. No further actions allowed." });
        }

        let d = JSON.parse(cur.recordset[0].FullDataJSON);
        let renewals = JSON.parse(cur.recordset[0].RenewalsJSON || "[]");
        const now = getNowIST();

        // --- MERGE EXTRAS ---
        Object.assign(d, extras);
        if (bgColor) d.PdfBgColor = bgColor;
        if (IOCLSupervisors) d.IOCLSupervisors = IOCLSupervisors;
        if (req.body.Site_Restored_Check) d.Site_Restored_Check = req.body.Site_Restored_Check;

        // FEATURE C: Save Approver's Photo Preference
        if (role === 'Approver' && action === 'approve' && RequireRenewalPhotos) {
            d.RequireRenewalPhotos = RequireRenewalPhotos;
        }

        if (comment) {
            if (role === 'Reviewer') d.Reviewer_Remarks = comment;
            if (role === 'Approver') d.Approver_Remarks = comment;
        }
        if (req.body.Closure_Requestor_Remarks) d.Closure_Requestor_Remarks = req.body.Closure_Requestor_Remarks;
        if (req.body.Closure_Reviewer_Remarks) d.Closure_Reviewer_Remarks = req.body.Closure_Reviewer_Remarks;
        if (req.body.Closure_Approver_Remarks) d.Closure_Approver_Remarks = req.body.Closure_Approver_Remarks;

        // --- 1ST RENEWAL LOGIC ---
        if (renewals.length === 1 && FirstRenewalAction) {
            const ren = renewals[0];
            if (role === 'Reviewer' && action === 'review') {
                if (FirstRenewalAction === 'accept') {
                    ren.status = 'pending_approval';
                    ren.rev_name = user; ren.rev_at = now;
                } else if (FirstRenewalAction === 'reject') {
                    ren.status = 'rejected';
                    ren.rej_by = user; ren.rej_at = now; ren.rej_reason = "Rejected during 1st Review"; ren.rej_role = 'Reviewer';
                }
            }
            else if (role === 'Approver' && action === 'approve') {
                if (ren.status !== 'rejected') {
                    if (FirstRenewalAction === 'accept') {
                        ren.status = 'approved';
                        ren.app_name = user; ren.app_at = now;
                    } else if (FirstRenewalAction === 'reject') {
                        ren.status = 'rejected';
                        ren.rej_by = user; ren.rej_at = now; ren.rej_reason = "Rejected during 1st Approval"; ren.rej_role = 'Approver';
                    }
                }
            }
        }

        // --- MAIN PERMIT STATUS LOGIC ---
        let isFinalClosure = false;

        if (action === 'reject_closure') {
            st = 'Active';
        }
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
                // Add final closure timestamp to full data before archiving
                d.Closure_Approver_Sig = `${user} on ${now}`;
                isFinalClosure = true;
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
        else if (action === 'reject') {
            st = 'Rejected';
            if (renewals.length > 0) {
                const last = renewals[renewals.length - 1];
                if (last.status.includes('pending')) {
                    last.status = 'rejected';
                    last.rej_reason = "Parent Permit Rejected";
                }
            }
        }
        else if (role === 'Reviewer' && action === 'review') {
            st = 'Pending Approval';
            d.Reviewer_Sig = `${user} on ${now}`;
        }

        // --- ARCHIVAL LOGIC (Feature A) ---
        let finalPdfUrl = null;
        let finalJson = JSON.stringify(d);

        if (isFinalClosure) {
            // Generate PDF Buffer *before* deleting data
            // We pass status='Closed' explicitly so watermark draws
            const pdfRecord = { ...cur.recordset[0], Status: 'Closed', PermitID: PermitID, ValidFrom: cur.recordset[0].ValidFrom, ValidTo: cur.recordset[0].ValidTo };
            
            // Generate PDF in memory
            const pdfBuffer = await new Promise((resolve, reject) => {
                const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
                const buffers = [];
                doc.on('data', buffers.push.bind(buffers));
                doc.on('end', () => resolve(Buffer.concat(buffers)));
                doc.on('error', reject);
                
                // Pass current `d` and `renewals` which are fully updated
                drawPermitPDF(doc, pdfRecord, d, renewals);
                doc.end();
            });

            // Upload to Azure Blob
            const blobName = `closed-permits/${PermitID}_FINAL.pdf`;
            finalPdfUrl = await uploadToAzure(pdfBuffer, blobName, "application/pdf");

            // Prepare for deletion
            finalJson = null; 
        }

        // --- SQL UPDATE ---
        const q = pool.request()
            .input('p', PermitID)
            .input('s', st)
            .input('r', JSON.stringify(renewals));

        if (isFinalClosure) {
            // FIX: Wipe RenewalsJSON too
            await q.input('url', finalPdfUrl)
                   .query("UPDATE Permits SET Status=@s, FullDataJSON=NULL, RenewalsJSON=NULL, FinalPdfUrl=@url WHERE PermitID=@p");
        } else {
            await q.input('j', finalJson)
                   .query("UPDATE Permits SET Status=@s, FullDataJSON=@j, RenewalsJSON=@r WHERE PermitID=@p");
        }

        res.json({ success: true, archived: isFinalClosure });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// --- RENEWAL ROUTE ---
app.post('/api/renewal', upload.any(), async (req, res) => {
    try {
        const { PermitID, userRole, userName, action, rejectionReason, renewalWorkers, oddHourReq, ...data } = req.body;
        const pool = await getConnection();
        const cur = await pool.request().input('p', PermitID).query("SELECT RenewalsJSON, Status, ValidFrom, ValidTo FROM Permits WHERE PermitID=@p");
        if (cur.recordset[0].Status === 'Closed') return res.status(400).json({ error: "Permit is CLOSED. Renewals are disabled." });

        let r = JSON.parse(cur.recordset[0].RenewalsJSON || "[]");
        const now = getNowIST();

        if (userRole === 'Requester') {
            const rs = new Date(data.RenewalValidFrom); const re = new Date(data.RenewalValidTo);
            const pS = new Date(cur.recordset[0].ValidFrom); const pE = new Date(cur.recordset[0].ValidTo);

            if (re <= rs) return res.status(400).json({ error: "Renewal End time must be later than Start time" });
            if (rs < pS || re > pE) return res.status(400).json({ error: "Renewal must be within permit validity" });
            if ((re - rs) / 36e5 > 8) return res.status(400).json({ error: "Max 8 hours per clearance" });

            if (r.length > 0) {
                const last = r[r.length - 1];
                if (last.status !== 'rejected' && last.status !== 'approved') return res.status(400).json({ error: "Previous renewal pending" });
                if (last.status !== 'rejected' && rs < new Date(last.valid_till)) return res.status(400).json({ error: "Overlap detected" });
            }

            // --- PHOTO UPLOAD LOGIC ---
            let photoUrl = null;
            const renImageFile = req.files ? req.files.find(f => f.fieldname === 'RenewalImage') : null;
            if (renImageFile) {
                const renewalCount = r.length + 1;
                const ordinal = getOrdinal(renewalCount);
                const blobName = `${PermitID}-${ordinal}Renewal.jpg`;
                photoUrl = await uploadToAzure(renImageFile.buffer, blobName);
            }

            r.push({
                status: 'pending_review',
                valid_from: data.RenewalValidFrom,
                valid_till: data.RenewalValidTo,
                hc: data.hc, toxic: data.toxic, oxygen: data.oxygen, precautions: data.precautions,
                req_name: userName,
                req_at: now,
                worker_list: JSON.parse(renewalWorkers || "[]"),
                photoUrl: photoUrl,
                odd_hour_req: (oddHourReq === 'Y') // FEATURE B: Capture Odd Hour Flag
            });
        } else {
            const last = r[r.length - 1];
            if (action === 'reject') {
                last.status = 'rejected';
                last.rej_by = userName;
                last.rej_at = now;
                last.rej_reason = rejectionReason;
                last.rej_role = userRole;
            }
            else {
                last.status = userRole === 'Reviewer' ? 'pending_approval' : 'approved';
                if (userRole === 'Reviewer') { last.rev_name = userName; last.rev_at = now; last.rev_rem = rejectionReason; }
                if (userRole === 'Approver') { last.app_name = userName; last.app_at = now; last.app_rem = rejectionReason; }
            }
        }
        let newStatus = r[r.length - 1].status === 'approved' ? 'Active' : (r[r.length - 1].status === 'rejected' ? 'Active' : 'Renewal Pending ' + (userRole === 'Requester' ? 'Review' : 'Approval'));
        await pool.request().input('p', PermitID).input('r', JSON.stringify(r)).input('s', newStatus).query("UPDATE Permits SET RenewalsJSON=@r, Status=@s WHERE PermitID=@p");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/permit-data', async (req, res) => { 
    try { 
        const pool = await getConnection(); 
        const r = await pool.request().input('p', sql.NVarChar, req.body.permitId).query("SELECT * FROM Permits WHERE PermitID=@p"); 
        if (r.recordset.length) {
            // Feature A: Safety check for Closed permits (NULL JSON)
            const jsonStr = r.recordset[0].FullDataJSON;
            const data = jsonStr ? JSON.parse(jsonStr) : {};
            res.json({ 
                ...data, 
                Status: r.recordset[0].Status, 
                RenewalsJSON: r.recordset[0].RenewalsJSON, 
                // FEATURE C: Send photo requirement flag to frontend
                RequireRenewalPhotos: data.RequireRenewalPhotos || 'N',
                FullDataJSON: null // Don't send raw large string
            }); 
        } else res.json({ error: "404" }); 
    } catch (e) { res.status(500).json({ error: e.message }) } 
});

app.post('/api/map-data', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT PermitID, FullDataJSON, Latitude, Longitude FROM Permits WHERE Status='Active'"); res.json(r.recordset.map(x => ({ PermitID: x.PermitID, lat: parseFloat(x.Latitude), lng: parseFloat(x.Longitude), ...JSON.parse(x.FullDataJSON) }))); } catch (e) { res.status(500).json({ error: e.message }) } });
app.post('/api/stats', async (req, res) => { try { const pool = await getConnection(); const r = await pool.request().query("SELECT Status, WorkType FROM Permits"); const s = {}, t = {}; r.recordset.forEach(x => { s[x.Status] = (s[x.Status] || 0) + 1; t[x.WorkType] = (t[x.WorkType] || 0) + 1; }); res.json({ success: true, statusCounts: s, typeCounts: t }); } catch (e) { res.status(500).json({ error: e.message }) } });
app.get('/api/download-excel', async (req, res) => { 
    try { 
        const pool = await getConnection(); 
        const result = await pool.request().query("SELECT * FROM Permits ORDER BY Id DESC"); 
        const workbook = new ExcelJS.Workbook(); 
        const sheet = workbook.addWorksheet('Permits'); 
        sheet.columns = [{ header: 'Permit ID', key: 'id', width: 15 }, { header: 'Status', key: 'status', width: 20 }, { header: 'Work', key: 'wt', width: 25 }, { header: 'Requester', key: 'req', width: 25 }, { header: 'Location', key: 'loc', width: 30 }, { header: 'Vendor', key: 'ven', width: 20 }, { header: 'Valid From', key: 'vf', width: 20 }, { header: 'Valid To', key: 'vt', width: 20 }]; 
        sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 }; 
        sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFED7D31' } }; 
        result.recordset.forEach(r => { 
            const d = r.FullDataJSON ? JSON.parse(r.FullDataJSON) : {}; 
            sheet.addRow({ id: r.PermitID, status: r.Status, wt: d.WorkType||'-', req: d.RequesterName||'-', loc: d.ExactLocation||'-', ven: d.Vendor||'-', vf: formatDate(r.ValidFrom), vt: formatDate(r.ValidTo) }); 
        }); 
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'); 
        res.setHeader('Content-Disposition', 'attachment; filename=IndianOil_Permits.xlsx'); 
        await workbook.xlsx.write(res); res.end(); 
    } catch (e) { res.status(500).send(e.message); } 
});

// --- UPDATED PDF GENERATION ROUTE ---
app.get('/api/download-pdf/:id', async (req, res) => {
    try {
        const pool = await getConnection();
        const result = await pool.request().input('p', req.params.id).query("SELECT * FROM Permits WHERE PermitID = @p");
        if (!result.recordset.length) return res.status(404).send('Not Found');
        const p = result.recordset[0]; 
        const d = p.FullDataJSON ? JSON.parse(p.FullDataJSON) : {};
        // Retrieve renewals for standard download
        const renewals = p.RenewalsJSON ? JSON.parse(p.RenewalsJSON) : [];

        const doc = new PDFDocument({ margin: 30, size: 'A4', bufferPages: true });
        res.setHeader('Content-Type', 'application/pdf'); 
        res.setHeader('Content-Disposition', `attachment; filename=${p.PermitID}.pdf`);
        doc.pipe(res);

        // Pass renewal list explicitly
        await drawPermitPDF(doc, p, d, renewals);
        doc.end();

    } catch (e) {
        console.error(e);
        res.status(500).send(e.message);
    }
});

// START SERVER
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log('Server running on port ' + PORT));
