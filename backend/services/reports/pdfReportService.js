const PDFDocument = require('pdfkit');

/**
 * Maps numeric score to letter grade
 * @param {number} score
 * @returns {string}
 */
const getGrade = (score) => {
  if (score === null || score === undefined) return 'N/A';
  if (score >= 90) return 'A (Secure)';
  if (score >= 75) return 'B (Good)';
  if (score >= 60) return 'C (Moderate Risk)';
  if (score >= 40) return 'D (High Risk)';
  return 'F (Critical Risk)';
};

/**
 * Builds a professional PDF security audit report stream
 * @param {object} scan - Scan document
 * @param {object} project - Project document
 * @param {Array<object>} vulnerabilities - Array of vulnerability documents
 * @param {NodeJS.WritableStream} res - Express response stream
 */
const generatePdfReport = (scan, project, vulnerabilities, res) => {
  const doc = new PDFDocument({
    margin: 50,
    size: 'A4',
    info: {
      Title: `AEGISOR Security Audit Report - ${project.name}`,
      Author: 'AEGISOR AI Security Platform',
      Subject: 'Security Audit & Vulnerability Assessment'
    }
  });

  doc.pipe(res);

  // 1. Header Banner
  doc
    .rect(0, 0, 595.28, 80)
    .fill('#0f172a'); // Dark navy

  doc
    .fillColor('#38bdf8') // Cyan
    .fontSize(24)
    .text('AEGISOR', 50, 22, { bold: true });

  doc
    .fillColor('#94a3b8')
    .fontSize(10)
    .text('Rule Out Every Vulnerability  |  AI-Powered Code Security Audit Report', 50, 50);

  doc.moveDown(4);

  // 2. Project & Audit Metadata
  doc
    .fillColor('#0f172a')
    .fontSize(16)
    .text(`Project Audit: ${project.name}`, { underline: true });

  doc.moveDown(0.5);

  const formattedDate = scan.scanCompletedAt
    ? new Date(scan.scanCompletedAt).toUTCString()
    : new Date().toUTCString();

  doc
    .fontSize(10)
    .fillColor('#334155')
    .text(`Scan ID: ${scan._id}`)
    .text(`Audit Date: ${formattedDate}`)
    .text(`Original Archive: ${project.originalFileName || 'Direct Upload'}`)
    .text(`Languages Detected: ${project.programmingLanguages.join(', ') || 'N/A'}`)
    .text(`Frameworks: ${project.frameworks.join(', ') || 'None identified'}`)
    .text(`Scanners Executed: ${scan.scannersRun.join(', ') || 'AEGISOR Core Scanner'}`);

  doc.moveDown(1.5);

  // 3. Security Scorecard Box
  const score = scan.securityScore !== null ? scan.securityScore : 'N/A';
  const grade = getGrade(scan.securityScore);

  doc
    .rect(50, doc.y, 495, 60)
    .fillAndStroke('#f8fafc', '#cbd5e1');

  const scoreY = doc.y + 12;
  doc
    .fillColor('#0f172a')
    .fontSize(12)
    .text('SECURITY POSTURE SCORE', 70, scoreY, { bold: true });

  doc
    .fontSize(22)
    .fillColor(score >= 75 ? '#16a34a' : score >= 50 ? '#ca8a04' : '#dc2626')
    .text(`${score} / 100`, 70, scoreY + 16, { bold: true });

  doc
    .fontSize(12)
    .fillColor('#475569')
    .text(`Grade: ${grade}`, 260, scoreY + 20);

  doc.moveDown(4);

  // 4. Severity Breakdown Summary Table
  doc
    .fillColor('#0f172a')
    .fontSize(14)
    .text('Vulnerability Severity Summary', { bold: true });

  doc.moveDown(0.5);

  const breakdown = scan.severityBreakdown || {};
  const breakdownData = [
    { label: 'Critical', count: breakdown.critical || 0, color: '#dc2626' },
    { label: 'High', count: breakdown.high || 0, color: '#ea580c' },
    { label: 'Medium', count: breakdown.medium || 0, color: '#ca8a04' },
    { label: 'Low', count: breakdown.low || 0, color: '#2563eb' },
    { label: 'Informational', count: breakdown.informational || 0, color: '#64748b' }
  ];

  let tableX = 50;
  for (const item of breakdownData) {
    doc
      .rect(tableX, doc.y, 90, 45)
      .fillAndStroke('#ffffff', '#e2e8f0');

    doc
      .fillColor(item.color)
      .fontSize(16)
      .text(`${item.count}`, tableX + 10, doc.y + 8, { width: 70, align: 'center', bold: true });

    doc
      .fillColor('#475569')
      .fontSize(9)
      .text(item.label, tableX + 10, doc.y + 28, { width: 70, align: 'center' });

    tableX += 100;
  }

  doc.moveDown(4.5);

  // 5. Executive / AI Summary if present
  if (scan.aiSummary) {
    doc
      .fillColor('#0f172a')
      .fontSize(14)
      .text('AI Executive Assessment', { bold: true });

    doc.moveDown(0.5);
    doc
      .fontSize(9.5)
      .fillColor('#334155')
      .text(scan.aiSummary, { lineGap: 3 });

    doc.moveDown(1.5);
  }

  // 6. Detailed Vulnerabilities List
  doc
    .fillColor('#0f172a')
    .fontSize(14)
    .text(`Discovered Vulnerabilities (${vulnerabilities.length})`, { bold: true });

  doc.moveDown(0.5);

  if (vulnerabilities.length === 0) {
    doc
      .fillColor('#16a34a')
      .fontSize(10)
      .text('No security vulnerabilities were detected in this audit. Code conforms to current security baseline.');
  } else {
    vulnerabilities.forEach((v, index) => {
      // Add page if close to bottom
      if (doc.y > 680) {
        doc.addPage();
      }

      const severityColor =
        v.severity === 'critical'
          ? '#dc2626'
          : v.severity === 'high'
          ? '#ea580c'
          : v.severity === 'medium'
          ? '#ca8a04'
          : '#2563eb';

      doc
        .fontSize(11)
        .fillColor(severityColor)
        .text(`${index + 1}. [${v.severity.toUpperCase()}] ${v.title}`, { bold: true });

      doc
        .fontSize(9)
        .fillColor('#64748b')
        .text(`Location: ${v.affectedFile}:${v.lineNumber || 1}  |  CWE: ${v.cwe || 'N/A'}  |  Engine: ${v.detectionSource}`);

      doc
        .fontSize(9.5)
        .fillColor('#1e293b')
        .text(`Description: ${v.description}`);

      if (v.recommendation) {
        doc
          .fontSize(9)
          .fillColor('#047857')
          .text(`Remediation: ${v.recommendation}`);
      }

      doc.moveDown(0.8);
    });
  }

  // Footer on all pages
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    doc
      .fontSize(8)
      .fillColor('#94a3b8')
      .text(
        `AEGISOR Security Platform  •  Confidential Audit Report  •  Page ${i + 1} of ${range.count}`,
        50,
        780,
        { align: 'center', width: 495 }
      );
  }

  doc.end();
};

module.exports = { generatePdfReport };

