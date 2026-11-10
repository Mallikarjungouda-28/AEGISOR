const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

// Security thresholds
const MAX_ENTRIES = 3000;
const MAX_EXTRACTED_SIZE = 150 * 1024 * 1024; // 150 MB
const MAX_COMPRESSION_RATIO = 100;

/**
 * Validate ZIP magic bytes (PK\x03\x04 or PK\x05\x06)
 * @param {string} filePath
 * @returns {boolean}
 */
const validateZipMagicBytes = (filePath) => {
  const fd = fs.openSync(filePath, 'r');
  const buffer = Buffer.alloc(4);
  fs.readSync(fd, buffer, 0, 4, 0);
  fs.closeSync(fd);

  // Standard ZIP header: 50 4B 03 04, Empty archive: 50 4B 05 06, Spanned: 50 4B 07 08
  return (
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    (buffer[2] === 0x03 || buffer[2] === 0x05 || buffer[2] === 0x07)
  );
};

/**
 * Safely extracts a ZIP archive preventing Zip Slip, Zip Bombs, and malicious entries
 * @param {string} zipFilePath - Temporary path of the uploaded zip
 * @param {string} targetDir - Destination directory
 * @returns {Promise<{ extractedCount: number, totalBytes: number }>}
 */
const safeExtractZip = async (zipFilePath, targetDir) => {
  // 1. Verify file signature
  if (!validateZipMagicBytes(zipFilePath)) {
    throw new Error('Security Error: Uploaded file is not a valid ZIP archive (corrupted or spoofed signature).');
  }

  let zip;
  try {
    zip = new AdmZip(zipFilePath);
  } catch (err) {
    throw new Error(`Failed to parse ZIP archive: ${err.message}`);
  }

  const entries = zip.getEntries();
  const zipStat = fs.statSync(zipFilePath);
  const zipSize = zipStat.size;

  // 2. Pre-extraction Zip Bomb checks
  if (entries.length > MAX_ENTRIES) {
    throw new Error(
      `Security Alert: Archive exceeds maximum allowed file count (${entries.length} > ${MAX_ENTRIES}).`
    );
  }

  let totalUncompressedSize = 0;
  for (const entry of entries) {
    totalUncompressedSize += entry.header.size;
  }

  if (totalUncompressedSize > MAX_EXTRACTED_SIZE) {
    throw new Error(
      `Security Alert: Uncompressed size exceeds maximum allowed limit (${Math.round(
        totalUncompressedSize / (1024 * 1024)
      )}MB > ${Math.round(MAX_EXTRACTED_SIZE / (1024 * 1024))}MB).`
    );
  }

  if (zipSize > 0 && totalUncompressedSize / zipSize > MAX_COMPRESSION_RATIO) {
    throw new Error(
      'Security Alert: Suspicious compression ratio detected (potential Zip Bomb attack).'
    );
  }

  // Ensure clean target directory
  if (fs.existsSync(targetDir)) {
    fs.rmSync(targetDir, { recursive: true, force: true });
  }
  fs.mkdirSync(targetDir, { recursive: true });

  const resolvedTarget = path.resolve(targetDir);
  let extractedCount = 0;

  // 3. Extract entry-by-entry with strict path validation (Zip Slip defense)
  for (const entry of entries) {
    const rawName = entry.entryName;

    // ZIP SLIP CHECK: Immediately detect path traversal sequences
    if (rawName.includes('..') || path.isAbsolute(rawName)) {
      throw new Error(
        `Security Alert: Path traversal attempt detected in ZIP entry: "${rawName}". Extraction halted.`
      );
    }

    // Filter unwanted OS metadata files
    if (
      rawName.includes('__MACOSX') ||
      rawName.endsWith('.DS_Store') ||
      rawName.endsWith('Thumbs.db')
    ) {
      continue;
    }

    // Resolve destination path
    const resolvedPath = path.resolve(resolvedTarget, rawName);

    // Strict boundary check: Destination MUST strictly reside inside targetDir
    if (!resolvedPath.startsWith(resolvedTarget + path.sep) && resolvedPath !== resolvedTarget) {
      throw new Error(
        `Security Alert: Path traversal attempt detected in ZIP entry: "${rawName}". Extraction halted.`
      );
    }

    if (entry.isDirectory) {
      if (!fs.existsSync(resolvedPath)) {
        fs.mkdirSync(resolvedPath, { recursive: true });
      }
    } else {
      // Ensure parent directory exists
      const parentDir = path.dirname(resolvedPath);
      if (!fs.existsSync(parentDir)) {
        fs.mkdirSync(parentDir, { recursive: true });
      }

      // Write content safely (never executable mode)
      fs.writeFileSync(resolvedPath, entry.getData(), { mode: 0o644 });
      extractedCount++;
    }
  }

  return {
    extractedCount,
    totalBytes: totalUncompressedSize
  };
};

module.exports = {
  validateZipMagicBytes,
  safeExtractZip
};
