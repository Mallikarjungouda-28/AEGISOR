const multer = require('multer');
const path = require('path');
const fs = require('fs');

const os = require('os');

// Ensure temporary upload directory exists (fallback to os.tmpdir in serverless environments)
const isServerless = Boolean(process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.LAMBDA_TASK_ROOT);
let tempUploadDir = isServerless
  ? path.join(os.tmpdir(), 'aegisor-uploads-temp')
  : path.join(__dirname, '../uploads/temp');

try {
  if (!fs.existsSync(tempUploadDir)) {
    fs.mkdirSync(tempUploadDir, { recursive: true });
  }
} catch (err) {
  // Read-only filesystem fallback
  tempUploadDir = path.join(os.tmpdir(), 'aegisor-uploads-temp');
  if (!fs.existsSync(tempUploadDir)) {
    fs.mkdirSync(tempUploadDir, { recursive: true });
  }
}

// Maximum upload size (default 50MB)
const MAX_UPLOAD_SIZE = parseInt(process.env.UPLOAD_MAX_SIZE, 10) || 50 * 1024 * 1024;

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, tempUploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `upload-${uniqueSuffix}.zip`);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedMimes = [
    'application/zip',
    'application/x-zip-compressed',
    'application/octet-stream',
    'multipart/x-zip'
  ];

  if (ext !== '.zip') {
    return cb(new Error('Invalid file type. Only ZIP archives (.zip) are allowed.'), false);
  }

  cb(null, true);
};

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_UPLOAD_SIZE,
    files: 1
  },
  fileFilter
});

// Middleware wrapper to catch Multer errors gracefully
const uploadZip = (fieldName = 'file') => {
  const multerUpload = upload.single(fieldName);

  return (req, res, next) => {
    multerUpload(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({
            status: 'fail',
            message: `File exceeds maximum allowed size limit of ${Math.round(MAX_UPLOAD_SIZE / (1024 * 1024))}MB`
          });
        }
        return res.status(400).json({
          status: 'fail',
          message: `Upload error: ${err.message}`
        });
      } else if (err) {
        return res.status(400).json({
          status: 'fail',
          message: err.message
        });
      }
      next();
    });
  };
};

module.exports = { uploadZip };

