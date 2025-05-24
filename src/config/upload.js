// src/config/upload.js
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Cria pasta se não existir
const pastaUploads = path.resolve(__dirname, '..', '..', 'uploads');
if (!fs.existsSync(pastaUploads)) {
  fs.mkdirSync(pastaUploads, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, pastaUploads);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const fileName = `${Date.now()}-${file.fieldname}${ext}`;
    cb(null, fileName);
  }
});

const upload = multer({ storage });

module.exports = upload;
