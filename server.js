require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cors = require("cors");
const {
  BlobServiceClient,
  BlobSASPermissions,
  generateBlobSASQueryParameters,
  StorageSharedKeyCredential,
  SASProtocol,
} = require("@azure/storage-blob");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));
const upload = multer({ storage: multer.memoryStorage() });

// Azure setup
const blobServiceClient = BlobServiceClient.fromConnectionString(process.env.AZURE_STORAGE_CONNECTION_STRING);
const containerClient = blobServiceClient.getContainerClient("files");
const sharedKeyCredential = new StorageSharedKeyCredential(
  process.env.AZURE_STORAGE_ACCOUNT_NAME,
  process.env.AZURE_STORAGE_ACCOUNT_KEY
);

// SQLite database
const db = new sqlite3.Database("./files.db");
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT UNIQUE, 
    password TEXT
)`);
db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    user_id INTEGER, 
    name TEXT, 
    size INTEGER, 
    url TEXT, 
    created_at TEXT, 
    public_key TEXT
)`);

// JWT authentication middleware
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "Токен відсутній" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || "SECRET");
    next();
  } catch {
    res.status(401).json({ error: "Невірний токен" });
  }
}

// User registration
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Введіть дані" });
  const hash = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], err => {
    if (err) return res.status(400).json({ error: "Ім'я вже зайняте" });
    res.json({ message: "OK" });
  });
});

// User login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(400).json({ error: "Невірні дані" });
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET || "SECRET",
      { expiresIn: "7d" }
    );
    res.json({ token });
  });
});

// File upload — magic happens here
app.post("/upload", auth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Файл не завантажено" });

  try {
    const blobName = `${req.user.id}/${Date.now()}-${req.file.originalname}`;
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);

    await blockBlobClient.uploadData(req.file.buffer, {
      blobHTTPHeaders: { blobContentType: req.file.mimetype || "application/octet-stream" }
    });

    const expiresOn = new Date();
    expiresOn.setFullYear(expiresOn.getFullYear() + 1);

    const sasToken = generateBlobSASQueryParameters({
      containerName: "files",
      blobName,
      permissions: BlobSASPermissions.parse("r"),
      protocol: SASProtocol.Https,
      startsOn: new Date(),
      expiresOn,
      contentDisposition: "inline" // ← Forces browser to open instead of download
    }, sharedKeyCredential).toString();

    const permanentUrl = `https://${process.env.AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/files/${blobName}?${sasToken}`;

    db.run(
      "INSERT INTO files (user_id, name, size, url, created_at, public_key) VALUES (?, ?, ?, ?, ?, ?)",
      [req.user.id, req.file.originalname, req.file.size, permanentUrl, new Date().toISOString(), uuidv4()],
      function (err) {
        if (err) return res.status(500).json({ error: "Помилка бази даних" });
        res.json({ message: "Завантажено" });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Помилка завантаження" });
  }
});

// Get file list
app.get("/files", auth, (req, res) => {
  db.all("SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC", [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Delete file
app.delete("/files/:id", auth, async (req, res) => {
  const id = req.params.id;
  db.get("SELECT url FROM files WHERE id = ? AND user_id = ?", [id, req.user.id], async (err, row) => {
    if (!row) return res.status(404).json({ error: "Файл не знайдено" });
    const blobName = row.url.split("/").slice(5).join("/").split("?")[0];
    await containerClient.getBlockBlobClient(blobName).deleteIfExists();
    db.run("DELETE FROM files WHERE id = ?", [id]);
    res.json({ message: "Видалено" });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущено: http://localhost:${PORT}`));
