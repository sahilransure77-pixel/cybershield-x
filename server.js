require("dotenv").config();

const path = require("path");
const fs = require("fs");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { rateLimit } = require("express-rate-limit");
const { analyzeUrl, normalizeHttpUrl } = require("./security");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const isProduction = process.env.NODE_ENV === "production";
if (!JWT_SECRET || JWT_SECRET.length < 32 || JWT_SECRET.includes("replace-this")) {
  console.error("Set JWT_SECRET to a unique random value of at least 32 characters in .env.");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "cybershield.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-7", legacyHeaders: false, message: { error: "Too many authentication attempts. Please try again later." } });
const toolLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false, message: { error: "Too many requests. Please try again later." } });
const tokenCookieOptions = { httpOnly: true, secure: isProduction, sameSite: "strict", path: "/", maxAge: 2 * 60 * 60 * 1000 };

function issueToken(user) {
  return jwt.sign({ sub: String(user.id), email: user.email }, JWT_SECRET, { expiresIn: "2h", issuer: "cybershield-x" });
}
function requireAuth(req, res, next) {
  const token = req.cookies?.csrf_auth;
  if (!token) return res.status(401).json({ error: "Please log in to continue." });
  try {
    req.auth = jwt.verify(token, JWT_SECRET, { issuer: "cybershield-x" });
    next();
  } catch {
    res.clearCookie("csrf_auth", { httpOnly: true, secure: isProduction, sameSite: "strict", path: "/" });
    return res.status(401).json({ error: "Your session has expired. Please log in again." });
  }
}
function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, createdAt: user.created_at };
}

app.post("/api/auth/register", authLimiter, async (req, res, next) => {
  try {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (name.length < 2 || name.length > 80) return res.status(400).json({ error: "Name must be between 2 and 80 characters." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: "Enter a valid email address." });
    if (password.length < 8 || Buffer.byteLength(password, "utf8") > 72) return res.status(400).json({ error: "Password must be at least 8 characters and no more than 72 bytes." });
    if (db.prepare("SELECT id FROM users WHERE email = ?").get(email)) return res.status(409).json({ error: "An account with that email already exists." });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)").run(name, email, passwordHash);
    const user = db.prepare("SELECT id, name, email, created_at FROM users WHERE id = ?").get(result.lastInsertRowid);
    res.cookie("csrf_auth", issueToken(user), tokenCookieOptions);
    return res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    if (error?.code === "SQLITE_CONSTRAINT_UNIQUE") return res.status(409).json({ error: "An account with that email already exists." });
    next(error);
  }
});
app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Invalid email or password." });
    res.cookie("csrf_auth", issueToken(user), tokenCookieOptions);
    return res.json({ user: publicUser(user) });
  } catch (error) { next(error); }
});
app.get("/api/auth/me", requireAuth, (req, res) => {
  const user = db.prepare("SELECT id, name, email, created_at FROM users WHERE id = ?").get(Number(req.auth.sub));
  if (!user) return res.status(401).json({ error: "Account not found. Please log in again." });
  res.json({ user: publicUser(user) });
});
app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie("csrf_auth", { httpOnly: true, secure: isProduction, sameSite: "strict", path: "/" });
  res.status(204).end();
});

app.post("/api/security/check-url", requireAuth, toolLimiter, (req, res) => {
  const normalized = normalizeHttpUrl(typeof req.body.url === "string" ? req.body.url.trim() : "");
  if (!normalized) return res.status(400).json({ error: "Enter a valid HTTP or HTTPS URL." });
  res.json(analyzeUrl(normalized));
});
app.post("/api/reports", requireAuth, toolLimiter, (req, res, next) => {
  try {
    const normalized = normalizeHttpUrl(typeof req.body.url === "string" ? req.body.url.trim() : "");
    const reason = typeof req.body.reason === "string" ? req.body.reason.trim() : "";
    if (!normalized) return res.status(400).json({ error: "Enter a valid HTTP or HTTPS URL." });
    if (reason.length < 5 || reason.length > 500) return res.status(400).json({ error: "Describe the concern in 5–500 characters." });
    const result = db.prepare("INSERT INTO reports (user_id, url, reason) VALUES (?, ?, ?)").run(Number(req.auth.sub), normalized, reason);
    res.status(201).json({ report: { id: result.lastInsertRowid, url: normalized, reason, message: "Report saved in this demo. It has not been sent to a security team." } });
  } catch (error) { next(error); }
});
app.get("/api/reports", requireAuth, (req, res, next) => {
  try {
    const reports = db.prepare("SELECT id, url, reason, created_at AS createdAt FROM reports WHERE user_id = ? ORDER BY id DESC LIMIT 20").all(Number(req.auth.sub));
    res.json({ reports });
  } catch (error) { next(error); }
});

app.use("/api", (_req, res) => res.status(404).json({ error: "API endpoint not found." }));
app.use(express.static(path.join(__dirname, "public")));
app.use((err, _req, res, _next) => {
  console.error("Request failed:", err.message);
  res.status(500).json({ error: "An unexpected server error occurred." });
});
app.listen(PORT, () => console.log(`CyberShield X is running at http://localhost:${PORT}`));
function shutdown() { db.close(); process.exit(0); }
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
