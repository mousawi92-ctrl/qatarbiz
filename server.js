/* =========================================================================
   QatarBiz.com — production server
   Zero dependencies: pure Node.js (v18+). Run with:  node server.js
   Data lives in ./data (JSON database + uploaded documents).
   ========================================================================= */
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const FILES_DIR = path.join(DATA_DIR, "files");
const DB_PATH = path.join(DATA_DIR, "db.json");
const FLAT = !fs.existsSync(path.join(ROOT, "public"));
const PUBLIC_DIR = FLAT ? ROOT : path.join(ROOT, "public");
const MAX_BODY = 30 * 1024 * 1024; // 30 MB uploads
const SESSION_DAYS = 30;

/* ---------------- tiny JSON database ---------------- */
let db;
function loadDB() {
  fs.mkdirSync(FILES_DIR, { recursive: true });
  if (fs.existsSync(DB_PATH)) {
    db = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } else {
    db = { users: [], listings: [], inquiries: [], sessions: {}, counters: { cr: 1000, bz: 1000, inq: 1000 } };
  }
  db.users ||= []; db.listings ||= []; db.inquiries ||= [];
  db.sessions ||= {}; db.counters ||= { cr: 1000, bz: 1000, inq: 1000 };
}
let saveTimer = null;
function saveDB() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = DB_PATH + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(db, null, 1));
    fs.renameSync(tmp, DB_PATH);
  }, 50);
}
function saveDBNow() {
  const tmp = DB_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 1));
  fs.renameSync(tmp, DB_PATH);
}

/* ---------------- passwords & sessions ---------------- */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return salt + ":" + hash;
}
function checkPassword(pw, stored) {
  const [salt, hash] = String(stored).split(":");
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(pw, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(test, "hex"));
}
function newSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  db.sessions[token] = { userId, exp: Date.now() + SESSION_DAYS * 86400000 };
  saveDB();
  return token;
}
function getUser(req) {
  const cookie = req.headers.cookie || "";
  const m = cookie.match(/(?:^|;\s*)qb_session=([a-f0-9]{64})/);
  if (!m) return null;
  const s = db.sessions[m[1]];
  if (!s || s.exp < Date.now()) { if (s) { delete db.sessions[m[1]]; saveDB(); } return null; }
  return db.users.find((u) => u.id === s.userId) || null;
}
function sessionCookie(req, token, clear) {
  const secure = (req.headers["x-forwarded-proto"] === "https") ? "; Secure" : "";
  if (clear) return "qb_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" + secure;
  return "qb_session=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + SESSION_DAYS * 86400 + secure;
}

/* ---------------- helpers ---------------- */
function json(res, code, obj, headers) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, headers || {}));
  res.end(body);
}
function bad(res, code, msg) { json(res, code, { error: msg }); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error("Payload too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
function parseJSONBody(buf) { try { return JSON.parse(buf.toString("utf8") || "{}"); } catch (e) { return null; } }
const clean = (v, max = 500) => String(v == null ? "" : v).slice(0, max).trim();

/* naive per-IP rate limit for auth endpoints */
const hits = new Map();
function rateLimit(req, key, max, windowMs) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").split(",")[0].trim();
  const k = key + ":" + ip;
  const now = Date.now();
  const rec = hits.get(k) || { n: 0, t: now };
  if (now - rec.t > windowMs) { rec.n = 0; rec.t = now; }
  rec.n++;
  hits.set(k, rec);
  return rec.n <= max;
}

/* ---------------- multipart/form-data parser ---------------- */
function parseMultipart(buf, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || "");
  if (!m) return null;
  const boundary = Buffer.from("--" + (m[1] || m[2]));
  const fields = {}; const files = [];
  let start = buf.indexOf(boundary);
  while (start !== -1) {
    start += boundary.length;
    if (buf.slice(start, start + 2).toString() === "--") break; // closing
    if (buf.slice(start, start + 2).toString() === "\r\n") start += 2;
    const headEnd = buf.indexOf("\r\n\r\n", start);
    if (headEnd === -1) break;
    const head = buf.slice(start, headEnd).toString("utf8");
    const next = buf.indexOf(boundary, headEnd + 4);
    if (next === -1) break;
    let body = buf.slice(headEnd + 4, next);
    if (body.slice(-2).toString() === "\r\n") body = body.slice(0, -2);
    const nameM = /name="([^"]*)"/i.exec(head);
    const fileM = /filename="([^"]*)"/i.exec(head);
    const name = nameM ? nameM[1] : "";
    if (fileM && fileM[1]) {
      files.push({ field: name, filename: fileM[1], data: body });
    } else {
      fields[name] = body.toString("utf8");
    }
    start = next;
  }
  return { fields, files };
}

/* ---------------- listings ---------------- */
const PUBLIC_FIELDS = ["id", "type", "title", "category", "location", "established", "price", "negotiable",
  "expiry", "legalForm", "permit", "estCard", "staff", "rentMonthly", "leaseExpiry", "revenueRange",
  "badges", "activities", "extraLicenses", "desc", "brokerNote", "immediate", "status", "createdAt"];
function publicView(l) {
  const o = {};
  for (const k of PUBLIC_FIELDS) if (l[k] !== undefined) o[k] = l[k];
  o.badges ||= []; o.activities ||= []; o.extraLicenses ||= [];
  o.photos = (l.files || []).filter((f) => /^Business photo/i.test(f.label))
    .map((f) => "/api/photos/" + l.id + "/" + encodeURIComponent(f.stored));
  return o;
}
function nextRef(type) {
  const key = type === "bz" ? "bz" : "cr";
  db.counters[key] = (db.counters[key] || 1000) + 1;
  return "QB-" + key.toUpperCase() + "-" + db.counters[key];
}
const PRIVATE_KEYS_HINT = [/name/i, /qatar id/i, /phone|mobile|جوال/i, /email|بريد/i, /address|عنوان/i, /cr number|رقم السجل/i, /company|شركة/i];
function splitPrivate(answers) {
  const priv = {}, rest = {};
  for (const [k, v] of Object.entries(answers || {})) {
    if (PRIVATE_KEYS_HINT.some((r) => r.test(k))) priv[k] = v; else rest[k] = v;
  }
  return { priv, rest };
}

/* ---------------- static files ---------------- */
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".png": "image/png",
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".pdf": "application/pdf",
  ".woff2": "font/woff2", ".json": "application/json", ".webmanifest": "application/manifest+json" };
function serveStatic(req, res, urlPath) {
  if (FLAT) urlPath = "/index.html"; // flat layout: only the site itself is ever served
  let p = path.normalize(path.join(PUBLIC_DIR, urlPath));
  if (!p.startsWith(PUBLIC_DIR)) return bad(res, 403, "Forbidden");
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) p = path.join(PUBLIC_DIR, "index.html");
  const ext = path.extname(p).toLowerCase();
  res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream", "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600" });
  fs.createReadStream(p).pipe(res);
}

/* ---------------- router ---------------- */
async function handle(req, res) {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;

  if (!p.startsWith("/api/")) {
    if (req.method !== "GET" && req.method !== "HEAD") return bad(res, 405, "Method not allowed");
    return serveStatic(req, res, p === "/" ? "/index.html" : p);
  }

  const user = getUser(req);
  const isAdmin = user && user.role === "admin";

  /* ---------- auth ---------- */
  if (p === "/api/register" && req.method === "POST") {
    if (!rateLimit(req, "reg", 20, 3600000)) return bad(res, 429, "Too many attempts. Try later.");
    const b = parseJSONBody(await readBody(req));
    if (!b) return bad(res, 400, "Invalid request");
    const email = clean(b.email, 160).toLowerCase();
    const password = String(b.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return bad(res, 400, "Please enter a valid email address.");
    if (password.length < 8) return bad(res, 400, "Password must be at least 8 characters.");
    if (db.users.find((u) => u.email === email)) return bad(res, 409, "An account with this email already exists.");
    const rawPhone = clean(b.phone, 40).replace(/[^0-9]/g, "");
    const qatarPhone = rawPhone.replace(/^00974/, "").replace(/^974/, "");
    if (!/^[3567][0-9]{7}$/.test(qatarPhone)) return bad(res, 400, "Please enter a valid Qatari mobile number (+974).");
    const u = { id: crypto.randomUUID(), email, pass: hashPassword(password),
      name: clean(b.name, 120), phone: "+974 " + qatarPhone,
      role: b.role === "buyer" ? "buyer" : "seller", createdAt: new Date().toISOString() };
    db.users.push(u); saveDBNow();
    const token = newSession(u.id);
    return json(res, 200, { user: { email: u.email, name: u.name, role: u.role } }, { "Set-Cookie": sessionCookie(req, token) });
  }

  if (p === "/api/login" && req.method === "POST") {
    if (!rateLimit(req, "login", 30, 900000)) return bad(res, 429, "Too many attempts. Try again in 15 minutes.");
    const b = parseJSONBody(await readBody(req));
    if (!b) return bad(res, 400, "Invalid request");
    const email = clean(b.email, 160).toLowerCase();
    const u = db.users.find((x) => x.email === email);
    if (!u || !checkPassword(String(b.password || ""), u.pass)) return bad(res, 401, "Incorrect email or password.");
    const token = newSession(u.id);
    return json(res, 200, { user: { email: u.email, name: u.name, role: u.role } }, { "Set-Cookie": sessionCookie(req, token) });
  }

  if (p === "/api/logout" && req.method === "POST") {
    const cookie = req.headers.cookie || "";
    const m = cookie.match(/qb_session=([a-f0-9]{64})/);
    if (m) { delete db.sessions[m[1]]; saveDB(); }
    return json(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", true) });
  }

  if (p === "/api/me" && req.method === "GET") {
    if (!user) return bad(res, 401, "Not signed in");
    return json(res, 200, { user: { email: user.email, name: user.name, role: user.role } });
  }

  if (p === "/api/me/password" && req.method === "PATCH") {
    if (!user) return bad(res, 401, "Not signed in");
    const b = parseJSONBody(await readBody(req));
    if (!b || !checkPassword(String(b.current || ""), user.pass)) return bad(res, 401, "Current password is incorrect.");
    if (String(b.next || "").length < 8) return bad(res, 400, "New password must be at least 8 characters.");
    user.pass = hashPassword(String(b.next)); saveDBNow();
    return json(res, 200, { ok: true });
  }

  /* ---------- public listings ---------- */
  if (p === "/api/listings" && req.method === "GET") {
    const items = db.listings.filter((l) => l.status === "Published")
      .sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""))
      .map(publicView);
    return json(res, 200, { listings: items });
  }

  const mList = p.match(/^\/api\/listings\/([A-Za-z0-9-]+)$/);
  if (mList && req.method === "GET") {
    const l = db.listings.find((x) => x.id === mList[1]);
    if (!l || l.status !== "Published") return bad(res, 404, "Listing not found");
    return json(res, 200, { listing: publicView(l) });
  }


  /* ---------- automatic CR reading (Claude API) ---------- */
  if (p === "/api/extract" && req.method === "POST") {
    if (!rateLimit(req, "extract", 30, 3600000)) return bad(res, 429, "Too many attempts. Try later.");
    const buf = await readBody(req);
    const mp = parseMultipart(buf, req.headers["content-type"]);
    const f = mp && mp.files && mp.files[0];
    if (!f) return bad(res, 400, "No file received");
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return json(res, 200, { manual: true });
    try {
      const isPdf = /\.pdf$/i.test(f.filename);
      const media = isPdf ? "application/pdf" : (/\.png$/i.test(f.filename) ? "image/png" : "image/jpeg");
      const source = { type: "base64", media_type: media, data: f.data.toString("base64") };
      const block = isPdf ? { type: "document", source } : { type: "image", source };
      const prompt = "This is a Qatari Commercial Registration (السجل التجاري) document, in Arabic and/or English. Extract these fields and respond with ONLY a JSON object, no other text, no markdown fences: {\"businessName\": legal business name, \"crNumber\": CR number, \"legalForm\": legal form (e.g. W.L.L.), \"establishmentDate\": establishment/registration date, \"expiryDate\": expiry date, \"activities\": array of registered business activities in English}. Use empty string or [] for anything not found.";
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-sonnet-4-6", max_tokens: 1000, messages: [{ role: "user", content: [block, { type: "text", text: prompt }] }] }),
      });
      const d = await r.json();
      const text = (d.content || []).map((c) => c.text || "").join("");
      const jsonText = text.replace(/```json|```/g, "").trim();
      const m = jsonText.match(/\{[\s\S]*\}/);
      const fields = m ? JSON.parse(m[0]) : null;
      if (!fields) return json(res, 200, { manual: true });
      return json(res, 200, { fields: {
        businessName: clean(fields.businessName, 200), crNumber: clean(fields.crNumber, 60),
        legalForm: clean(fields.legalForm, 100), establishmentDate: clean(fields.establishmentDate, 60),
        expiryDate: clean(fields.expiryDate, 60),
        activities: Array.isArray(fields.activities) ? fields.activities.map((a) => clean(a, 120)).slice(0, 15) : [],
      } });
    } catch (e) { console.error("extract failed:", e.message); return json(res, 200, { manual: true }); }
  }


  const mPhoto = p.match(/^\/api\/photos\/([A-Za-z0-9-]+)\/(.+)$/);
  if (mPhoto && req.method === "GET") {
    const l = db.listings.find((x) => x.id === mPhoto[1]);
    if (!l || l.status !== "Published") return bad(res, 404, "Not found");
    const stored = decodeURIComponent(mPhoto[2]).replace(/[^A-Za-z0-9._-]/g, "_");
    const isPhoto = (l.files || []).some((f) => f.stored === stored && /^Business photo/i.test(f.label));
    if (!isPhoto) return bad(res, 404, "Not found");
    const fp = path.normalize(path.join(FILES_DIR, l.id, stored));
    if (!fp.startsWith(FILES_DIR) || !fs.existsSync(fp)) return bad(res, 404, "Not found");
    const ext = path.extname(fp).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME[ext] || "image/jpeg", "Cache-Control": "public, max-age=86400" });
    return fs.createReadStream(fp).pipe(res);
  }

  /* ---------- seller submission (multipart) ---------- */
  if (p === "/api/listings" && req.method === "POST") {
    if (!rateLimit(req, "submit", 20, 3600000)) return bad(res, 429, "Too many submissions. Try later.");
    const buf = await readBody(req);
    const mp = parseMultipart(buf, req.headers["content-type"]);
    if (!mp) return bad(res, 400, "Invalid form data");
    const type = mp.fields.type === "bz" ? "bz" : "cr";
    let answers = {}; let structured = {};
    try { answers = JSON.parse(mp.fields.answers || "{}"); } catch (e) {}
    try { structured = JSON.parse(mp.fields.structured || "{}"); } catch (e) {}
    // sanitize
    const cleanAnswers = {};
    for (const [k, v] of Object.entries(answers)) cleanAnswers[clean(k, 160)] = clean(v, 2000);
    const { priv, rest } = splitPrivate(cleanAnswers);
    const id = nextRef(type);
    const dir = path.join(FILES_DIR, id);
    fs.mkdirSync(dir, { recursive: true });
    const files = [];
    for (const f of mp.files.slice(0, 15)) {
      const label = clean(f.field.replace(/^file::/, ""), 120) || "Document";
      const safe = f.filename.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120) || "file";
      const stored = crypto.randomBytes(6).toString("hex") + "-" + safe;
      fs.writeFileSync(path.join(dir, stored), f.data);
      files.push({ label, name: safe, stored, size: f.data.length });
    }
    const ex = (structured && structured.extracted) || {};
    const yearM = String(ex.establishmentDate || "").match(/(19|20)\d\d/);
    const priceEntry = Object.entries(rest).find(([k]) => /asking price|السعر المطلوب/i.test(k));
    const listing = {
      id, type, status: "Submitted", createdAt: new Date().toISOString(),
      sellerId: user ? user.id : null, sellerEmail: user ? user.email : (priv["Email address"] || priv["البريد الإلكتروني"] || null),
      answers: rest, private: priv, structured, files,
      title: (type === "cr" ? "Commercial Registration for Sale" : "Running Business for Sale"),
      established: yearM ? yearM[0] : "",
      expiry: clean(ex.expiryDate, 60),
      legalForm: clean(ex.legalForm, 100),
      activities: Array.isArray(ex.activities) ? ex.activities.map((a) => clean(a, 120)).slice(0, 15) : [],
      price: priceEntry ? (Number(String(priceEntry[1]).replace(/[^0-9.]/g, "")) || 0) : 0,
      negotiable: structured && structured.neg === "Yes",
      badges: ["Broker Managed"], extraLicenses: [],
    };
    if (ex.businessName) listing.private["Legal business name (extracted)"] = clean(ex.businessName, 200);
    if (ex.crNumber) listing.private["CR number (extracted)"] = clean(ex.crNumber, 60);
    db.listings.push(listing); saveDBNow();
    return json(res, 200, { ok: true, reference: id });
  }

  /* ---------- inquiries ---------- */
  if (p === "/api/inquiries" && req.method === "POST") {
    if (!rateLimit(req, "inq", 30, 3600000)) return bad(res, 429, "Too many inquiries. Try later.");
    const b = parseJSONBody(await readBody(req));
    if (!b) return bad(res, 400, "Invalid request");
    const listing = db.listings.find((x) => x.id === b.listingId && x.status === "Published");
    if (!listing) return bad(res, 404, "Listing not found");
    const fields = {};
    for (const [k, v] of Object.entries(b.fields || {})) fields[clean(k, 160)] = clean(v, 2000);
    db.counters.inq = (db.counters.inq || 1000) + 1;
    const q = { id: "INQ-" + db.counters.inq, listingId: listing.id, intent: clean(b.intent, 40) || "info",
      fields, status: "New", note: "", buyerId: user ? user.id : null,
      buyerEmail: user ? user.email : (fields["Email address"] || fields["البريد الإلكتروني"] || fields["you@email.com"] || null),
      createdAt: new Date().toISOString() };
    db.inquiries.push(q); saveDBNow();
    return json(res, 200, { ok: true, id: q.id });
  }

  /* ---------- my data ---------- */
  if (p === "/api/my/listings" && req.method === "GET") {
    if (!user) return bad(res, 401, "Not signed in");
    const items = db.listings
      .filter((l) => l.sellerId === user.id || (l.sellerEmail && l.sellerEmail.toLowerCase() === user.email))
      .map((l) => ({ id: l.id, type: l.type, title: l.title || "", status: l.status, createdAt: l.createdAt }));
    return json(res, 200, { listings: items });
  }
  if (p === "/api/my/inquiries" && req.method === "GET") {
    if (!user) return bad(res, 401, "Not signed in");
    const items = db.inquiries
      .filter((q) => q.buyerId === user.id || (q.buyerEmail && q.buyerEmail.toLowerCase() === user.email))
      .map((q) => ({ id: q.id, listingId: q.listingId, intent: q.intent, status: q.status, createdAt: q.createdAt }));
    return json(res, 200, { inquiries: items });
  }

  /* ---------- admin ---------- */
  if (p.startsWith("/api/admin/")) {
    if (!isAdmin) return bad(res, 403, "Admin access required");

    if (p === "/api/admin/overview" && req.method === "GET") {
      const listings = db.listings.slice().sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
      const inquiries = db.inquiries.slice().sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
      const stats = {
        total: listings.length,
        published: listings.filter((l) => l.status === "Published").length,
        pending: listings.filter((l) => ["Submitted", "Under Review", "Additional Information Required"].includes(l.status)).length,
        newInquiries: inquiries.filter((q) => q.status === "New").length,
      };
      return json(res, 200, { stats, listings, inquiries });
    }

    const mAdm = p.match(/^\/api\/admin\/listings\/([A-Za-z0-9-]+)$/);
    if (mAdm && req.method === "PATCH") {
      const l = db.listings.find((x) => x.id === mAdm[1]);
      if (!l) return bad(res, 404, "Listing not found");
      const b = parseJSONBody(await readBody(req));
      if (!b) return bad(res, 400, "Invalid request");
      const EDITABLE = ["title", "category", "location", "established", "price", "negotiable", "expiry", "legalForm",
        "permit", "estCard", "staff", "rentMonthly", "leaseExpiry", "revenueRange", "badges", "activities",
        "extraLicenses", "desc", "brokerNote", "immediate", "status"];
      for (const k of EDITABLE) if (b[k] !== undefined) {
        if (["badges", "activities", "extraLicenses"].includes(k)) l[k] = Array.isArray(b[k]) ? b[k].map((x) => clean(x, 120)).slice(0, 20) : [];
        else if (k === "price") l[k] = Number(b[k]) || 0;
        else if (k === "negotiable" || k === "immediate") l[k] = !!b[k];
        else if (k === "status") { if (typeof b[k] === "string" && b[k].length < 60) l[k] = b[k]; }
        else l[k] = clean(b[k], k === "desc" || k === "brokerNote" ? 3000 : 300);
      }
      saveDBNow();
      return json(res, 200, { ok: true, listing: l });
    }

    if (p === "/api/admin/listings" && req.method === "POST") {
      const b = parseJSONBody(await readBody(req));
      if (!b) return bad(res, 400, "Invalid request");
      const type = b.type === "bz" ? "bz" : "cr";
      const id = nextRef(type);
      const l = { id, type, status: ["Published", "Approved"].includes(b.status) ? b.status : "Approved",
        createdAt: new Date().toISOString(), sellerId: null, sellerEmail: null,
        answers: {}, private: {}, structured: {}, files: [],
        title: clean(b.title, 200), category: clean(b.category, 120), location: clean(b.location, 120),
        established: clean(b.established, 12), price: Number(b.price) || 0, negotiable: b.negotiable !== false,
        desc: clean(b.desc, 3000), revenueRange: clean(b.revenueRange, 120),
        badges: Array.isArray(b.badges) ? b.badges.map((x) => clean(x, 120)).slice(0, 20) : [],
        activities: Array.isArray(b.activities) ? b.activities.map((x) => clean(x, 120)).slice(0, 20) : [],
        extraLicenses: [] };
      db.listings.push(l); saveDBNow();
      return json(res, 200, { ok: true, reference: id });
    }

    const mInq = p.match(/^\/api\/admin\/inquiries\/([A-Za-z0-9-]+)$/);
    if (mInq && req.method === "PATCH") {
      const q = db.inquiries.find((x) => x.id === mInq[1]);
      if (!q) return bad(res, 404, "Inquiry not found");
      const b = parseJSONBody(await readBody(req));
      if (!b) return bad(res, 400, "Invalid request");
      if (typeof b.status === "string" && b.status.length < 60) q.status = b.status;
      if (b.note !== undefined) q.note = clean(b.note, 2000);
      saveDBNow();
      return json(res, 200, { ok: true });
    }

    const mFile = p.match(/^\/api\/admin\/files\/([A-Za-z0-9-]+)\/(.+)$/);
    if (mFile && req.method === "GET") {
      const stored = decodeURIComponent(mFile[2]).replace(/[^A-Za-z0-9._-]/g, "_");
      const fp = path.normalize(path.join(FILES_DIR, mFile[1], stored));
      if (!fp.startsWith(FILES_DIR) || !fs.existsSync(fp)) return bad(res, 404, "File not found");
      const ext = path.extname(fp).toLowerCase();
      res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream", "Content-Disposition": "inline; filename=\"" + stored + "\"" });
      return fs.createReadStream(fp).pipe(res);
    }
  }

  return bad(res, 404, "Not found");
}

/* ---------------- boot ---------------- */
loadDB();
{
  const envPw = process.env.ADMIN_PASSWORD;
  const adminU = db.users.find((u) => u.role === "admin");
  if (adminU && envPw && !checkPassword(envPw, adminU.pass)) {
    adminU.pass = hashPassword(envPw);
    saveDBNow();
    console.log("Admin password synced from ADMIN_PASSWORD environment variable.");
  }
}
if (!db.users.some((u) => u.role === "admin")) {
  const pw = process.env.ADMIN_PASSWORD || "QatarBiz-" + crypto.randomBytes(4).toString("hex");
  db.users.push({ id: crypto.randomUUID(), email: "admin@qatarbiz.com", pass: hashPassword(pw),
    name: "QatarBiz Admin", phone: "", role: "admin", createdAt: new Date().toISOString() });
  saveDBNow();
  console.log("==========================================================");
  console.log("  Admin account created:");
  console.log("  Email:    admin@qatarbiz.com");
  console.log("  Password: " + pw);
  console.log("  (change it from Admin → Settings after first sign-in)");
  console.log("==========================================================");
}

http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    console.error(e);
    if (!res.headersSent) bad(res, 500, "Server error");
  });
}).listen(PORT, () => console.log("QatarBiz running on http://localhost:" + PORT));
