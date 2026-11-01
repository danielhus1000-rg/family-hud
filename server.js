'use strict';

/**
 * Family HUD – خادم محادثة ومشاركة موقع عائلي محلي
 * Node.js + Express + Socket.io
 *
 * التشغيل:   npm install && npm start
 * متغيرات اختيارية:
 *   PORT         المنفذ (الافتراضي 3000)
 *   HOST         العنوان (الافتراضي 0.0.0.0 ليصل إليه أفراد العائلة على نفس الشبكة)
 *   FAMILY_CODE  رمز سري يُطلب عند إنشاء حساب جديد (موصى به)
 *   MAX_USERS    الحد الأقصى للحسابات (الافتراضي 50)
 */

const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const express = require('express');
const { Server } = require('socket.io');

/* ───────────── الإعدادات ───────────── */

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const FAMILY_CODE = (process.env.FAMILY_CODE || '').trim();
const MAX_USERS = Number(process.env.MAX_USERS) || 50;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 يومًا
const HISTORY_LIMIT = 100;                     // عدد الرسائل المرسلة عند الاتصال
const MAX_STORED_MESSAGES = 500;               // عدد الرسائل المحفوظة على القرص
const MAX_TEXT_LENGTH = 1000;
const MIN_PASSWORD = 6;
const MAX_PASSWORD = 100;
const SUFFIX = '@Dan';

/* ───────────── التخزين المحلي (JSON) ───────────── */

fs.mkdirSync(DATA_DIR, { recursive: true });

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(file, data) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, file);
}

function loadSecret() {
  try {
    const existing = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    if (existing.length >= 32) return existing;
  } catch { /* سيُنشأ سر جديد */ }
  const secret = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 });
  return secret;
}

const SECRET = loadSecret();
/** @type {Record<string, {name:string, salt:string, hash:string, createdAt:number}>} */
const users = readJson(USERS_FILE, {});
/** @type {{id:string, key:string, name:string, text:string, ts:number}[]} */
let messages = readJson(MESSAGES_FILE, []);
if (!Array.isArray(messages)) messages = [];

let saveTimer = null;
function scheduleMessagesSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    flushMessages();
  }, 400);
}
function flushMessages() {
  try {
    writeJsonAtomic(MESSAGES_FILE, messages);
  } catch (err) {
    console.error('تعذر حفظ الرسائل:', err.message);
  }
}

/* ───────────── المصادقة ───────────── */

const USERNAME_RE = /^([\p{L}\p{N}_.-]{2,20})@dan$/iu;

/** يتحقق من اسم المستخدم (يجب أن ينتهي بـ @Dan) ويعيد الصيغة القياسية. */
function parseUsername(raw) {
  if (typeof raw !== 'string') return null;
  const match = raw.trim().normalize('NFC').match(USERNAME_RE);
  if (!match) return null;
  const name = `${match[1]}${SUFFIX}`;
  return { name, key: name.toLowerCase() };
}

function scrypt(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derived) => (err ? reject(err) : resolve(derived)));
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await scrypt(password, salt);
  return { salt: salt.toString('hex'), hash: derived.toString('hex') };
}

const DUMMY_SALT = crypto.randomBytes(16);
async function verifyPassword(password, record) {
  // عند غياب المستخدم نُجري حسابًا وهميًا حتى لا يكشف زمن الاستجابة وجود الحساب
  const salt = record ? Buffer.from(record.salt, 'hex') : DUMMY_SALT;
  const derived = await scrypt(password, salt);
  if (!record) return false;
  const stored = Buffer.from(record.hash, 'hex');
  return stored.length === derived.length && crypto.timingSafeEqual(stored, derived);
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

function signToken(key) {
  const payload = Buffer.from(JSON.stringify({ u: key, exp: Date.now() + TOKEN_TTL_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

/** يعيد {key, name} أو null. */
function verifyToken(token) {
  if (typeof token !== 'string' || token.length > 600) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || typeof data.u !== 'string' || typeof data.exp !== 'number' || data.exp < Date.now()) return null;
    const record = users[data.u];
    return record ? { key: data.u, name: record.name } : null;
  } catch {
    return null;
  }
}

/** محدِّد معدل بسيط في الذاكرة. */
function createRateLimiter({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
  }, windowMs).unref();

  return (req, res, next) => {
    const now = Date.now();
    const id = req.ip || 'unknown';
    let entry = hits.get(id);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(id, entry);
    }
    entry.count += 1;
    if (entry.count > max) {
      res.set('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
      return res.status(429).json({ error: 'محاولات كثيرة. انتظر بضع دقائق ثم حاول مجددًا.' });
    }
    next();
  };
}

/* ───────────── Express ───────────── */

const app = express();
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(self), camera=(), microphone=()'
  });
  next();
});

app.use(express.json({ limit: '2kb' }));

const authLimiter = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 30 });

app.get('/api/config', (req, res) => {
  res.json({ requiresCode: Boolean(FAMILY_CODE), suffix: SUFFIX });
});

app.post('/api/signup', authLimiter, async (req, res) => {
  try {
    const { username, password, code } = req.body || {};
    const parsed = parseUsername(username);
    if (!parsed) {
      return res.status(400).json({
        error: `اسم المستخدم يجب أن يتكوّن من 2 إلى 20 حرفًا (حروف أو أرقام أو _ . -) وينتهي بـ ${SUFFIX}`
      });
    }
    if (typeof password !== 'string' || password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) {
      return res.status(400).json({ error: `كلمة المرور يجب أن تكون بين ${MIN_PASSWORD} و${MAX_PASSWORD} حرفًا.` });
    }
    if (FAMILY_CODE) {
      const ok = typeof code === 'string' && crypto.timingSafeEqual(sha256(code.trim()), sha256(FAMILY_CODE));
      if (!ok) return res.status(403).json({ error: 'رمز العائلة غير صحيح.' });
    }
    if (users[parsed.key]) return res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل. اختر اسمًا آخر.' });
    if (Object.keys(users).length >= MAX_USERS) {
      return res.status(403).json({ error: 'تم بلوغ الحد الأقصى لعدد الحسابات.' });
    }

    const { salt, hash } = await hashPassword(password);
    if (users[parsed.key]) return res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل. اختر اسمًا آخر.' });

    users[parsed.key] = { name: parsed.name, salt, hash, createdAt: Date.now() };
    writeJsonAtomic(USERS_FILE, users);
    res.status(201).json({ token: signToken(parsed.key), user: { key: parsed.key, name: parsed.name } });
  } catch (err) {
    console.error('signup:', err);
    res.status(500).json({ error: 'حدث خطأ في الخادم.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const parsed = parseUsername(username);
    const record = parsed ? users[parsed.key] : null;
    const valid = typeof password === 'string' && password.length <= MAX_PASSWORD
      ? await verifyPassword(password, record)
      : false;
    if (!parsed || !record || !valid) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
    }
    res.json({ token: signToken(parsed.key), user: { key: parsed.key, name: record.name } });
  } catch (err) {
    console.error('login:', err);
    res.status(500).json({ error: 'حدث خطأ في الخادم.' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.use('/api', (req, res) => res.status(404).json({ error: 'غير موجود.' }));

// معالج أخطاء عام (مثل JSON غير صالح)
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'طلب غير صالح.' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'الطلب كبير جدًا.' });
  console.error(err);
  res.status(500).json({ error: 'حدث خطأ في الخادم.' });
});

/* ───────────── Socket.io ───────────── */

const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 10 * 1024,
  pingInterval: 20000,
  pingTimeout: 20000
});

/** المتصلون حاليًا: key → {key, name, sockets:Set<string>} */
const online = new Map();
/** المواقع المشتركة حاليًا (في الذاكرة فقط ولا تُحفظ): key → {key, name, lat, lng, accuracy, ts} */
const locations = new Map();

const presenceList = () => [...online.values()].map(({ key, name }) => ({ key, name }));

function allow(bucket, limit, windowMs) {
  const now = Date.now();
  bucket.hits = bucket.hits.filter((t) => now - t < windowMs);
  if (bucket.hits.length >= limit) return false;
  bucket.hits.push(now);
  return true;
}

function cleanText(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '')
    .replace(/\n{4,}/g, '\n\n\n')
    .trim();
}

io.use((socket, next) => {
  const user = verifyToken(socket.handshake.auth && socket.handshake.auth.token);
  if (!user) return next(new Error('unauthorized'));
  socket.data.user = user;
  next();
});

io.on('connection', (socket) => {
  const { key, name } = socket.data.user;
  const chatBucket = { hits: [] };
  let lastLocationAt = 0;

  let entry = online.get(key);
  const isFirstConnection = !entry;
  if (!entry) {
    entry = { key, name, sockets: new Set() };
    online.set(key, entry);
  }
  entry.sockets.add(socket.id);

  socket.emit('init', {
    me: { key, name },
    now: Date.now(),
    history: messages.slice(-HISTORY_LIMIT),
    online: presenceList(),
    locations: [...locations.values()]
  });
  if (isFirstConnection) io.emit('presence', presenceList());

  socket.on('chat:send', (payload, ack) => {
    const reply = (r) => { if (typeof ack === 'function') ack(r); };
    const text = cleanText(payload && payload.text);
    if (!text) return reply({ ok: false, error: 'الرسالة فارغة.' });
    if (text.length > MAX_TEXT_LENGTH) return reply({ ok: false, error: `الحد الأقصى ${MAX_TEXT_LENGTH} حرف.` });
    if (!allow(chatBucket, 12, 10000)) return reply({ ok: false, error: 'أنت ترسل بسرعة كبيرة. انتظر لحظة.' });

    const message = { id: crypto.randomUUID(), key, name, text, ts: Date.now() };
    messages.push(message);
    if (messages.length > MAX_STORED_MESSAGES) messages = messages.slice(-MAX_STORED_MESSAGES);
    scheduleMessagesSave();
    io.emit('chat:message', message);
    reply({ ok: true });
  });

  socket.on('chat:typing', () => {
    socket.broadcast.emit('chat:typing', { key, name });
  });

  socket.on('location:update', (payload) => {
    const now = Date.now();
    if (now - lastLocationAt < 1000) return;
    const lat = Number(payload && payload.lat);
    const lng = Number(payload && payload.lng);
    const accuracy = Number(payload && payload.accuracy);
    if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) return;
    lastLocationAt = now;

    const location = {
      key,
      name,
      lat: Math.round(lat * 1e6) / 1e6,
      lng: Math.round(lng * 1e6) / 1e6,
      accuracy: Number.isFinite(accuracy) ? Math.min(Math.max(Math.round(accuracy), 0), 100000) : 0,
      ts: now
    };
    locations.set(key, location);
    io.emit('location:update', location);
  });

  socket.on('location:stop', () => {
    if (locations.delete(key)) io.emit('location:remove', { key });
  });

  socket.on('disconnect', () => {
    const current = online.get(key);
    if (!current) return;
    current.sockets.delete(socket.id);
    if (current.sockets.size === 0) {
      online.delete(key);
      if (locations.delete(key)) io.emit('location:remove', { key });
      io.emit('presence', presenceList());
    }
  });
});

/* ───────────── التشغيل والإغلاق ───────────── */

function lanAddresses() {
  const result = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const item of list || []) {
      if (item.family === 'IPv4' && !item.internal) result.push(item.address);
    }
  }
  return result;
}

server.listen(PORT, HOST, () => {
  console.log('\nFamily HUD يعمل الآن');
  console.log(`  على هذا الجهاز:   http://localhost:${PORT}`);
  for (const ip of lanAddresses()) console.log(`  على الشبكة:       http://${ip}:${PORT}`);
  if (!FAMILY_CODE) {
    console.log('\n  تنبيه: أي شخص على الشبكة يستطيع إنشاء حساب. عيّن FAMILY_CODE لطلب رمز عائلي:');
    console.log('  FAMILY_CODE=رمزك npm start\n');
  }
});

function shutdown() {
  console.log('\nجارٍ الإغلاق…');
  if (saveTimer) clearTimeout(saveTimer);
  flushMessages();
  io.close(() => server.close(() => process.exit(0)));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
