const crypto = require('crypto');
require('dotenv').config();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const express = require('express');
const jwt = require('jsonwebtoken');
const https = require('https');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1); // Trust Render's proxy
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const API_SECRET = process.env.API_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const BREVO_API_KEY = process.env.BREVO_API_KEY;

// Fail fast if critical secrets are missing (set these on Render → Environment)
const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET', 'ADMIN_SECRET'];
const missing = REQUIRED_ENV.filter(function(k){ return !process.env[k]; });
if (missing.length > 0) {
  console.error('FATAL: missing required environment variables: ' + missing.join(', '));
  process.exit(1);
}

function sendBrevoEmail(to, subject, html) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      sender: { name: 'Punëza', email: 'gencbalisha@gmail.com' },
      to: [{ email: to }],
      subject: subject,
      htmlContent: html
    });
    const options = {
      hostname: 'api.brevo.com',
      path: '/v3/smtp/email',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': BREVO_API_KEY,
        'Content-Length': Buffer.byteLength(body)
      }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if(res.statusCode >= 200 && res.statusCode < 300) resolve(data);
        else reject(new Error('Brevo API error: ' + res.statusCode + ' ' + data));
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
console.log('📧 Brevo HTTP API ready');

// ─── Database ─────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ─── Middleware ────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://ems-frontend-five-tau.vercel.app',
  'http://localhost:3000',
  'http://localhost:5500'
];
const corsOptions = {
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if(!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET','POST','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','x-api-key','x-admin-key','x-session-token','x-emp-token']
};
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false
}));
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
// The logo upload carries a base64 image (up to ~500KB), so that one route gets its own larger limit.
// It must be registered first: once a body has been parsed, the 100kb parser below skips it.
app.use('/api/business/:code/logo', express.json({ limit: '700kb' }));
app.use(express.json({ limit: '100kb' }));

// ─── Input Sanitization ───────────────────────────────────────────────────────
function sanitizeObj(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  for (const key of Object.keys(obj)) {
    if (key === 'logo') continue; // base64 image: sanitizing would truncate/corrupt it; the logo route validates it
    const val = obj[key];
    if (typeof val === 'string') {
      obj[key] = val
        .replace(/<script[^>]*?>[\s\S]*?<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .slice(0, 5000);
    } else if (val && typeof val === 'object') {
      sanitizeObj(val);
    }
  }
  return obj;
}
app.use((req, res, next) => { if (req.body) sanitizeObj(req.body); next(); });

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500, // loadAll() makes 6 calls every 15s = ~360 calls/15min per active manager session
  message: { error: 'Too many requests, please try again later' }
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many login attempts' }
});
app.use('/api/', limiter);

// ─── (API key gate removed — JWT is the single auth source) ───────────────

// ─── Account Lockout ──────────────────────────────────────────────────────
const loginAttempts = new Map(); // in-memory: key -> { count, lockedUntil }

function checkLockout(key) {
  const attempts = loginAttempts.get(key) || { count: 0, lockedUntil: null };
  if (attempts.lockedUntil && attempts.lockedUntil > Date.now()) {
    const mins = Math.ceil((attempts.lockedUntil - Date.now()) / 60000);
    return { locked: true, mins };
  }
  return { locked: false };
}

function recordFailedAttempt(key) {
  const attempts = loginAttempts.get(key) || { count: 0, lockedUntil: null };
  attempts.count += 1;
  if (attempts.count >= 5) {
    attempts.lockedUntil = Date.now() + (15 * 60 * 1000); // 15 min lockout
    attempts.count = 0;
    console.log(`Account locked: ${key}`);
  }
  loginAttempts.set(key, attempts);
}

function clearAttempts(key) {
  loginAttempts.delete(key);
}

// ─── Init DB ──────────────────────────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS businesses (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        name TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        mgr_pin TEXT NOT NULL DEFAULT '0000',
        mgr_pin_hashed TEXT
      );

      CREATE TABLE IF NOT EXISTS employees (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        business_id INTEGER REFERENCES businesses(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        salary NUMERIC DEFAULT 0,
        rate NUMERIC DEFAULT 0,
        pin TEXT NOT NULL,
        pin_hashed BOOLEAN DEFAULT FALSE,
        start_time TEXT DEFAULT '09:00',
        end_time TEXT DEFAULT '17:00'
      );

      CREATE TABLE IF NOT EXISTS shifts (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        business_id INTEGER REFERENCES businesses(id) ON DELETE CASCADE,
        emp_id INTEGER REFERENCES employees(id) ON DELETE CASCADE,
        date TEXT NOT NULL,
        check_in TEXT,
        check_out TEXT,
        hours NUMERIC DEFAULT 0,
        regular_hours NUMERIC DEFAULT 0,
        ot_hours NUMERIC DEFAULT 0,
        manual_bonus NUMERIC DEFAULT 0,
        is_late BOOLEAN DEFAULT FALSE,
        late_minutes INTEGER DEFAULT 0,
        note TEXT,
    qr_token TEXT UNIQUE
      );

      CREATE TABLE IF NOT EXISTS leaves (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        business_id INTEGER REFERENCES businesses(id) ON DELETE CASCADE,
        emp_id INTEGER REFERENCES employees(id) ON DELETE CASCADE,
        date TEXT NOT NULL,
        type TEXT NOT NULL,
        note TEXT,
    qr_token TEXT UNIQUE
      );

      CREATE TABLE IF NOT EXISTS deductions (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        business_id INTEGER REFERENCES businesses(id) ON DELETE CASCADE,
        emp_id INTEGER REFERENCES employees(id) ON DELETE CASCADE,
        month TEXT NOT NULL,
        type TEXT NOT NULL,
        label TEXT NOT NULL,
        amount NUMERIC DEFAULT 0,
        note TEXT,
    qr_token TEXT UNIQUE
      );

      CREATE TABLE IF NOT EXISTS schedules (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        business_id INTEGER REFERENCES businesses(id) ON DELETE CASCADE,
        emp_id INTEGER REFERENCES employees(id) ON DELETE CASCADE,
        date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        note TEXT,
    qr_token TEXT UNIQUE,
        UNIQUE(emp_id, date)
      );
    `);

    // Column migrations
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS mgr_pin_hashed TEXT;`);
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free';`);
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS notify_email TEXT;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS mgr_password TEXT;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS reset_token TEXT;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS reset_token_expiry TIMESTAMPTZ;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS pro_expires_at TIMESTAMPTZ;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS pro_reminder_sent_at TIMESTAMPTZ;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS logo_url TEXT;`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT FALSE;`).catch(()=>{});
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_open_shift_per_day ON shifts (emp_id, date) WHERE check_out IS NULL;`).catch(()=>{});
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_leave_per_day ON leaves (emp_id, date) WHERE status IS DISTINCT FROM 'rejected';`).catch(()=>{});
    await client.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS currency_symbol TEXT DEFAULT '$';`).catch(()=>{});
    await client.query(`ALTER TABLE leaves ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending';`).catch(()=>{});
    await client.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS business_id INTEGER;`);
    await client.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS pin_hashed BOOLEAN DEFAULT FALSE;`);
    await client.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS end_time TEXT DEFAULT '17:00';`);
    await client.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS business_id INTEGER;`);
    await client.query(`ALTER TABLE leaves ADD COLUMN IF NOT EXISTS business_id INTEGER;`);

    // Create default business if none exists
    const biz = await client.query(`SELECT id FROM businesses LIMIT 1`);
    if (biz.rows.length === 0) {
      const hashedDefault = await bcrypt.hash('0000', SALT_ROUNDS);
      await client.query(
        `INSERT INTO businesses (name, code, mgr_pin, mgr_pin_hashed) VALUES ('My Business', 'default', $1, 'true')`,
        [hashedDefault]
      );
      console.log('✅ Default business created (code: default, mgr_pin: 0000)');
      await client.query(`UPDATE employees SET business_id = (SELECT id FROM businesses WHERE code='default') WHERE business_id IS NULL`);
      await client.query(`UPDATE shifts SET business_id = (SELECT id FROM businesses WHERE code='default') WHERE business_id IS NULL`);
      await client.query(`UPDATE leaves SET business_id = (SELECT id FROM businesses WHERE code='default') WHERE business_id IS NULL`);
    }

    // Migrate any plain-text manager PINs to bcrypt
    const unhashed = await client.query(`SELECT id, mgr_pin FROM businesses WHERE mgr_pin_hashed IS NULL OR mgr_pin_hashed = 'false'`);
    for (const row of unhashed.rows) {
      const hashed = await bcrypt.hash(String(row.mgr_pin), SALT_ROUNDS);
      await client.query(`UPDATE businesses SET mgr_pin=$1, mgr_pin_hashed='true' WHERE id=$2`, [hashed, row.id]);
    }
    if (unhashed.rows.length > 0) {
      console.log(`✅ Migrated ${unhashed.rows.length} manager PIN(s) to bcrypt`);
    }

    console.log('✅ Database tables ready');
  } finally {
    client.release();
  }
}

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', message: 'Punëza API running' }));

// ─── Admin Auth ───────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_SECRET) return res.status(401).json({ error: 'Admin access required' });
  next();
}

// ─── Manager Session (JWT) ─────────────────────────────────────────────────────
function requireSession(req, res, next) {
  const token = req.headers['x-session-token'];
  if(!token) return res.status(401).json({ error: 'No session token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.session = decoded;
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}


// Verify the session's business owns the requested resource
function requireBusinessMatch(req, res, next) {
  const token = req.headers['x-session-token'] || req.headers['x-emp-token'];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch(e) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
  req.session = decoded;
  // business_id can come from query, body, or be looked up
  const reqBizId = req.query.business_id || req.body.business_id;
  if (reqBizId && String(reqBizId) !== String(decoded.biz_id)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
}

// For routes with :id where we must confirm the row belongs to the session's business
// Checks a business's plan and auto-downgrades to 'free' if their Pro period has expired.
// Returns the *effective* plan (correcting the DB if needed), so every caller sees accurate access.
async function getEffectivePlan(bizId) {
  const r = await pool.query('SELECT plan, pro_expires_at FROM businesses WHERE id=$1', [bizId]);
  if (r.rows.length === 0) return 'free';
  const biz = r.rows[0];
  if ((biz.plan === 'pro' || biz.plan === 'business') && biz.pro_expires_at && new Date(biz.pro_expires_at) < new Date()) {
    await pool.query('UPDATE businesses SET plan=$1, pro_expires_at=NULL, pro_reminder_sent_at=NULL WHERE id=$2', ['free', bizId]);
    return 'free';
  }
  return biz.plan || 'free';
}

async function ownsResource(table, id, bizId) {
  const r = await pool.query('SELECT business_id FROM ' + table + ' WHERE id=$1', [id]);
  if (r.rows.length === 0) return false;
  return String(r.rows[0].business_id) === String(bizId);
}

// Accepts a valid manager OR employee session token. Sets req.session.
function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'] || req.headers['x-emp-token'];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.session = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

// Issue JWT token on successful manager login
// (legacy /api/auth/manager-login removed — real login is manager-login-password below;
// this old PIN-based route was unused by the frontend and had no rate limiting or lockout)

// ═══════════════════════════════════════════════════════════════════════════════
// BUSINESSES
// ═══════════════════════════════════════════════════════════════════════════════

// Get business by code (used on login)
app.get('/api/business/:code', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, code, currency_symbol FROM businesses WHERE code=$1', [req.params.code]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Business not found' });
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Save currency symbol setting
app.post('/api/business/:code/currency', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) return res.status(403).json({ error: 'Access denied' });
  const { currency } = req.body;
  if (!currency || currency.length > 5) return res.status(400).json({ error: 'Invalid currency symbol' });
  try {
    await pool.query('UPDATE businesses SET currency_symbol=$1 WHERE code=$2', [currency, req.params.code]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Public business registration (self-serve)
app.post('/api/business', async (req, res) => {
  const { name, code, email } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'name and code required' });
  if (code.length < 3) return res.status(400).json({ error: 'Code must be at least 3 characters' });

  const cleanCode = code.toLowerCase().replace(/[^a-z0-9_-]/g, '');
  if (!cleanCode) return res.status(400).json({ error: 'Invalid business code' });

  try {
    const { password } = req.body;
    let hashedPassword = null;
    if (password && password.length >= 6) {
      hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    }
    const result = await pool.query(
      `INSERT INTO businesses (name, code, notify_email, mgr_password) VALUES ($1, $2, $3, $4) RETURNING id, name, code`,
      [name.trim(), cleanCode, email || null, hashedPassword]
    );
    console.log(`✅ New business registered: ${name} (${cleanCode})`);
    if(email) { sendWelcomeEmail(email, name.trim(), cleanCode); sendOnboardingSequence(email, name.trim(), cleanCode); }
    res.json(result.rows[0]);
  } catch(e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Business code already taken' });
    res.status(500).json({ error: e.message });
  }
});

// Admin: create business manually
app.post('/api/admin/business', requireAdmin, async (req, res) => {
  const { name, code, mgr_pin } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'name and code required' });
  try {
    const hashedPin = await bcrypt.hash(String(mgr_pin || '0000'), SALT_ROUNDS);
    const result = await pool.query(
      'INSERT INTO businesses (name, code, mgr_pin) VALUES ($1, $2, $3) RETURNING id, name, code',
      [name, code.toLowerCase(), hashedPin]
    );
    res.json(result.rows[0]);
  } catch(e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Business code already exists' });
    res.status(500).json({ error: e.message });
  }
});

// Admin: list all businesses

// Verify manager PIN (bcrypt)
app.post('/api/business/:code/verify-mgr', async (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: 'pin required' });
  try {
    const result = await pool.query('SELECT mgr_pin, mgr_pin_hashed FROM businesses WHERE code=$1', [req.params.code]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Business not found' });

    const biz = result.rows[0];
    let valid = false;

    if (biz.mgr_pin_hashed) {
      valid = await bcrypt.compare(String(pin), biz.mgr_pin);
    } else {
      // Legacy plain-text fallback — auto-upgrade on success
      valid = String(biz.mgr_pin) === String(pin);
      if (valid) {
        const hashedPin = await bcrypt.hash(String(pin), SALT_ROUNDS);
        await pool.query('UPDATE businesses SET mgr_pin=$1, mgr_pin_hashed=\'true\' WHERE code=$2', [hashedPin, req.params.code]);
        console.log(`✅ Manager PIN auto-upgraded to bcrypt for: ${req.params.code}`);
      }
    }

    res.json({ valid });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Change manager PIN (verifies old, hashes new)
// (legacy /api/business/:code/mgr-pin removed — unused, unauthenticated, checked the wrong
// column; real password change is /api/business/:code/change-mgr-pin below, now rate-limited)

// ═══════════════════════════════════════════════════════════════════════════════
// EMPLOYEES (scoped to business)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/employees', requireBusinessMatch, async (req, res) => {
  const { business_id } = req.query;
  if (!business_id) return res.status(400).json({ error: 'business_id required' });
  try {
    const isEmp = req.session.role === 'employee';
    let query = 'SELECT id,created_at,name,role,salary,rate,start_time,end_time,qr_token,phone FROM employees WHERE business_id=$1';
    let params = [business_id];
    // Employees have no need to see the full staff roster (including everyone's pay rates) - only their own record
    if (isEmp) { params.push(req.session.emp_id); query += ' AND id=$2'; }
    query += ' ORDER BY id ASC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/employees', requireBusinessMatch, async (req, res) => {
  if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
  const { name, role, salary, rate, pin, start_time, end_time, business_id } = req.body;
  if (!name || !role || !pin || !business_id) return res.status(400).json({ error: 'name, role, pin and business_id required' });
  try {
    // Enforce Free plan employee limit (auto-downgrades if Pro period has expired)
    const bizR = await pool.query('SELECT id FROM businesses WHERE id=$1', [business_id]);
    if (bizR.rows.length === 0) return res.status(404).json({ error: 'Business not found' });
    const plan = await getEffectivePlan(business_id);
    if (plan !== 'pro' && plan !== 'business') {
      const countR = await pool.query('SELECT COUNT(*)::int AS n FROM employees WHERE business_id=$1', [business_id]);
      if (countR.rows[0].n >= 5) {
        return res.status(403).json({ error: 'Free plan is limited to 5 employees. Upgrade to Pro for unlimited staff.', code: 'PLAN_LIMIT' });
      }
    }
    const hashedPin = await bcrypt.hash(String(pin), SALT_ROUNDS);
    const result = await pool.query(
      'INSERT INTO employees (name,role,salary,rate,pin,start_time,end_time,pin_hashed,business_id,qr_token,phone) VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,$8,$9,$10) RETURNING id,created_at,name,role,salary,rate,start_time,end_time,qr_token,phone',
      [name, role, salary||0, rate||0, hashedPin, start_time||'09:00', end_time||'17:00', business_id, crypto.randomBytes(16).toString('hex'), req.body.phone||null]
    );
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

const pinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: function(req) {
    // Rate-limit per IP + business_code combo, not just IP alone.
    // This prevents employees on the same WiFi (same IP) from blocking each other
    // while still preventing brute-force against any single business.
    var code = (req.body && req.body.business_code) ? req.body.business_code : 'unknown';
    return req.ip + ':' + code;
  },
  message: { error: 'Too many PIN attempts for this account. Please wait 15 minutes.' }
});
app.post('/api/employees/verify-pin', pinLimiter, async (req, res) => {
  const { emp_id, pin, business_code, name } = req.body;
  if (!pin || (!emp_id && !(business_code && name))) {
    return res.status(400).json({ error: 'pin plus emp_id or business_code+name required' });
  }
  try {
    let result;
    if (emp_id) {
      result = await pool.query('SELECT id, pin, pin_hashed, business_id, name, role, rate, start_time, end_time FROM employees WHERE id=$1', [emp_id]);
    } else {
      result = await pool.query(
        `SELECT e.id, e.pin, e.pin_hashed, e.business_id, e.name, e.role, e.rate, e.start_time, e.end_time
         FROM employees e JOIN businesses b ON e.business_id=b.id
         WHERE b.code=$1 AND LOWER(e.name)=LOWER($2)`,
        [String(business_code).toLowerCase(), String(name).trim()]
      );
    }
    if (result.rows.length === 0) return res.status(404).json({ error: 'Employee not found' });
    const emp = result.rows[0];
    // Check if business is suspended
    const bizCheck = await pool.query('SELECT is_blocked FROM businesses WHERE id=$1', [emp.business_id]);
    if (bizCheck.rows[0]?.is_blocked) return res.status(403).json({ error: 'This account has been suspended. Please contact your manager.' });
    let valid = false;
    if (emp.pin_hashed) {
      valid = await bcrypt.compare(String(pin), emp.pin);
    } else {
      // Legacy plain-text fallback — auto-upgrade on success
      valid = String(emp.pin) === String(pin);
      if (valid) {
        const hashedPin = await bcrypt.hash(String(pin), SALT_ROUNDS);
        await pool.query('UPDATE employees SET pin=$1, pin_hashed=TRUE WHERE id=$2', [hashedPin, emp.id]);
      }
    }
    // On success, issue a short-lived employee token scoped to this one employee
    let emp_token = null;
    if (valid) {
      emp_token = jwt.sign(
        { emp_id: Number(emp.id), biz_id: emp.business_id, role: 'employee' },
        JWT_SECRET,
        { expiresIn: '12h' }
      );
    }
    res.json({
      valid, match: valid, emp_token,
      employee: valid ? { id: emp.id, name: emp.name, role: emp.role, rate: emp.rate, start_time: emp.start_time, end_time: emp.end_time, business_id: emp.business_id } : null
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ─── Update Employee ───────────────────────────────────────────────────────
app.patch('/api/employees/:id', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
    const { name, role, rate, start_time, end_time, phone, pin } = req.body;
    const empId = req.params.id;

    // Validate
    if (name !== undefined && !name.trim()) return res.status(400).json({ error: 'Name cannot be empty' });
    if (rate !== undefined && isNaN(parseFloat(rate))) return res.status(400).json({ error: 'Invalid rate' });
    if (pin !== undefined && pin.length < 4) return res.status(400).json({ error: 'PIN must be at least 4 digits' });

    // Get current employee
    const current = await pool.query('SELECT * FROM employees WHERE id=$1', [empId]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Employee not found' });
    const emp = current.rows[0];

    // Cross-business protection: this employee must belong to the manager's own business
    if (String(emp.business_id) !== String(req.session.biz_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Check duplicate name (if name changed)
    if (name && name.trim() !== emp.name) {
      const dup = await pool.query(
        'SELECT id FROM employees WHERE business_id=$1 AND LOWER(name)=LOWER($2) AND id!=$3',
        [emp.business_id, name.trim(), empId]
      );
      if (dup.rows.length > 0) return res.status(400).json({ error: 'An employee with this name already exists' });
    }

    // Hash new PIN if provided
    let hashedPin = emp.pin;
    if (pin) {
      hashedPin = await bcrypt.hash(String(pin), SALT_ROUNDS);
    }

    const result = await pool.query(
      `UPDATE employees SET 
        name=COALESCE($1, name),
        role=COALESCE($2, role),
        rate=COALESCE($3, rate),
        start_time=COALESCE($4, start_time),
        end_time=COALESCE($5, end_time),
        phone=COALESCE($6, phone),
        pin=CASE WHEN $7::text IS NOT NULL THEN $7 ELSE pin END,
        pin_hashed=CASE WHEN $7::text IS NOT NULL THEN TRUE ELSE pin_hashed END
      WHERE id=$8 RETURNING id,created_at,name,role,salary,rate,start_time,end_time,qr_token,phone`,
      [
        name ? name.trim() : null,
        role || null,
        rate !== undefined ? parseFloat(rate) : null,
        start_time || null,
        end_time || null,
        phone || null,
        pin ? hashedPin : null,
        empId
      ]
    );

    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/employees/:id', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
    const current = await pool.query('SELECT business_id FROM employees WHERE id=$1', [req.params.id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Employee not found' });
    if (String(current.rows[0].business_id) !== String(req.session.biz_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    await pool.query('DELETE FROM employees WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SHIFTS (scoped to business)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/shifts', requireBusinessMatch, async (req, res) => {
  const { business_id } = req.query;
  let { emp_id } = req.query;
  if (!business_id) return res.status(400).json({ error: 'business_id required' });
  // Employees can only ever see their own shifts, regardless of what emp_id was requested
  if (req.session.role === 'employee') emp_id = req.session.emp_id;
  try {
    let query = 'SELECT * FROM shifts WHERE business_id=$1';
    let params = [business_id];
    if (emp_id) { query += ' AND emp_id=$2'; params.push(emp_id); }
    query += ' ORDER BY id ASC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/shifts', requireBusinessMatch, async (req, res) => {
  let { emp_id, date, check_in, is_late, late_minutes, business_id } = req.body;
  // If this is an employee's own token, they can only ever act on their own record
  if (req.session && req.session.role === 'employee') {
    emp_id = req.session.emp_id;
  }
  if (!emp_id || !date || !check_in || !business_id) return res.status(400).json({ error: 'emp_id, date, check_in and business_id required' });
  try {
    // An employee cannot clock in on a day with approved leave. Checked for the date sent by the device AND
    // today's date in Albania, so changing the device clock does not get around it. Managers can still add a shift manually.
    if (req.session && req.session.role === 'employee') {
      const todayTirane = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Tirane' }).format(new Date());
      const onLeave = await pool.query(
        "SELECT 1 FROM leaves WHERE emp_id=$1 AND status='approved' AND date = ANY($2::text[]) LIMIT 1",
        [emp_id, [String(date).slice(0, 10), todayTirane]]
      );
      if (onLeave.rows.length > 0) return res.status(403).json({ error: 'You have approved leave today, so you cannot clock in. Contact your manager if this is a mistake.', code: 'ON_LEAVE' });
    }
    const existing = await pool.query('SELECT id FROM shifts WHERE emp_id=$1 AND date=$2 AND check_out IS NULL', [emp_id, date]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Already checked in today' });
    // Check if late based on schedule
    let isLate = is_late || false;
    let lateMin = late_minutes || 0;
    
    // Auto-detect lateness from schedule
    const schedResult = await pool.query(
      'SELECT * FROM schedules WHERE emp_id=$1 AND date=$2',
      [emp_id, date]
    ).catch(function(){ return { rows: [] }; });
    
    if (schedResult.rows.length > 0 && !isLate) {
      const sched = schedResult.rows[0];
      const [sh, sm] = sched.start_time.split(':').map(Number);
      const [ch, cm] = check_in.split(':').map(Number);
      const schedMins = sh * 60 + sm;
      const checkMins = ch * 60 + cm;
      const diff = checkMins - schedMins;
      if (diff >= 10) {
        isLate = true;
        lateMin = diff;
      }
    }
    
    let result;
    try {
      result = await pool.query(
        'INSERT INTO shifts (emp_id,date,check_in,is_late,late_minutes,business_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
        [emp_id, date, check_in, isLate, lateMin, business_id]
      );
    } catch (insErr) {
      // Two taps / two devices at the same instant: the database allows only one open shift per person per day
      if (insErr.code === '23505') return res.status(400).json({ error: 'Already checked in today' });
      throw insErr;
    }
    
    // Send late alert if needed
    if (isLate && lateMin >= 10) {
      const bizResult = await pool.query('SELECT * FROM businesses WHERE id=$1', [business_id]).catch(function(){ return { rows: [] }; });
      const empResult = await pool.query('SELECT * FROM employees WHERE id=$1', [emp_id]).catch(function(){ return { rows: [] }; });
      if (bizResult.rows[0] && empResult.rows[0]) {
        const sched = schedResult.rows[0];
        sendLateAlert(bizResult.rows[0], empResult.rows[0], sched ? sched.start_time : '?', check_in, lateMin).catch(function(){});
      }
    }

    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Close stale open shifts (shifts left open from a previous day) ──────────
app.post('/api/shifts/close-stale', requireBusinessMatch, async (req, res) => {
  const { business_id } = req.body;
  if (!business_id) return res.status(400).json({ error: 'business_id required' });
  try {
    const today = new Date().toLocaleDateString('en-CA');
    // Find open shifts from before today
    const stale = await pool.query(
      'SELECT * FROM shifts WHERE business_id=$1 AND check_out IS NULL AND date < $2',
      [business_id, today]
    );
    let closed = 0;
    for (const shift of stale.rows) {
      if (!shift.check_in) continue;
      // Assume they worked their scheduled hours; default close at check_in + 8h capped at 23:59
      const [inH, inM] = String(shift.check_in).split(':').map(Number);
      let outMins = Math.min(inH * 60 + inM + 8 * 60, 23 * 60 + 59);
      const outH = Math.floor(outMins / 60);
      const outM = outMins % 60;
      const checkOut = String(outH).padStart(2, '0') + ':' + String(outM).padStart(2, '0');
      const totalHours = Math.round(((outMins - (inH * 60 + inM)) / 60) * 100) / 100;
      const regularHours = Math.min(totalHours, 8);
      const otHours = Math.max(0, Math.round((totalHours - 8) * 100) / 100);
      await pool.query(
        'UPDATE shifts SET check_out=$1, hours=$2, regular_hours=$3, ot_hours=$4, note=COALESCE(note,\'\')||$5 WHERE id=$6',
        [checkOut, totalHours, regularHours, otHours, ' [auto-closed]', shift.id]
      );
      closed++;
    }
    res.json({ success: true, closed });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Dedicated Checkout (auto-calculates hours) ──────────────────────────────
app.post('/api/shifts/:id/checkout', requireAuth, async (req, res) => {
  const { check_out } = req.body;
  if (!check_out) return res.status(400).json({ error: 'check_out time required' });
  try {
    // Get the shift to read its check_in
    const shiftRes = await pool.query('SELECT * FROM shifts WHERE id=$1', [req.params.id]);
    if (shiftRes.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    const shift = shiftRes.rows[0];

    // Ownership checks: must be same business, and if it's an employee token, must be their own shift
    if (String(shift.business_id) !== String(req.session.biz_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    if (req.session.role === 'employee' && String(shift.emp_id) !== String(req.session.emp_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    if (!shift.check_in) return res.status(400).json({ error: 'Shift has no check-in time' });
    if (shift.check_out) return res.status(400).json({ error: 'Already checked out' });

    // Parse HH:MM times into minutes
    const [inH, inM] = String(shift.check_in).split(':').map(Number);
    const [outH, outM] = String(check_out).split(':').map(Number);
    let inMins = inH * 60 + inM;
    let outMins = outH * 60 + outM;
    // Handle overnight shift (checkout past midnight)
    if (outMins < inMins) outMins += 24 * 60;

    const totalMins = outMins - inMins;
    const totalHours = Math.round((totalMins / 60) * 100) / 100;

    // Regular up to 8h, overtime beyond 8h
    const regularHours = Math.min(totalHours, 8);
    const otHours = Math.max(0, Math.round((totalHours - 8) * 100) / 100);

    const result = await pool.query(
      `UPDATE shifts SET check_out=$1, hours=$2, regular_hours=$3, ot_hours=$4 WHERE id=$5 RETURNING *`,
      [check_out, totalHours, regularHours, otHours, req.params.id]
    );
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/shifts/:id', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
  const { check_out, hours, regular_hours, ot_hours, manual_bonus, note } = req.body;
  try {
    const current = await pool.query('SELECT business_id FROM shifts WHERE id=$1', [req.params.id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    if (String(current.rows[0].business_id) !== String(req.session.biz_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const result = await pool.query(
      `UPDATE shifts SET check_out=COALESCE($1,check_out), hours=COALESCE($2,hours),
       regular_hours=COALESCE($3,regular_hours), ot_hours=COALESCE($4,ot_hours),
       manual_bonus=COALESCE($5,manual_bonus), note=COALESCE($6,note)
       WHERE id=$7 RETURNING *`,
      [check_out, hours, regular_hours, ot_hours, manual_bonus, note, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// LEAVES (scoped to business)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/leaves', requireBusinessMatch, async (req, res) => {
  const { business_id } = req.query;
  if (!business_id) return res.status(400).json({ error: 'business_id required' });
  try {
    let query = 'SELECT * FROM leaves WHERE business_id=$1';
    let params = [business_id];
    // Employees can only ever see their own leave records
    if (req.session.role === 'employee') { query += ' AND emp_id=$2'; params.push(req.session.emp_id); }
    query += ' ORDER BY id ASC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/leaves', requireBusinessMatch, async (req, res) => {
  let { emp_id, date, type, note, business_id } = req.body;
  const isEmployee = req.session && req.session.role === 'employee';
  if (isEmployee) emp_id = req.session.emp_id;   // employees can only request leave for themselves
  if (!emp_id || !date || !type || !business_id) return res.status(400).json({ error: 'emp_id, date, type and business_id required' });
  try {
    const status = isEmployee ? 'pending' : 'approved';   // leave entered by the manager is already granted
    // One leave per person per day (a rejected request does not count). Stops double-taps and duplicates.
    const dup = await pool.query("SELECT status FROM leaves WHERE emp_id=$1 AND date=$2 AND status IS DISTINCT FROM 'rejected' LIMIT 1", [emp_id, date]);
    if (dup.rows.length > 0) return res.status(409).json({ error: dup.rows[0].status === 'approved' ? 'This employee already has approved leave on that date.' : 'A leave request for that date already exists.' });
    let result;
    try {
      result = await pool.query(
        'INSERT INTO leaves (emp_id,date,type,note,business_id,status) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
        [emp_id, date, type, note||null, business_id, status]
      );
    } catch (insErr) {
      if (insErr.code === '23505') return res.status(409).json({ error: 'A leave for that date already exists.' });   // two taps at the same instant
      throw insErr;
    }
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/leaves/:id', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
    const current = await pool.query('SELECT business_id FROM leaves WHERE id=$1', [req.params.id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Leave not found' });
    if (String(current.rows[0].business_id) !== String(req.session.biz_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    await pool.query('DELETE FROM leaves WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DEDUCTIONS (scoped to business)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/deductions', requireBusinessMatch, async (req, res) => {
  const { business_id, month } = req.query;
  if (!business_id) return res.status(400).json({ error: 'business_id required' });
  try {
    const isEmp = req.session.role === 'employee';
    let query = 'SELECT * FROM deductions WHERE business_id=$1';
    let params = [business_id];
    if (month) { params.push(month); query += ` AND month=$${params.length}`; }
    // Employees can only ever see their own bonuses/deductions
    if (isEmp) { params.push(req.session.emp_id); query += ` AND emp_id=$${params.length}`; }
    query += ' ORDER BY id ASC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/deductions', requireBusinessMatch, async (req, res) => {
  const { emp_id, month, type, label, amount, note, business_id } = req.body;
  if (!emp_id || !month || !type || !label || !business_id) {
    return res.status(400).json({ error: 'emp_id, month, type, label and business_id required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO deductions (emp_id,month,type,label,amount,note,business_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [emp_id, month, type, label, amount||0, note||null, business_id]
    );
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/deductions/:id', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
    const current = await pool.query('SELECT business_id FROM deductions WHERE id=$1', [req.params.id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Deduction not found' });
    if (String(current.rows[0].business_id) !== String(req.session.biz_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    await pool.query('DELETE FROM deductions WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SCHEDULES (scoped to business)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/schedules', requireBusinessMatch, async (req, res) => {
  const { business_id, week } = req.query;
  if (!business_id) return res.status(400).json({ error: 'business_id required' });
  try {
    const isEmp = req.session.role === 'employee';
    let query = week
      ? 'SELECT * FROM schedules WHERE business_id=$1 AND date >= $2 AND date <= $3'
      : 'SELECT * FROM schedules WHERE business_id=$1';
    let params = week
      ? [business_id, week + '-01', week + '-07']
      : [business_id];
    // Employees can only ever see their own schedule entries
    if (isEmp) { params.push(req.session.emp_id); query += ` AND emp_id=$${params.length}`; }
    query += ' ORDER BY date ASC, emp_id ASC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/schedules', requireBusinessMatch, async (req, res) => {
  const { emp_id, date, start_time, end_time, note, business_id } = req.body;
  if (!emp_id || !date || !start_time || !end_time || !business_id)
    return res.status(400).json({ error: 'emp_id, date, start_time, end_time and business_id required' });
  try {
    const result = await pool.query(
      `INSERT INTO schedules (emp_id,date,start_time,end_time,note,business_id)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (emp_id, date) DO UPDATE
       SET start_time=$3, end_time=$4, note=$5
       RETURNING *`,
      [emp_id, date, start_time, end_time, note||null, business_id]
    );
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/schedules/:id', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
    const current = await pool.query('SELECT business_id FROM schedules WHERE id=$1', [req.params.id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Schedule not found' });
    if (String(current.rows[0].business_id) !== String(req.session.biz_id)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    await pool.query('DELETE FROM schedules WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ═══════════════════════════════════════════════════════════════════════════════
// EMAIL HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

async function sendWelcomeEmail(to, bizName, bizCode) {
  if(!to) return;
  console.log('📧 Sending welcome email to:', to);
  try {
    await sendBrevoEmail(to, '🎉 Welcome to Punëza — Your account is ready', `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#060e1e;font-family:'Helvetica Neue',Arial,sans-serif;">
  <div style="max-width:580px;margin:0 auto;padding:32px 16px;">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#1e3a6e,#0f2044);border-radius:16px 16px 0 0;padding:32px;text-align:center;border:1px solid rgba(59,130,246,0.3);border-bottom:none;">
      <div style="font-size:48px;font-weight:900;letter-spacing:6px;background:linear-gradient(135deg,#60a5fa,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Punëza</div>
      <div style="color:#6b82a8;font-size:11px;letter-spacing:3px;margin-top:4px;">STAFF MANAGER</div>
    </div>

    <!-- Body -->
    <div style="background:#0a1630;border:1px solid rgba(59,130,246,0.2);border-top:none;border-radius:0 0 16px 16px;padding:32px;">

      <h1 style="color:#e8f0ff;font-size:24px;font-weight:700;margin:0 0 8px;">Welcome, ${bizName}! 👋</h1>
      <p style="color:#6b82a8;font-size:14px;line-height:1.7;margin:0 0 24px;">Your Punëza account is set up and ready to go. Here's everything you need to get started.</p>

      <!-- Login code box -->
      <div style="background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:12px;padding:20px;margin-bottom:24px;text-align:center;">
        <div style="color:#6b82a8;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">Your Business Code</div>
        <div style="color:#60a5fa;font-size:32px;font-weight:800;letter-spacing:6px;font-family:monospace;">${bizCode}</div>
        <div style="color:#6b82a8;font-size:12px;margin-top:8px;">Use this code every time you log in</div>
      </div>

      <!-- Next steps -->
      <div style="margin-bottom:24px;">
        <div style="color:#e8f0ff;font-size:15px;font-weight:600;margin-bottom:14px;">Get started in 3 steps:</div>

        <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:14px;">
          <div style="background:linear-gradient(135deg,#3b82f6,#06b6d4);color:#fff;border-radius:50%;width:28px;height:28px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;line-height:28px;text-align:center;">1</div>
          <div><div style="color:#e8f0ff;font-size:14px;font-weight:600;">Add your employees</div><div style="color:#6b82a8;font-size:12px;margin-top:2px;">Go to the STAFF tab and add each team member with their role and pay rate</div></div>
        </div>

        <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:14px;">
          <div style="background:linear-gradient(135deg,#3b82f6,#06b6d4);color:#fff;border-radius:50%;width:28px;height:28px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;line-height:28px;text-align:center;">2</div>
          <div><div style="color:#e8f0ff;font-size:14px;font-weight:600;">Set up your schedule</div><div style="color:#6b82a8;font-size:12px;margin-top:2px;">Use the SCHED tab to plan shifts for the week ahead</div></div>
        </div>

        <div style="display:flex;align-items:flex-start;gap:12px;">
          <div style="background:linear-gradient(135deg,#3b82f6,#06b6d4);color:#fff;border-radius:50%;width:28px;height:28px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;line-height:28px;text-align:center;">3</div>
          <div><div style="color:#e8f0ff;font-size:14px;font-weight:600;">Install the app</div><div style="color:#6b82a8;font-size:12px;margin-top:2px;">Open the app in Chrome and tap Install for quick access from your home screen</div></div>
        </div>
      </div>

      <!-- CTA -->
      <div style="text-align:center;margin-bottom:24px;">
        <a href="https://ems-frontend-five-tau.vercel.app" style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#06b6d4);color:#fff;text-decoration:none;padding:14px 32px;border-radius:10px;font-size:14px;font-weight:700;letter-spacing:.5px;">Open Punëza →</a>
      </div>

      <!-- Features -->
      <div style="background:rgba(14,28,58,0.6);border-radius:10px;padding:16px;margin-bottom:24px;">
        <div style="color:#6b82a8;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px;">What's included in your plan</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
          <div style="color:#e8f0ff;font-size:12px;">✓ Employee check in/out</div>
          <div style="color:#e8f0ff;font-size:12px;">✓ Shift scheduling</div>
          <div style="color:#e8f0ff;font-size:12px;">✓ Pay & hours tracking</div>
          <div style="color:#e8f0ff;font-size:12px;">✓ Leave management</div>
          <div style="color:#e8f0ff;font-size:12px;">✓ Live dashboard</div>
          <div style="color:#e8f0ff;font-size:12px;">✓ Charts & reports</div>
        </div>
      </div>

      <p style="color:#3d5070;font-size:12px;text-align:center;margin:0;">Questions? Reply to this email anytime.<br>Punëza</p>
    </div>

  </div>
</body>
</html>`);
    console.log('📧 Welcome email sent successfully to:', to);
  } catch(e) {
    console.error('📧 Welcome email failed:', e.message, e);
  }
}

async function sendExpiryReminderEmail(to, bizName, expiresAt, daysLeft, planName) {
  planName = planName || 'Pro';
  if(!to) return;
  try {
    const dateStr = new Date(expiresAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    await sendBrevoEmail(to, `⏳ Your Punëza ${planName} plan expires in ${daysLeft} day${daysLeft===1?'':'s'}`, `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#060e1e;font-family:'Helvetica Neue',Arial,sans-serif;">
  <div style="max-width:580px;margin:0 auto;padding:32px 16px;">
    <div style="background:linear-gradient(135deg,#1e3a6e,#0f2044);border-radius:16px 16px 0 0;padding:32px;text-align:center;border:1px solid rgba(6,182,212,0.4);border-bottom:none;">
      <div style="font-size:48px;font-weight:900;letter-spacing:6px;background:linear-gradient(135deg,#60a5fa,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Punëza</div>
      <div style="color:#f59e0b;font-size:11px;letter-spacing:3px;margin-top:4px;">${planName.toUpperCase()} PLAN EXPIRING SOON</div>
    </div>
    <div style="background:#0a1630;border:1px solid rgba(6,182,212,0.2);border-top:2px solid #f59e0b;border-radius:0 0 16px 16px;padding:32px;">
      <div style="text-align:center;margin-bottom:24px;">
        <div style="font-size:48px;">⏳</div>
        <h1 style="color:#e8f0ff;font-size:22px;font-weight:700;margin:12px 0 8px;">${bizName}, your ${planName} plan expires soon</h1>
        <p style="color:#94a3b8;font-size:14px;line-height:1.6;margin:0;">Your ${planName} subscription ends on <strong style="color:#f59e0b;">${dateStr}</strong>. Renew now to keep unlimited employees, scheduling, and payslips without interruption.</p>
      </div>
      <div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:12px;padding:16px;text-align:center;">
        <p style="color:#e8f0ff;font-size:13px;margin:0;">If payment isn't received before then, your account will automatically return to the Free plan (up to 5 employees) — no action needed to stay on Free, but Pro features will pause until you renew.</p>
      </div>
      <p style="color:#64748b;font-size:12px;text-align:center;margin-top:24px;">Open the PLANS tab in Punëza to see renewal details.</p>
    </div>
  </div>
</body>
</html>`);
  } catch(e) { console.error('Expiry reminder email error:', e.message); }
}

async function sendUpgradeEmail(to, bizName) {
  if(!to) return;
  try {
    await sendBrevoEmail(to, '🚀 You are now on Punëza Pro!', `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#060e1e;font-family:'Helvetica Neue',Arial,sans-serif;">
  <div style="max-width:580px;margin:0 auto;padding:32px 16px;">
    <div style="background:linear-gradient(135deg,#1e3a6e,#0f2044);border-radius:16px 16px 0 0;padding:32px;text-align:center;border:1px solid rgba(6,182,212,0.4);border-bottom:none;">
      <div style="font-size:48px;font-weight:900;letter-spacing:6px;background:linear-gradient(135deg,#60a5fa,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Punëza</div>
      <div style="color:#06b6d4;font-size:11px;letter-spacing:3px;margin-top:4px;">PRO PLAN ACTIVATED</div>
    </div>
    <div style="background:#0a1630;border:1px solid rgba(6,182,212,0.2);border-top:2px solid #06b6d4;border-radius:0 0 16px 16px;padding:32px;">
      <div style="text-align:center;margin-bottom:24px;">
        <div style="font-size:48px;">🚀</div>
        <h1 style="color:#e8f0ff;font-size:22px;font-weight:700;margin:12px 0 8px;">You're on Pro, ${bizName}!</h1>
        <p style="color:#6b82a8;font-size:14px;line-height:1.7;margin:0;">All Pro features are now unlocked for your account.</p>
      </div>
      <div style="background:rgba(6,182,212,0.08);border:1px solid rgba(6,182,212,0.2);border-radius:12px;padding:20px;margin-bottom:24px;">
        <div style="color:#06b6d4;font-size:11px;letter-spacing:2px;margin-bottom:12px;">NOW UNLOCKED</div>
        <div style="color:#e8f0ff;font-size:13px;line-height:2;">
          ✓ Unlimited employees<br>
          ✓ Payslips & PDF export<br>
          ✓ Deductions & Tax calculator<br>
          ✓ Full shift scheduling<br>
          ✓ Priority support
        </div>
      </div>
      <div style="text-align:center;">
        <a href="https://ems-frontend-five-tau.vercel.app" style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#06b6d4);color:#fff;text-decoration:none;padding:14px 32px;border-radius:10px;font-size:14px;font-weight:700;">Open Punëza →</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  } catch(e) {
    console.error('Upgrade email failed:', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// OWNER ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// Get all businesses with employee counts
app.get('/api/admin/businesses', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT b.id, b.name, b.code, b.plan, b.created_at, b.notify_email,
        COUNT(e.id)::int as emp_count
      FROM businesses b
      LEFT JOIN employees e ON e.business_id = b.id
      GROUP BY b.id
      ORDER BY b.created_at DESC
    `);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Set plan for a business
app.patch('/api/admin/businesses/:id/plan', requireAdmin, async (req, res) => {
  const { plan, days } = req.body;
  if(!plan || !['free','pro','business'].includes(plan)) return res.status(400).json({ error: 'plan must be free, pro or business' });
  try {
    let result;
    if (plan === 'pro' || plan === 'business') {
      const period = Number(days) > 0 ? Number(days) : (plan === 'business' ? 365 : 30);
      result = await pool.query(
        `UPDATE businesses
         SET plan=$1, pro_expires_at = GREATEST(COALESCE(pro_expires_at, NOW()), NOW()) + ($3 || ' days')::interval, pro_reminder_sent_at = NULL
         WHERE id=$2 RETURNING id, name, plan, pro_expires_at`,
        [plan, req.params.id, period]
      );
    } else {
      result = await pool.query(
        `UPDATE businesses SET plan='free', pro_expires_at=NULL, pro_reminder_sent_at=NULL WHERE id=$1 RETURNING id, name, plan, pro_expires_at`,
        [req.params.id]
      );
    }
    if(result.rows.length === 0) return res.status(404).json({ error: 'Business not found' });
    if(plan === 'pro' || plan === 'business') {
      const bizData = await pool.query('SELECT name, notify_email FROM businesses WHERE id=$1', [req.params.id]);
      if(bizData.rows[0]?.notify_email) sendUpgradeEmail(bizData.rows[0].notify_email, bizData.rows[0].name);
    }
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Delete a business
app.delete('/api/admin/businesses/:id', requireAdmin, async (req, res) => {
  try {
    // Delete all related data first, then the business
    await pool.query('DELETE FROM shifts WHERE business_id=$1', [req.params.id]);
    await pool.query('DELETE FROM leaves WHERE business_id=$1', [req.params.id]);
    await pool.query('DELETE FROM deductions WHERE business_id=$1', [req.params.id]);
    await pool.query('DELETE FROM schedules WHERE business_id=$1', [req.params.id]);
    await pool.query('DELETE FROM employees WHERE business_id=$1', [req.params.id]);
    await pool.query('DELETE FROM businesses WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Block or unblock a business (suspends login without deleting data)
app.patch('/api/admin/businesses/:id/block', requireAdmin, async (req, res) => {
  const { blocked } = req.body;
  try {
    const result = await pool.query(
      'UPDATE businesses SET is_blocked=$1 WHERE id=$2 RETURNING id, name, is_blocked',
      [blocked ? true : false, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Business not found' });
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Save notify email (called from frontend)
app.post('/api/business/:code/notify-email', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { email } = req.body;
  if(!email) return res.status(400).json({ error: 'email required' });
  try {
    await pool.query('UPDATE businesses SET notify_email=$1 WHERE code=$2', [email, req.params.code]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Approve or reject a leave request
app.patch('/api/leaves/:id', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
  const { status } = req.body;
  if (!['approved','rejected'].includes(status)) return res.status(400).json({ error: 'status must be approved or rejected' });
  try {
    const current = await pool.query('SELECT business_id, emp_id FROM leaves WHERE id=$1', [req.params.id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Leave not found' });
    if (String(current.rows[0].business_id) !== String(req.session.biz_id)) return res.status(403).json({ error: 'Access denied' });
    const result = await pool.query('UPDATE leaves SET status=$1 WHERE id=$2 RETURNING *', [status, req.params.id]);
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Upload business logo (base64 stored in DB — Business tier only)
app.post('/api/business/:code/logo', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) return res.status(403).json({ error: 'Access denied' });
  try {
    const plan = await getEffectivePlan(req.session.biz_id);
    if (plan !== 'business') return res.status(403).json({ error: 'Business plan required', code: 'PLAN_LIMIT' });
    const { logo } = req.body;
    if (logo === null) {   // Remove logo
      await pool.query('UPDATE businesses SET logo_url=NULL WHERE code=$1', [req.params.code]);
      return res.json({ success: true });
    }
    if (typeof logo !== 'string' || !logo) return res.status(400).json({ error: 'logo required' });
    if (logo.length > 500000) return res.status(400).json({ error: 'Logo too large — max 500KB' });
    // Whitelist: only real PNG/JPEG/WebP data URLs (no SVG or anything that could carry script)
    if (!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/]+={0,2}$/.test(logo)) return res.status(400).json({ error: 'Logo must be a PNG, JPG or WebP image' });
    await pool.query('UPDATE businesses SET logo_url=$1 WHERE code=$2', [logo, req.params.code]);
    res.json({ success: true });
  } catch(e) { console.error('Logo save error:', e.message); res.status(500).json({ error: 'Could not save the logo. Please try again.' }); }
});

app.get('/api/business/:code/logo', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) return res.status(403).json({ error: 'Access denied' });
  try {
    const r = await pool.query('SELECT logo_url FROM businesses WHERE code=$1', [req.params.code]);
    res.json({ logo: r.rows[0]?.logo_url || null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// >>> PAYROLL_CORE_BEGIN >>>
var PAYROLL_RULES = {
  // Albanian rules by effective year. When rates change, ADD a new year; never edit a past year,
  // so older months can still be calculated with the rules that applied then.
  2026: {
    minBase: 50000,       // minimum monthly contribution base (L)
    maxBase: 186416,      // maximum monthly contribution base (L)
    empSocial: 0.095,     // employee social insurance
    empHealth: 0.017,     // employee health insurance
    emplrSocial: 0.15,    // employer social insurance
    emplrHealth: 0.017,   // employer health insurance
    pit: {                // income tax (TAP) bands
      exemptUpTo: 50000,
      band1UpTo: 60000, band1Deduct: 35000,
      band2UpTo: 200000, band2Deduct: 30000,
      rate: 0.13,
      topBase: 22100, topRate: 0.23
    }
  }
};

function payrollRound(n) { return Math.round((Number(n) + Number.EPSILON) * 100) / 100; }
function payrollLek(n) { return 'L ' + Math.round(Number(n) || 0).toLocaleString('en-US'); }

// Pick the rules in force for a month ('YYYY-MM'). Falls back to the nearest known year and says so.
function payrollRulesFor(month) {
  var year = parseInt(String(month || '').slice(0, 4), 10);
  var years = Object.keys(PAYROLL_RULES).map(Number).sort(function (a, b) { return a - b; });
  if (!year) return { rules: PAYROLL_RULES[years[years.length - 1]], year: years[years.length - 1], requested: null, exact: true };
  var use = years[0];
  years.forEach(function (y) { if (y <= year) use = y; });
  return { rules: PAYROLL_RULES[use], year: use, requested: year, exact: use === year };
}

// calcPayroll({ gross, month }) -> amounts + warnings. Never hides a problem:
// a negative net stays negative and is flagged; every assumption is reported in warnings.
function calcPayroll(input) {
  input = input || {};
  var sel = payrollRulesFor(input.month);
  var R = sel.rules;
  var warnings = [];
  function warn(code, level, en, sq) { warnings.push({ code: code, level: level, en: en, sq: sq }); }

  var gross = Number(input.gross);
  if (!isFinite(gross)) gross = 0;
  if (gross < 0) {
    warn('NEGATIVE_GROSS', 'error',
      'Deductions exceed earnings this month (' + payrollLek(gross) + '). Treated as L 0 — review the deductions.',
      'Zbritjet tejkalojnë të ardhurat këtë muaj (' + payrollLek(gross) + '). Trajtohet si L 0 — rishikoni zbritjet.');
    gross = 0;
  }
  if (!sel.exact) {
    warn('RULES_YEAR_FALLBACK', 'info',
      'No payroll rules stored for ' + sel.requested + '; using the ' + sel.year + ' rates.',
      'Nuk ka rregulla të ruajtura për vitin ' + sel.requested + '; përdoren normat e vitit ' + sel.year + '.');
  }

  var out = {
    gross: payrollRound(gross), base: 0, rulesYear: sel.year,
    empSocial: 0, empHealth: 0, empTotal: 0,
    emplrSocial: 0, emplrHealth: 0, emplrTotal: 0,
    pit: 0, net: payrollRound(gross), employerCost: payrollRound(gross),
    effectiveRate: 0, warnings: warnings
  };

  if (gross === 0) {
    warn('NO_PAY', 'info', 'No pay this month — no contributions calculated.', 'Pa pagë këtë muaj — nuk llogariten kontribute.');
    return out;
  }

  var base = Math.min(Math.max(gross, R.minBase), R.maxBase);
  out.base = base;
  out.empSocial = payrollRound(base * R.empSocial);
  out.empHealth = payrollRound(base * R.empHealth);
  out.empTotal = payrollRound(out.empSocial + out.empHealth);
  out.emplrSocial = payrollRound(base * R.emplrSocial);
  out.emplrHealth = payrollRound(base * R.emplrHealth);
  out.emplrTotal = payrollRound(out.emplrSocial + out.emplrHealth);

  var p = R.pit, pit;
  if (gross <= p.exemptUpTo) pit = 0;
  else if (gross <= p.band1UpTo) pit = (gross - p.band1Deduct) * p.rate;
  else if (gross <= p.band2UpTo) pit = (gross - p.band2Deduct) * p.rate;
  else pit = p.topBase + (gross - p.band2UpTo) * p.topRate;
  out.pit = payrollRound(pit);

  out.net = payrollRound(gross - out.empTotal - out.pit);          // deliberately NOT clamped at zero
  out.employerCost = payrollRound(gross + out.emplrTotal);
  out.effectiveRate = (out.empTotal + out.pit) / gross * 100;

  if (gross < R.minBase) {
    warn('MIN_BASE_APPLIED', 'warn',
      'Gross pay (' + payrollLek(gross) + ') is below the ' + payrollLek(R.minBase) + ' minimum contribution base, so contributions use ' + payrollLek(R.minBase) + '. Part-time or short-hour contracts may be treated differently — confirm with your accountant.',
      'Paga bruto (' + payrollLek(gross) + ') është nën bazën minimale të kontributeve (' + payrollLek(R.minBase) + '), ndaj kontributet llogariten mbi ' + payrollLek(R.minBase) + '. Kontratat me orar të shkurtuar mund të trajtohen ndryshe — konfirmojeni me llogaritarin.');
  }
  if (gross > R.maxBase) {
    warn('CAP_APPLIED', 'info',
      'Gross pay is above the ' + payrollLek(R.maxBase) + ' maximum base; contributions are capped at the maximum.',
      'Paga bruto tejkalon bazën maksimale (' + payrollLek(R.maxBase) + '); kontributet llogariten mbi bazën maksimale.');
  }
  if (out.empTotal > gross) {
    warn('CONTRIB_EXCEEDS_GROSS', 'error',
      'Employee contributions (' + payrollLek(out.empTotal) + ') exceed gross pay (' + payrollLek(gross) + '). Net pay is negative — check the contract type and contribution base before filing.',
      'Kontributet e punonjësit (' + payrollLek(out.empTotal) + ') tejkalojnë pagën bruto (' + payrollLek(gross) + '). Paga neto del negative — kontrolloni llojin e kontratës dhe bazën e kontributeve para dorëzimit.');
  }
  return out;
}

// Short text for a CSV/notes cell. lang: 'sq' or 'en'. Skips plain "info" notes unless asked.
function payrollNotes(result, lang, includeInfo) {
  return result.warnings
    .filter(function (w) { return includeInfo || w.level !== 'info'; })
    .map(function (w) { return w[lang === 'en' ? 'en' : 'sq']; })
    .join(' | ');
}
// <<< PAYROLL_CORE_END <<<

// Tatimet monthly declaration export (DSH)
// Returns all data needed for the Albanian social security & health insurance declaration
app.get('/api/business/:code/tatimet', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { month } = req.query; // format: YYYY-MM
  if (!month) return res.status(400).json({ error: 'month required (YYYY-MM)' });
  try {
    // Get all employees with their shifts for the month
    const empsResult = await pool.query(
      'SELECT id, name, role, rate FROM employees WHERE business_id=$1 ORDER BY name ASC',
      [req.session.biz_id]
    );
    const shiftsResult = await pool.query(
      `SELECT emp_id,
        ROUND(SUM(regular_hours::numeric),2) as reg_h,
        ROUND(SUM(ot_hours::numeric),2) as ot_h,
        ROUND(SUM(hours::numeric),2) as total_h
       FROM shifts
       WHERE business_id=$1 AND LEFT(date,7)=$2 AND check_out IS NOT NULL
       GROUP BY emp_id`,
      [req.session.biz_id, month]
    );
    const dedsResult = await pool.query(
      `SELECT emp_id, type, SUM(amount::numeric) as total
       FROM deductions WHERE business_id=$1 AND month=$2
       GROUP BY emp_id, type`,
      [req.session.biz_id, month]
    );

    const shiftMap = {};
    shiftsResult.rows.forEach(s => { shiftMap[s.emp_id] = s; });
    const dedMap = {};
    dedsResult.rows.forEach(d => {
      if (!dedMap[d.emp_id]) dedMap[d.emp_id] = { bonus: 0, deduction: 0 };
      if (d.type === 'bonus') dedMap[d.emp_id].bonus += parseFloat(d.total);
      else dedMap[d.emp_id].deduction += parseFloat(d.total);
    });

    const rows = empsResult.rows.map(emp => {
      const shift = shiftMap[emp.id] || { reg_h: 0, ot_h: 0, total_h: 0 };
      const ded = dedMap[emp.id] || { bonus: 0, deduction: 0 };
      const rate = parseFloat(emp.rate) || 0;
      const regH = parseFloat(shift.reg_h) || 0;
      const otH = parseFloat(shift.ot_h) || 0;
      const rawGross = (regH * rate) + (otH * rate * 1.5) + ded.bonus - ded.deduction;
      const p = calcPayroll({ gross: rawGross, month });   // shared rules: see PAYROLL_CORE
      return {
        keep: rawGross !== 0,   // no pay and no deductions this month = nothing to declare
        name: emp.name,
        role: emp.role || '',
        totalHours: parseFloat(shift.total_h) || 0,
        grossSalary: p.gross,
        base: p.base,
        empSocialIns: p.empSocial, empHealthIns: p.empHealth, empTotalIns: p.empTotal,
        emplrSocialIns: p.emplrSocial, emplrHealthIns: p.emplrHealth, emplrTotalIns: p.emplrTotal,
        totalInsurance: payrollRound(p.empTotal + p.emplrTotal),
        incomeTax: p.pit,
        netPay: p.net,
        totalEmployerCost: p.employerCost,
        notes: payrollNotes(p, 'sq')
      };
    }).filter(r => r.keep).map(r => { delete r.keep; return r; });

    res.json({ month, rows, generatedAt: new Date().toISOString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Payroll history archive — all months with shift data (Business tier only)
app.get('/api/business/:code/payroll-history', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) return res.status(403).json({ error: 'Access denied' });
  const plan = await getEffectivePlan(req.session.biz_id);
  if (plan !== 'business') return res.status(403).json({ error: 'Business plan required', code: 'PLAN_LIMIT' });
  try {
    const r = await pool.query(
      `SELECT LEFT(date,7) as month, COUNT(*)::int as shifts, ROUND(SUM(hours::numeric),2) as total_hours
       FROM shifts WHERE business_id=$1 AND check_out IS NOT NULL
       GROUP BY LEFT(date,7) ORDER BY month DESC`,
      [req.session.biz_id]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get current plan for a business (called on login)
app.get('/api/business/:code/plan', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, plan, pro_expires_at, currency_symbol FROM businesses WHERE code=$1', [req.params.code]);
    if(result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const plan = await getEffectivePlan(result.rows[0].id);
    res.json({ plan, pro_expires_at: result.rows[0].pro_expires_at || null, currency: result.rows[0].currency_symbol || '$' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ─── Stripe Payments ──────────────────────────────────────────────────────────

// Create Stripe checkout session
app.post('/api/stripe/create-checkout', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
    const business_code = req.session.biz_code;

    const bizResult = await pool.query('SELECT * FROM businesses WHERE code=$1', [business_code]);
    if(bizResult.rows.length === 0) return res.status(404).json({ error: 'Business not found' });
    const biz = bizResult.rows[0];

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: {
            name: 'Punëza Pro',
            description: 'Unlimited employees, payslips, scheduling and more',
          },
          unit_amount: 1000,
          recurring: { interval: 'month' },
        },
        quantity: 1,
      }],
      metadata: { business_code: business_code },
      customer_email: biz.notify_email || undefined,
      success_url: 'https://ems-frontend-five-tau.vercel.app/app.html?upgraded=1&code=' + business_code,
      cancel_url: 'https://ems-frontend-five-tau.vercel.app/app.html?code=' + business_code,
    });

    res.json({ url: session.url });
  } catch(e) {
    console.error('Stripe checkout error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Stripe webhook — upgrade business to Pro on successful payment
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch(e) {
    console.error('Webhook signature error:', e.message);
    return res.status(400).send('Webhook Error: ' + e.message);
  }

  if(event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const business_code = session.metadata.business_code;
    if(business_code) {
      try {
        // Save stripe customer + subscription IDs
        await pool.query(
          'UPDATE businesses SET plan=$1, stripe_customer_id=$2, stripe_subscription_id=$3 WHERE code=$4',
          ['pro', session.customer, session.subscription, business_code]
        );
        // Send upgrade email
        const biz = await pool.query('SELECT * FROM businesses WHERE code=$1', [business_code]);
        if(biz.rows[0]?.notify_email) {
          await sendBrevoEmail(biz.rows[0].notify_email, 'Welcome to Punëza Pro! 🎉', `
            <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:32px;">
              <h2 style="color:#1a56db;">You're now on Punëza Pro! 🎉</h2>
              <p>Your business <strong>${biz.rows[0].name}</strong> has been upgraded to Pro.</p>
              <p>You now have access to:</p>
              <ul>
                <li>Unlimited employees</li>
                <li>Payslips & tax calculator</li>
                <li>Shift scheduling</li>
                <li>Priority support</li>
              </ul>
              <a href="https://ems-frontend-five-tau.vercel.app/app.html" style="background:#1a56db;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block;margin-top:16px;">Open Punëza →</a>
            </div>
          `).catch(e => console.error('Upgrade email error:', e));
        }
        console.log('✅ Business upgraded to Pro:', business_code);
      } catch(e) {
        console.error('Webhook DB error:', e);
      }
    }
  }

  if(event.type === 'customer.subscription.deleted') {
    // Downgrade to free if subscription cancelled
    const subscription = event.data.object;
    try {
      await pool.query(
        'UPDATE businesses SET plan=$1 WHERE stripe_subscription_id=$2',
        ['free', subscription.id]
      );
      console.log('⬇️ Business downgraded to Free:', subscription.id);
    } catch(e) {
      console.error('Webhook downgrade error:', e);
    }
  }

  res.json({ received: true });
});

// Get subscription status
app.get('/api/stripe/status/:code', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const result = await pool.query(
      'SELECT plan, stripe_customer_id, stripe_subscription_id FROM businesses WHERE code=$1',
      [req.params.code]
    );
    if(result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Cancel subscription
app.post('/api/stripe/cancel', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'manager') return res.status(403).json({ error: 'Manager access required' });
    const business_code = req.session.biz_code;
    const result = await pool.query('SELECT stripe_subscription_id FROM businesses WHERE code=$1', [business_code]);
    if(!result.rows[0]?.stripe_subscription_id) return res.status(400).json({ error: 'No active subscription' });
    await stripe.subscriptions.update(result.rows[0].stripe_subscription_id, { cancel_at_period_end: true });
    res.json({ success: true, message: 'Subscription will cancel at end of billing period' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});





// ─── Manager Password Auth ─────────────────────────────────────────────────

// Register with password
app.post('/api/business/:code/set-password', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    // Only allow setting a password if one is not already set.
    // Changing an existing password must go through change-mgr-pin (requires current password).
    const existing = await pool.query('SELECT mgr_password FROM businesses WHERE code=$1', [req.params.code]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Business not found' });
    if (existing.rows[0].mgr_password) {
      return res.status(403).json({ error: 'Password already set. Use change password instead.' });
    }
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    await pool.query('UPDATE businesses SET mgr_password=$1 WHERE code=$2', [hashed, req.params.code]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Login with password
app.post('/api/business/:code/manager-login-password', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });

    // Check lockout
    const lockKey = `login_${req.params.code}_${req.ip}`;
    const lock = checkLockout(lockKey);
    if (lock.locked) return res.status(429).json({ error: `Too many failed attempts. Try again in ${lock.mins} minutes.` });

    const result = await pool.query('SELECT * FROM businesses WHERE code=$1', [req.params.code]);
    if (result.rows.length === 0) { recordFailedAttempt(lockKey); return res.status(404).json({ error: 'Invalid credentials' }); }
    const biz = result.rows[0];

    // Block suspended accounts immediately
    if (biz.is_blocked) return res.status(403).json({ error: 'This account has been suspended. Please contact Punëza support.' });

    if (!biz.mgr_password) return res.status(400).json({ error: 'No password set. Please set a password first.' });
    
    const match = await bcrypt.compare(password, biz.mgr_password);
    if (!match) { recordFailedAttempt(lockKey); return res.status(401).json({ error: 'Incorrect password' }); }
    clearAttempts(lockKey);
    
    const token = jwt.sign({ biz_code: biz.code, biz_id: biz.id, role: 'manager' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, biz_name: biz.name, biz_code: biz.code });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Forgot password - send reset email
app.post('/api/business/:code/forgot-password', loginLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const result = await pool.query('SELECT * FROM businesses WHERE code=$1', [req.params.code]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Business not found' });
    const biz = result.rows[0];
    if (!biz.notify_email) return res.status(400).json({ error: 'No email on file for this business' });
    if (!biz.notify_email || biz.notify_email.toLowerCase() !== email.toLowerCase()) {
      // Don't reveal if email exists - security best practice
      return res.json({ success: true }); // Always return success
    }

    // Generate reset token valid for 1 hour
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 3600000).toISOString();
    await pool.query('UPDATE businesses SET reset_token=$1, reset_token_expiry=$2 WHERE code=$3', [resetToken, expiry, req.params.code]);

    const resetUrl = 'https://ems-frontend-five-tau.vercel.app/reset-password.html?token=' + resetToken + '&code=' + req.params.code;
    await sendBrevoEmail(biz.notify_email, 'Reset your Punëza password', `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#fafaf8;border-radius:16px;overflow:hidden;border:1px solid #e8e6e1;">
        <div style="background:#0d0d0d;padding:20px 24px;display:flex;align-items:center;gap:8px;">
          <div style="width:8px;height:8px;background:#1a56db;border-radius:50%;"></div>
          <span style="color:#fff;font-size:18px;font-weight:800;">Punëza</span>
        </div>
        <div style="padding:28px;">
          <h2 style="font-size:20px;font-weight:800;color:#0d0d0d;margin-bottom:8px;">Reset your password</h2>
          <p style="color:#888;font-size:14px;margin-bottom:24px;">Click the button below to reset your password for <strong>${biz.name}</strong>. This link expires in 1 hour.</p>
          <a href="${resetUrl}" style="display:inline-block;background:#1a56db;color:#fff;padding:14px 28px;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px;">Reset Password →</a>
          <p style="color:#aaa;font-size:12px;margin-top:20px;">If you didn't request this, ignore this email.</p>
        </div>
      </div>
    `);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Reset password with token
app.post('/api/business/reset-password', async (req, res) => {
  try {
    const { code, token, new_password } = req.body;
    if (!code || !token || !new_password) return res.status(400).json({ error: 'Missing required fields' });
    if (new_password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const result = await pool.query('SELECT * FROM businesses WHERE code=$1 AND reset_token=$2', [code, token]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired reset link' });
    const biz = result.rows[0];
    if (new Date(biz.reset_token_expiry) < new Date()) return res.status(400).json({ error: 'Reset link has expired' });
    const hashed = await bcrypt.hash(new_password, SALT_ROUNDS);
    await pool.query('UPDATE businesses SET mgr_password=$1, reset_token=NULL, reset_token_expiry=NULL WHERE code=$2', [hashed, code]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ─── Admin: run raw SQL migration ─────────────────────────────────────────
app.post('/api/admin/run-migration', requireAdmin, async (req, res) => {
  try {
    const { sql } = req.body;
    if (!sql) return res.status(400).json({ error: 'sql required' });
    await pool.query(sql);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── TEMP: Emergency PIN reset via admin key ──────────────────────────────
app.post('/api/admin/reset-pin', requireAdmin, async (req, res) => {
  try {
    const { business_code, new_pin } = req.body;
    if (!business_code || !new_pin) return res.status(400).json({ error: 'business_code and new_pin required' });
    const hashed = await bcrypt.hash(new_pin, SALT_ROUNDS);
    await pool.query('UPDATE businesses SET mgr_pin=$1, mgr_pin_hashed=$2 WHERE code=$3', [new_pin, hashed, business_code]);
    res.json({ success: true, message: 'PIN reset for ' + business_code });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── PIN Recovery ──────────────────────────────────────────────────────────
app.post('/api/business/:code/reset-pin', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const result = await pool.query('SELECT * FROM businesses WHERE code=$1', [req.params.code]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Business not found' });
    const biz = result.rows[0];

    if (!biz.notify_email) return res.status(400).json({ error: 'No email on file for this business' });
    if (!biz.notify_email || biz.notify_email.toLowerCase() !== email.toLowerCase()) {
      // Don't reveal if email exists - security best practice
      return res.json({ success: true }); // Always return success
    }

    // Generate 6-digit temp PIN
    const tempPin = Math.floor(100000 + Math.random() * 900000).toString();
    const hashed = await bcrypt.hash(tempPin, SALT_ROUNDS);
    await pool.query('UPDATE businesses SET mgr_pin=$1, mgr_pin_hashed=$2 WHERE code=$3', [tempPin, hashed, req.params.code]);

    await sendBrevoEmail(biz.notify_email, 'Your Punëza temporary PIN', `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#fafaf8;border-radius:16px;overflow:hidden;border:1px solid #e8e6e1;">
        <div style="background:#0d0d0d;padding:20px 24px;display:flex;align-items:center;gap:8px;">
          <div style="width:8px;height:8px;background:#1a56db;border-radius:50%;"></div>
          <span style="color:#fff;font-size:18px;font-weight:800;">Punëza</span>
        </div>
        <div style="padding:28px;">
          <h2 style="font-size:20px;font-weight:800;color:#0d0d0d;margin-bottom:8px;">Your temporary PIN</h2>
          <p style="color:#888;font-size:14px;margin-bottom:24px;">Use this PIN to log in to <strong>${biz.name}</strong>. Change it immediately after logging in.</p>
          <div style="background:#fff;border:2px solid #1a56db;border-radius:12px;padding:20px;text-align:center;margin-bottom:24px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:36px;font-weight:800;color:#1a56db;letter-spacing:8px;">${tempPin}</div>
          </div>
          <p style="color:#aaa;font-size:12px;">If you didn't request this, someone may be trying to access your account. Change your PIN immediately.</p>
          <a href="https://ems-frontend-five-tau.vercel.app/app.html" style="display:inline-block;margin-top:16px;background:#0d0d0d;color:#fff;padding:12px 24px;border-radius:10px;text-decoration:none;font-weight:600;font-size:14px;">Open Punëza →</a>
        </div>
      </div>
    `);

    res.json({ success: true });
  } catch(e) {
    console.error('PIN reset error:', e);
    res.status(500).json({ error: e.message });
  }
});





// ─── One-time migration endpoint ──────────────────────────────────────────
app.post('/api/admin/migrate', requireAdmin, async (req, res) => {
  try {
    const results = [];
    const migrations = [
      'ALTER TABLE employees ADD COLUMN IF NOT EXISTS qr_token TEXT',
      'ALTER TABLE employees ADD COLUMN IF NOT EXISTS phone TEXT',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS mgr_password TEXT',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS reset_token TEXT',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS reset_token_expiry TIMESTAMPTZ',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS pro_expires_at TIMESTAMPTZ',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS pro_reminder_sent_at TIMESTAMPTZ',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS logo_url TEXT',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT FALSE',
      "ALTER TABLE businesses ADD COLUMN IF NOT EXISTS currency_symbol TEXT DEFAULT '$'",
      'ALTER TABLE leaves ADD COLUMN IF NOT EXISTS status TEXT DEFAULT \'pending\'',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT',
      'ALTER TABLE businesses ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT',
      'ALTER TABLE businesses ALTER COLUMN mgr_pin_hashed TYPE TEXT USING NULL',
      // Remove open shifts that merely duplicate another shift's identical check-in (double-tap leftovers)
      'DELETE FROM shifts s WHERE s.check_out IS NULL AND EXISTS (SELECT 1 FROM shifts t WHERE t.emp_id = s.emp_id AND t.date = s.date AND t.check_in = s.check_in AND t.id <> s.id AND (t.check_out IS NOT NULL OR t.id < s.id))',
      'CREATE UNIQUE INDEX IF NOT EXISTS uniq_open_shift_per_day ON shifts (emp_id, date) WHERE check_out IS NULL',
      // Remove duplicate leaves for the same person and day (keeps the approved one, otherwise the earliest)
      "DELETE FROM leaves l USING leaves k WHERE l.emp_id = k.emp_id AND l.date = k.date AND l.id <> k.id AND l.status IS DISTINCT FROM 'rejected' AND k.status IS DISTINCT FROM 'rejected' AND ((k.status = 'approved' AND l.status IS DISTINCT FROM 'approved') OR (k.status IS NOT DISTINCT FROM l.status AND k.id < l.id))",
      "CREATE UNIQUE INDEX IF NOT EXISTS uniq_leave_per_day ON leaves (emp_id, date) WHERE status IS DISTINCT FROM 'rejected'"
    ];
    for (const sql of migrations) {
      try { const r = await pool.query(sql); results.push({ sql: sql.slice(0,50), ok: true, rows: r.rowCount }); }
      catch(e) { results.push({ sql: sql.slice(0,50), error: e.message }); }
    }
    res.json({ success: true, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Generate QR tokens for employees that don't have one ─────────────────
// (generate-qr-tokens route removed — QR check-in was replaced by PIN check-in; nothing calls this anymore)


// ─── Set Manager PIN (first time / onboarding) ────────────────────────────
app.post('/api/business/:code/set-mgr-pin', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) return res.status(403).json({ error: 'Access denied' });
  try {
    const { pin } = req.body;
    if (!pin || pin.length < 4) return res.status(400).json({ error: 'PIN must be at least 4 digits' });
    const hashed = await bcrypt.hash(pin, SALT_ROUNDS);
    await pool.query('UPDATE businesses SET mgr_pin=$1, mgr_pin_hashed=$2 WHERE code=$3', [pin, hashed, req.params.code]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Logout — invalidates session
app.post('/api/logout', requireAuth, (req, res) => {
  req.session = null;
  res.json({ success: true });
});


// ─── Late Check-in Alert Email ────────────────────────────────────────────
async function sendLateAlert(biz, emp, scheduledStart, actualCheckin, lateMinutes) {
  if (!biz.notify_email) return;
  const html = `
  <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#fafaf8;border-radius:16px;overflow:hidden;border:1px solid #e8e6e1;">
    <div style="background:#0d0d0d;padding:18px 24px;display:flex;align-items:center;gap:8px;">
      <div style="width:8px;height:8px;background:#1a56db;border-radius:50%;"></div>
      <span style="color:#fff;font-size:17px;font-weight:800;">Punëza</span>
      <span style="color:#888;font-size:11px;margin-left:auto;font-family:monospace;">LATE ALERT</span>
    </div>
    <div style="padding:24px;">
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:12px;padding:16px;margin-bottom:20px;">
        <div style="font-size:13px;font-weight:700;color:#dc2626;margin-bottom:4px;">⚠️ Late Check-in</div>
        <div style="font-size:22px;font-weight:800;color:#0d0d0d;">${emp.name}</div>
        <div style="font-family:monospace;font-size:12px;color:#888;margin-top:4px;">${emp.role || 'Staff'}</div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:20px;">
        <div style="background:#fff;border:1px solid #e8e6e1;border-radius:10px;padding:12px;text-align:center;">
          <div style="font-size:18px;font-weight:800;color:#1a56db;">${scheduledStart}</div>
          <div style="font-family:monospace;font-size:9px;color:#888;margin-top:3px;">SCHEDULED</div>
        </div>
        <div style="background:#fff;border:1px solid #e8e6e1;border-radius:10px;padding:12px;text-align:center;">
          <div style="font-size:18px;font-weight:800;color:#dc2626;">${actualCheckin}</div>
          <div style="font-family:monospace;font-size:9px;color:#888;margin-top:3px;">CHECKED IN</div>
        </div>
        <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:12px;text-align:center;">
          <div style="font-size:18px;font-weight:800;color:#dc2626;">+${lateMinutes}m</div>
          <div style="font-family:monospace;font-size:9px;color:#888;margin-top:3px;">LATE</div>
        </div>
      </div>
      <a href="https://ems-frontend-five-tau.vercel.app/app.html" style="display:inline-block;background:#0d0d0d;color:#fff;padding:12px 24px;border-radius:10px;text-decoration:none;font-weight:600;font-size:14px;">View Dashboard →</a>
    </div>
    <div style="padding:14px 24px;border-top:1px solid #e8e6e1;font-size:10px;color:#aaa;font-family:monospace;">Punëza · ${biz.name}</div>
  </div>`;
  
  await sendBrevoEmail(biz.notify_email, `⚠️ ${emp.name} checked in ${lateMinutes} minutes late`, html).catch(e => console.error('Late alert email error:', e));
}

// ─── Change Manager PIN ────────────────────────────────────────────────────
app.post('/api/business/:code/change-mgr-pin', loginLimiter, async (req, res) => {
  try {
    const { current_pin, new_pin } = req.body;
    if (!current_pin || !new_pin) return res.status(400).json({ error: 'Both fields required' });
    if (new_pin.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const result = await pool.query('SELECT mgr_password, mgr_pin, mgr_pin_hashed FROM businesses WHERE code=$1', [req.params.code]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const biz = result.rows[0];

    // Verify current password (try mgr_password first, then legacy mgr_pin_hashed)
    let match = false;
    if (biz.mgr_password) {
      match = await bcrypt.compare(current_pin, biz.mgr_password);
    } else if (biz.mgr_pin_hashed) {
      match = await bcrypt.compare(current_pin, biz.mgr_pin_hashed);
    } else if (biz.mgr_pin) {
      match = biz.mgr_pin === current_pin;
    } else {
      match = true;
    }
    if (!match) return res.status(401).json({ error: 'Current password is incorrect' });

    // Hash new password
    const hashed = await bcrypt.hash(new_pin, SALT_ROUNDS);
    await pool.query('UPDATE businesses SET mgr_password=$1 WHERE code=$2', [hashed, req.params.code]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});



// ─── Onboarding Email Sequence ────────────────────────────────────────────
async function sendOnboardingSequence(email, bizName, bizCode) {
  if (!email) return;

  // Day 1 - Welcome (sent immediately via welcome email)
  // Day 3 - Tips
  setTimeout(async () => {
    try {
      await sendBrevoEmail(email, `💡 3 tips to get the most out of Punëza`, `
      <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#fafaf8;border-radius:16px;overflow:hidden;border:1px solid #e8e6e1;">
        <div style="background:#0d0d0d;padding:18px 24px;display:flex;align-items:center;gap:8px;">
          <div style="width:8px;height:8px;background:#1a56db;border-radius:50%;"></div>
          <span style="color:#fff;font-size:17px;font-weight:800;">Punëza</span>
        </div>
        <div style="padding:24px;">
          <div style="font-size:18px;font-weight:800;margin-bottom:6px;">You've been using Punëza for 3 days 🎉</div>
          <div style="font-size:14px;color:#888;margin-bottom:24px;">Here are 3 tips to get even more out of it:</div>
          <div style="display:flex;flex-direction:column;gap:16px;">
            <div style="display:flex;gap:12px;align-items:flex-start;">
              <div style="font-size:24px;">📱</div>
              <div><div style="font-weight:700;margin-bottom:4px;">Share QR codes with your team</div><div style="font-size:13px;color:#888;">Go to STAFF tab, tap QR next to each employee, and share the link. They can check in/out from their phone without a PIN.</div></div>
            </div>
            <div style="display:flex;gap:12px;align-items:flex-start;">
              <div style="font-size:24px;">🗓</div>
              <div><div style="font-weight:700;margin-bottom:4px;">Set up schedules for late alerts</div><div style="font-size:13px;color:#888;">Go to SCHED tab and assign shifts. When employees check in late, you'll get an instant email alert.</div></div>
            </div>
            <div style="display:flex;gap:12px;align-items:flex-start;">
              <div style="font-size:24px;">📊</div>
              <div><div style="font-weight:700;margin-bottom:4px;">Export payroll at month end</div><div style="font-size:13px;color:#888;">Go to REPORT tab, select the month, and download the payroll CSV. Share it with your accountant.</div></div>
            </div>
          </div>
          <div style="margin-top:24px;">
            <a href="https://ems-frontend-five-tau.vercel.app/app.html" style="display:inline-block;background:#0d0d0d;color:#fff;padding:12px 24px;border-radius:10px;text-decoration:none;font-weight:600;font-size:14px;">Open Punëza →</a>
          </div>
        </div>
      </div>`);
    } catch(e) { console.error('Day 3 email error:', e.message); }
  }, 3 * 24 * 60 * 60 * 1000); // 3 days

  // Day 7 - Check in
  setTimeout(async () => {
    try {
      await sendBrevoEmail(email, `How is Punëza working for ${bizName}?`, `
      <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#fafaf8;border-radius:16px;overflow:hidden;border:1px solid #e8e6e1;">
        <div style="background:#0d0d0d;padding:18px 24px;display:flex;align-items:center;gap:8px;">
          <div style="width:8px;height:8px;background:#1a56db;border-radius:50%;"></div>
          <span style="color:#fff;font-size:17px;font-weight:800;">Punëza</span>
        </div>
        <div style="padding:24px;">
          <div style="font-size:18px;font-weight:800;margin-bottom:6px;">You've been using Punëza for 1 week!</div>
          <div style="font-size:14px;color:#888;line-height:1.7;margin-bottom:20px;">How is it going? We'd love to hear your feedback. Reply to this email with any questions, suggestions, or issues — we read every message.</div>
          <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:16px;margin-bottom:20px;">
            <div style="font-weight:700;margin-bottom:4px;font-size:14px;">Need unlimited employees?</div>
            <div style="font-size:13px;color:#888;margin-bottom:10px;">Upgrade to Pro for just €10/month and add as many staff as you need.</div>
            <a href="https://ems-frontend-five-tau.vercel.app/app.html" style="display:inline-block;background:#1a56db;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:13px;">Upgrade to Pro →</a>
          </div>
          <a href="https://ems-frontend-five-tau.vercel.app/app.html" style="display:inline-block;background:#0d0d0d;color:#fff;padding:12px 24px;border-radius:10px;text-decoration:none;font-weight:600;font-size:14px;">Open Punëza →</a>
        </div>
      </div>`);
    } catch(e) { console.error('Day 7 email error:', e.message); }
  }, 7 * 24 * 60 * 60 * 1000); // 7 days
}

// ─── Daily Digest Email (call this at 6pm) ────────────────────────────────
async function sendDailyDigest(bizCode) {
  try {
    const bizResult = await pool.query('SELECT * FROM businesses WHERE code=$1', [bizCode]);
    if (!bizResult.rows[0] || !bizResult.rows[0].notify_email) return;
    const biz = bizResult.rows[0];
    const today = new Date().toLocaleDateString('en-CA');
    
    const empsResult = await pool.query('SELECT * FROM employees WHERE business_id=$1', [biz.id]);
    const shiftsResult = await pool.query('SELECT * FROM shifts WHERE business_id=$1 AND date=$2', [biz.id, today]);
    
    const emps = empsResult.rows;
    const shifts = shiftsResult.rows;
    const onShift = shifts.filter(s => s.check_in && !s.check_out);
    const completed = shifts.filter(s => s.check_out);
    const totalHours = completed.reduce((a,s) => a + (parseFloat(s.hours)||0), 0);
    const lateCount = shifts.filter(s => s.is_late).length;
    const notWorked = emps.filter(e => !shifts.find(s => s.emp_id === e.id));

    let rows = '';
    emps.forEach(emp => {
      const shift = shifts.find(s => s.emp_id === emp.id);
      const status = shift ? (shift.check_out ? `✓ ${shift.check_in}–${shift.check_out} (${parseFloat(shift.hours||0).toFixed(1)}h)` : `⏳ Since ${shift.check_in}`) : '✗ Not in';
      const late = shift && shift.is_late ? ` <span style="color:#dc2626;">+${shift.late_minutes}m late</span>` : '';
      rows += `<tr>
        <td style="padding:8px 12px;border-bottom:1px solid #f2f1ee;font-weight:600;">${emp.name}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #f2f1ee;font-family:monospace;font-size:12px;">${emp.role||''}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #f2f1ee;font-family:monospace;font-size:12px;">${status}${late}</td>
      </tr>`;
    });

    const html = `
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#fafaf8;border-radius:16px;overflow:hidden;border:1px solid #e8e6e1;">
      <div style="background:#0d0d0d;padding:18px 24px;display:flex;align-items:center;gap:8px;">
        <div style="width:8px;height:8px;background:#1a56db;border-radius:50%;"></div>
        <span style="color:#fff;font-size:17px;font-weight:800;">Punëza</span>
        <span style="color:#888;font-size:11px;margin-left:auto;font-family:monospace;">DAILY DIGEST</span>
      </div>
      <div style="padding:24px;">
        <div style="font-size:18px;font-weight:800;margin-bottom:4px;">Daily Summary</div>
        <div style="font-family:monospace;font-size:11px;color:#888;margin-bottom:20px;">${biz.name} · ${today}</div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px;">
          <div style="background:#fff;border:1px solid #e8e6e1;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:800;color:#1a56db;">${completed.length}</div>
            <div style="font-family:monospace;font-size:9px;color:#888;">WORKED</div>
          </div>
          <div style="background:#fff;border:1px solid #e8e6e1;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:800;color:#0891b2;">${onShift.length}</div>
            <div style="font-family:monospace;font-size:9px;color:#888;">ON SHIFT</div>
          </div>
          <div style="background:#fff;border:1px solid #e8e6e1;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:800;color:#16a34a;">${totalHours.toFixed(1)}h</div>
            <div style="font-family:monospace;font-size:9px;color:#888;">TOTAL HRS</div>
          </div>
          <div style="background:${lateCount>0?'#fef2f2':'#f0fdf4'};border:1px solid ${lateCount>0?'#fecaca':'#bbf7d0'};border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:800;color:${lateCount>0?'#dc2626':'#16a34a'};">${lateCount}</div>
            <div style="font-family:monospace;font-size:9px;color:#888;">LATE</div>
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e8e6e1;border-radius:10px;overflow:hidden;">
          <thead>
            <tr style="background:#f2f1ee;">
              <th style="padding:8px 12px;text-align:left;font-family:monospace;font-size:10px;color:#888;">EMPLOYEE</th>
              <th style="padding:8px 12px;text-align:left;font-family:monospace;font-size:10px;color:#888;">ROLE</th>
              <th style="padding:8px 12px;text-align:left;font-family:monospace;font-size:10px;color:#888;">STATUS</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
        <div style="margin-top:20px;">
          <a href="https://ems-frontend-five-tau.vercel.app/app.html" style="display:inline-block;background:#0d0d0d;color:#fff;padding:11px 22px;border-radius:10px;text-decoration:none;font-weight:600;font-size:13px;">Open Punëza →</a>
        </div>
      </div>
    </div>`;

    await sendBrevoEmail(biz.notify_email, `📊 Daily Summary — ${biz.name} · ${today}`, html);
    console.log(`Daily digest sent to ${biz.notify_email}`);
  } catch(e) {
    console.error('Daily digest error:', e.message);
  }
}

// ─── Daily Digest Route ────────────────────────────────────────────────────
app.post('/api/business/:code/send-daily-digest', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) return res.status(403).json({ error: 'Access denied' });
  try {
    await sendDailyDigest(req.params.code);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Scheduled Daily Digest (runs at 6pm server time) ─────────────────────
// Checks every hour for Pro businesses expiring within 3 days that haven't been reminded yet for this billing period
function scheduleExpiryReminders() {
  setInterval(async () => {
    try {
      const soon = await pool.query(`
        SELECT id, code, name, notify_email, pro_expires_at, plan
        FROM businesses
        WHERE plan IN ('pro','business')
          AND pro_expires_at IS NOT NULL
          AND pro_expires_at > NOW()
          AND pro_expires_at <= NOW() + INTERVAL '3 days'
          AND pro_reminder_sent_at IS NULL
          AND notify_email IS NOT NULL AND notify_email != ''
      `);
      for (const biz of soon.rows) {
        const daysLeft = Math.max(1, Math.ceil((new Date(biz.pro_expires_at) - new Date()) / (1000*60*60*24)));
        await sendExpiryReminderEmail(biz.notify_email, biz.name, biz.pro_expires_at, daysLeft, biz.plan === 'business' ? 'Business' : 'Pro');
        await pool.query('UPDATE businesses SET pro_reminder_sent_at=NOW() WHERE id=$1', [biz.id]);
        await new Promise(r => setTimeout(r, 1000));
      }
      if (soon.rows.length > 0) console.log(`Sent ${soon.rows.length} Pro expiry reminder(s)`);
    } catch(e) { console.error('Expiry reminder scheduler error:', e); }
  }, 60 * 60 * 1000); // check once per hour
}

function scheduleDailyDigests() {
  setInterval(async () => {
    const now = new Date();
    if (now.getHours() === 18 && now.getMinutes() === 0) {
      try {
        const businesses = await pool.query("SELECT code FROM businesses WHERE notify_email IS NOT NULL AND notify_email != ''");
        for (const biz of businesses.rows) {
          await sendDailyDigest(biz.code);
          await new Promise(r => setTimeout(r, 1000)); // 1s delay between emails
        }
        console.log(`Daily digests sent to ${businesses.rows.length} businesses`);
      } catch(e) { console.error('Scheduled digest error:', e); }
    }
  }, 60000); // Check every minute
}

// ─── Weekly Summary Email ──────────────────────────────────────────────────
app.post('/api/business/:code/send-weekly-summary', requireAuth, async (req, res) => {
  if (req.session.role !== 'manager' || req.session.biz_code !== req.params.code) return res.status(403).json({ error: 'Access denied' });
  try {
    const bizResult = await pool.query('SELECT * FROM businesses WHERE code=$1', [req.params.code]);
    if (bizResult.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const biz = bizResult.rows[0];
    if (!biz.notify_email) return res.status(400).json({ error: 'No email on file' });

    // Get last week's data
    const today = new Date();
    const lastMonday = new Date(today);
    lastMonday.setDate(today.getDate() - today.getDay() - 6);
    const lastSunday = new Date(lastMonday);
    lastSunday.setDate(lastMonday.getDate() + 6);
    const fmt = d => d.toISOString().slice(0,10);

    const shiftsResult = await pool.query(
      'SELECT s.*, e.name as emp_name, e.rate FROM shifts s JOIN employees e ON s.emp_id=e.id WHERE s.business_id=$1 AND s.date>=$2 AND s.date<=$3 AND s.check_out IS NOT NULL',
      [biz.id, fmt(lastMonday), fmt(lastSunday)]
    );
    const empsResult = await pool.query('SELECT * FROM employees WHERE business_id=$1', [biz.id]);
    const shifts = shiftsResult.rows;
    const emps = empsResult.rows;

    const totalHours = shifts.reduce((a,s) => a + (parseFloat(s.hours)||0), 0);
    const totalPay = shifts.reduce((a,s) => a + (parseFloat(s.hours)||0) * (parseFloat(s.rate)||0), 0);
    const uniqueWorked = new Set(shifts.map(s => s.emp_id)).size;

    let empRows = emps.map(emp => {
      const empShifts = shifts.filter(s => s.emp_id === emp.id);
      const hours = empShifts.reduce((a,s) => a + (parseFloat(s.hours)||0), 0);
      const pay = hours * (parseFloat(emp.rate)||0);
      return `<tr><td style="padding:8px;border-bottom:1px solid #e8e6e1;">${emp.name}</td><td style="padding:8px;border-bottom:1px solid #e8e6e1;text-align:center;">${empShifts.length}</td><td style="padding:8px;border-bottom:1px solid #e8e6e1;text-align:center;">${hours.toFixed(1)}h</td><td style="padding:8px;border-bottom:1px solid #e8e6e1;text-align:right;">L ${pay.toFixed(2)}</td></tr>`;
    }).join('');

    const html = `
    <div style="font-family:'Outfit',sans-serif;max-width:580px;margin:0 auto;background:#fafaf8;border-radius:16px;overflow:hidden;border:1px solid #e8e6e1;">
      <div style="background:#0d0d0d;padding:24px 28px;display:flex;align-items:center;gap:8px;">
        <div style="width:10px;height:10px;background:#1a56db;border-radius:50%;"></div>
        <span style="color:#fff;font-size:20px;font-weight:800;letter-spacing:-0.5px;">Punëza</span>
        <span style="color:#888;font-size:12px;margin-left:auto;font-family:'JetBrains Mono',monospace;">WEEKLY SUMMARY</span>
      </div>
      <div style="padding:28px;">
        <h2 style="font-size:22px;font-weight:800;color:#0d0d0d;margin-bottom:4px;">Week of ${lastMonday.getDate()} ${lastMonday.toLocaleString('default',{month:'long'})}</h2>
        <p style="color:#888;font-size:13px;margin-bottom:24px;">${biz.name}</p>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px;">
          <div style="background:#fff;border:1px solid #e8e6e1;border-radius:12px;padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:800;color:#1a56db;">${totalHours.toFixed(0)}h</div>
            <div style="font-size:10px;color:#888;font-family:'JetBrains Mono',monospace;margin-top:4px;">TOTAL HOURS</div>
          </div>
          <div style="background:#fff;border:1px solid #e8e6e1;border-radius:12px;padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:800;color:#16a34a;">L ${totalPay.toFixed(0)}</div>
            <div style="font-size:10px;color:#888;font-family:'JetBrains Mono',monospace;margin-top:4px;">TOTAL PAY</div>
          </div>
          <div style="background:#fff;border:1px solid #e8e6e1;border-radius:12px;padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:800;color:#d97706;">${uniqueWorked}/${emps.length}</div>
            <div style="font-size:10px;color:#888;font-family:'JetBrains Mono',monospace;margin-top:4px;">ATTENDANCE</div>
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e8e6e1;border-radius:12px;overflow:hidden;">
          <thead><tr style="background:#f2f1ee;">
            <th style="padding:10px 8px;text-align:left;font-size:10px;font-family:'JetBrains Mono',monospace;color:#888;">EMPLOYEE</th>
            <th style="padding:10px 8px;text-align:center;font-size:10px;font-family:'JetBrains Mono',monospace;color:#888;">SHIFTS</th>
            <th style="padding:10px 8px;text-align:center;font-size:10px;font-family:'JetBrains Mono',monospace;color:#888;">HOURS</th>
            <th style="padding:10px 8px;text-align:right;font-size:10px;font-family:'JetBrains Mono',monospace;color:#888;">PAY</th>
          </tr></thead>
          <tbody>${empRows}</tbody>
        </table>
        <div style="margin-top:24px;text-align:center;">
          <a href="https://ems-frontend-five-tau.vercel.app/app.html" style="background:#0d0d0d;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:600;font-size:14px;">Open Punëza →</a>
        </div>
      </div>
      <div style="padding:16px 28px;border-top:1px solid #e8e6e1;font-size:11px;color:#aaa;font-family:'JetBrains Mono',monospace;">© 2026 Punëza · You're receiving this because you're a manager at ${biz.name}</div>
    </div>`;

    await sendBrevoEmail(biz.notify_email, `Weekly Summary — ${biz.name} — w/c ${fmt(lastMonday)}`, html);
    res.json({ success: true });
  } catch(e) {
    console.error('Weekly summary error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found', path: req.path });
});

// Global error handler
app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.too.large' || err.status === 413)) return res.status(413).json({ error: 'That file is too large. Please choose a smaller image.' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid request data' });
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`🚀 Punëza API running on port ${PORT}`);
  scheduleDailyDigests();
  scheduleExpiryReminders();
  initDB().catch(e => console.error('DB init error:', e));
});
