const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'r2c-secret-2024';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const FIREBERRY_API = 'https://api.powerlink.co.il/api';
const FIREBERRY_TOKEN = process.env.FIREBERRY_TOKEN || '4863e71d-5503-47b3-8745-5217fe928861';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Init DB ──────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS agents (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      is_admin BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS clients (
      id SERIAL PRIMARY KEY,
      agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      object_type TEXT NOT NULL,
      record_id TEXT NOT NULL,
      total_investment NUMERIC DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT now(),
      UNIQUE(agent_id, record_id)
    );
    CREATE TABLE IF NOT EXISTS invite_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      used BOOLEAN DEFAULT false,
      created_by UUID REFERENCES agents(id),
      used_by UUID REFERENCES agents(id),
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  // Create default admin if not exists
  const existing = await pool.query("SELECT id FROM agents WHERE username = 'joss'");
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash('35618728', 10);
    await pool.query(
      "INSERT INTO agents (username, password_hash, name, is_admin) VALUES ($1, $2, $3, true)",
      ['joss', hash, 'Joss']
    );
    console.log('Admin creado: joss');
  }
  console.log('Base de datos lista');
}

// ── Auth middleware ──────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Solo administradores' });
    next();
  });
}

// ── Login ────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM agents WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });
    const token = jwt.sign({ id: user.id, username: user.username, name: user.name, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, name: user.name, is_admin: user.is_admin });
  } catch (e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: 'Error del servidor: ' + e.message });
  }
});

// ── Registro ─────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password, name, invite_code } = req.body;
  if (!username || !password || !name || !invite_code)
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  try {
    const inv = await pool.query("SELECT * FROM invite_codes WHERE code = $1 AND used = false", [invite_code.toUpperCase()]);
    if (!inv.rows[0]) return res.status(400).json({ error: 'Código de invitación inválido o ya usado' });
    const existing = await pool.query('SELECT id FROM agents WHERE username = $1', [username]);
    if (existing.rows[0]) return res.status(409).json({ error: 'El nombre de usuario ya está en uso' });
    const hash = await bcrypt.hash(password, 10);
    const agent = await pool.query(
      'INSERT INTO agents (username, password_hash, name, is_admin) VALUES ($1, $2, $3, false) RETURNING *',
      [username, hash, name]
    );
    await pool.query('UPDATE invite_codes SET used = true, used_by = $1, used_at = now() WHERE id = $2', [agent.rows[0].id, inv.rows[0].id]);
    const token = jwt.sign({ id: agent.rows[0].id, username, name, is_admin: false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, name, is_admin: false });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Invites ──────────────────────────────────────────────────
app.post('/api/invite', adminAuth, async (req, res) => {
  const code = 'R2C-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const result = await pool.query('INSERT INTO invite_codes (code, created_by) VALUES ($1, $2) RETURNING *', [code, req.user.id]);
  res.json({ code: result.rows[0].code });
});

app.get('/api/invites', adminAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM invite_codes ORDER BY created_at DESC');
  res.json(result.rows);
});

app.get('/api/agents', adminAuth, async (req, res) => {
  const result = await pool.query('SELECT id, username, name, is_admin, created_at FROM agents ORDER BY created_at DESC');
  res.json(result.rows);
});

// ── Clientes ─────────────────────────────────────────────────
app.get('/api/clients', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM clients WHERE agent_id = $1 ORDER BY created_at DESC', [req.user.id]);
  res.json(result.rows);
});

app.post('/api/clients', auth, async (req, res) => {
  const { url, object_type, record_id } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO clients (agent_id, url, object_type, record_id, total_investment) VALUES ($1, $2, $3, $4, 0) RETURNING *',
      [req.user.id, url, object_type, record_id]
    );
    res.json(result.rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Este cliente ya está registrado' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/clients/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM clients WHERE id = $1 AND agent_id = $2', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

app.patch('/api/clients/:id/investment', auth, async (req, res) => {
  const { total_investment } = req.body;
  const result = await pool.query(
    'UPDATE clients SET total_investment = $1 WHERE id = $2 AND agent_id = $3 RETURNING *',
    [parseFloat(total_investment) || 0, req.params.id, req.user.id]
  );
  res.json(result.rows[0]);
});

// ── Proxy Fireberry ──────────────────────────────────────────
app.get('/api/fireberry/record/:objectType/:id', auth, async (req, res) => {
  try {
    const response = await fetch(`${FIREBERRY_API}/record/${req.params.objectType}/${req.params.id}`, {
      headers: { 'tokenid': FIREBERRY_TOKEN, 'Content-Type': 'application/json' }
    });
    res.json(await response.json());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/fireberry/orders/:recordId', auth, async (req, res) => {
  try {
    const body = {
      objecttype: 13,
      query: `(accountid = '${req.params.recordId}')`,
      pageSize: 100, page: 1, sortby: 'createdon', sorttype: 'ASC'
    };
    const response = await fetch(`${FIREBERRY_API}/query`, {
      method: 'POST',
      headers: { 'tokenid': FIREBERRY_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    // Fireberry returns {success, data: {Data: [...], TotalRecords: N}, message}
    const orders = data?.data?.Data || data?.Data || [];
    console.log('Orders found:', orders.length);
    res.json({ orders });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/fireberry/query', auth, async (req, res) => {
  try {
    const response = await fetch(`${FIREBERRY_API}/query`, {
      method: 'POST',
      headers: { 'tokenid': FIREBERRY_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    res.json(await response.json());
  } catch (err) { res.status(500).json({ error: err.message }); }
});


app.get('/api/debug/fireberry/:objectType/:id', async (req, res) => {
  try {
    const response = await fetch(`${FIREBERRY_API}/record/${req.params.objectType}/${req.params.id}`, {
      headers: { 'tokenid': FIREBERRY_TOKEN, 'Content-Type': 'application/json' }
    });
    const data = await response.json();
    console.log('FIREBERRY RAW:', JSON.stringify(data).substring(0, 500));
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/debug/orders/:recordId', async (req, res) => {
  try {
    const results = {};
    for (const ot of [1,2,3,4,5,6,7,8,9,10,14,15,16,17,18,19,20]) {
      const body = {
        objecttype: ot,
        query: `(accountid = '${req.params.recordId}') OR (regardingobjectid = '${req.params.recordId}') OR (contactid = '${req.params.recordId}')`,
        pageSize: 10, page: 1
      };
      const response = await fetch(`${FIREBERRY_API}/query`, {
        method: 'POST',
        headers: { 'tokenid': FIREBERRY_TOKEN, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await response.json();
      const records = data.Data || data.data || data.records || [];
      if (Array.isArray(records) && records.length > 0) {
        results[ot] = records;
        console.log(`ORDERS FOUND at objectType ${ot}:`, records.length);
      }
    }
    res.json(results);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Temp: clear all clients
app.get('/api/reset-clients', async (req, res) => {
  await pool.query('DELETE FROM clients');
  res.json({ ok: true, message: 'Todos los clientes eliminados' });
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDB().then(() => {
  app.listen(PORT, () => console.log(`R2C server running on port ${PORT}`));
}).catch(err => {
  console.error('DB init error:', err);
  process.exit(1);
});
