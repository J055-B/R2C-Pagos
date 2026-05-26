const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'r2c-secret-2024';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const FIREBERRY_API = 'https://api.powerlink.co.il/api';
const FIREBERRY_TOKEN = process.env.FIREBERRY_TOKEN || '4863e71d-5503-47b3-8745-5217fe928861';
const ORDERS_OBJECT_TYPE = process.env.ORDERS_OBJECT_TYPE || '2'; // ajustar cuando se confirme

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
  const { data: user, error } = await supabase
    .from('agents').select('*').eq('username', username).single();
  if (error || !user) return res.status(401).json({ error: 'Usuario no encontrado' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });
  const token = jwt.sign({ id: user.id, username: user.username, name: user.name, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, name: user.name, is_admin: user.is_admin });
});

// ── Registro ─────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password, name, invite_code } = req.body;
  if (!username || !password || !name || !invite_code)
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  const { data: invite } = await supabase.from('invite_codes').select('*').eq('code', invite_code.toUpperCase()).eq('used', false).single();
  if (!invite) return res.status(400).json({ error: 'Código de invitación inválido o ya usado' });
  const { data: existing } = await supabase.from('agents').select('id').eq('username', username).single();
  if (existing) return res.status(409).json({ error: 'El nombre de usuario ya está en uso' });
  const password_hash = await bcrypt.hash(password, 10);
  const { data: agent, error: agentErr } = await supabase.from('agents').insert([{ username, password_hash, name, is_admin: false }]).select().single();
  if (agentErr) return res.status(500).json({ error: agentErr.message });
  await supabase.from('invite_codes').update({ used: true, used_by: agent.id, used_at: new Date().toISOString() }).eq('id', invite.id);
  const token = jwt.sign({ id: agent.id, username: agent.username, name: agent.name, is_admin: false }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, name: agent.name, is_admin: false });
});

// ── Invites (admin) ──────────────────────────────────────────
app.post('/api/invite', adminAuth, async (req, res) => {
  const code = 'R2C-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const { data } = await supabase.from('invite_codes').insert([{ code, created_by: req.user.id }]).select().single();
  res.json({ code: data.code });
});
app.get('/api/invites', adminAuth, async (req, res) => {
  const { data } = await supabase.from('invite_codes').select('*').order('created_at', { ascending: false });
  res.json(data || []);
});
app.get('/api/agents', adminAuth, async (req, res) => {
  const { data } = await supabase.from('agents').select('id, username, name, is_admin, created_at').order('created_at', { ascending: false });
  res.json(data || []);
});

// ── Clientes ─────────────────────────────────────────────────
app.get('/api/clients', auth, async (req, res) => {
  const { data } = await supabase.from('clients').select('*').eq('agent_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});

app.post('/api/clients', auth, async (req, res) => {
  const { url, object_type, record_id } = req.body;
  const { data: existing } = await supabase.from('clients').select('id').eq('agent_id', req.user.id).eq('record_id', record_id).single();
  if (existing) return res.status(409).json({ error: 'Este cliente ya está registrado' });
  const { data, error } = await supabase.from('clients').insert([{ agent_id: req.user.id, url, object_type, record_id, total_investment: 0 }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/clients/:id', auth, async (req, res) => {
  await supabase.from('clients').delete().eq('id', req.params.id).eq('agent_id', req.user.id);
  res.json({ ok: true });
});

// Actualizar inversión total (lo pone el agente manualmente)
app.patch('/api/clients/:id/investment', auth, async (req, res) => {
  const { total_investment } = req.body;
  const { data, error } = await supabase.from('clients')
    .update({ total_investment: parseFloat(total_investment) || 0 })
    .eq('id', req.params.id).eq('agent_id', req.user.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── Proxy Fireberry: registro ─────────────────────────────────
app.get('/api/fireberry/record/:objectType/:id', auth, async (req, res) => {
  try {
    const response = await fetch(`${FIREBERRY_API}/record/${req.params.objectType}/${req.params.id}`, {
      headers: { 'tokenid': FIREBERRY_TOKEN, 'Content-Type': 'application/json' }
    });
    res.json(await response.json());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Proxy Fireberry: órdenes del cliente ─────────────────────
// Busca todas las órdenes relacionadas al record_id del cliente
app.get('/api/fireberry/orders/:recordId', auth, async (req, res) => {
  try {
    const ordersType = process.env.ORDERS_OBJECT_TYPE || ORDERS_OBJECT_TYPE;
    // Intenta buscar órdenes relacionadas al account/lead
    const body = {
      objecttype: parseInt(ordersType),
      fields: ['orderid','ordernumber','createdon','totalamount','paymentmethod','description','statuscode','cf_formapago','cf_cuota','name'],
      query: `(accountid = '${req.params.recordId}') OR (regardingobjectid = '${req.params.recordId}') OR (parentaccountid = '${req.params.recordId}')`,
      pageSize: 100,
      page: 1,
      sortby: 'createdon',
      sorttype: 'ASC'
    };
    const response = await fetch(`${FIREBERRY_API}/query`, {
      method: 'POST',
      headers: { 'tokenid': FIREBERRY_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Query genérico (para explorar estructura)
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

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`R2C server running on port ${PORT}`));
