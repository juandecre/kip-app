const express = require('express');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kip_secret_2025';
const resend = new Resend(process.env.RESEND_API_KEY);
console.log('RESEND_API_KEY loaded:', !!process.env.RESEND_API_KEY);
if (!process.env.RESEND_API_KEY) console.error('WARNING: RESEND_API_KEY is not configured. Email verification will fail.');

// Carpeta para fotos
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `foto_${Date.now()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Solo se permiten imágenes o PDF'));
  }
});

// Base de datos
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  // Crear tabla users con todos los campos necesarios
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      apellido TEXT,
      email TEXT UNIQUE NOT NULL,
      password TEXT,
      email_verified INTEGER DEFAULT 0,
      phone TEXT,
      phone_verified INTEGER DEFAULT 0,
      role TEXT DEFAULT 'cliente',
      city TEXT,
      profile_image TEXT,
      descripcion TEXT,
      experiencia INTEGER,
      google_id TEXT,
      onboarding_complete INTEGER DEFAULT 0,
      categoria TEXT,
      verification_level TEXT DEFAULT 'none',
      verification_status TEXT DEFAULT 'pending',
      matricula TEXT,
      titulo_url TEXT,
      dni_url TEXT,
      precio_estimado TEXT,
      profile_completion INTEGER DEFAULT 0,
      localidad TEXT,
      codigo_postal TEXT,
      es_profesional INTEGER DEFAULT 0,
      pro_onboarding_step INTEGER DEFAULT 0,
      especialidad TEXT,
      telefono TEXT,
      zona TEXT,
      foto TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Intentar agregar campos que podrían faltar (por compatibilidad)
  try { await db.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS apellido TEXT'); } catch (e) {}
  try { await db.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS especialidad TEXT'); } catch (e) {}
  try { await db.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS telefono TEXT'); } catch (e) {}
  try { await db.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS zona TEXT'); } catch (e) {}
  try { await db.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS foto TEXT'); } catch (e) {}

  // Crear otras tablas (cada una en su propia query para evitar problemas con pg Pool y multi-statements)
  await db.query(`
    CREATE TABLE IF NOT EXISTS trabajos (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER,
      profesional_id INTEGER,
      titulo TEXT,
      descripcion TEXT,
      estado TEXT DEFAULT 'pendiente',
      precio REAL,
      creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS mensajes (
      id SERIAL PRIMARY KEY,
      de_usuario INTEGER,
      para_usuario INTEGER,
      texto TEXT,
      creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS email_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used INTEGER DEFAULT 0
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS calificaciones (
      id SERIAL PRIMARY KEY,
      de_usuario INTEGER,
      para_usuario INTEGER,
      estrellas INTEGER,
      comentario TEXT,
      trabajo_desc TEXT,
      creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Crear tabla profesional_profiles
  await db.query(`
    CREATE TABLE IF NOT EXISTS profesional_profiles (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL,
      especialidad TEXT,
      categoria TEXT,
      descripcion TEXT,
      experiencia_anios INTEGER DEFAULT 0,
      zona TEXT,
      fotos_portfolio TEXT DEFAULT '[]',
      telefono TEXT,
      verification_level TEXT DEFAULT 'none',
      verification_status TEXT DEFAULT 'pending',
      matricula TEXT,
      titulo_url TEXT,
      dni_url TEXT,
      activo INTEGER DEFAULT 1,
      creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(uploadsDir));

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ ok: false, error: 'No autorizado' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ ok: false, error: 'Token inválido' });
  }
}

function getUserPayload(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    apellido: user.apellido || null,
    email: user.email,
    role: user.role,
    city: user.city,
    zona: user.zona || null,
    profile_image: user.profile_image,
    foto: user.foto || null,
    descripcion: user.descripcion || null,
    experiencia: user.experiencia || null,
    especialidad: user.especialidad || null,
    telefono: user.telefono || null,
    onboarding_complete: user.onboarding_complete,
    email_verified: user.email_verified,
    phone_verified: user.phone_verified,
    categoria: user.categoria || null,
    verification_level: user.verification_level || 'none',
    verification_status: user.verification_status || 'pending',
    matricula: user.matricula || null,
    titulo_url: user.titulo_url || null,
    dni_url: user.dni_url || null,
    precio_estimado: user.precio_estimado || null,
    profile_completion: user.profile_completion || 0,
    es_profesional: user.es_profesional === 1,
    localidad: user.localidad || null,
    codigo_postal: user.codigo_postal || null,
    pro_onboarding_step: user.pro_onboarding_step || 0
  };
}

async function sendVerificationEmail(email, token) {
  const verifyUrl = `https://servikip.com.ar/api/auth/verify-email?token=${encodeURIComponent(token)}`;
  const html = `
    <div style="font-family:sans-serif;background:#0A0A0A;color:white;padding:40px;max-width:500px;margin:0 auto;border-radius:16px">
      <div style="text-align:center;margin-bottom:32px">
        <div style="width:48px;height:48px;background:#FF6B2B;border-radius:12px;display:inline-flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:white">K</div>
        <h1 style="font-size:22px;margin-top:16px;color:white">Verificá tu cuenta en ServiKIP</h1>
      </div>
      <p style="color:#CCCCCC;line-height:1.6">Hacé click en el botón para confirmar tu email y empezar a usar ServiKIP.</p>
      <div style="text-align:center;margin:32px 0">
        <a href="${verifyUrl}"
           style="background:#FF6B2B;color:white;padding:16px 32px;border-radius:999px;text-decoration:none;font-weight:700;font-size:16px">
          ✓ Verificar mi cuenta
        </a>
      </div>
      <p style="color:#888;font-size:13px;text-align:center">Si no creaste una cuenta en ServiKIP, ignorá este email.</p>
    </div>`;
  try {
    const response = await resend.emails.send({
      from: 'ServiKIP <noreply@servikip.com.ar>',
      to: email,
      subject: 'Verificá tu cuenta en ServiKIP',
      html
    });
    console.log('Resend email sent:', response.id || response);
  } catch (err) {
    console.error('Error enviando email de verificación con Resend:', err);
    throw err;
  }
}

async function findAuthUserByEmail(email) {
  const result = await db.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
  return result.rows[0];
}

async function registerAuthAccount({ name, email, password, role, categoria, legacyData }) {
  if (!name || !email || !password || !role) return { ok: false, error: 'Faltan datos obligatorios' };

  const existingAuth = await findAuthUserByEmail(email);
  if (existingAuth) return { ok: false, error: 'El email ya existe' };

  const hash = bcrypt.hashSync(password, 12);
  const legacy = legacyData || {};

  const [firstName, ...rest] = name.trim().split(' ');
  const lastName = rest.join(' ');

  const createUser = await db.query(
    'INSERT INTO users (name, apellido, email, password, role, email_verified, phone_verified, onboarding_complete, categoria, descripcion, experiencia, telefono, zona, especialidad, foto) VALUES ($1, $2, $3, $4, $5, 0, 0, 0, $6, $7, $8, $9, $10, $11, $12) RETURNING id',
    [
      firstName || name,
      lastName,
      email,
      hash,
      role,
      categoria || null,
      legacy.descripcion || null,
      legacy.experiencia || null,
      legacy.telefono || null,
      legacy.zona || null,
      legacy.especialidad || null,
      null
    ]
  );

  if (!createUser || !createUser.rows || createUser.rows.length === 0) {
    throw new Error('No se pudo crear el usuario en la base de datos');
  }

  const userId = createUser.rows[0].id;
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  await db.query(
    'INSERT INTO email_tokens (user_id, token, expires_at, used) VALUES ($1, $2, $3, 0)',
    [userId, token, expiresAt]
  );

  await sendVerificationEmail(email, token);
  return { ok: true, userId, token };
}

app.get('/', (req, res) => {
  const html = fs.readFileSync(path.join(__dirname, 'kip-app.html'), 'utf8');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(html);
});

app.get('/como-funciona', (req, res) => {
  res.sendFile(path.join(__dirname, 'como-funciona.html'));
});

app.get('/preguntas-frecuentes', (req, res) => {
  res.sendFile(path.join(__dirname, 'faq.html'));
});

app.get('/nuestras-politicas', (req, res) => {
  res.sendFile(path.join(__dirname, 'politicas.html'));
});

app.get('/recuperar-contrasena', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recuperar contraseña - ServiKIP</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Plus Jakarta Sans', sans-serif; background: #F5F5F7; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; }
.card { background: white; padding: 42px; border-radius: 22px; max-width: 480px; width: 100%; border: 1px solid rgba(0,0,0,0.08); }
.logo { display: flex; align-items: center; gap: 10px; justify-content: center; margin-bottom: 32px; }
.logo-icon { width: 34px; height: 34px; border-radius: 12px; background: linear-gradient(135deg, #FF6B2B, #FF8C4B); display: flex; align-items: center; justify-content: center; color: white; font-size: 14px; font-weight: 800; }
.logo-text { font-size: 22px; font-weight: 800; color: #1A1A2E; }
h2 { font-size: 26px; font-weight: 800; text-align: center; color: #1A1A2E; margin-bottom: 10px; }
p { font-size: 14px; color: #888; text-align: center; margin-bottom: 28px; line-height: 1.6; }
label { display: block; font-size: 13px; font-weight: 600; color: #1A1A2E; margin-bottom: 8px; }
input { width: 100%; padding: 14px 16px; border-radius: 14px; border: 1px solid rgba(0,0,0,0.12); background: #F5F5F7; font-size: 15px; font-family: inherit; outline: none; margin-bottom: 18px; }
input:focus { border-color: rgba(255,107,43,0.4); background: white; }
button { width: 100%; padding: 14px; background: #FF6B2B; color: white; border: none; border-radius: 14px; font-size: 15px; font-weight: 700; cursor: pointer; font-family: inherit; }
button:hover { background: #FF8C4B; }
.back { text-align: center; margin-top: 20px; font-size: 14px; color: #888; }
.back a { color: #FF6B2B; font-weight: 700; text-decoration: none; }
.msg { text-align: center; margin-top: 16px; font-size: 14px; padding: 12px; border-radius: 12px; display: none; }
.msg.success { background: rgba(34,197,94,0.1); color: #22c55e; display: block; }
.msg.error { background: rgba(255,68,68,0.1); color: #ef4444; display: block; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">K</div>
    <span class="logo-text">servi<span style="color:#FF6B2B">KIP</span></span>
  </div>
  <h2>Recuperar contraseña</h2>
  <p>Ingresá tu email y te enviamos un link para restablecer tu contraseña</p>
  <label>Email</label>
  <input type="email" id="email" placeholder="tu@email.com">
  <button onclick="enviar()">Enviar link de recuperación</button>
  <div id="msg" class="msg"></div>
  <div class="back"><a href="/">← Volver al inicio</a></div>
</div>
<script>
async function enviar() {
  const email = document.getElementById('email').value.trim();
  const msg = document.getElementById('msg');
  msg.className = 'msg';
  if (!email) { msg.className = 'msg error'; msg.textContent = 'Ingresá tu email'; return; }
  try {
    const r = await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const d = await r.json();
    if (d.ok) {
      msg.className = 'msg success';
      msg.textContent = '¡Email enviado! Revisá tu bandeja de entrada y spam.';
    } else {
      msg.className = 'msg error';
      msg.textContent = d.error || 'Error al enviar';
    }
  } catch(e) {
    msg.className = 'msg error';
    msg.textContent = 'Error al conectar';
  }
}
</script>
</body>
</html>`);
});

// ── REGISTRO ──────────────────────────────────
app.post('/api/registro', async (req, res) => {
  const { nombre, apellido, email, password, telefono, tipo, zona, especialidad, descripcion, experiencia, categoria } = req.body;
  const name = `${nombre || ''} ${apellido || ''}`.trim();
  if (!name || !email || !password || !tipo) return res.status(400).json({ error: 'Faltan datos obligatorios' });
  try {
    const result = await registerAuthAccount({
      name,
      email,
      password,
      role: tipo,
      categoria,
      legacyData: { telefono, zona, especialidad, descripcion, experiencia, categoria }
    });
    if (!result.ok) return res.status(400).json({ error: result.error });
    res.json({ ok: true, id: result.userId });
  } catch (err) {
    console.error('Error en /api/registro:', err);
    res.status(500).json({ ok: false, error: 'Error al enviar email de verificación' });
  }
});

// ── LOGIN ─────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await findAuthUserByEmail(email);
  if (!user) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  const ok = user.password && bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  if (user.email_verified === 0) return res.json({ ok: false, error: 'Debés verificar tu email primero', needsVerification: true });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, user: getUserPayload(user) });
});

// ── AUTH ─────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role, categoria, especialidad } = req.body;
  try {
    const result = await registerAuthAccount({ name, email, password, role, categoria, legacyData: { especialidad, categoria } });
    if (!result.ok) return res.status(400).json({ ok: false, error: result.error });
    res.json({ ok: true, message: 'Revisá tu email para verificar tu cuenta' });
  } catch (err) {
    console.error('Error en /api/auth/register:', err);
    res.status(500).json({ ok: false, error: 'Error al enviar email de verificación' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await findAuthUserByEmail(email);
  if (!user) return res.status(401).json({ ok: false, error: 'Email o contraseña incorrectos' });
  const ok = user.password && bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(401).json({ ok: false, error: 'Email o contraseña incorrectos' });
  if (user.email_verified === 0) return res.json({ ok: false, error: 'Debés verificar tu email primero', needsVerification: true });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, user: getUserPayload(user) });
});

app.get('/api/auth/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('<h1>Token inválido</h1>');
  const result = await db.query('SELECT * FROM email_tokens WHERE token = $1 AND used = 0 AND expires_at > $2', [token, new Date().toISOString()]);
  const tokenRow = result.rows[0];
  if (!tokenRow) {
    return res.status(400).send('<h1>Token inválido o expirado</h1>');
  }
  await db.query('UPDATE email_tokens SET used = 1 WHERE id = $1', [tokenRow.id]);
  await db.query('UPDATE users SET email_verified = 1 WHERE id = $1', [tokenRow.user_id]);
  res.redirect('https://servikip.com.ar/kip-app.html?verified=true');
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ ok: false, error: 'Email requerido' });
  const user = await findAuthUserByEmail(email);
  if (!user) return res.json({ ok: true }); // No revelar si existe
  console.log('Enviando email de recuperación a:', email);
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  await db.query('INSERT INTO email_tokens (user_id, token, expires_at, used) VALUES ($1, $2, $3, 0)', [user.id, token, expiresAt]);
  const resetUrl = `https://servikip.com.ar/api/auth/reset-password?token=${token}`;
  try {
    const response = await resend.emails.send({
      from: 'ServiKIP <noreply@servikip.com.ar>',
      to: email,
      subject: 'Restablecer contraseña - ServiKIP',
      html: `<div style="font-family:sans-serif;padding:40px;max-width:500px;margin:0 auto">
        <h2>Restablecer contraseña</h2>
        <p>Hacé click en el botón para restablecer tu contraseña. El link expira en 1 hora.</p>
        <a href="${resetUrl}" style="background:#FF6B2B;color:white;padding:14px 28px;border-radius:999px;text-decoration:none;font-weight:700;display:inline-block;margin:20px 0">
          Restablecer contraseña
        </a>
        <p style="color:#888;font-size:13px">Si no pediste esto, ignorá este email.</p>
      </div>`
    });
    console.log('Email enviado:', response);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ ok: false, error: 'Error al enviar email' });
  }
});

app.get('/api/auth/reset-password', (req, res) => {
  const { token } = req.query;
  res.send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Nueva contraseña - ServiKIP</title>
<style>body{font-family:sans-serif;background:#F5F5F7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:white;padding:40px;border-radius:22px;max-width:400px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,0.08)}
input{width:100%;padding:14px;border:1px solid rgba(0,0,0,0.12);border-radius:12px;font-size:15px;margin-bottom:16px;box-sizing:border-box}
button{width:100%;padding:14px;background:#FF6B2B;color:white;border:none;border-radius:12px;font-size:16px;font-weight:700;cursor:pointer}
p{text-align:center;margin-top:16px;color:#888}
</style></head>
<body><div class="card">
<h2 style="margin-bottom:8px">Nueva contraseña</h2>
<p style="color:#888;margin-bottom:24px">Ingresá tu nueva contraseña para ServiKIP</p>
<input type="password" id="np" placeholder="Nueva contraseña">
<input type="password" id="np2" placeholder="Repetir contraseña">
<button onclick="reset()">Guardar nueva contraseña</button>
<p id="msg"></p>
</div>
<script>
async function reset() {
  const p1 = document.getElementById('np').value;
  const p2 = document.getElementById('np2').value;
  const msg = document.getElementById('msg');
  if (!p1 || p1.length < 8) { msg.textContent = 'Mínimo 8 caracteres'; return; }
  if (p1 !== p2) { msg.textContent = 'Las contraseñas no coinciden'; return; }
  const r = await fetch('/api/auth/reset-password', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ token: '${token}', password: p1 })
  });
  const d = await r.json();
  if (d.ok) { msg.style.color='green'; msg.textContent = '¡Contraseña actualizada! Ya podés iniciar sesión.'; }
  else { msg.textContent = d.error || 'Error al actualizar'; }
}
</script></body></html>`);
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ ok: false, error: 'Datos incompletos' });
  const result = await db.query('SELECT * FROM email_tokens WHERE token = $1 AND used = 0 AND expires_at > $2', [token, new Date().toISOString()]);
  const tokenRow = result.rows[0];
  if (!tokenRow) return res.status(400).json({ ok: false, error: 'Token inválido o expirado' });
  const hash = bcrypt.hashSync(password, 12);
  await db.query('UPDATE users SET password = $1 WHERE id = $2', [hash, tokenRow.user_id]);
  await db.query('UPDATE email_tokens SET used = 1 WHERE id = $1', [tokenRow.id]);
  res.json({ ok: true });
});

app.put('/api/auth/onboarding', authMiddleware, async (req, res) => {
  const { phone, city, role } = req.body;
  await db.query('UPDATE users SET phone = $1, city = $2, role = $3, onboarding_complete = 1 WHERE id = $4', [phone, city, role, req.user.id]);
  const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const updated = result.rows[0];
  res.json({ ok: true, user: getUserPayload(updated) });
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const user = result.rows[0];
  if (!user) return res.status(404).json({ ok: false, error: 'Usuario no encontrado' });
  res.json({ ok: true, user: getUserPayload(user) });
});

app.put('/api/perfil/verificacion', authMiddleware, async (req, res) => {
  const { verification_level, matricula } = req.body;
  const validLevels = ['universitario', 'matriculado', 'independiente'];
  if (!validLevels.includes(verification_level)) return res.status(400).json({ ok: false, error: 'Nivel de verificación inválido' });
  await db.query('UPDATE users SET verification_level = $1, matricula = $2, verification_status = $3 WHERE id = $4', [verification_level, matricula || null, 'pending_review', req.user.id]);
  const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const updated = result.rows[0];
  res.json({ ok: true, user: getUserPayload(updated) });
});

app.post('/api/perfil/documento', authMiddleware, upload.single('documento'), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, error: 'Documento no recibido' });
  const { tipo } = req.body;
  const url = `/uploads/${req.file.filename}`;
  if (tipo === 'titulo') {
    await db.query('UPDATE users SET titulo_url = $1, verification_status = $2 WHERE id = $3', [url, 'pending_review', req.user.id]);
  } else if (tipo === 'dni') {
    await db.query('UPDATE users SET dni_url = $1, verification_status = $2 WHERE id = $3', [url, 'pending_review', req.user.id]);
  } else {
    return res.status(400).json({ ok: false, error: 'Tipo de documento inválido' });
  }
  res.json({ ok: true, url });
});

app.put('/api/perfil/precio', authMiddleware, async (req, res) => {
  const { precio_estimado } = req.body;
  if (!precio_estimado) return res.status(400).json({ ok: false, error: 'Precio estimado requerido' });
  await db.query('UPDATE users SET precio_estimado = $1 WHERE id = $2', [precio_estimado, req.user.id]);
  const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const updated = result.rows[0];
  res.json({ ok: true, user: getUserPayload(updated) });
});

app.get('/api/perfil/completitud', authMiddleware, async (req, res) => {
  try {
  const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const user = result.rows[0];
  if (!user) return res.status(404).json({ ok: false, error: 'Usuario no encontrado' });
  const calResult = await db.query('SELECT COUNT(*) AS cnt FROM calificaciones WHERE para_usuario = $1', [req.user.id]);
  const calificacionesCount = calResult && calResult.rows && calResult.rows[0] ? (calResult.rows[0].cnt || 0) : 0;
  const detalle = {
    foto: !!user.profile_image,
    descripcion: !!(user.descripcion && user.descripcion.length > 10),
    zona: !!(user.city || user.zona),
    telefono: !!user.phone,
    nivel_verificacion: !!user.verification_level && user.verification_level !== 'none',
    documento: !!(user.titulo_url || user.dni_url),
    matricula: !!user.matricula,
    calificaciones: calificacionesCount > 0,
    precio: !!user.precio_estimado,
    email_verificado: user.email_verified === 1
  };
  const porcentaje = Math.min(100,
    (detalle.foto ? 10 : 0) +
    (detalle.descripcion ? 10 : 0) +
    (detalle.zona ? 10 : 0) +
    (detalle.telefono ? 10 : 0) +
    (detalle.nivel_verificacion ? 10 : 0) +
    (detalle.documento ? 20 : 0) +
    (detalle.matricula ? 15 : 0) +
    (detalle.calificaciones ? 10 : 0) +
    (detalle.precio ? 5 : 0) +
    (detalle.email_verificado ? 10 : 0)
  );
  await db.query('UPDATE users SET profile_completion = $1 WHERE id = $2', [porcentaje, req.user.id]);
  res.json({ ok: true, porcentaje, detalle });
  } catch (err) {
    console.error('Error en /api/perfil/completitud:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

// ── PROFESIONALES ─────────────────────────────
app.get('/api/profesionales', async (req, res) => {
  try {
    await db.query(`CREATE TABLE IF NOT EXISTS calificaciones (
      id SERIAL PRIMARY KEY,
      de_usuario INTEGER,
      para_usuario INTEGER,
      estrellas INTEGER,
      comentario TEXT,
      trabajo_desc TEXT,
      creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    const { categoria, especialidad, zona, q } = req.query;
    let query = `
      SELECT
        u.id, u.name as nombre, u.apellido, u.especialidad, u.categoria,
        u.zona, u.descripcion, u.experiencia, u.foto,
        u.verification_level, u.verification_status,
        COALESCE(AVG(c.estrellas), 0) as calificacion_promedio,
        COUNT(c.id) as total_calificaciones
      FROM users u
      LEFT JOIN calificaciones c ON c.para_usuario = u.id
      WHERE u.role = 'professional'
    `;
    const params = [];
    if (categoria) { query += ' AND u.categoria = $' + (params.length + 1); params.push(categoria); }
    if (especialidad) { query += ' AND u.especialidad LIKE $' + (params.length + 1); params.push(`%${especialidad}%`); }
    if (zona) { query += ' AND u.zona LIKE $' + (params.length + 1); params.push(`%${zona}%`); }
    if (q) { query += ' AND (u.name LIKE $' + (params.length + 1) + ' OR u.apellido LIKE $' + (params.length + 2) + ' OR u.especialidad LIKE $' + (params.length + 3) + ' OR u.descripcion LIKE $' + (params.length + 4) + ')'; params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
    query += ' GROUP BY u.id ORDER BY calificacion_promedio DESC, RANDOM()';
    const result = await db.query(query, params);
    res.json(result.rows);
  } catch(err) {
    console.error('Error en /api/profesionales:', err);
    return res.json([]);
  }
});

// ── FOTO DE PERFIL ────────────────────────────
app.post('/api/foto', upload.single('foto'), async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const fotoUrl = `/uploads/${req.file.filename}`;
    await db.query('UPDATE users SET foto = $1, profile_image = $2 WHERE id = $3', [fotoUrl, fotoUrl, decoded.id]);
    res.json({ ok: true, foto: fotoUrl });
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// ── ACTUALIZAR PERFIL ─────────────────────────
app.put('/api/perfil', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { nombre, apellido, telefono, zona, especialidad, descripcion, experiencia } = req.body;
    await db.query('UPDATE users SET name=$1, apellido=$2, telefono=$3, zona=$4, especialidad=$5, descripcion=$6, experiencia=$7 WHERE id=$8', [nombre, apellido, telefono, zona, especialidad, descripcion, experiencia, decoded.id]);
    const result = await db.query('SELECT id, name as nombre, apellido, email, role as tipo, especialidad, zona, foto FROM users WHERE id=$1', [decoded.id]);
    const usuario = result.rows[0];
    res.json({ ok: true, usuario });
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// ── MENSAJES ──────────────────────────────────
app.post('/api/mensajes', async (req, res) => {
  const { de_usuario, para_usuario, texto } = req.body;
  try {
    const result = await db.query('INSERT INTO mensajes (de_usuario, para_usuario, texto) VALUES ($1, $2, $3) RETURNING id', [de_usuario, para_usuario, texto]);
    res.json({ ok: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Error en /api/mensajes:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

app.get('/api/mensajes/:usuario1/:usuario2', async (req, res) => {
  const { usuario1, usuario2 } = req.params;
  const result = await db.query(`
    SELECT m.*, u.nombre, u.apellido, u.foto FROM mensajes m
    JOIN users u ON m.de_usuario = u.id
    WHERE (m.de_usuario = $1 AND m.para_usuario = $2) OR (m.de_usuario = $2 AND m.para_usuario = $1)
    ORDER BY m.creado_en ASC
  `, [usuario1, usuario2, usuario2, usuario1]);
  res.json(result.rows);
});

app.get('/api/conversaciones/:usuario_id', async (req, res) => {
  const { usuario_id } = req.params;
  const result = await db.query(`
    SELECT DISTINCT
      CASE WHEN m.de_usuario = $1 THEN m.para_usuario ELSE m.de_usuario END as otro_id,
      u.name as nombre, u.apellido, u.foto, u.especialidad,
      (SELECT texto FROM mensajes WHERE (de_usuario=m.de_usuario AND para_usuario=m.para_usuario) OR (de_usuario=m.para_usuario AND para_usuario=m.de_usuario) ORDER BY creado_en DESC LIMIT 1) as ultimo_mensaje,
      (SELECT creado_en FROM mensajes WHERE (de_usuario=m.de_usuario AND para_usuario=m.para_usuario) OR (de_usuario=m.para_usuario AND para_usuario=m.de_usuario) ORDER BY creado_en DESC LIMIT 1) as ultimo_tiempo
    FROM mensajes m
    JOIN users u ON u.id = CASE WHEN m.de_usuario = $1 THEN m.para_usuario ELSE m.de_usuario END
    WHERE m.de_usuario = $1 OR m.para_usuario = $1
    GROUP BY otro_id
    ORDER BY ultimo_tiempo DESC
  `, [usuario_id, usuario_id, usuario_id, usuario_id]);
  res.json(result.rows);
});

// ── TRABAJOS ──────────────────────────────────
app.post('/api/trabajos', async (req, res) => {
  const { cliente_id, profesional_id, titulo, descripcion, precio } = req.body;
  const result = await db.query('INSERT INTO trabajos (cliente_id, profesional_id, titulo, descripcion, precio) VALUES ($1, $2, $3, $4, $5) RETURNING id', [cliente_id, profesional_id, titulo, descripcion, precio]);
  res.json({ ok: true, id: result.rows[0].id });
});

app.get('/api/trabajos/:usuario_id', async (req, res) => {
  const { usuario_id } = req.params;
  const result = await db.query('SELECT * FROM trabajos WHERE cliente_id = $1 OR profesional_id = $1', [usuario_id, usuario_id]);
  res.json(result.rows);
});

// ── SOCKET.IO — CHAT EN TIEMPO REAL ───────────
const usuariosConectados = {};

io.on('connection', (socket) => {
  socket.on('identificar', (userId) => {
    usuariosConectados[userId] = socket.id;
    socket.userId = userId;
  });

  socket.on('mensaje', async (data) => {
    const { de_usuario, para_usuario, texto } = data;
    const result = await db.query('INSERT INTO mensajes (de_usuario, para_usuario, texto) VALUES ($1, $2, $3) RETURNING id', [de_usuario, para_usuario, texto]);
    const mensajeCompleto = { id: result.rows[0].id, de_usuario, para_usuario, texto, creado_en: new Date().toISOString() };
    const socketDest = usuariosConectados[para_usuario];
    if (socketDest) io.to(socketDest).emit('mensaje', mensajeCompleto);
    socket.emit('mensaje_enviado', mensajeCompleto);
  });

  socket.on('disconnect', () => {
    if (socket.userId) delete usuariosConectados[socket.userId];
  });
});

// ── CALIFICACIONES ──────────────────────────────
app.post('/api/calificaciones', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { para_usuario, trabajo_desc, estrellas, comentario } = req.body;
    await db.query(`CREATE TABLE IF NOT EXISTS calificaciones (id SERIAL PRIMARY KEY, de_usuario INTEGER, para_usuario INTEGER, estrellas INTEGER, comentario TEXT, trabajo_desc TEXT, creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await db.query('INSERT INTO calificaciones (de_usuario,para_usuario,estrellas,comentario,trabajo_desc) VALUES ($1,$2,$3,$4,$5)', [decoded.id, para_usuario, estrellas, comentario, trabajo_desc]);
    const avgResult = await db.query('SELECT AVG(estrellas) as avg FROM calificaciones WHERE para_usuario=$1', [para_usuario]);
    const avg = avgResult.rows[0].avg;
    await db.query('UPDATE users SET calificacion=$1 WHERE id=$2', [Math.round(avg*10)/10, para_usuario]);
    res.json({ok:true});
  } catch(e) { res.status(401).json({error:e.message}); }
});

app.get('/api/calificaciones/:id', async (req, res) => {
  try {
    await db.query(`CREATE TABLE IF NOT EXISTS calificaciones (id SERIAL PRIMARY KEY, de_usuario INTEGER, para_usuario INTEGER, estrellas INTEGER, comentario TEXT, trabajo_desc TEXT, creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    const result = await db.query(`SELECT c.*, u.name as nombre, u.apellido FROM calificaciones c JOIN users u ON c.de_usuario=u.id WHERE c.para_usuario=$1 ORDER BY c.creado_en DESC`, [req.params.id]);
    res.json(result.rows);
  } catch(e) { res.json([]); }
});

// ── PANEL ADMIN ──────────────────────────────
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'kip_admin_2026';

function adminMiddleware(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (secret !== ADMIN_SECRET) return res.status(401).json({ ok: false, error: 'No autorizado' });
  next();
}

app.get('/api/admin/verificaciones', adminMiddleware, async (req, res) => {
  try {
    const pendientesResult = await db.query(`
      SELECT u.id, u.name, u.email, u.verification_level, u.verification_status,
             u.titulo_url, u.dni_url, u.matricula, u.created_at
      FROM users u
      WHERE u.role IN ('professional', 'profesional')
      AND u.verification_level != 'none'
      AND u.verification_status = 'pending_review'
      ORDER BY u.created_at DESC
    `);
    res.json({ ok: true, pendientes: pendientesResult.rows });
  } catch (err) {
    console.error('Error en /api/admin/verificaciones:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

app.put('/api/admin/verificaciones/:id/aprobar', adminMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await db.query("UPDATE users SET verification_status = 'approved' WHERE id = $1", [id]);
    res.json({ ok: true, message: 'Verificación aprobada' });
  } catch (err) {
    console.error('Error en /api/admin/verificaciones/:id/aprobar:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

app.put('/api/admin/verificaciones/:id/rechazar', adminMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await db.query("UPDATE users SET verification_status = 'rejected', verification_level = 'none' WHERE id = $1", [id]);
    res.json({ ok: true, message: 'Verificación rechazada' });
  } catch (err) {
    console.error('Error en /api/admin/verificaciones/:id/rechazar:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

app.get('/api/admin/usuarios', adminMiddleware, async (req, res) => {
  try {
    const usuariosResult = await db.query(`
      SELECT id, name, email, role, verification_level, verification_status, 
             email_verified, created_at, profile_completion
      FROM users ORDER BY created_at DESC
    `);
    res.json({ ok: true, usuarios: usuariosResult.rows });
  } catch (err) {
    console.error('Error en /api/admin/usuarios:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const prosResult = await db.query("SELECT COUNT(*) as cnt FROM users WHERE role = 'professional'");
    const clientesResult = await db.query("SELECT COUNT(*) as cnt FROM users WHERE role = 'client'");
    const trabajosResult = await db.query("SELECT COUNT(*) as cnt FROM trabajos");
    const califsResult = await db.query("SELECT AVG(estrellas) as avg, COUNT(*) as cnt FROM calificaciones");
    const califs = califsResult.rows[0];
    res.json({
      ok: true,
      profesionales: prosResult.rows[0].cnt || 0,
      clientes: clientesResult.rows[0].cnt || 0,
      trabajos: trabajosResult.rows[0].cnt || 0,
      calificacion_promedio: califs.avg ? Math.round(califs.avg * 10) / 10 : 0,
      total_calificaciones: califs.cnt || 0
    });
  } catch(e) {
    res.json({ ok: true, profesionales: 0, clientes: 0, trabajos: 0, calificacion_promedio: 0 });
  }
});

// Activar modo profesional - paso 1: especialidad
app.post('/api/pro/activar', authMiddleware, async (req, res) => {
  const { especialidad, categoria, descripcion, experiencia_anios, zona } = req.body;
  if (!especialidad) return res.status(400).json({ ok: false, error: 'La especialidad es obligatoria' });
  try {
    const existingResult = await db.query('SELECT id FROM profesional_profiles WHERE user_id = $1', [req.user.id]);
    const existing = existingResult.rows[0];
    if (existing) {
      await db.query('UPDATE profesional_profiles SET especialidad=$1, categoria=$2, descripcion=$3, experiencia_anios=$4, zona=$5 WHERE user_id=$6',
        [especialidad, categoria||null, descripcion||null, experiencia_anios||0, zona||null, req.user.id]);
    } else {
      await db.query('INSERT INTO profesional_profiles (user_id, especialidad, categoria, descripcion, experiencia_anios, zona) VALUES ($1,$2,$3,$4,$5,$6)',
        [req.user.id, especialidad, categoria||null, descripcion||null, experiencia_anios||0, zona||null]);
    }
    await db.query('UPDATE users SET es_profesional=1, pro_onboarding_step=1, role=$1 WHERE id=$2',
      ['professional', req.user.id]);
    const updatedResult = await db.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    const updated = updatedResult.rows[0];
    res.json({ ok: true, user: getUserPayload(updated) });
  } catch (err) {
    console.error('Error en /api/pro/activar:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

// Actualizar localidad del usuario
app.put('/api/perfil/localidad', authMiddleware, async (req, res) => {
  const { localidad, codigo_postal } = req.body;
  try {
    await db.query('UPDATE users SET localidad=$1, codigo_postal=$2 WHERE id=$3',
      [localidad||null, codigo_postal||null, req.user.id]);
    const updatedResult = await db.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    const updated = updatedResult.rows[0];
    res.json({ ok: true, user: getUserPayload(updated) });
  } catch (err) {
    console.error('Error en /api/perfil/localidad:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

// Obtener perfil profesional
app.get('/api/pro/perfil', authMiddleware, async (req, res) => {
  try {
    const profileResult = await db.query('SELECT * FROM profesional_profiles WHERE user_id=$1', [req.user.id]);
    res.json({ ok: true, profile: profileResult.rows[0] || null });
  } catch (err) {
    console.error('Error en /api/pro/perfil:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
  }
});

app.get('/api/profesionales/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const proResult = await db.query(`
      SELECT
        u.id, u.name as nombre, u.apellido, u.especialidad, u.categoria,
        u.zona, u.descripcion, u.experiencia, u.foto,
        u.verification_level, u.verification_status,
        COALESCE(AVG(c.estrellas), 0) as calificacion_promedio,
        COUNT(c.id) as total_calificaciones
      FROM users u
      LEFT JOIN calificaciones c ON c.para_usuario = u.id
      WHERE u.id = $1 AND u.role = 'professional'
      GROUP BY u.id
    `, [id]);
    const pro = proResult.rows[0];
    if (!pro) return res.status(404).json({ ok: false, error: 'Profesional no encontrado' });
    res.json(pro);
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── INICIO ────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`✅ Servidor KIP corriendo en http://localhost:${PORT}`);
    console.log(`💬 Socket.io activo`);
    console.log(`📷 Fotos en /uploads`);
  });
}).catch(err => {
  console.error('❌ Error inicializando base de datos:', err);
  process.exit(1);
});
