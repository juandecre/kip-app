const express = require('express');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const Database = require('better-sqlite3');
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
const db = new Database('kip.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    apellido TEXT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    telefono TEXT,
    tipo TEXT NOT NULL,
    zona TEXT,
    especialidad TEXT,
    descripcion TEXT,
    experiencia INTEGER,
    foto TEXT,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS trabajos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cliente_id INTEGER,
    profesional_id INTEGER,
    titulo TEXT,
    descripcion TEXT,
    estado TEXT DEFAULT 'pendiente',
    precio REAL,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS mensajes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    de_usuario INTEGER,
    para_usuario INTEGER,
    texto TEXT,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS email_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0
  );
`);

try { db.prepare('ALTER TABLE users ADD COLUMN categoria TEXT').run(); } catch (e) {}
try { db.prepare('ALTER TABLE usuarios ADD COLUMN categoria TEXT').run(); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN verification_level TEXT DEFAULT 'none'`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN verification_status TEXT DEFAULT 'pending'`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN matricula TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN titulo_url TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN dni_url TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN precio_estimado TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN profile_completion INTEGER DEFAULT 0`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN descripcion TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN experiencia INTEGER`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN localidad TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN codigo_postal TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN es_profesional INTEGER DEFAULT 0`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN pro_onboarding_step INTEGER DEFAULT 0`); } catch (e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS profesional_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

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
    email: user.email,
    role: user.role,
    city: user.city,
    profile_image: user.profile_image,
    descripcion: user.descripcion || null,
    experiencia: user.experiencia || null,
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

function findAuthUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

function findLegacyUserByEmail(email) {
  return db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
}

async function registerAuthAccount({ name, email, password, role, categoria, legacyData }) {
  if (!name || !email || !password || !role) return { ok: false, error: 'Faltan datos obligatorios' };
  const existingAuth = findAuthUserByEmail(email);
  const existingLegacy = findLegacyUserByEmail(email);
  if (existingAuth || existingLegacy) return { ok: false, error: 'El email ya existe' };

  const hash = bcrypt.hashSync(password, 12);
  const legacy = legacyData || {};

  const createUser = db.prepare('INSERT INTO users (name, email, password, role, email_verified, phone_verified, onboarding_complete, categoria, descripcion, experiencia) VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?, ?)');
  const userResult = createUser.run(name, email, hash, role, categoria || null, legacy.descripcion || null, legacy.experiencia || null);
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO email_tokens (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)').run(userResult.lastInsertRowid, token, expiresAt);

  const [firstName, ...rest] = name.trim().split(' ');
  const lastName = rest.join(' ');

  const createLegacy = db.prepare('INSERT INTO usuarios (nombre, apellido, email, password, telefono, tipo, zona, especialidad, descripcion, experiencia, foto, categoria) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
  const legacyResult = createLegacy.run(
    firstName || name,
    lastName,
    email,
    hash,
    legacy.telefono || null,
    role === 'professional' ? 'profesional' : role === 'client' ? 'cliente' : role,
    legacy.zona || null,
    legacy.especialidad || null,
    legacy.descripcion || null,
    legacy.experiencia || null,
    null,
    legacy.categoria || null
  );

  await sendVerificationEmail(email, token);
  return { ok: true, userId: userResult.lastInsertRowid, legacyId: legacyResult.lastInsertRowid, token };
}

app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.sendFile(path.join(__dirname, 'kip-app.html'));
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
    res.json({ ok: true, id: result.legacyId });
  } catch (err) {
    console.error('Error en /api/registro:', err);
    res.status(500).json({ ok: false, error: 'Error al enviar email de verificación' });
  }
});

// ── LOGIN ─────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const authUser = findAuthUserByEmail(email);
  if (authUser) {
    const ok = authUser.password && bcrypt.compareSync(password, authUser.password);
    if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
    if (authUser.email_verified === 0) return res.json({ ok: false, error: 'Debés verificar tu email primero', needsVerification: true });
    const token = jwt.sign({ id: authUser.id, email: authUser.email, role: authUser.role, name: authUser.name }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ ok: true, token, user: getUserPayload(authUser) });
  }

  const usuario = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
  if (!usuario) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  const ok = bcrypt.compareSync(password, usuario.password);
  if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  const token = jwt.sign({ id: usuario.id, email: usuario.email, role: usuario.tipo, name: `${usuario.nombre} ${usuario.apellido || ''}`.trim() }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    ok: true, token,
    usuario: { id: usuario.id, nombre: usuario.nombre, apellido: usuario.apellido, email: usuario.email, tipo: usuario.tipo, especialidad: usuario.especialidad, zona: usuario.zona, foto: usuario.foto }
  });
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

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = findAuthUserByEmail(email);
  if (!user) return res.status(401).json({ ok: false, error: 'Email o contraseña incorrectos' });
  const ok = user.password && bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(401).json({ ok: false, error: 'Email o contraseña incorrectos' });
  if (user.email_verified === 0) return res.json({ ok: false, error: 'Debés verificar tu email primero', needsVerification: true });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, user: getUserPayload(user) });
});

app.get('/api/auth/verify-email', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('<h1>Token inválido</h1>');
  const tokenRow = db.prepare('SELECT * FROM email_tokens WHERE token = ? AND used = 0 AND expires_at > ?').get(token, new Date().toISOString());
  if (!tokenRow) {
    return res.status(400).send('<h1>Token inválido o expirado</h1>');
  }
  db.prepare('UPDATE email_tokens SET used = 1 WHERE id = ?').run(tokenRow.id);
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(tokenRow.user_id);
  res.redirect('https://servikip.com.ar/kip-app.html?verified=true');
});

app.put('/api/auth/onboarding', authMiddleware, (req, res) => {
  const { phone, city, role } = req.body;
  db.prepare('UPDATE users SET phone = ?, city = ?, role = ?, onboarding_complete = 1 WHERE id = ?')
    .run(phone, city, role, req.user.id);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ ok: true, user: getUserPayload(updated) });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ ok: false, error: 'Usuario no encontrado' });
  res.json({ ok: true, user: getUserPayload(user) });
});

app.put('/api/perfil/verificacion', authMiddleware, (req, res) => {
  const { verification_level, matricula } = req.body;
  const validLevels = ['universitario', 'matriculado', 'independiente'];
  if (!validLevels.includes(verification_level)) return res.status(400).json({ ok: false, error: 'Nivel de verificación inválido' });
  db.prepare('UPDATE users SET verification_level = ?, matricula = ?, verification_status = ? WHERE id = ?')
    .run(verification_level, matricula || null, 'pending_review', req.user.id);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ ok: true, user: getUserPayload(updated) });
});

app.post('/api/perfil/documento', authMiddleware, upload.single('documento'), (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, error: 'Documento no recibido' });
  const { tipo } = req.body;
  const url = `/uploads/${req.file.filename}`;
  if (tipo === 'titulo') {
    db.prepare('UPDATE users SET titulo_url = ?, verification_status = ? WHERE id = ?')
      .run(url, 'pending_review', req.user.id);
  } else if (tipo === 'dni') {
    db.prepare('UPDATE users SET dni_url = ?, verification_status = ? WHERE id = ?')
      .run(url, 'pending_review', req.user.id);
  } else {
    return res.status(400).json({ ok: false, error: 'Tipo de documento inválido' });
  }
  res.json({ ok: true, url });
});

app.put('/api/perfil/precio', authMiddleware, (req, res) => {
  const { precio_estimado } = req.body;
  if (!precio_estimado) return res.status(400).json({ ok: false, error: 'Precio estimado requerido' });
  db.prepare('UPDATE users SET precio_estimado = ? WHERE id = ?').run(precio_estimado, req.user.id);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ ok: true, user: getUserPayload(updated) });
});

app.get('/api/perfil/completitud', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ ok: false, error: 'Usuario no encontrado' });
  const calificacionesCount = db.prepare('SELECT COUNT(*) AS cnt FROM calificaciones WHERE para_usuario = ?').get(req.user.id)?.cnt || 0;
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
  db.prepare('UPDATE users SET profile_completion = ? WHERE id = ?').run(porcentaje, req.user.id);
  res.json({ ok: true, porcentaje, detalle });
});

// ── PROFESIONALES ─────────────────────────────
app.get('/api/profesionales', (req, res) => {
  try {
    db.prepare(`CREATE TABLE IF NOT EXISTS calificaciones (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      de_usuario INTEGER,
      para_usuario INTEGER,
      estrellas INTEGER,
      comentario TEXT,
      trabajo_desc TEXT,
      creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
    )`).run();
    const { categoria, especialidad, zona, q } = req.query;
    let query = `
      SELECT 
        u.id, u.nombre, u.apellido, u.especialidad, u.categoria, 
        u.zona, u.descripcion, u.experiencia, u.foto,
        us.verification_level, us.verification_status,
        COALESCE(AVG(c.estrellas), 0) as calificacion_promedio,
        COUNT(c.id) as total_calificaciones
      FROM usuarios u 
      LEFT JOIN users us ON us.email = u.email 
      LEFT JOIN calificaciones c ON c.para_usuario = u.id
      WHERE u.tipo = 'profesional'
    `;
    const params = [];
    if (categoria) { query += ' AND u.categoria = ?'; params.push(categoria); }
    if (especialidad) { query += ' AND u.especialidad LIKE ?'; params.push(`%${especialidad}%`); }
    if (zona) { query += ' AND u.zona LIKE ?'; params.push(`%${zona}%`); }
    if (q) { query += ' AND (u.nombre LIKE ? OR u.apellido LIKE ? OR u.especialidad LIKE ? OR u.descripcion LIKE ?)'; params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
    query += ' GROUP BY u.id ORDER BY calificacion_promedio DESC, RANDOM()';
    res.json(db.prepare(query).all(...params));
  } catch(err) {
    console.error('Error en /api/profesionales:', err);
    return res.json([]);
  }
});

// ── FOTO DE PERFIL ────────────────────────────
app.post('/api/foto', upload.single('foto'), (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const fotoUrl = `/uploads/${req.file.filename}`;
    db.prepare('UPDATE usuarios SET foto = ? WHERE id = ?').run(fotoUrl, decoded.id);
    db.prepare('UPDATE users SET profile_image = ? WHERE email=(SELECT email FROM usuarios WHERE id=?)').run(fotoUrl, decoded.id);
    res.json({ ok: true, foto: fotoUrl });
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// ── ACTUALIZAR PERFIL ─────────────────────────
app.put('/api/perfil', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { nombre, apellido, telefono, zona, especialidad, descripcion, experiencia } = req.body;
    db.prepare('UPDATE usuarios SET nombre=?, apellido=?, telefono=?, zona=?, especialidad=?, descripcion=?, experiencia=? WHERE id=?')
      .run(nombre, apellido, telefono, zona, especialidad, descripcion, experiencia, decoded.id);
    db.prepare('UPDATE users SET phone=?, city=?, descripcion=?, experiencia=? WHERE email=(SELECT email FROM usuarios WHERE id=?)')
      .run(telefono, zona, descripcion || null, experiencia || null, decoded.id);
    const usuario = db.prepare('SELECT id, nombre, apellido, email, tipo, especialidad, zona, foto FROM usuarios WHERE id=?').get(decoded.id);
    res.json({ ok: true, usuario });
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// ── MENSAJES ──────────────────────────────────
app.post('/api/mensajes', (req, res) => {
  const { de_usuario, para_usuario, texto } = req.body;
  const result = db.prepare('INSERT INTO mensajes (de_usuario, para_usuario, texto) VALUES (?, ?, ?)').run(de_usuario, para_usuario, texto);
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.get('/api/mensajes/:usuario1/:usuario2', (req, res) => {
  const { usuario1, usuario2 } = req.params;
  const mensajes = db.prepare(`
    SELECT m.*, u.nombre, u.apellido, u.foto FROM mensajes m
    JOIN usuarios u ON m.de_usuario = u.id
    WHERE (m.de_usuario = ? AND m.para_usuario = ?) OR (m.de_usuario = ? AND m.para_usuario = ?)
    ORDER BY m.creado_en ASC
  `).all(usuario1, usuario2, usuario2, usuario1);
  res.json(mensajes);
});

app.get('/api/conversaciones/:usuario_id', (req, res) => {
  const { usuario_id } = req.params;
  const convos = db.prepare(`
    SELECT DISTINCT 
      CASE WHEN m.de_usuario = ? THEN m.para_usuario ELSE m.de_usuario END as otro_id,
      u.nombre, u.apellido, u.foto, u.especialidad,
      (SELECT texto FROM mensajes WHERE (de_usuario=m.de_usuario AND para_usuario=m.para_usuario) OR (de_usuario=m.para_usuario AND para_usuario=m.de_usuario) ORDER BY creado_en DESC LIMIT 1) as ultimo_mensaje,
      (SELECT creado_en FROM mensajes WHERE (de_usuario=m.de_usuario AND para_usuario=m.para_usuario) OR (de_usuario=m.para_usuario AND para_usuario=m.de_usuario) ORDER BY creado_en DESC LIMIT 1) as ultimo_tiempo
    FROM mensajes m
    JOIN usuarios u ON u.id = CASE WHEN m.de_usuario = ? THEN m.para_usuario ELSE m.de_usuario END
    WHERE m.de_usuario = ? OR m.para_usuario = ?
    GROUP BY otro_id
    ORDER BY ultimo_tiempo DESC
  `).all(usuario_id, usuario_id, usuario_id, usuario_id);
  res.json(convos);
});

// ── TRABAJOS ──────────────────────────────────
app.post('/api/trabajos', (req, res) => {
  const { cliente_id, profesional_id, titulo, descripcion, precio } = req.body;
  const result = db.prepare('INSERT INTO trabajos (cliente_id, profesional_id, titulo, descripcion, precio) VALUES (?, ?, ?, ?, ?)').run(cliente_id, profesional_id, titulo, descripcion, precio);
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.get('/api/trabajos/:usuario_id', (req, res) => {
  const { usuario_id } = req.params;
  const trabajos = db.prepare('SELECT * FROM trabajos WHERE cliente_id = ? OR profesional_id = ?').all(usuario_id, usuario_id);
  res.json(trabajos);
});

// ── SOCKET.IO — CHAT EN TIEMPO REAL ───────────
const usuariosConectados = {};

io.on('connection', (socket) => {
  socket.on('identificar', (userId) => {
    usuariosConectados[userId] = socket.id;
    socket.userId = userId;
  });

  socket.on('mensaje', (data) => {
    const { de_usuario, para_usuario, texto } = data;
    const result = db.prepare('INSERT INTO mensajes (de_usuario, para_usuario, texto) VALUES (?, ?, ?)').run(de_usuario, para_usuario, texto);
    const mensajeCompleto = { id: result.lastInsertRowid, de_usuario, para_usuario, texto, creado_en: new Date().toISOString() };
    const socketDest = usuariosConectados[para_usuario];
    if (socketDest) io.to(socketDest).emit('mensaje', mensajeCompleto);
    socket.emit('mensaje_enviado', mensajeCompleto);
  });

  socket.on('disconnect', () => {
    if (socket.userId) delete usuariosConectados[socket.userId];
  });
});

// ── CALIFICACIONES ──────────────────────────────
app.post('/api/calificaciones', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { para_usuario, trabajo_desc, estrellas, comentario } = req.body;
    db.prepare(`CREATE TABLE IF NOT EXISTS calificaciones (id INTEGER PRIMARY KEY AUTOINCREMENT, de_usuario INTEGER, para_usuario INTEGER, estrellas INTEGER, comentario TEXT, trabajo_desc TEXT, creado_en DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
    db.prepare('INSERT INTO calificaciones (de_usuario,para_usuario,estrellas,comentario,trabajo_desc) VALUES (?,?,?,?,?)').run(decoded.id, para_usuario, estrellas, comentario, trabajo_desc);
    const avg = db.prepare('SELECT AVG(estrellas) as avg FROM calificaciones WHERE para_usuario=?').get(para_usuario);
    db.prepare('UPDATE usuarios SET calificacion=? WHERE id=?').run(Math.round(avg.avg*10)/10, para_usuario);
    res.json({ok:true});
  } catch(e) { res.status(401).json({error:e.message}); }
});

app.get('/api/calificaciones/:id', (req, res) => {
  try {
    db.prepare(`CREATE TABLE IF NOT EXISTS calificaciones (id INTEGER PRIMARY KEY AUTOINCREMENT, de_usuario INTEGER, para_usuario INTEGER, estrellas INTEGER, comentario TEXT, trabajo_desc TEXT, creado_en DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
    const cals = db.prepare(`SELECT c.*, u.nombre, u.apellido FROM calificaciones c JOIN usuarios u ON c.de_usuario=u.id WHERE c.para_usuario=? ORDER BY c.creado_en DESC`).all(req.params.id);
    res.json(cals);
  } catch(e) { res.json([]); }
});

// ── PANEL ADMIN ──────────────────────────────
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'kip_admin_2026';

function adminMiddleware(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (secret !== ADMIN_SECRET) return res.status(401).json({ ok: false, error: 'No autorizado' });
  next();
}

app.get('/api/admin/verificaciones', adminMiddleware, (req, res) => {
  const pendientes = db.prepare(`
    SELECT u.id, u.name, u.email, u.verification_level, u.verification_status,
           u.titulo_url, u.dni_url, u.matricula, u.created_at
    FROM users u
    WHERE u.role IN ('professional', 'profesional')
    AND u.verification_level != 'none'
    AND u.verification_status = 'pending_review'
    ORDER BY u.created_at DESC
  `).all();
  res.json({ ok: true, pendientes });
});

app.put('/api/admin/verificaciones/:id/aprobar', adminMiddleware, (req, res) => {
  const { id } = req.params;
  db.prepare("UPDATE users SET verification_status = 'approved' WHERE id = ?").run(id);
  res.json({ ok: true, message: 'Verificación aprobada' });
});

app.put('/api/admin/verificaciones/:id/rechazar', adminMiddleware, (req, res) => {
  const { id } = req.params;
  db.prepare("UPDATE users SET verification_status = 'rejected', verification_level = 'none' WHERE id = ?").run(id);
  res.json({ ok: true, message: 'Verificación rechazada' });
});

app.get('/api/admin/usuarios', adminMiddleware, (req, res) => {
  const usuarios = db.prepare(`
    SELECT id, name, email, role, verification_level, verification_status, 
           email_verified, created_at, profile_completion
    FROM users ORDER BY created_at DESC
  `).all();
  res.json({ ok: true, usuarios });
});

app.get('/api/stats', (req, res) => {
  try {
    const pros = db.prepare("SELECT COUNT(*) as cnt FROM usuarios WHERE tipo = 'profesional'").get();
    const clientes = db.prepare("SELECT COUNT(*) as cnt FROM usuarios WHERE tipo = 'cliente'").get();
    const trabajos = db.prepare("SELECT COUNT(*) as cnt FROM trabajos").get();
    const califs = db.prepare("SELECT AVG(estrellas) as avg, COUNT(*) as cnt FROM calificaciones").get();
    res.json({
      ok: true,
      profesionales: pros.cnt || 0,
      clientes: clientes.cnt || 0,
      trabajos: trabajos.cnt || 0,
      calificacion_promedio: califs.avg ? Math.round(califs.avg * 10) / 10 : 0,
      total_calificaciones: califs.cnt || 0
    });
  } catch(e) {
    res.json({ ok: true, profesionales: 0, clientes: 0, trabajos: 0, calificacion_promedio: 0 });
  }
});

// Activar modo profesional - paso 1: especialidad
app.post('/api/pro/activar', authMiddleware, (req, res) => {
  const { especialidad, categoria, descripcion, experiencia_anios, zona } = req.body;
  if (!especialidad) return res.status(400).json({ ok: false, error: 'La especialidad es obligatoria' });
  const existing = db.prepare('SELECT id FROM profesional_profiles WHERE user_id = ?').get(req.user.id);
  if (existing) {
    db.prepare('UPDATE profesional_profiles SET especialidad=?, categoria=?, descripcion=?, experiencia_anios=?, zona=? WHERE user_id=?')
      .run(especialidad, categoria||null, descripcion||null, experiencia_anios||0, zona||null, req.user.id);
  } else {
    db.prepare('INSERT INTO profesional_profiles (user_id, especialidad, categoria, descripcion, experiencia_anios, zona) VALUES (?,?,?,?,?,?)')
      .run(req.user.id, especialidad, categoria||null, descripcion||null, experiencia_anios||0, zona||null);
  }
  db.prepare('UPDATE users SET es_profesional=1, pro_onboarding_step=1, role=? WHERE id=?')
    .run('professional', req.user.id);
  // Sincronizar con tabla usuarios legacy
  db.prepare('UPDATE usuarios SET tipo=?, especialidad=?, descripcion=?, categoria=? WHERE email=(SELECT email FROM users WHERE id=?)')
    .run('profesional', especialidad, descripcion||null, categoria||null, req.user.id);
  const updated = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  res.json({ ok: true, user: getUserPayload(updated) });
});

// Actualizar localidad del usuario
app.put('/api/perfil/localidad', authMiddleware, (req, res) => {
  const { localidad, codigo_postal } = req.body;
  db.prepare('UPDATE users SET localidad=?, codigo_postal=? WHERE id=?')
    .run(localidad||null, codigo_postal||null, req.user.id);
  db.prepare('UPDATE usuarios SET zona=? WHERE email=(SELECT email FROM users WHERE id=?)')
    .run(localidad||null, req.user.id);
  const updated = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  res.json({ ok: true, user: getUserPayload(updated) });
});

// Obtener perfil profesional
app.get('/api/pro/perfil', authMiddleware, (req, res) => {
  const profile = db.prepare('SELECT * FROM profesional_profiles WHERE user_id=?').get(req.user.id);
  res.json({ ok: true, profile: profile || null });
});

app.get('/api/profesionales/:id', (req, res) => {
  const { id } = req.params;
  try {
    const pro = db.prepare(`
      SELECT 
        u.id, u.nombre, u.apellido, u.especialidad, u.categoria,
        u.zona, u.descripcion, u.experiencia, u.foto,
        us.verification_level, us.verification_status,
        COALESCE(AVG(c.estrellas), 0) as calificacion_promedio,
        COUNT(c.id) as total_calificaciones
      FROM usuarios u
      LEFT JOIN users us ON us.email = u.email
      LEFT JOIN calificaciones c ON c.para_usuario = u.id
      WHERE u.id = ? AND u.tipo = 'profesional'
      GROUP BY u.id
    `).get(id);
    if (!pro) return res.status(404).json({ ok: false, error: 'Profesional no encontrado' });
    res.json(pro);
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── INICIO ────────────────────────────────────
server.listen(PORT, () => {
  console.log(`✅ Servidor KIP corriendo en http://localhost:${PORT}`);
  console.log(`💬 Socket.io activo`);
  console.log(`📷 Fotos en /uploads`);
});
