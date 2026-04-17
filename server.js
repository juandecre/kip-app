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
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Solo se permiten imágenes'));
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

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(uploadsDir));

const allowedCities = ['CABA', 'GBA Norte', 'GBA Sur', 'GBA Oeste', 'Interior'];

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
    onboarding_complete: user.onboarding_complete,
    email_verified: user.email_verified,
    phone_verified: user.phone_verified,
    categoria: user.categoria || null
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
  const createUser = db.prepare('INSERT INTO users (name, email, password, role, email_verified, phone_verified, onboarding_complete, categoria) VALUES (?, ?, ?, ?, 0, 0, 0, ?)');
  const userResult = createUser.run(name, email, hash, role, categoria || null);
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO email_tokens (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)').run(userResult.lastInsertRowid, token, expiresAt);

  const [firstName, ...rest] = name.trim().split(' ');
  const lastName = rest.join(' ');
  const legacy = legacyData || {};
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
  res.sendFile(path.join(__dirname, 'kip-app.html'));
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
  if (!allowedCities.includes(city)) return res.status(400).json({ ok: false, error: 'Ciudad inválida' });
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

// ── PROFESIONALES ─────────────────────────────
app.get('/api/profesionales', (req, res) => {
  const { categoria, especialidad, zona, q } = req.query;
  let query = "SELECT id, nombre, apellido, especialidad, categoria, zona, descripcion, experiencia, foto FROM usuarios WHERE tipo = 'profesional'";
  const params = [];
  if (categoria) { query += ' AND categoria = ?'; params.push(categoria); }
  if (especialidad) { query += ' AND especialidad LIKE ?'; params.push(`%${especialidad}%`); }
  if (zona) { query += ' AND zona LIKE ?'; params.push(`%${zona}%`); }
  if (q) { query += ' AND (nombre LIKE ? OR apellido LIKE ? OR especialidad LIKE ? OR descripcion LIKE ?)'; params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
  res.json(db.prepare(query).all(...params));
});

// ── FOTO DE PERFIL ────────────────────────────
app.post('/api/foto', upload.single('foto'), (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const fotoUrl = `/uploads/${req.file.filename}`;
    db.prepare('UPDATE usuarios SET foto = ? WHERE id = ?').run(fotoUrl, decoded.id);
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

// ── INICIO ────────────────────────────────────
server.listen(PORT, () => {
  console.log(`✅ Servidor KIP corriendo en http://localhost:${PORT}`);
  console.log(`💬 Socket.io activo`);
  console.log(`📷 Fotos en /uploads`);
});
