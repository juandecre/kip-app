const express = require('express');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'kip_secret_2025';

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
`);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(uploadsDir));

// ── REGISTRO ──────────────────────────────────
app.post('/api/registro', (req, res) => {
  const { nombre, apellido, email, password, telefono, tipo, zona, especialidad, descripcion, experiencia } = req.body;
  if (!nombre || !email || !password || !tipo) return res.status(400).json({ error: 'Faltan datos obligatorios' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare(`INSERT INTO usuarios (nombre, apellido, email, password, telefono, tipo, zona, especialidad, descripcion, experiencia) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    const result = stmt.run(nombre, apellido, email, hash, telefono, tipo, zona, especialidad, descripcion, experiencia);
    res.json({ ok: true, id: result.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: 'El email ya está registrado' });
  }
});

// ── LOGIN ─────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const usuario = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
  if (!usuario) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  const ok = bcrypt.compareSync(password, usuario.password);
  if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  const token = jwt.sign({ id: usuario.id, tipo: usuario.tipo }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    ok: true, token,
    usuario: { id: usuario.id, nombre: usuario.nombre, apellido: usuario.apellido, email: usuario.email, tipo: usuario.tipo, especialidad: usuario.especialidad, zona: usuario.zona, foto: usuario.foto }
  });
});

// ── PROFESIONALES ─────────────────────────────
app.get('/api/profesionales', (req, res) => {
  const { especialidad, zona } = req.query;
  let query = "SELECT id, nombre, apellido, especialidad, zona, descripcion, experiencia, foto FROM usuarios WHERE tipo = 'profesional'";
  const params = [];
  if (especialidad) { query += ' AND especialidad LIKE ?'; params.push(`%${especialidad}%`); }
  if (zona) { query += ' AND zona LIKE ?'; params.push(`%${zona}%`); }
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
