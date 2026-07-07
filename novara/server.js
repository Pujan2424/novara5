const express = require('express');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const db = new Database(path.join(__dirname, 'novara.db'));
db.pragma('journal_mode = WAL');

const initSql = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin'
  );

  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    price REAL NOT NULL,
    pieces INTEGER NOT NULL,
    image TEXT
  );

  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    customer_name TEXT NOT NULL,
    customer_address TEXT NOT NULL,
    customer_phone TEXT NOT NULL,
    customer_email TEXT NOT NULL,
    items TEXT NOT NULL,
    total REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS slides (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    idx INTEGER NOT NULL,
    image TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    UNIQUE(category, idx)
  );
`;
db.exec(initSql);

const defaultAdmin = process.env.ADMIN_USERNAME || 'admin';
const defaultPassword = process.env.ADMIN_PASSWORD || 'admin';
const adminExists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(defaultAdmin);
if (!adminExists) {
  const hash = bcrypt.hashSync(defaultPassword, 10);
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(defaultAdmin, hash, 'admin');
}

const seedProducts = [
  { id: 'm1', category: 'men', title: 'Tailored Wool Coat', price: 18500, pieces: 5, image: 'https://images.unsplash.com/photo-1544022613-e87ca75a784a?q=80&w=500' },
  { id: 'm2', category: 'men', title: 'Classic Knit Sweater', price: 8200, pieces: 12, image: 'https://images.unsplash.com/photo-1614975058789-41316d0e2e9c?q=80&w=500' },
  { id: 'w1', category: 'women', title: 'Asymmetrical Blazer', price: 14500, pieces: 8, image: 'https://images.unsplash.com/photo-1548624149-f1bc346fe72b?q=80&w=500' },
  { id: 'a1', category: 'accessories', title: 'Minimalist Timepiece', price: 24000, pieces: 4, image: 'https://images.unsplash.com/photo-1522312346375-d1a52e2b99b3?q=80&w=500' }
];

const existingProducts = db.prepare('SELECT COUNT(*) as count FROM products').get();
if (existingProducts.count === 0) {
  const insert = db.prepare('INSERT INTO products (id, category, title, price, pieces, image) VALUES (@id, @category, @title, @price, @pieces, @image)');
  const insertMany = db.transaction((rows) => {
    rows.forEach((row) => insert.run(row));
  });
  insertMany(seedProducts);
}

const defaultSlides = [
  { id: 'men-0', category: 'men', idx: 0, image: 'https://images.unsplash.com/photo-1490481651871-ab68de25d43d?q=80&w=1200', title: 'Men Autumn Collection', description: 'Luxury tailoring reinvented' },
  { id: 'men-1', category: 'men', idx: 1, image: 'https://images.unsplash.com/photo-1507679799987-c73779587ccf?q=80&w=1200', title: 'Sartorial Excellence', description: 'Premium Italian woven fabrics' },
  { id: 'women-0', category: 'women', idx: 0, image: 'https://images.unsplash.com/photo-1469334031218-e382a71b716b?q=80&w=1200', title: 'Haute Couture 26', description: 'Crafted exclusively in-house' },
  { id: 'women-1', category: 'women', idx: 1, image: 'https://images.unsplash.com/photo-1485968579580-b6d095142e6e?q=80&w=1200', title: 'Modern Femme Silhouette', description: 'Bold structures for the vanguard eye' },
  { id: 'accessories-0', category: 'accessories', idx: 0, image: 'https://images.unsplash.com/photo-1441986300917-64674bd600d8?q=80&w=1200', title: 'Timeless Statements', description: 'Minimalist structural design' },
  { id: 'accessories-1', category: 'accessories', idx: 1, image: 'https://images.unsplash.com/photo-1584917865442-de89df76afd3?q=80&w=1200', title: 'Leatherwork Binary Bags', description: 'Hand-stitched full grain masterpieces' }
];
const slidesCount = db.prepare('SELECT COUNT(*) as count FROM slides').get();
if (slidesCount.count === 0) {
  const insertSlide = db.prepare('INSERT INTO slides (id, category, idx, image, title, description) VALUES (@id, @category, @idx, @image, @title, @description)');
  defaultSlides.forEach((slide) => insertSlide.run(slide));
}

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});

function generateToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
}

function authRequired(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = generateToken(user.username);
  res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'lax' });
  res.json({ success: true, role: user.role });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/products', (req, res) => {
  const rows = db.prepare('SELECT * FROM products ORDER BY category, title').all();
  res.json(rows);
});

app.get('/api/slides', (req, res) => {
  const rows = db.prepare('SELECT * FROM slides ORDER BY category, idx').all();
  res.json(rows);
});

app.post('/api/orders', (req, res) => {
  const { customer, items, total } = req.body;
  if (!customer || !Array.isArray(items) || !customer.name || !customer.address || !customer.phone || !customer.email) {
    return res.status(400).json({ error: 'Incomplete order payload' });
  }
  const id = 'NVR-' + Math.floor(100000 + Math.random() * 900000);
  const itemSummary = items.map((item) => `${item.title} (${item.size})`).join(', ');
  db.prepare('INSERT INTO orders (id, customer_name, customer_address, customer_phone, customer_email, items, total, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, customer.name, customer.address, customer.phone, customer.email, itemSummary, Number(total), 'pending');

  items.forEach((item) => {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(item.id);
    if (product) {
      db.prepare('UPDATE products SET pieces = pieces - 1 WHERE id = ?').run(item.id);
    }
  });

  res.json({ success: true, orderId: id });
});

app.get('/api/orders', authRequired, (req, res) => {
  const rows = db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
  res.json(rows);
});

app.post('/api/orders/:id/confirm', authRequired, (req, res) => {
  const { id } = req.params;
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('confirmed', id);
  res.json({ success: true });
});

app.post('/api/products', authRequired, (req, res) => {
  const { id, category, title, price, pieces, image } = req.body;
  if (!id || !category || !title || !price || !pieces) return res.status(400).json({ error: 'Missing product fields' });
  db.prepare('INSERT INTO products (id, category, title, price, pieces, image) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, category, title, Number(price), Number(pieces), image || null);
  res.json({ success: true });
});

app.put('/api/products/:id', authRequired, (req, res) => {
  const { title, price, pieces } = req.body;
  db.prepare('UPDATE products SET title = ?, price = ?, pieces = ? WHERE id = ?').run(title, Number(price), Number(pieces), req.params.id);
  res.json({ success: true });
});

app.delete('/api/products/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.put('/api/slides/:category/:idx', authRequired, (req, res) => {
  const { image, title, description } = req.body;
  db.prepare('INSERT INTO slides (id, category, idx, image, title, description) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET image = excluded.image, title = excluded.title, description = excluded.description')
    .run(`${req.params.category}-${req.params.idx}`, req.params.category, Number(req.params.idx), image, title, description);
  res.json({ success: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Novara server running on http://localhost:${PORT}`);
});
