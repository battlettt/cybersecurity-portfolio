/**
 * SECURE SERVER — Project 1 (fixed branch)
 *
 * Same feature set as ../../vulnerable/server/server.js, with each of the 4
 * vulnerabilities remediated using industry-standard controls:
 *
 *   1. SQL Injection          -> parameterized queries (mysql2 placeholders) everywhere
 *   2. Stored XSS             -> input sanitized server-side (sanitize-html strips all
 *                                 tags) AND client renders as text, never raw HTML
 *   3. Broken Authentication  -> bcrypt password hashing (cost 12) + JWT session tokens
 *   4. Broken Access Control  -> every protected route verifies a signed JWT server-side;
 *                                 delete requires the requester to be the review's author
 *                                 OR an admin, checked from the verified token, never from
 *                                 a client-supplied header
 */

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sanitizeHtml = require('sanitize-html');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4001;
const JWT_SECRET = 'portfolio-demo-secret-do-not-use-in-prod'; // in real deployment: env var + rotation

const pool = mysql.createPool({
  host: '127.0.0.1',
  port: 3309,
  user: 'root',
  password: '',
  database: 'appdb_secure',
  socketPath: '/tmp/mysql-portfolio.sock',
});

// --- FIX 4: real auth middleware. Every protected route runs this instead of
// trusting a client-supplied header. ---
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET); // { id, username, role }
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// --- FIX 1 + FIX 3: parameterized query, bcrypt comparison, real signed session ---
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
  const user = rows[0];
  if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ success: true, token, user: { id: user.id, username: user.username, role: user.role } });
});

app.get('/api/reviews', async (_req, res) => {
  const [rows] = await pool.query('SELECT * FROM reviews ORDER BY created_at DESC');
  res.json(rows);
});

// --- FIX 1: parameterized LIKE query — no string concatenation, so no
// UNION/comment injection is possible regardless of input content. ---
app.get('/api/reviews/search', async (req, res) => {
  const q = req.query.q || '';
  const [rows] = await pool.query(
    'SELECT id, movie_title, review_text, author_id, created_at FROM reviews WHERE movie_title LIKE ?',
    [`%${q}%`]
  );
  res.json(rows);
});

// --- FIX 2: server-side sanitization (defense in depth alongside the client
// no longer using dangerouslySetInnerHTML). Strips ALL tags/attributes. ---
// --- FIX 4: author_id comes from the verified JWT, never from the request body. ---
app.post('/api/reviews', requireAuth, async (req, res) => {
  const { movie_title, review_text } = req.body;
  const cleanText = sanitizeHtml(review_text, { allowedTags: [], allowedAttributes: {} });
  const [result] = await pool.query(
    'INSERT INTO reviews (movie_title, review_text, author_id) VALUES (?, ?, ?)',
    [movie_title, cleanText, req.user.id]
  );
  res.json({ success: true, id: result.insertId });
});

// --- FIX 4: ownership check. Only the review's author or an admin may delete it,
// and both facts come from the verified JWT, not anything the client claims. ---
app.delete('/api/reviews/:id', requireAuth, async (req, res) => {
  const [rows] = await pool.query('SELECT author_id FROM reviews WHERE id = ?', [req.params.id]);
  const review = rows[0];
  if (!review) return res.status(404).json({ error: 'Not found' });

  if (review.author_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden — you do not own this review' });
  }

  await pool.query('DELETE FROM reviews WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// --- FIX 4: role comes from the verified JWT server-side, not a client header. ---
app.get('/api/admin/users', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const [rows] = await pool.query('SELECT id, username, email, role FROM users'); // note: no password_hash in response either
  res.json(rows);
});

app.listen(PORT, () => {
  console.log(`[SECURE] server listening on http://localhost:${PORT}`);
});
