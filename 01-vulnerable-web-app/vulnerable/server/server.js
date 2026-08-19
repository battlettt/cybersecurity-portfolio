/**
 * INTENTIONALLY VULNERABLE SERVER — Project 1 (vulnerable branch)
 *
 * This file deliberately contains 4 OWASP Top 10 vulnerabilities so they can
 * be exploited and documented, then compared against ../../secure/server/server.js
 * which fixes each one. DO NOT deploy this code anywhere real.
 *
 *   1. SQL Injection          -> /api/login, /api/reviews/search
 *   2. Stored XSS             -> POST /api/reviews (rendered unescaped by the client)
 *   3. Broken Authentication  -> plaintext password storage + comparison
 *   4. Broken Access Control  -> DELETE /api/reviews/:id and /api/admin/users trust
 *                                 client-supplied headers instead of a verified session
 */

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

const pool = mysql.createPool({
  host: '127.0.0.1',
  port: 3309,
  user: 'root',
  password: '',
  database: 'appdb',
  socketPath: '/tmp/mysql-portfolio.sock',
});

// --- VULNERABILITY 1: SQL Injection (auth bypass via string concatenation) ---
// VULNERABILITY 3: Broken Authentication (plaintext password stored + compared)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // Raw string concatenation into SQL — classic injection point.
  // Try: username = admin' -- and any password.
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  try {
    const [rows] = await pool.query(query);
    if (rows.length > 0) {
      const user = rows[0];
      // No session/JWT — client is simply handed the role and trusted to self-report it later.
      return res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
    }
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message, query });
  }
});

app.get('/api/reviews', async (_req, res) => {
  const [rows] = await pool.query('SELECT * FROM reviews ORDER BY created_at DESC');
  res.json(rows);
});

// --- VULNERABILITY 1b: SQL Injection (UNION-based data exfiltration) ---
app.get('/api/reviews/search', async (req, res) => {
  const q = req.query.q || '';

  // Try: ' UNION SELECT id, username, password, role, NOW() FROM users --
  const query = `SELECT id, movie_title, review_text, author_id, created_at FROM reviews WHERE movie_title LIKE '%${q}%'`;

  try {
    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message, query });
  }
});

// --- VULNERABILITY 2: Stored XSS ---
// review_text is stored completely unsanitized. The vulnerable React client
// renders it with dangerouslySetInnerHTML, so a script payload here executes
// in every future visitor's browser.
app.post('/api/reviews', async (req, res) => {
  const { movie_title, review_text, author_id } = req.body;
  const [result] = await pool.query(
    'INSERT INTO reviews (movie_title, review_text, author_id) VALUES (?, ?, ?)',
    [movie_title, review_text, author_id]
  );
  res.json({ success: true, id: result.insertId });
});

// --- VULNERABILITY 4: Broken Access Control (IDOR) ---
// Any authenticated-or-not client can delete any review by guessing/incrementing
// the id — there is no check that the requester owns the review or is an admin.
app.delete('/api/reviews/:id', async (req, res) => {
  await pool.query('DELETE FROM reviews WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// --- VULNERABILITY 4b: Broken Access Control (client-controlled authorization) ---
// "Admin check" trusts a header the client sets itself — trivially spoofed in devtools,
// curl, or Burp, no server-side verification of an actual session/role at all.
app.get('/api/admin/users', async (req, res) => {
  if (req.headers['x-role'] !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const [rows] = await pool.query('SELECT id, username, password, email, role FROM users');
  res.json(rows);
});

app.listen(PORT, () => {
  console.log(`[VULNERABLE] server listening on http://localhost:${PORT}`);
});
