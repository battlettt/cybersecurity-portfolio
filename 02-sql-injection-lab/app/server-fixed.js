// FIXED server. Identical routes and behavior to server.js, except every
// query uses parameterized placeholders (`?`) instead of string
// concatenation. User input is sent to MySQL as data, never as SQL text, so
// quotes/comments/UNION keywords in input can't change the query structure.
const express = require('express');
const crypto = require('crypto');
const pool = require('./db');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// POST /login  { username, password }
// FIXED: username and password_hash are bound parameters. mysql2 sends the
// query template and the values separately over the wire — the driver
// never re-parses attacker input as SQL.
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const passwordHash = sha256(password || '');
  const sql = 'SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?';
  try {
    const [rows] = await pool.query(sql, [username, passwordHash]);
    if (rows.length > 0) {
      res.json({ success: true, user: rows[0] });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /search?q=...
// FIXED: `q` is bound as a parameter, with the `%...%` wildcard applied to
// the value itself (not the SQL text). A payload like `' UNION SELECT ...`
// is matched literally against product names/categories — it just won't
// match anything, instead of being parsed as SQL.
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  const sql = 'SELECT id, name, category, price, description FROM products WHERE name LIKE ? OR category LIKE ?';
  const like = `%${q}%`;
  try {
    const [rows] = await pool.query(sql, [like, like]);
    res.json({ count: rows.length, results: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => res.send('sqli-lab: FIXED server running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[FIXED] listening on port ${PORT}`));
