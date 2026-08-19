// INTENTIONALLY VULNERABLE server. Both endpoints build SQL by splicing
// request input directly into the query string — the classic junior-dev
// mistake this whole lab is about. Do not run this against real data.
const express = require('express');
const crypto = require('crypto');
const pool = require('./db');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// POST /login  { username, password }
// VULNERABLE: `username` is spliced straight into the SQL text. The password
// is hashed first, so injecting through the password field alone doesn't
// help an attacker — but the username field is untouched raw input, which is
// exactly where classic auth-bypass payloads like  admin' --  land.
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const passwordHash = sha256(password || '');
  const sql = `SELECT id, username, role FROM users WHERE username = '${username}' AND password_hash = '${passwordHash}'`;
  try {
    const [rows] = await pool.query(sql);
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
// VULNERABLE: `q` is spliced straight into the SQL text on both sides of a
// LIKE match. This single endpoint is the target for both the UNION-based
// and blind injection demos.
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  const sql = `SELECT id, name, category, price, description FROM products WHERE name LIKE '%${q}%' OR category LIKE '%${q}%'`;
  try {
    const [rows] = await pool.query(sql);
    res.json({ count: rows.length, results: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => res.send('sqli-lab: VULNERABLE server running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[VULNERABLE] listening on port ${PORT}`));
