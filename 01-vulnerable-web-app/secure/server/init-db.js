/**
 * Seeds appdb_secure with the same three users/two reviews as the vulnerable
 * build, but with bcrypt-hashed passwords instead of plaintext.
 */
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

async function main() {
  const conn = await mysql.createConnection({
    host: '127.0.0.1',
    port: 3309,
    user: 'root',
    password: '',
    socketPath: '/tmp/mysql-portfolio.sock',
    multipleStatements: true,
  });

  await conn.query(`
    CREATE DATABASE IF NOT EXISTS appdb_secure;
    USE appdb_secure;
    DROP TABLE IF EXISTS reviews;
    DROP TABLE IF EXISTS users;
    CREATE TABLE users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      email VARCHAR(100) NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user'
    );
    CREATE TABLE reviews (
      id INT AUTO_INCREMENT PRIMARY KEY,
      movie_title VARCHAR(200) NOT NULL,
      review_text TEXT NOT NULL,
      author_id INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (author_id) REFERENCES users(id)
    );
  `);

  const users = [
    ['alice', 'alicepass123', 'alice@example.com', 'user'],
    ['bob', 'bobsecret456', 'bob@example.com', 'user'],
    ['admin', 'SuperSecretAdmin2026!', 'admin@corp-app.com', 'admin'],
  ];

  for (const [username, plain, email, role] of users) {
    const hash = await bcrypt.hash(plain, 12); // cost factor 12 — deliberately slow to brute-force
    await conn.query(
      'INSERT INTO appdb_secure.users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
      [username, hash, email, role]
    );
  }

  const [userRows] = await conn.query('SELECT id, username FROM appdb_secure.users');
  const idByName = Object.fromEntries(userRows.map(u => [u.username, u.id]));

  await conn.query(
    'INSERT INTO appdb_secure.reviews (movie_title, review_text, author_id) VALUES (?, ?, ?), (?, ?, ?)',
    ['Dune: Part Two', 'Visually stunning, great sound design.', idByName.alice,
     'Oppenheimer', 'Christopher Nolan does it again.', idByName.bob]
  );

  console.log('appdb_secure seeded. Passwords are bcrypt-hashed (cost 12), not plaintext.');
  const [check] = await conn.query('SELECT username, password_hash FROM appdb_secure.users');
  console.table(check);

  await conn.end();
}

main().catch(err => { console.error(err); process.exit(1); });
