// Creates the schema and loads seed data for the SQL injection lab.
// Run once before starting either server: `node seed.js`
const crypto = require('crypto');
const pool = require('./db');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// [username, email, plaintext_password, role]
// Plaintext passwords are only used here to derive password_hash; the app
// never stores plaintext. The 'admin' row is the high-value target the
// exploit scripts are meant to reach.
const users = [
  ['alice', 'alice@example.com', 'Password123!', 'user'],
  ['bob', 'bob@example.com', 'Summer2025', 'user'],
  ['carol', 'carol@example.com', 'CarolC00l', 'user'],
  ['dave', 'dave@example.com', 'Dave!2025', 'user'],
  ['erin', 'erin@example.com', 'Erin_1234', 'user'],
  ['frank', 'frank@example.com', 'FrankyBoy9', 'user'],
  ['grace', 'grace@example.com', 'GraceHopper1', 'user'],
  ['heidi', 'heidi@example.com', 'Heidi#2025', 'user'],
  ['ivan', 'ivan@example.com', 'IvanTheG8', 'user'],
  ['admin', 'admin@corp-internal.local', 'Sup3rSecretAdminPass!2026', 'admin'],
];

const products = [
  ['Wireless Mouse', 'Electronics', 19.99, 'Ergonomic 2.4GHz wireless mouse'],
  ['Mechanical Keyboard', 'Electronics', 79.99, 'Hot-swappable tactile switches'],
  ['USB-C Hub', 'Electronics', 29.99, '7-in-1 USB-C dock'],
  ['Standing Desk', 'Furniture', 249.99, 'Electric height-adjustable desk'],
  ['Office Chair', 'Furniture', 149.99, 'Mesh back ergonomic chair'],
  ['Notebook Set', 'Stationery', 6.99, 'Pack of 3 dotted notebooks'],
  ['Fountain Pen', 'Stationery', 24.99, 'Fine nib, refillable ink'],
  ['Desk Lamp', 'Furniture', 34.99, 'LED lamp with adjustable brightness'],
  ['Webcam HD', 'Electronics', 45.99, '1080p webcam with mic'],
  ['Laptop Stand', 'Electronics', 22.99, 'Aluminum adjustable laptop stand'],
];

async function seed() {
  await pool.query('DROP TABLE IF EXISTS users');
  await pool.query('DROP TABLE IF EXISTS products');

  await pool.query(`
    CREATE TABLE users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL,
      email VARCHAR(100) NOT NULL,
      password_hash CHAR(64) NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user'
    )
  `);

  await pool.query(`
    CREATE TABLE products (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      category VARCHAR(50) NOT NULL,
      price DECIMAL(10,2) NOT NULL,
      description VARCHAR(255)
    )
  `);

  for (const [username, email, password, role] of users) {
    await pool.query(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      [username, email, sha256(password), role]
    );
  }

  for (const p of products) {
    await pool.query(
      'INSERT INTO products (name, category, price, description) VALUES (?, ?, ?, ?)',
      p
    );
  }

  console.log(`Seeded ${users.length} users and ${products.length} products into sqli_lab.`);
  console.log('Reference (for verifying exploit output only — the app never exposes plaintext passwords):');
  for (const [username, , password] of users) {
    console.log(`  ${username.padEnd(8)} password="${password}" sha256=${sha256(password)}`);
  }
  process.exit(0);
}

seed().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
