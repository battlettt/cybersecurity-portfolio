// Shared MySQL connection pool used by both the vulnerable and fixed servers.
// Connection details can be overridden with env vars; defaults match the
// local MySQL instance used to build/verify this lab (see README.md).
const mysql = require('mysql2/promise');

// If MYSQL_HOST is set, connect over TCP; otherwise fall back to the local
// unix socket (short path required — see README "MySQL setup notes").
const connectionConfig = process.env.MYSQL_HOST
  ? {
      host: process.env.MYSQL_HOST,
      port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306,
    }
  : {
      socketPath: process.env.MYSQL_SOCKET || '/private/tmp/sqllab_mysql.sock',
    };

const pool = mysql.createPool({
  ...connectionConfig,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
  waitForConnections: true,
  connectionLimit: 5,
});

module.exports = pool;
