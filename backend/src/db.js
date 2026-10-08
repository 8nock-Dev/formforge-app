const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
});
async function initDb() {
  const sql = fs.readFileSync(path.join(__dirname, '../migrations/001_initial.sql'), 'utf8');
  await pool.query(sql);
}
module.exports = { pool, initDb };
