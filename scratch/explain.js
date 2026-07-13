const { db } = require('../src/db.js');
async function test() {
  const pool = db.getPool();
  try {
    const res = await pool.query("EXPLAIN ANALYZE SELECT * FROM tickets WHERE company_id = 1 ORDER BY id DESC LIMIT 50");
    console.log(res.rows.map(r=>r['QUERY PLAN']).join('\n'));
  } catch(e) { console.error(e) }
  process.exit(0);
}
test();
