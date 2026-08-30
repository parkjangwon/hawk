// ruleid: korea.js.sql-injection
const query = `SELECT email FROM user WHERE id = ${userInput}`;
// ok: korea.js.sql-injection
con.query("SELECT email FROM user WHERE id = ?", [userId]);
