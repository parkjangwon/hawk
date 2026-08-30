// ruleid: korea.js.ssrf
const r = await axios.get("http://internal/" + req.query.url);
// ok: korea.js.ssrf
const r = await axios.get("https://api.example.com/v1");
