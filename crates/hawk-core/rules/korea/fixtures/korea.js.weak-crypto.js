// ruleid: korea.js.weak-crypto
const h = crypto.createHash("md5").update(pw).digest("hex");
// ok: korea.js.weak-crypto
const h = crypto.createHash("sha256").update(pw).digest("hex");
