// ruleid: javascript.security.weak-crypto
const hash = crypto.createHash('md5').update(data).digest('hex');
// ok: javascript.security.weak-crypto
const secureHash = crypto.createHash('sha256').update(data).digest('hex');
