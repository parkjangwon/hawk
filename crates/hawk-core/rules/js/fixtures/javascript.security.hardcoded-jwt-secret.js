// ruleid: javascript.security.hardcoded-jwt-secret
const token = jwt.sign(payload, 'super_production_secret_key_12345');
// ok: javascript.security.hardcoded-jwt-secret
const verified = jwt.sign(payload, process.env.JWT_SECRET);
