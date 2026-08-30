// ruleid: korea.js.weak-random
const token = Math.random().toString(36);
// ok: korea.js.weak-random
const token = crypto.randomBytes(16).toString("hex");
