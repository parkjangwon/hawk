// ruleid: korea.js.error-message-info
res.status(500).send(err.stack);
// ok: korea.js.error-message-info
res.status(500).send("internal error");
