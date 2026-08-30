// ruleid: korea.js.improper-exception
try { work(); } catch (e) {}
// ok: korea.js.improper-exception
try { work(); } catch (e) { logger.error(e); }
