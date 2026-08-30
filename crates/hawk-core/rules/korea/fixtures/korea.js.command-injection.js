// ruleid: korea.js.command-injection
child_process.exec("ls -l " + req.query.path, cb);
// ok: korea.js.command-injection
child_process.execFile("ls", ["-l"], cb);
