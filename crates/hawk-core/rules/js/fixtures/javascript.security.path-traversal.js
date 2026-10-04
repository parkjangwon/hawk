// ruleid: javascript.security.path-traversal
fs.readFile(req.query.filename, 'utf8', (err, data) => {});
// ok: javascript.security.path-traversal
fs.readFile('/etc/app.conf', 'utf8', (err, data) => {});
