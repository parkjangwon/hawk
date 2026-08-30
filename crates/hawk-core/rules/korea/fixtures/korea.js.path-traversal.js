// ruleid: korea.js.path-traversal
fs.readFile(path.resolve(__dirname, requestFile), 'utf8', cb);
// ok: korea.js.path-traversal
fs.readFile('/etc/hosts', 'utf8', cb);
