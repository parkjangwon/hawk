// ruleid: korea.js.ldap-injection
client.search("ou=users", "(uid=" + req.query.uid + ")", cb);
// ok: korea.js.ldap-injection
client.search("ou=users", "(uid=admin)", cb);
