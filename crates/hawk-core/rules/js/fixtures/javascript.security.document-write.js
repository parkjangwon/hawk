// ruleid: javascript.security.document-write
document.write("<b>" + user.name + "</b>");
// ok: javascript.security.document-write
document.title = "safe";
