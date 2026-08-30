// ruleid: javascript.security.unsafe-innerhtml
el.innerHTML = user.name;
// ok: javascript.security.unsafe-innerhtml
el.textContent = user.name;
