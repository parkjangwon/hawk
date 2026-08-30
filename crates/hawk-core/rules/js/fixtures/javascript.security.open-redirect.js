// ruleid: javascript.security.open-redirect
window.location.href = getParameter("next");
// ok: javascript.security.open-redirect
window.location.assign("/home");
