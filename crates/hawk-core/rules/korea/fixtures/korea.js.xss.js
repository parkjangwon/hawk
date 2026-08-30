// ruleid: korea.js.xss
el.outerHTML = req.query.q;
// ruleid: korea.js.xss
el.insertAdjacentHTML("beforeend", req.query.q);
// ok: korea.js.xss
el.textContent = req.query.q;
