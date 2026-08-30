// ruleid: korea.js.infinite-loop
while (true) { doWork(); }
// ok: korea.js.infinite-loop
while (running) { doWork(); }
