// Ticket pattern, the way a browser does it:
//   1. POST /ws-ticket with the Authorization header (fetch can set headers).
//   2. Open the WebSocket with only ?ticket=... (no headers, standard WebSocket API).
//   3. Try to reuse the ticket.
//
// Usage:
//   node scripts/ticket-probe.mjs <base-url> [ttl-seconds]
//   base-url: http://localhost:9000 or https://<hostname>
// Token settings: see token.mjs.
import { makeToken } from "./token.mjs";

const [base, ttlArg = "5"] = process.argv.slice(2);
if (!base) {
  console.error("usage: node scripts/ticket-probe.mjs <base-url> [ttl-seconds]");
  process.exit(2);
}
const wsBase = base.replace(/^http/, "ws");
const started = Date.now();
const t = () => `+${((Date.now() - started) / 1000).toFixed(1)}s`;

const { token, exp } = makeToken(Number(ttlArg));
console.log(`${t()} token exp=${new Date(exp * 1000).toISOString()}`);

const res = await fetch(`${base}/ws-ticket`, {
  method: "POST",
  headers: { Authorization: `Bearer ${token}` },
});
const { ticket, validUntil } = await res.json();
console.log(`${t()} POST /ws-ticket -> ${res.status}, validUntil ${validUntil}`);

function run(url) {
  return new Promise((resolve) => {
    const ws = new WebSocket(url); // no headers, as in a browser
    let n = 0;
    let timer;
    ws.addEventListener("open", () => {
      console.log(`${t()} open ${url.split("?")[0]}`);
      const send = () => ws.send(`msg ${++n}`);
      send();
      timer = setInterval(send, 1500);
    });
    ws.addEventListener("message", (e) => {
      let text = e.data;
      try {
        const r = JSON.parse(e.data);
        text = `seq=${r.seq} sub=${r.subject} tokenExpired=${r.tokenExpired}`;
      } catch {}
      console.log(`${t()} recv ${text}`);
    });
    ws.addEventListener("close", (e) => {
      clearInterval(timer);
      console.log(`${t()} closed code=${e.code}`);
      resolve();
    });
  });
}

await run(`${wsBase}/ws/ticket?ticket=${ticket}`);
console.log("-- reuse the same ticket");
await run(`${wsBase}/ws/ticket?ticket=${ticket}`);
