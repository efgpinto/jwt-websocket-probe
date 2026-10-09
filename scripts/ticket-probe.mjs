// Ticket pattern, the way a browser does it:
//   1. POST /ws-ticket with the Authorization header (fetch can set headers).
//   2. Open the WebSocket with only ?ticket=... (no headers, standard WebSocket API).
//   3. Try to reuse the ticket.
//   4. Forwarding variant: get a new ticket, open /ws/ticket-with-token, send the JWT first.
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

async function issueTicket(token) {
  const res = await fetch(`${base}/ws-ticket`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  const body = await res.json();
  console.log(`${t()} POST /ws-ticket -> ${res.status}, validUntil ${body.validUntil}`);
  return body.ticket;
}

function run(url, firstMessage) {
  return new Promise((resolve) => {
    const ws = new WebSocket(url); // no headers, as in a browser
    let n = 0;
    let timer;
    ws.addEventListener("open", () => {
      console.log(`${t()} open ${url.split("?")[0]}`);
      if (firstMessage) {
        ws.send(firstMessage);
        console.log(`${t()} sent the JWT as the first message`);
      }
      const send = () => ws.send(`msg ${++n}`);
      send();
      timer = setInterval(send, 1500);
    });
    ws.addEventListener("message", (e) => {
      let text = e.data;
      try {
        const r = JSON.parse(e.data);
        text = `seq=${r.seq} sub=${r.subject} tokenExpired=${r.tokenExpired}`;
        if (r.claims?.forwardableTokenSha256) text += " token=available";
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

const first = makeToken(Number(ttlArg));
console.log(`${t()} token exp=${new Date(first.exp * 1000).toISOString()}`);
const ticket = await issueTicket(first.token);
await run(`${wsBase}/ws/ticket?ticket=${ticket}`);
console.log("-- reuse the same ticket");
await run(`${wsBase}/ws/ticket?ticket=${ticket}`);
console.log("-- forwarding variant: JWT as the first message");
const second = makeToken(Number(ttlArg));
console.log(`${t()} new token exp=${new Date(second.exp * 1000).toISOString()}`);
await run(`${wsBase}/ws/ticket-with-token?ticket=${await issueTicket(second.token)}`, second.token);
