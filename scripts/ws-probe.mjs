// Opens a WebSocket with a short-lived JWT and keeps sending messages past "exp".
//
// Usage:
//   node scripts/ws-probe.mjs <ws-url> [ttl-seconds] [run-seconds]
//
// Environment:
//   JWT_PRIVATE_KEY_FILE  PEM file with a P-256 private key. When set, signs the token with ES256.
//                         When unset, the token is unsigned (alg "none"), which only local dev
//                         mode accepts.
//   JWT_KID               key id for the "kid" header (deployed services).
//   JWT_ISS               issuer claim (default "probe-issuer").
import crypto from "node:crypto";
import fs from "node:fs";

const [url, ttlArg = "5", runArg = "12"] = process.argv.slice(2);
if (!url) {
  console.error("usage: node scripts/ws-probe.mjs <ws-url> [ttl-seconds] [run-seconds]");
  process.exit(2);
}
const ttl = Number(ttlArg);
const runFor = Number(runArg);

const b64url = (buf) => Buffer.from(buf).toString("base64url");

function makeToken() {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: process.env.JWT_ISS ?? "probe-issuer", sub: "alice", iat: now, exp: now + ttl };
  const keyFile = process.env.JWT_PRIVATE_KEY_FILE;
  const header = keyFile
    ? { alg: "ES256", typ: "JWT", ...(process.env.JWT_KID ? { kid: process.env.JWT_KID } : {}) }
    : { alg: "none" };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = keyFile
    ? crypto
        .sign("sha256", Buffer.from(signingInput), {
          key: fs.readFileSync(keyFile),
          dsaEncoding: "ieee-p1363",
        })
        .toString("base64url")
    : "";
  return { token: `${signingInput}.${signature}`, exp: claims.exp };
}

const { token, exp } = makeToken();
const started = Date.now();
const t = () => `+${((Date.now() - started) / 1000).toFixed(1)}s`;
console.log(`${t()} exp=${new Date(exp * 1000).toISOString()} (ttl ${ttl}s), running ${runFor}s`);

// Node's WebSocket (undici) accepts a non-standard "headers" option. Browsers cannot do this.
const ws = new WebSocket(url, { headers: { Authorization: `Bearer ${token}` } });
let seq = 0;
let timer;

ws.addEventListener("open", () => {
  console.log(`${t()} open`);
  const send = () => {
    seq += 1;
    const expired = Date.now() / 1000 >= exp;
    ws.send(`msg ${seq} (token expired on client clock: ${expired})`);
  };
  send();
  timer = setInterval(send, 2000);
});
ws.addEventListener("message", (e) => {
  let text = e.data;
  try {
    const r = JSON.parse(e.data);
    text = `seq=${r.seq} tokenExpired=${r.tokenExpired} message="${r.message}"`;
  } catch {}
  console.log(`${t()} recv ${text}`);
});
ws.addEventListener("error", (e) => console.log(`${t()} error ${e.message ?? ""}`));
ws.addEventListener("close", (e) => {
  clearInterval(timer);
  console.log(`${t()} closed code=${e.code} reason="${e.reason}"`);
  process.exit(0);
});

setTimeout(() => {
  console.log(`${t()} client done, socket still open: ${ws.readyState === WebSocket.OPEN}`);
  ws.close(1000, "client done");
}, runFor * 1000);
