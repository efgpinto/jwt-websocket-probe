// Generates an ES256 key pair for the probes.
//
// Usage:
//   node scripts/generate-key.mjs [key-id]
//
// Writes:
//   probe-es256.pem  private key, used by the probe scripts to sign tokens. Keep it private.
//   jwks.json        public key as a JWKS document, to store in an Akka secret.
import crypto from "node:crypto";
import fs from "node:fs";

const kid = process.argv[2] ?? "probe-key";
const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

fs.writeFileSync("probe-es256.pem", privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
const jwk = publicKey.export({ format: "jwk" });
fs.writeFileSync("jwks.json", JSON.stringify({ keys: [{ ...jwk, kid, alg: "ES256", use: "sig" }] }, null, 2));

console.log(`Wrote probe-es256.pem and jwks.json (kid "${kid}")`);
