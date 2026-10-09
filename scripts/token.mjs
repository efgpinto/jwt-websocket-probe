// Builds a JWT for the probes.
//
// Environment:
//   JWT_PRIVATE_KEY_FILE  PEM file with a P-256 private key. When set, signs the token with ES256.
//                         When unset, the token is unsigned (alg "none"), which only local dev
//                         mode accepts.
//   JWT_KID               key id for the "kid" header (deployed services).
//   JWT_ISS               issuer claim (default "probe-issuer").
import crypto from "node:crypto";
import fs from "node:fs";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

export function makeToken(ttlSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: process.env.JWT_ISS ?? "probe-issuer", sub: "alice", iat: now, exp: now + ttlSeconds };
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
