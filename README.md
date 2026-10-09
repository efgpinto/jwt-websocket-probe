# JWT WebSocket probe

This service tests how `@JWT(validate = JWT.JwtMethodMode.BEARER_TOKEN)` behaves on an HTTP endpoint `@WebSocket` method.

## Endpoints

| Path | Behavior |
| --- | --- |
| `/ws/echo` | `@JWT` only. Echoes each message as JSON, with the claims and whether the token has expired since the handshake. |
| `/ws/echo-until-exp` | Same, but the Flow completes at the `exp` claim. Completing the Flow closes the WebSocket. |

## Results

Tested with Akka SDK 3.6.6 (runtime 1.6.17) in three ways:
- the integration tests (`mvn verify`)
- the service running locally
- a deployment to dev with ES256-signed tokens

All three give the same results.

| Case | Result |
| --- | --- |
| No `Authorization` header | 400, `Bearer token authorization header missing` |
| Token in `?access_token=` query parameter | 400. The runtime ignores the parameter. |
| Token in `Sec-WebSocket-Protocol` | 400. The runtime ignores the header. |
| Expired token | 403, `The token is expired since ...` |
| Wrong signature, malformed token, or `alg: none` on a deployed service | 403 |
| Valid token | 101, upgrade succeeds |
| Messages after `exp` on an open socket | Delivered. The runtime does no per-message validation and does not close the socket. |
| Same token on a new handshake after `exp` | 403 |
| `/ws/echo-until-exp` | The socket closes at `exp` with code 1000. |
| `requestContext().getJwtClaims()` in a WebSocket method | Works. It returns the handshake claims, which never refresh. |
| `JwtClaims.expirationTime()` | **Always empty for a numeric `exp`** (see below) |

### SDK bug: typed claim getters return empty for non-string claims

In `akka.javasdk.impl.http.JwtClaimsImpl`, every typed getter (`getLong`, `getInteger`, `getDouble`, `getBoolean`, `getNumericDate`, the list getters) parses the result of `getString`.

The runtime returns a value from `getStringClaim` only when the claim is a JSON string. A numeric claim therefore always returns empty. This includes `expirationTime()`, `issuedAt()` and `notBefore()`.

`asMap()` reads the raw claim and works. This service reads `exp` from `asMap()` (see `TokenLifetime.fromRawExp`).

## Run the tests

```shell
mvn verify
```

The tests run in dev mode, which accepts unsigned tokens (`alg: none`) but still checks `exp`. The testkit `WebSocketRouteTester` cannot set headers, so the tests use an akka-http WebSocket client.

## Run locally

```shell
mvn compile exec:java
```

```shell
node scripts/ws-probe.mjs ws://localhost:9000/ws/echo 4 10
```

The script needs Node 22 or later for the built-in `WebSocket`. Without `JWT_PRIVATE_KEY_FILE` it sends an unsigned token.

## Run against a deployed service

1. Create a P-256 key pair. Store the public key as a JWKS document in a secret:

   ```shell
   akka secret create generic jwt-probe-jwks --from-file jwks.json=jwks.json
   ```

2. Add the keyset:

   ```shell
   akka service jwks add jwt-websocket-probe --secret jwt-probe-jwks --issuer probe-issuer
   ```

3. Set `enableWebsockets: true` on the route. Without it, the platform rejects the upgrade with 403.

4. Run the probe with signed tokens:

   ```shell
   JWT_PRIVATE_KEY_FILE=probe-es256.pem JWT_KID=probe-key node scripts/ws-probe.mjs wss://<hostname>/ws/echo 5 14
   ```
