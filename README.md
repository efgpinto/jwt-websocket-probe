# JWT WebSocket probe

This service tests how `@JWT(validate = JWT.JwtMethodMode.BEARER_TOKEN)` behaves on an HTTP endpoint `@WebSocket` method.

## Endpoints

| Path | Behavior |
| --- | --- |
| `/ws/echo` | `@JWT` only. Echoes each message as JSON, with the claims and whether the token has expired since the handshake. |
| `/ws/echo-until-exp` | Same, but the Flow completes at the `exp` claim. Completing the Flow closes the WebSocket. |
| `POST /ws-ticket` | `@JWT`. Returns a random, single-use ticket for `/ws/ticket`. |
| `/ws/ticket?ticket=...` | No `@JWT`. Redeems the ticket, echoes messages, and closes at the JWT's `exp`. |
| `/ws/ticket-throws` | Throws `HttpException.forbidden()`. Shows that the runtime returns 500 instead of 403. |

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

## Ticket pattern for browser clients

The browser `WebSocket` API cannot set request headers, so a browser cannot use a `@JWT` WebSocket method directly. The ticket pattern lets it still rely on `@JWT`, with no JWT signature code in the service:

1. The client calls `POST /ws-ticket` with `Authorization: Bearer <jwt>`. `fetch` can set headers. `@JWT` validates the token.
2. The endpoint stores a random 256-bit ticket in `WsTicketEntity` (a Key Value Entity), with the subject and the JWT's `exp`. The ticket is valid for `probe.ws-ticket.ttl` (30 seconds), or until `exp` if that comes first.
3. The client opens `/ws/ticket?ticket=<ticket>` with the plain `WebSocket` API.
4. The method redeems the ticket. The entity handles one command at a time per ticket, so a ticket works only once, even across instances.
5. The Flow closes at the JWT's `exp`. The client then gets a new ticket with a fresh JWT.

Tested in a real browser (local), with Node's standard `WebSocket` API (local and dev), and in `WsTicketIntegrationTest`:

| Case | Result |
| --- | --- |
| Browser `new WebSocket(url, { headers })` | `SyntaxError`. The browser treats the second argument as a subprotocol. |
| Browser socket to `/ws/echo` without the header | Fails with close code 1006. The browser does not expose the 400 status. |
| `POST /ws-ticket` without a JWT, or with an invalid JWT | 400 or 403 |
| Valid ticket | Socket opens and works. The subject comes from the JWT. |
| At the JWT's `exp` | Server sends `token expired, closing connection` and closes with 1000 |
| Same ticket again, unknown ticket, or ticket past `validUntil` | Upgrade succeeds, server sends `rejected: invalid ticket` and closes |
| Missing ticket | Server sends `rejected: missing ticket` and closes |

### Runtime gap: `HttpException` from a WebSocket method returns 500

`HttpEndpointRouter` calls a `@WebSocket` method synchronously, outside the Future that `.recover(defaultErrorHandling)` covers. An `HttpException` thrown from the method is therefore not mapped to its status, and the upgrade fails with 500.

This service does not throw to reject a ticket. It accepts the upgrade, sends the reason, and closes. A browser cannot read the status of a failed handshake anyway.

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

```shell
node scripts/ticket-probe.mjs http://localhost:9000 4
```

The scripts need Node 22 or later for the built-in `WebSocket`. Without `JWT_PRIVATE_KEY_FILE` they send an unsigned token.

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

4. Run the probes with signed tokens:

   ```shell
   export JWT_PRIVATE_KEY_FILE=probe-es256.pem JWT_KID=probe-key
   node scripts/ws-probe.mjs wss://<hostname>/ws/echo 5 14
   node scripts/ticket-probe.mjs https://<hostname> 6
   ```
