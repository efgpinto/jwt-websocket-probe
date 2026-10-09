# JWT authentication for WebSocket endpoints

This sample shows how `@JWT(validate = JWT.JwtMethodMode.BEARER_TOKEN)` works on a `@WebSocket` method in an Akka HTTP endpoint. It also shows two patterns for long-lived connections:

- **Close at token expiry:** for clients that can set the `Authorization` header.
- **Ticket:** for browser clients, which cannot set headers on a WebSocket. A variant also gives the WebSocket handler the user's JWT, for when it must forward the token to downstream services.

The sample was tested with Akka SDK 3.6.6. The `@JWT` behavior, pattern 1, and the basic ticket flow were also checked on a deployed service.

## How `@JWT` works on a WebSocket method

`@JWT` validates the token once, on the HTTP request that opens the WebSocket. After the connection opens, messages go to your `Flow` with no further token checks.

| Situation | Result |
| --- | --- |
| Valid token in `Authorization: Bearer <token>` | The connection opens. |
| No `Authorization` header | 400. The connection does not open. |
| Token in a query parameter, such as `?access_token=` | 400. `@JWT` reads only the `Authorization` header. |
| Token in the `Sec-WebSocket-Protocol` header | 400. `@JWT` reads only the `Authorization` header. |
| Expired token, bad signature, or malformed token | 403. The connection does not open. |
| The token expires while the connection is open | The connection stays open, and messages still go through. |
| A new connection with the same expired token | 403 |

Inside the WebSocket method, `requestContext().getJwtClaims()` returns the claims of the token used to open the connection. The claims do not change while the connection is open.

To end a connection when its token expires, use one of the patterns below.

## Pattern 1: close the connection at token expiry

Use this pattern when the client can set the `Authorization` header. Native mobile apps and backend clients can do this.

Read `exp` from the claims and complete the `Flow` at that time. Completing the `Flow` closes the WebSocket with code 1000. The client then reconnects with a new token.

```java
@JWT(validate = JWT.JwtMethodMode.BEARER_TOKEN)
@WebSocket("/my-socket")
public Flow<String, String, NotUsed> socket() {
  var claims = requestContext().getJwtClaims();
  // Read "exp" from asMap(). See "Implementation notes".
  var exp = Optional.ofNullable(claims.asMap().get("exp"))
    .map(raw -> Instant.ofEpochSecond(Long.parseLong(raw)));
  var flow = Flow.of(String.class).map(this::handle);
  return exp
    .map(e -> {
      var remaining = Duration.between(Instant.now(), e);
      // "exp" can pass between the token check and this line.
      return flow.takeWithin(remaining.isNegative() ? Duration.ZERO : remaining);
    })
    .orElse(flow);
}
```

In this sample: `/ws/echo-until-exp` in [`JwtProbeEndpoint`](src/main/java/com/example/api/JwtProbeEndpoint.java).

Your clients need reconnect logic in any case, because the platform also closes WebSocket connections from time to time.

## Pattern 2: ticket for browser clients

The browser `WebSocket` API cannot set request headers. `new WebSocket(url, { headers })` fails, and a connection without the header gets 400 from `@JWT`. The browser does not show that status: the connection only fails with close code 1006.

With a ticket, the token is still validated by `@JWT`, so the service needs no JWT signature code:

1. The client sends `POST /ws-ticket` with `Authorization: Bearer <token>`. `fetch` can set this header. `@JWT` validates the token.
2. The service returns a random ticket. The ticket stores the token's subject, its `exp`, and a SHA-256 hash of the token. The token itself is not stored.
3. The client opens `/ws/ticket?ticket=<ticket>` with the plain `WebSocket` API.
4. The service redeems the ticket and opens the connection. The connection closes at the token's `exp`.
5. To reconnect, the client gets a new ticket with a valid token.

Ticket rules in this sample:

- A ticket works once. A second attempt with the same ticket is refused, also when the service runs on more than one instance.
- A ticket must be used within 30 seconds, or before the token's `exp` if that comes first. Set the time with `probe.ws-ticket.ttl` in `application.conf`.
- A used ticket is deleted. An unused ticket is deleted automatically after it expires (`expireAfter` on the Key Value Entity).
- When a ticket is missing, unknown, used, or expired, the connection opens, the service sends `rejected: invalid ticket` (or `rejected: missing ticket`), and then closes the connection. See "Implementation notes" for why it does not return an HTTP error.
- When the service cannot check a ticket, for example after a timeout, it sends `rejected: temporarily unavailable, try again` and closes. The ticket may already be used, so the client gets a new ticket and reconnects.
- `POST /ws-ticket` returns 201 with the ticket. If the service cannot store the ticket, it returns 503. The client then calls again. A ticket is returned only after it is stored, so a client never receives a ticket that does not work.

What the browser code looks like:

```js
const res = await fetch("/ws-ticket", {
  method: "POST",
  headers: { Authorization: `Bearer ${token}` },
});
const { ticket } = await res.json();
const ws = new WebSocket(`wss://${location.host}/ws/ticket?ticket=${ticket}`);
```

In this sample: [`WsTicketEndpoint`](src/main/java/com/example/api/WsTicketEndpoint.java) and [`WsTicketEntity`](src/main/java/com/example/application/WsTicketEntity.java).

The ticket is part of the URL, so it can appear in access logs. It is short-lived and works only once, so a logged ticket cannot be reused.

### When the handler must forward the token downstream

With a ticket, the WebSocket connection carries no JWT. If your WebSocket handler calls other services with the user's token, use `/ws/ticket-with-token` instead of `/ws/ticket`:

1. The client gets a ticket with `POST /ws-ticket`, as above.
2. The client opens `/ws/ticket-with-token?ticket=<ticket>`.
3. The client sends the same JWT as the first message.
4. The service hashes that message and compares it with the hash in the ticket. `@JWT` already validated this exact token on `POST /ws-ticket`, so no signature check is needed.
5. The handler keeps the token in memory for this connection and uses it for downstream calls. The connection closes at the token's `exp`, so the handler never forwards an expired token.

```js
const ws = new WebSocket(`wss://${location.host}/ws/ticket-with-token?ticket=${ticket}`);
ws.onopen = () => ws.send(token); // first message: the JWT used for POST /ws-ticket
```

The connection is refused with `rejected: token does not match ticket` when the first message is a different token, and with `rejected: no token received` when no message arrives within 5 seconds (`probe.ws-ticket.first-message-timeout`).

The token is sent only once per connection, over the encrypted `wss://` connection, and it is never stored. This is why the ticket keeps only a hash.

In this sample: `ticketWithTokenSocket()` in [`WsTicketEndpoint`](src/main/java/com/example/api/WsTicketEndpoint.java). The handler shows where to add the downstream call. It only reports a fingerprint of the token, to show that the token is available.

If the downstream services are other Akka services, check first whether you need the user's token at all. Service-to-service access control (`@Acl`) plus the subject from the ticket is often enough.

## Implementation notes (Akka SDK 3.6.6)

**Read `exp` from `asMap()`.** In SDK 3.6.6, `JwtClaims.expirationTime()` returns empty. So do `issuedAt()`, `notBefore()` and the other getters for claims that are not strings, such as `getLong()`. This sample reads the raw value from `asMap()` in [`TokenLifetime`](src/main/java/com/example/domain/TokenLifetime.java).

**Refuse a WebSocket connection by completing the `Flow`.** An `HttpException` thrown from a `@WebSocket` method returns 500, whatever status it carries. To refuse a connection with a clear reason, return a `Flow` that sends the reason and completes. `/ws/ticket-throws` shows the behavior of a thrown exception.

**Tokens without `exp`.** A connection opened with a token that has no `exp` stays open until the client closes it or the platform's connection limit ends it.

**Testing `@JWT` WebSocket methods.** The test kit's `WebSocketRouteTester` does not set request headers. To send an `Authorization` header in tests, use an akka-http WebSocket client, as [`WsTestClient`](src/test/java/com/example/api/WsTestClient.java) does.

**Surefire version.** This sample sets `maven-surefire-plugin.version` to 3.1.2 in `pom.xml`, so that `mvn test` runs the JUnit 5 unit tests. Without it, `mvn test` finds no tests and still reports success. Remove the override when you upgrade to an SDK version that sets it.

## Endpoints

| Path | Description |
| --- | --- |
| `/ws/echo` | `@JWT`. Echoes each message as JSON, with the claims and whether the token has expired. |
| `/ws/echo-until-exp` | Pattern 1. Same as `/ws/echo`, and closes at the token's `exp`. |
| `POST /ws-ticket` | Pattern 2. `@JWT`. Returns 201 with a ticket, or 503 when the ticket cannot be stored. |
| `/ws/ticket?ticket=...` | Pattern 2. Opens with a ticket, and closes at the token's `exp`. |
| `/ws/ticket-with-token?ticket=...` | Pattern 2, forwarding variant. Expects the JWT as the first message, and keeps it for downstream calls. |
| `/ws/ticket-throws` | Throws `HttpException.forbidden()` from a WebSocket method. |

## Run the tests

```shell
mvn verify
```

In tests and local development, the service accepts unsigned tokens (`alg: none`). It still checks `exp`.

## Run locally

Start the service:

```shell
mvn compile exec:java
```

Open a connection with a token that expires after 4 seconds, and send messages for 10 seconds:

```shell
node scripts/ws-probe.mjs ws://localhost:9000/ws/echo 4 10
```

Get a ticket and connect the way a browser does:

```shell
node scripts/ticket-probe.mjs http://localhost:9000 4
```

The ticket script also runs the forwarding variant: it opens `/ws/ticket-with-token` and sends the JWT as the first message.

The scripts need Node 22 or later.

## Run against a deployed service

1. Deploy the service and expose it.

2. Generate a key pair. This writes `probe-es256.pem` (private key) and `jwks.json` (public key):

   ```shell
   node scripts/generate-key.mjs
   ```

3. Store the public key in a secret and add it as a keyset for the service:

   ```shell
   akka secret create generic jwt-probe-jwks --from-file jwks.json=jwks.json
   ```

   ```shell
   akka service jwks add jwt-websocket-probe --secret jwt-probe-jwks --issuer probe-issuer
   ```

4. Enable WebSockets on the route. Without this, the platform refuses WebSocket connections with 403. Export the route with `akka route export <route-name>`, add `enableWebsockets: true`, and apply it with `akka route update <route-name> -f route.yaml`:

   ```yaml
   routes:
   - prefix: /
     enableWebsockets: true
     route:
       service: jwt-websocket-probe
   ```

5. Run the scripts with signed tokens:

   ```shell
   export JWT_PRIVATE_KEY_FILE=probe-es256.pem JWT_KID=probe-key
   ```

   ```shell
   node scripts/ws-probe.mjs wss://<hostname>/ws/echo 5 14
   ```

   ```shell
   node scripts/ticket-probe.mjs https://<hostname> 6
   ```
