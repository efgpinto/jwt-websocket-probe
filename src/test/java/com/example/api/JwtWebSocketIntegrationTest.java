package com.example.api;

import static com.example.api.WsTestClient.bearer;
import static com.example.api.WsTestClient.claims;
import static com.example.api.WsTestClient.exp;
import static com.example.api.WsTestClient.expectClosedAtExp;
import static com.example.api.WsTestClient.rawToken;
import static com.example.api.WsTestClient.sendAndReceive;
import static com.example.api.WsTestClient.sleepUntil;
import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Checks how {@code @JWT(validate = BEARER_TOKEN)} behaves on a WebSocket method.
 *
 * <p>The testkit runs in dev mode, which accepts unsigned tokens (alg "none") but still checks
 * "exp".
 */
public class JwtWebSocketIntegrationTest extends TestKitSupport {

  private static final String ECHO = "/ws/echo";
  private static final String ECHO_UNTIL_EXP = "/ws/echo-until-exp";

  private WsTestClient ws;

  @BeforeEach
  public void setUp() {
    ws = new WsTestClient(testKit);
  }

  // ---- Handshake: where the token can come from, and what failures return ----

  @Test
  public void missingAuthorizationHeaderIsRejectedWith400() {
    var upgrade = ws.handshake(ECHO, Optional.empty(), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(400);
  }

  @Test
  public void tokenInQueryParameterIsIgnored() {
    var token = rawToken(claims("alice", 60));

    var upgrade = ws.handshake(ECHO + "?access_token=" + token, Optional.empty(), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(400);
  }

  @Test
  public void tokenInSecWebSocketProtocolIsIgnored() {
    var token = rawToken(claims("alice", 60));

    var upgrade = ws.handshake(ECHO, Optional.empty(), Optional.of(token));

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(400);
  }

  @Test
  public void expiredTokenIsRejectedWith403() {
    var upgrade = ws.handshake(ECHO, Optional.of(bearer(claims("alice", -10))), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(403);
  }

  @Test
  public void malformedTokenIsRejectedWith403() {
    var upgrade = ws.handshake(ECHO, Optional.of("Bearer not-a-jwt"), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(403);
  }

  // ---- Open connection ----

  @Test
  public void claimsFromHandshakeAreAvailableInsideTheFlow() {
    var conn = ws.connect(ECHO, Optional.of(bearer(claims("alice", 60))));

    var reply = sendAndReceive(conn, "hello");

    assertThat(reply.seq()).isEqualTo(1);
    assertThat(reply.subject()).isEqualTo("alice");
    assertThat(reply.message()).isEqualTo("hello");
    assertThat(reply.tokenExpired()).isFalse();
    conn.publisher().sendComplete();
  }

  @Test
  public void sdkExpirationTimeIsEmptyForNumericExpClaim() {
    var claims = claims("alice", 60);
    var conn = ws.connect(ECHO, Optional.of(bearer(claims)));

    var reply = sendAndReceive(conn, "hello");

    // The raw claim is there, but the typed SDK getter does not see it.
    assertThat(reply.claims()).containsEntry("exp", claims.get("exp").toString());
    assertThat(reply.expiresAt()).isEqualTo(exp(claims));
    assertThat(reply.sdkExpirationTime()).isNull();
    conn.publisher().sendComplete();
  }

  @Test
  public void openSocketKeepsWorkingAfterTokenExpires() throws Exception {
    var claims = claims("alice", 3);
    var conn = ws.connect(ECHO, Optional.of(bearer(claims)));

    var before = sendAndReceive(conn, "before exp");
    assertThat(before.tokenExpired()).isFalse();

    sleepUntil(exp(claims).plusSeconds(2));

    // No per-message validation and no close at "exp": the message still goes through.
    var after = sendAndReceive(conn, "after exp");
    assertThat(after.now()).isAfter(exp(claims));
    assertThat(after.tokenExpired()).isTrue();
    assertThat(after.seq()).isEqualTo(2);

    // A new handshake with the same token is rejected.
    var reconnect = ws.handshake(ECHO, Optional.of(bearer(claims)), Optional.empty());
    assertThat(reconnect.response().status().intValue()).isEqualTo(403);

    conn.publisher().sendComplete();
  }

  // ---- Workaround: complete the Flow at "exp" ----

  @Test
  public void flowThatCompletesAtExpClosesTheSocket() {
    var conn = ws.connect(ECHO_UNTIL_EXP, Optional.of(bearer(claims("alice", 3))));

    var before = sendAndReceive(conn, "before exp");
    assertThat(before.tokenExpired()).isFalse();

    expectClosedAtExp(conn);
  }
}
