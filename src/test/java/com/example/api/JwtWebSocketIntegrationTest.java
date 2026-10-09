package com.example.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.http.javadsl.Http;
import akka.http.javadsl.model.headers.RawHeader;
import akka.http.javadsl.model.ws.Message;
import akka.http.javadsl.model.ws.TextMessage;
import akka.http.javadsl.model.ws.WebSocketRequest;
import akka.http.javadsl.model.ws.WebSocketUpgradeResponse;
import akka.javasdk.JsonSupport;
import akka.javasdk.testkit.TestKitSupport;
import akka.japi.Pair;
import akka.stream.javadsl.Flow;
import akka.stream.javadsl.Keep;
import akka.stream.testkit.TestPublisher;
import akka.stream.testkit.TestSubscriber;
import akka.stream.testkit.javadsl.TestSink;
import akka.stream.testkit.javadsl.TestSource;
import com.example.api.JwtProbeEndpoint.EchoReply;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Checks how {@code @JWT(validate = BEARER_TOKEN)} behaves on a WebSocket method.
 *
 * <p>The testkit runs in dev mode, which accepts unsigned tokens (alg "none") but still checks
 * "exp". The testkit WebSocketRouteTester cannot set headers, so these tests use an akka-http
 * WebSocket client directly.
 */
public class JwtWebSocketIntegrationTest extends TestKitSupport {

  private static final String ECHO = "/ws/echo";
  private static final String ECHO_UNTIL_EXP = "/ws/echo-until-exp";

  // ---- Handshake: where the token can come from, and what failures return ----

  @Test
  public void missingAuthorizationHeaderIsRejectedWith400() {
    var upgrade = handshake(ECHO, Optional.empty(), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(400);
  }

  @Test
  public void tokenInQueryParameterIsIgnored() {
    var token = rawToken(validClaims("alice", 60));

    var upgrade = handshake(ECHO + "?access_token=" + token, Optional.empty(), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(400);
  }

  @Test
  public void tokenInSecWebSocketProtocolIsIgnored() {
    var token = rawToken(validClaims("alice", 60));

    var upgrade = handshake(ECHO, Optional.empty(), Optional.of(token));

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(400);
  }

  @Test
  public void expiredTokenIsRejectedWith403() {
    var upgrade = handshake(ECHO, Optional.of(bearer(validClaims("alice", -10))), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(403);
  }

  @Test
  public void malformedTokenIsRejectedWith403() {
    var upgrade = handshake(ECHO, Optional.of("Bearer not-a-jwt"), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(403);
  }

  // ---- Open connection ----

  @Test
  public void claimsFromHandshakeAreAvailableInsideTheFlow() {
    var ws = connect(ECHO, bearer(validClaims("alice", 60)));

    var reply = sendAndReceive(ws, "hello");

    assertThat(reply.seq()).isEqualTo(1);
    assertThat(reply.subject()).isEqualTo("alice");
    assertThat(reply.message()).isEqualTo("hello");
    assertThat(reply.tokenExpired()).isFalse();
    ws.publisher().sendComplete();
  }

  @Test
  public void sdkExpirationTimeIsEmptyForNumericExpClaim() {
    var claims = validClaims("alice", 60);
    var ws = connect(ECHO, bearer(claims));

    var reply = sendAndReceive(ws, "hello");

    // The raw claim is there, but the typed SDK getter does not see it.
    assertThat(reply.claims()).containsEntry("exp", claims.get("exp").toString());
    assertThat(reply.expiresAt()).isEqualTo(Instant.ofEpochSecond((Long) claims.get("exp")));
    assertThat(reply.sdkExpirationTime()).isNull();
    ws.publisher().sendComplete();
  }

  @Test
  public void openSocketKeepsWorkingAfterTokenExpires() throws Exception {
    var claims = validClaims("alice", 3);
    var exp = Instant.ofEpochSecond((Long) claims.get("exp"));
    var ws = connect(ECHO, bearer(claims));

    var before = sendAndReceive(ws, "before exp");
    assertThat(before.tokenExpired()).isFalse();

    sleepUntil(exp.plusSeconds(2));

    // No per-message validation and no close at "exp": the message still goes through.
    var after = sendAndReceive(ws, "after exp");
    assertThat(after.now()).isAfter(exp);
    assertThat(after.tokenExpired()).isTrue();
    assertThat(after.seq()).isEqualTo(2);

    // A new handshake with the same token is rejected.
    var reconnect = handshake(ECHO, Optional.of(bearer(claims)), Optional.empty());
    assertThat(reconnect.response().status().intValue()).isEqualTo(403);

    ws.publisher().sendComplete();
  }

  // ---- Workaround: complete the Flow at "exp" ----

  @Test
  public void flowThatCompletesAtExpClosesTheSocket() {
    var claims = validClaims("alice", 3);
    var ws = connect(ECHO_UNTIL_EXP, bearer(claims));

    var before = sendAndReceive(ws, "before exp");
    assertThat(before.tokenExpired()).isFalse();

    ws.subscriber().request(2);
    assertThat(ws.subscriber().expectNext(scala.concurrent.duration.Duration.create(6, TimeUnit.SECONDS)))
      .isEqualTo(JwtProbeEndpoint.CLOSING_MESSAGE);
    ws.subscriber().expectComplete();
  }

  // ---- Helpers ----

  private record WsConnection(TestPublisher.Probe<String> publisher, TestSubscriber.Probe<String> subscriber) {}

  private EchoReply sendAndReceive(WsConnection ws, String message) {
    ws.subscriber().request(1);
    ws.publisher().sendNext(message);
    var json = ws.subscriber().expectNext(scala.concurrent.duration.Duration.create(5, TimeUnit.SECONDS));
    try {
      return JsonSupport.getObjectMapper().readValue(json, EchoReply.class);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private WsConnection connect(String path, String authorization) {
    var system = testKit.getActorSystem();
    var materializer = testKit.getMaterializer();
    Pair<Pair<TestPublisher.Probe<String>, java.util.concurrent.CompletionStage<WebSocketUpgradeResponse>>, TestSubscriber.Probe<String>> mat =
      TestSource.<String>create(system)
        .map(text -> (Message) TextMessage.create(text))
        .viaMat(clientFlow(path, Optional.of(authorization), Optional.empty()), Keep.both())
        .mapAsync(1, msg -> msg.asTextMessage().toStrict(3000, materializer))
        .map(TextMessage::getStrictText)
        .toMat(TestSink.create(system), Keep.both())
        .run(materializer);

    var upgrade = getWithin5s(mat.first().second());
    assertThat(upgrade.isValid())
      .as("upgrade status %s", upgrade.response().status())
      .isTrue();
    return new WsConnection(mat.first().first(), mat.second());
  }

  private WebSocketUpgradeResponse handshake(
    String path,
    Optional<String> authorization,
    Optional<String> subprotocol
  ) {
    var system = testKit.getActorSystem();
    var upgrade = TestSource.<Message>create(system)
      .viaMat(clientFlow(path, authorization, subprotocol), Keep.right())
      .to(TestSink.create(system))
      .run(testKit.getMaterializer());
    return getWithin5s(upgrade);
  }

  private Flow<Message, Message, java.util.concurrent.CompletionStage<WebSocketUpgradeResponse>> clientFlow(
    String path,
    Optional<String> authorization,
    Optional<String> subprotocol
  ) {
    var uri = "ws://" + testKit.getHost() + ":" + testKit.getPort() + path;
    var request = WebSocketRequest.create(uri);
    if (authorization.isPresent()) {
      request = request.addHeader(RawHeader.create("Authorization", authorization.get()));
    }
    if (subprotocol.isPresent()) {
      request = request.requestSubprotocol(subprotocol.get());
    }
    return Http.get(testKit.getActorSystem()).webSocketClientFlow(request);
  }

  private static <T> T getWithin5s(java.util.concurrent.CompletionStage<T> stage) {
    try {
      return stage.toCompletableFuture().get(5, TimeUnit.SECONDS);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static void sleepUntil(Instant instant) throws InterruptedException {
    var wait = Duration.between(Instant.now(), instant);
    if (!wait.isNegative()) Thread.sleep(wait.toMillis());
  }

  private static Map<String, Object> validClaims(String subject, long expiresInSeconds) {
    var claims = new HashMap<String, Object>();
    claims.put("iss", "probe-issuer");
    claims.put("sub", subject);
    claims.put("exp", Instant.now().getEpochSecond() + expiresInSeconds);
    return claims;
  }

  private static String bearer(Map<String, Object> claims) {
    return "Bearer " + rawToken(claims);
  }

  /** Unsigned token (alg "none"). Dev mode skips the signature check but still checks "exp". */
  private static String rawToken(Map<String, Object> claims) {
    try {
      var encoder = Base64.getUrlEncoder().withoutPadding();
      var header = encoder.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
      var payload = encoder.encodeToString(JsonSupport.getObjectMapper().writeValueAsBytes(claims));
      return header + "." + payload + ".";
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
