package com.example.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.http.javadsl.Http;
import akka.http.javadsl.model.headers.RawHeader;
import akka.http.javadsl.model.ws.Message;
import akka.http.javadsl.model.ws.TextMessage;
import akka.http.javadsl.model.ws.WebSocketRequest;
import akka.http.javadsl.model.ws.WebSocketUpgradeResponse;
import akka.japi.Pair;
import akka.javasdk.JsonSupport;
import akka.javasdk.testkit.TestKit;
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
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

/**
 * WebSocket client for the integration tests. The testkit WebSocketRouteTester cannot set headers,
 * so this uses an akka-http WebSocket client directly.
 */
final class WsTestClient {

  record WsConnection(TestPublisher.Probe<String> publisher, TestSubscriber.Probe<String> subscriber) {}

  private final TestKit testKit;

  WsTestClient(TestKit testKit) {
    this.testKit = testKit;
  }

  /** Opens a socket and fails the test if the upgrade is rejected. */
  WsConnection connect(String path, Optional<String> authorization) {
    var system = testKit.getActorSystem();
    var materializer = testKit.getMaterializer();
    Pair<Pair<TestPublisher.Probe<String>, CompletionStage<WebSocketUpgradeResponse>>, TestSubscriber.Probe<String>> mat =
      TestSource.<String>create(system)
        .map(text -> (Message) TextMessage.create(text))
        .viaMat(clientFlow(path, authorization, Optional.empty()), Keep.both())
        .mapAsync(1, msg -> msg.asTextMessage().toStrict(3000, materializer))
        .map(TextMessage::getStrictText)
        .toMat(TestSink.create(system), Keep.both())
        .run(materializer);

    var upgrade = getWithin5s(mat.first().second());
    assertThat(upgrade.isValid()).as("upgrade status %s", upgrade.response().status()).isTrue();
    return new WsConnection(mat.first().first(), mat.second());
  }

  /** Runs only the handshake, to check the upgrade response. */
  WebSocketUpgradeResponse handshake(
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

  static EchoReply sendAndReceive(WsConnection ws, String message) {
    ws.subscriber().request(1);
    ws.publisher().sendNext(message);
    var json = ws.subscriber().expectNext(scala.concurrent.duration.Duration.create(5, TimeUnit.SECONDS));
    try {
      return JsonSupport.getObjectMapper().readValue(json, EchoReply.class);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static void expectClosedAtExp(WsConnection ws) {
    ws.subscriber().request(2);
    assertThat(ws.subscriber().expectNext(scala.concurrent.duration.Duration.create(6, TimeUnit.SECONDS)))
      .isEqualTo(JwtProbeEndpoint.CLOSING_MESSAGE);
    ws.subscriber().expectComplete();
  }

  private Flow<Message, Message, CompletionStage<WebSocketUpgradeResponse>> clientFlow(
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

  private static <T> T getWithin5s(CompletionStage<T> stage) {
    try {
      return stage.toCompletableFuture().get(5, TimeUnit.SECONDS);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static void sleepUntil(Instant instant) throws InterruptedException {
    var wait = Duration.between(Instant.now(), instant);
    if (!wait.isNegative()) Thread.sleep(wait.toMillis());
  }

  static Map<String, Object> claims(String subject, long expiresInSeconds) {
    var claims = new HashMap<String, Object>();
    claims.put("iss", "probe-issuer");
    claims.put("sub", subject);
    claims.put("exp", Instant.now().getEpochSecond() + expiresInSeconds);
    return claims;
  }

  static Instant exp(Map<String, Object> claims) {
    return Instant.ofEpochSecond((Long) claims.get("exp"));
  }

  static String bearer(Map<String, Object> claims) {
    return "Bearer " + rawToken(claims);
  }

  /** Unsigned token (alg "none"). Dev mode skips the signature check but still checks "exp". */
  static String rawToken(Map<String, Object> claims) {
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
