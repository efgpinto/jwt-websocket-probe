package com.example.api;

import akka.NotUsed;
import akka.javasdk.JsonSupport;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.JWT;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.WebSocket;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.stream.javadsl.Flow;
import akka.stream.javadsl.Source;
import com.example.domain.TokenLifetime;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Probes how {@code @JWT(validate = BEARER_TOKEN)} behaves on WebSocket methods.
 *
 * <ul>
 *   <li>{@code /ws/echo}: plain {@code @JWT}. The runtime validates the token on the upgrade
 *       request only. Every reply reports whether the token has expired since then.
 *   <li>{@code /ws/echo-until-exp}: same, but the Flow completes at the "exp" claim. Completing
 *       the Flow closes the WebSocket.
 * </ul>
 */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.INTERNET))
@HttpEndpoint("/ws")
public class JwtProbeEndpoint extends AbstractHttpEndpoint {

  /**
   * @param expiresAt "exp" read from the raw claims ({@code JwtClaims.asMap()})
   * @param sdkExpirationTime "exp" read with {@code JwtClaims.expirationTime()}
   * @param claims raw claims as JSON-encoded values
   */
  public record EchoReply(
    long seq,
    String subject,
    String message,
    Instant expiresAt,
    Instant sdkExpirationTime,
    Instant now,
    boolean tokenExpired,
    Map<String, String> claims
  ) {}

  public static final String CLOSING_MESSAGE = "token expired, closing connection";

  @JWT(validate = JWT.JwtMethodMode.BEARER_TOKEN)
  @WebSocket("/echo")
  public Flow<String, String, NotUsed> echo() {
    return echoFlow();
  }

  @JWT(validate = JWT.JwtMethodMode.BEARER_TOKEN)
  @WebSocket("/echo-until-exp")
  public Flow<String, String, NotUsed> echoUntilExp() {
    return tokenLifetime()
      .remaining(Instant.now())
      .map(remaining ->
        echoFlow().takeWithin(remaining).concat(Source.single(CLOSING_MESSAGE))
      )
      .orElseGet(this::echoFlow);
  }

  private Flow<String, String, NotUsed> echoFlow() {
    // Claims come from the upgrade request. They are a snapshot and never refresh.
    var claims = requestContext().getJwtClaims();
    var subject = claims.subject().orElse("unknown");
    var sdkExpirationTime = claims.expirationTime().orElse(null);
    var rawClaims = new TreeMap<>(claims.asMap());
    var lifetime = tokenLifetime();
    return Flow.of(String.class)
      .zipWithIndex()
      .map(pair -> {
        var now = Instant.now();
        var reply = new EchoReply(
          pair.second() + 1,
          subject,
          pair.first(),
          lifetime.expiresAt().orElse(null),
          sdkExpirationTime,
          now,
          lifetime.isExpired(now),
          rawClaims
        );
        return JsonSupport.encodeToString(reply);
      });
  }

  // JwtClaims.expirationTime() returns empty for a numeric "exp" claim, so read the raw value.
  private TokenLifetime tokenLifetime() {
    var raw = requestContext().getJwtClaims().asMap().get("exp");
    return TokenLifetime.fromRawExp(Optional.ofNullable(raw));
  }
}
