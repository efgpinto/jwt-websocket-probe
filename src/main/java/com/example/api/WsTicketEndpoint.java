package com.example.api;

import akka.NotUsed;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.JWT;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.annotations.http.WebSocket;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpException;
import akka.stream.javadsl.Flow;
import akka.stream.javadsl.Sink;
import akka.stream.javadsl.Source;
import com.example.application.WsTicketEntity;
import com.example.domain.TokenLifetime;
import com.example.domain.WsTicket;
import com.typesafe.config.Config;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Ticket pattern for clients that cannot set the Authorization header on the WebSocket handshake,
 * such as the browser WebSocket API.
 *
 * <ol>
 *   <li>The client calls {@code POST /ws-ticket} with {@code Authorization: Bearer <jwt>}. {@code
 *       @JWT} validates the token. The endpoint returns a random, single-use, short-lived ticket.
 *   <li>The client opens {@code /ws/ticket?ticket=<ticket>}. The method redeems the ticket and
 *       closes the socket at the JWT's "exp".
 * </ol>
 *
 * No JWT signature code is needed: the runtime validates the JWT on the ticket request.
 */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.INTERNET))
@HttpEndpoint
public class WsTicketEndpoint extends AbstractHttpEndpoint {

  public record TicketResponse(String ticket, Instant validUntil) {}

  public static final String REJECTED_PREFIX = "rejected: ";

  private static final SecureRandom RANDOM = new SecureRandom();

  private final ComponentClient componentClient;
  private final Duration ticketTtl;

  public WsTicketEndpoint(ComponentClient componentClient, Config config) {
    this.componentClient = componentClient;
    this.ticketTtl = config.getDuration("probe.ws-ticket.ttl");
  }

  @JWT(validate = JWT.JwtMethodMode.BEARER_TOKEN)
  @Post("/ws-ticket")
  public TicketResponse issueTicket() {
    var claims = requestContext().getJwtClaims();
    var subject = claims.subject().orElse("unknown");
    // JwtClaims.expirationTime() returns empty for a numeric "exp" claim, so read the raw value.
    var tokenExpiresAt = TokenLifetime.fromRawExp(Optional.ofNullable(claims.asMap().get("exp")))
      .expiresAt();
    var validUntil = WsTicket.validUntil(Instant.now(), ticketTtl, tokenExpiresAt);
    var ticket = newTicketValue();

    componentClient
      .forKeyValueEntity(ticket)
      .method(WsTicketEntity::issue)
      .invoke(new WsTicketEntity.Issue(subject, validUntil, tokenExpiresAt));

    return new TicketResponse(ticket, validUntil);
  }

  @WebSocket("/ws/ticket")
  public Flow<String, String, NotUsed> ticketSocket() {
    var ticketValue = requestContext().queryParams().getString("ticket").filter(v -> !v.isBlank());
    if (ticketValue.isEmpty()) {
      return reject("missing ticket");
    }

    WsTicket ticket;
    try {
      ticket = componentClient
        .forKeyValueEntity(ticketValue.get())
        .method(WsTicketEntity::redeem)
        .invoke();
    } catch (RuntimeException e) {
      // Unknown, used, or expired. Fail closed and do not say which.
      return reject("invalid ticket");
    }

    var lifetime = new TokenLifetime(ticket.tokenExpiresAt());
    var echo = JwtProbeEndpoint.echoFlow(
      ticket.subject(),
      lifetime,
      null,
      Map.of("sub", ticket.subject())
    );
    return JwtProbeEndpoint.closeAtExp(echo, lifetime);
  }

  /**
   * Throws HttpException.forbidden() from a WebSocket method. Kept to show that the runtime does
   * not map it to 403: the upgrade fails with 500.
   */
  @WebSocket("/ws/ticket-throws")
  public Flow<String, String, NotUsed> ticketSocketThatThrows() {
    throw HttpException.forbidden("invalid ticket");
  }

  /**
   * Accepts the upgrade, sends the reason, and closes. A browser cannot read the HTTP status of a
   * failed handshake (it only sees close code 1006), so a message is more useful to the client.
   */
  private static Flow<String, String, NotUsed> reject(String reason) {
    return Flow.fromSinkAndSourceCoupled(Sink.ignore(), Source.single(REJECTED_PREFIX + reason));
  }

  private static String newTicketValue() {
    var bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
