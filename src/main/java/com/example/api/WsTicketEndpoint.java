package com.example.api;

import akka.NotUsed;
import akka.http.javadsl.model.ContentTypes;
import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.CommandException;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.JWT;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.annotations.http.WebSocket;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpException;
import akka.javasdk.http.HttpResponses;
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
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
  public static final String INVALID_TICKET = "invalid ticket";
  public static final String MISSING_TICKET = "missing ticket";
  public static final String TRY_AGAIN = "temporarily unavailable, try again";

  private static final Logger log = LoggerFactory.getLogger(WsTicketEndpoint.class);

  private static final SecureRandom RANDOM = new SecureRandom();

  private final ComponentClient componentClient;
  private final Duration ticketTtl;

  public WsTicketEndpoint(ComponentClient componentClient, Config config) {
    this.componentClient = componentClient;
    this.ticketTtl = config.getDuration("probe.ws-ticket.ttl");
  }

  /**
   * Returns 201 with the ticket. The ticket is returned only after the entity has stored it.
   *
   * <p>When the entity call fails or times out, returns 503 and the client gets a new ticket by
   * calling again. If the write succeeded but the reply was lost, the stored ticket is never
   * returned to anyone, and its TTL deletes it.
   */
  @JWT(validate = JWT.JwtMethodMode.BEARER_TOKEN)
  @Post("/ws-ticket")
  public HttpResponse issueTicket() {
    var claims = requestContext().getJwtClaims();
    var subject = claims.subject().orElse("unknown");
    // JwtClaims.expirationTime() returns empty for a numeric "exp" claim, so read the raw value.
    var tokenExpiresAt = TokenLifetime.fromRawExp(Optional.ofNullable(claims.asMap().get("exp")))
      .expiresAt();
    var validUntil = WsTicket.validUntil(Instant.now(), ticketTtl, tokenExpiresAt);
    var ticket = newTicketValue();

    try {
      componentClient
        .forKeyValueEntity(ticket)
        .method(WsTicketEntity::issue)
        .invoke(new WsTicketEntity.Issue(subject, validUntil, tokenExpiresAt));
    } catch (RuntimeException e) {
      // Do not log the ticket value: it is a credential.
      log.error("Could not store WebSocket ticket", e);
      return tryAgainResponse();
    }

    return HttpResponses.created(new TicketResponse(ticket, validUntil));
  }

  @WebSocket("/ws/ticket")
  public Flow<String, String, NotUsed> ticketSocket() {
    var ticketValue = requestContext().queryParams().getString("ticket").filter(v -> !v.isBlank());
    if (ticketValue.isEmpty()) {
      return reject(MISSING_TICKET);
    }

    WsTicket ticket;
    try {
      ticket = componentClient
        .forKeyValueEntity(ticketValue.get())
        .method(WsTicketEntity::redeem)
        .invoke();
    } catch (RuntimeException e) {
      return reject(rejectionReason(e));
    }

    var lifetime = new TokenLifetime(ticket.tokenExpiresAt());
    var echo = JwtProbeEndpoint.echoFlow(
      ticket.subject(),
      lifetime,
      Optional.empty(),
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
    throw HttpException.forbidden(INVALID_TICKET);
  }

  /**
   * Accepts the upgrade, sends the reason, and closes. A browser cannot read the HTTP status of a
   * failed handshake (it only sees close code 1006), so a message is more useful to the client.
   */
  private static Flow<String, String, NotUsed> reject(String reason) {
    return Flow.fromSinkAndSourceCoupled(Sink.ignore(), Source.single(REJECTED_PREFIX + reason));
  }

  /**
   * The entity rejects unknown, used, and expired tickets with a CommandException. Those all get
   * the same reason, so a client cannot probe which case applies. Any other failure, such as a
   * timeout, means the service could not check the ticket. The client should get a new ticket and
   * try again. If the redeem succeeded but the reply was lost, the ticket is already used, so a new
   * ticket is needed in that case too.
   */
  static String rejectionReason(RuntimeException e) {
    if (e instanceof CommandException) {
      return INVALID_TICKET;
    }
    log.error("Could not redeem WebSocket ticket", e);
    return TRY_AGAIN;
  }

  static HttpResponse tryAgainResponse() {
    return HttpResponses.of(
      StatusCodes.SERVICE_UNAVAILABLE,
      ContentTypes.TEXT_PLAIN_UTF8,
      TRY_AGAIN.getBytes(StandardCharsets.UTF_8)
    );
  }

  private static String newTicketValue() {
    var bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
