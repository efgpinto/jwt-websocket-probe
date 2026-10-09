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
import com.example.domain.TokenHash;
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
import java.util.concurrent.TimeoutException;
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
 * <p>When the WebSocket handler must forward the user's JWT to downstream services, use {@code
 * /ws/ticket-with-token} instead. The client sends the JWT as the first message, and the method
 * checks it against the hash stored in the ticket. The JWT is never stored.
 *
 * <p>No JWT signature code is needed: the runtime validates the JWT on the ticket request.
 */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.INTERNET))
@HttpEndpoint
public class WsTicketEndpoint extends AbstractHttpEndpoint {

  public record TicketResponse(String ticket, Instant validUntil) {}

  public static final String REJECTED_PREFIX = "rejected: ";
  public static final String INVALID_TICKET = "invalid ticket";
  public static final String MISSING_TICKET = "missing ticket";
  public static final String TRY_AGAIN = "temporarily unavailable, try again";
  public static final String NO_TOKEN = "no token received";
  public static final String TOKEN_MISMATCH = "token does not match ticket";

  private static final Logger log = LoggerFactory.getLogger(WsTicketEndpoint.class);
  private static final String BEARER = "Bearer ";

  private static final SecureRandom RANDOM = new SecureRandom();

  private final ComponentClient componentClient;
  private final Duration ticketTtl;
  private final Duration firstMessageTimeout;

  public WsTicketEndpoint(ComponentClient componentClient, Config config) {
    this.componentClient = componentClient;
    this.ticketTtl = config.getDuration("probe.ws-ticket.ttl");
    this.firstMessageTimeout = config.getDuration("probe.ws-ticket.first-message-timeout");
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
    // Only the hash is stored, for /ws/ticket-with-token. @JWT guarantees the header is present.
    var tokenHash = requestContext()
      .requestHeader("Authorization")
      .map(header -> header.value())
      .filter(value -> value.startsWith(BEARER))
      .map(value -> TokenHash.of(value.substring(BEARER.length()).trim()));
    var ticket = newTicketValue();

    try {
      componentClient
        .forKeyValueEntity(ticket)
        .method(WsTicketEntity::issue)
        .invoke(new WsTicketEntity.Issue(subject, validUntil, tokenExpiresAt, tokenHash));
    } catch (RuntimeException e) {
      // Do not log the ticket value: it is a credential.
      log.error("Could not store WebSocket ticket", e);
      return tryAgainResponse();
    }

    return HttpResponses.created(new TicketResponse(ticket, validUntil));
  }

  @WebSocket("/ws/ticket")
  public Flow<String, String, NotUsed> ticketSocket() {
    return switch (redeemFromQuery()) {
      case Redemption.Rejected rejected -> reject(rejected.reason());
      case Redemption.Accepted accepted -> {
        var ticket = accepted.ticket();
        var lifetime = new TokenLifetime(ticket.tokenExpiresAt());
        var echo = JwtProbeEndpoint.echoFlow(
          ticket.subject(),
          lifetime,
          Optional.empty(),
          Map.of("sub", ticket.subject())
        );
        yield JwtProbeEndpoint.closeAtExp(echo, lifetime);
      }
    };
  }

  /**
   * Ticket pattern for a WebSocket handler that must forward the user's JWT to downstream
   * services. The ticket alone proves who the user is, but it does not give the handler the JWT.
   *
   * <ol>
   *   <li>The client opens {@code /ws/ticket-with-token?ticket=<ticket>}.
   *   <li>The client sends the same JWT it used for {@code POST /ws-ticket} as the first message.
   *   <li>The method checks the JWT against the hash in the ticket. @JWT already validated this
   *       exact token, so no signature check is needed here.
   *   <li>The method keeps the JWT in memory for this connection and closes at its "exp".
   * </ol>
   *
   * <p>The connection is refused when the first message does not match, or does not arrive within
   * {@code probe.ws-ticket.first-message-timeout}.
   */
  @WebSocket("/ws/ticket-with-token")
  public Flow<String, String, NotUsed> ticketWithTokenSocket() {
    return switch (redeemFromQuery()) {
      case Redemption.Rejected rejected -> reject(rejected.reason());
      case Redemption.Accepted accepted -> {
        var ticket = accepted.ticket();
        yield Flow.of(String.class)
          .initialTimeout(firstMessageTimeout)
          .prefixAndTail(1)
          .flatMapConcat(pair -> {
            if (pair.first().isEmpty()) {
              return Source.<String>empty();
            }
            var token = pair.first().get(0).trim();
            if (!ticket.isIssuedFor(token)) {
              // take(0) cancels the unused rest of the input.
              return pair.second().take(0).prepend(Source.single(REJECTED_PREFIX + TOKEN_MISMATCH));
            }
            return pair.second().via(forwardingFlow(ticket, token));
          })
          .recover(TimeoutException.class, () -> REJECTED_PREFIX + NO_TOKEN);
      }
    };
  }

  /** The application Flow, with the user's JWT available for downstream calls. */
  private static Flow<String, String, NotUsed> forwardingFlow(WsTicket ticket, String token) {
    // Use the token for downstream calls, for example:
    //   httpClient.GET("/orders").addHeader("Authorization", "Bearer " + token).invoke();
    // This sample only reports a fingerprint of the token, to show that it is available.
    var lifetime = new TokenLifetime(ticket.tokenExpiresAt());
    var echo = JwtProbeEndpoint.echoFlow(
      ticket.subject(),
      lifetime,
      Optional.empty(),
      Map.of("sub", ticket.subject(), "forwardableTokenSha256", TokenHash.of(token))
    );
    // Closing at "exp" also means the handler never forwards an expired token.
    return JwtProbeEndpoint.closeAtExp(echo, lifetime);
  }

  private sealed interface Redemption {
    record Accepted(WsTicket ticket) implements Redemption {}

    record Rejected(String reason) implements Redemption {}
  }

  private Redemption redeemFromQuery() {
    var ticketValue = requestContext().queryParams().getString("ticket").filter(v -> !v.isBlank());
    if (ticketValue.isEmpty()) {
      return new Redemption.Rejected(MISSING_TICKET);
    }
    try {
      var ticket = componentClient
        .forKeyValueEntity(ticketValue.get())
        .method(WsTicketEntity::redeem)
        .invoke();
      return new Redemption.Accepted(ticket);
    } catch (RuntimeException e) {
      return new Redemption.Rejected(rejectionReason(e));
    }
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
