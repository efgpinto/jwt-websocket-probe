package com.example.application;

import akka.Done;
import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import com.example.domain.WsTicket;
import java.time.Instant;
import java.util.Optional;

/**
 * Single-use WebSocket tickets, keyed by the ticket value. A Key Value Entity handles one command
 * at a time per id, so two concurrent redeems of the same ticket cannot both succeed.
 *
 * <p>Tickets do not stay in storage: a redeemed ticket is deleted, and an unused ticket expires
 * at its {@code validUntil}. The runtime removes expired entities in a periodic sweep
 * ({@code akka.runtime.delete-entity.ttl-cleanup-interval}, 1 minute by default).
 */
@Component(id = "ws-ticket")
public class WsTicketEntity extends KeyValueEntity<WsTicket> {

  public record Issue(String subject, Instant validUntil, Optional<Instant> tokenExpiresAt) {}

  public Effect<Done> issue(Issue command) {
    if (currentState() != null || isDeleted()) {
      return effects().error("ticket already exists");
    }
    var ticket = new WsTicket(command.subject(), command.validUntil(), command.tokenExpiresAt());
    return effects()
      .updateState(ticket)
      .expireAfter(ticket.timeToLive(Instant.now()))
      .thenReply(Done.getInstance());
  }

  public Effect<WsTicket> redeem() {
    // Redeemed and TTL-expired tickets are both deleted, so they cannot be told apart.
    if (isDeleted()) {
      return effects().error("ticket no longer valid");
    }
    if (currentState() == null) {
      return effects().error("unknown ticket");
    }
    // The TTL removes the ticket some time after validUntil, not at that exact moment.
    if (currentState().isExpired(Instant.now())) {
      return effects().error("ticket expired");
    }
    return effects().deleteEntity().thenReply(currentState());
  }
}
