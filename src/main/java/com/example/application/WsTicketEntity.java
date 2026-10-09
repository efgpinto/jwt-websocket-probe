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
 */
@Component(id = "ws-ticket")
public class WsTicketEntity extends KeyValueEntity<WsTicket> {

  public record Issue(String subject, Instant validUntil, Optional<Instant> tokenExpiresAt) {}

  public Effect<Done> issue(Issue command) {
    if (currentState() != null) {
      return effects().error("ticket already exists");
    }
    var ticket = WsTicket.issue(command.subject(), command.validUntil(), command.tokenExpiresAt());
    return effects().updateState(ticket).thenReply(Done.getInstance());
  }

  public Effect<WsTicket> redeem() {
    var now = Instant.now();
    if (currentState() == null) {
      return effects().error("unknown ticket");
    }
    if (currentState().isRedeemed()) {
      return effects().error("ticket already used");
    }
    if (currentState().isExpired(now)) {
      return effects().error("ticket expired");
    }
    var redeemed = currentState().redeem(now);
    return effects().updateState(redeemed).thenReply(redeemed);
  }
}
