package com.example.domain;

import java.time.Instant;
import java.util.Optional;

/**
 * A single-use ticket that lets a client open a WebSocket without an Authorization header.
 *
 * @param subject "sub" claim of the JWT that was used to issue the ticket
 * @param validUntil the ticket must be redeemed before this time
 * @param tokenExpiresAt "exp" claim of that JWT. The WebSocket must close at this time.
 * @param redeemedAt set when the ticket is used
 */
public record WsTicket(
  String subject,
  Instant validUntil,
  Optional<Instant> tokenExpiresAt,
  Optional<Instant> redeemedAt
) {
  public static WsTicket issue(String subject, Instant validUntil, Optional<Instant> tokenExpiresAt) {
    return new WsTicket(subject, validUntil, tokenExpiresAt, Optional.empty());
  }

  public boolean isRedeemed() {
    return redeemedAt.isPresent();
  }

  public boolean isExpired(Instant now) {
    return !now.isBefore(validUntil);
  }

  public WsTicket redeem(Instant now) {
    if (isRedeemed()) throw new IllegalStateException("ticket already used");
    if (isExpired(now)) throw new IllegalStateException("ticket expired");
    return new WsTicket(subject, validUntil, tokenExpiresAt, Optional.of(now));
  }

  /** The ticket ends at the configured TTL, or earlier when the JWT expires first. */
  public static Instant validUntil(Instant now, java.time.Duration ttl, Optional<Instant> tokenExpiresAt) {
    var byTtl = now.plus(ttl);
    return tokenExpiresAt.filter(exp -> exp.isBefore(byTtl)).orElse(byTtl);
  }
}
