package com.example.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * A single-use ticket that lets a client open a WebSocket without an Authorization header.
 *
 * @param subject "sub" claim of the JWT that was used to issue the ticket
 * @param validUntil the ticket must be redeemed before this time
 * @param tokenExpiresAt "exp" claim of that JWT. The WebSocket must close at this time.
 */
public record WsTicket(String subject, Instant validUntil, Optional<Instant> tokenExpiresAt) {

  private static final Duration MIN_TIME_TO_LIVE = Duration.ofSeconds(1);

  public boolean isExpired(Instant now) {
    return !now.isBefore(validUntil);
  }

  /** How long to keep the stored ticket. Never zero or negative. */
  public Duration timeToLive(Instant now) {
    var left = Duration.between(now, validUntil);
    return left.compareTo(MIN_TIME_TO_LIVE) < 0 ? MIN_TIME_TO_LIVE : left;
  }

  /** The ticket ends at the configured TTL, or earlier when the JWT expires first. */
  public static Instant validUntil(Instant now, Duration ttl, Optional<Instant> tokenExpiresAt) {
    var byTtl = now.plus(ttl);
    return tokenExpiresAt.filter(exp -> exp.isBefore(byTtl)).orElse(byTtl);
  }
}
