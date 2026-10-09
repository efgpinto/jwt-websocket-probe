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
 * @param tokenHash SHA-256 of that JWT (see {@link TokenHash}). The JWT itself is never stored.
 */
public record WsTicket(
  String subject,
  Instant validUntil,
  Optional<Instant> tokenExpiresAt,
  Optional<String> tokenHash
) {

  private static final Duration MIN_TIME_TO_LIVE = Duration.ofSeconds(1);

  public boolean isExpired(Instant now) {
    return !now.isBefore(validUntil);
  }

  /** True when the token is the one this ticket was issued for. */
  public boolean isIssuedFor(String token) {
    return tokenHash.map(hash -> TokenHash.matches(hash, token)).orElse(false);
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
