package com.example.domain;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/** The validity window of a JWT, taken from its "exp" claim. */
public record TokenLifetime(Optional<Instant> expiresAt) {

  /**
   * Builds the lifetime from the raw JSON value of the "exp" claim, for example "1760000000".
   * Returns no expiry when the value is missing or not a number.
   */
  public static TokenLifetime fromRawExp(Optional<String> rawExp) {
    return new TokenLifetime(
      rawExp.flatMap(raw -> {
        try {
          return Optional.of(Instant.ofEpochSecond(new BigDecimal(raw.trim()).longValue()));
        } catch (NumberFormatException e) {
          return Optional.empty();
        }
      })
    );
  }

  public boolean isExpired(Instant now) {
    return expiresAt.map(exp -> !now.isBefore(exp)).orElse(false);
  }

  /** Time left until "exp". Empty when the token has no "exp" claim. Never negative. */
  public Optional<Duration> remaining(Instant now) {
    return expiresAt.map(exp -> {
      var left = Duration.between(now, exp);
      return left.isNegative() ? Duration.ZERO : left;
    });
  }
}
