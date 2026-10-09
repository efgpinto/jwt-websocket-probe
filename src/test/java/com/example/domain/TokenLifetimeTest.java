package com.example.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class TokenLifetimeTest {

  private final Instant now = Instant.ofEpochSecond(1_000);

  @Test
  public void parsesRawNumericExp() {
    var lifetime = TokenLifetime.fromRawExp(Optional.of("1010"));

    assertThat(lifetime.expiresAt()).contains(Instant.ofEpochSecond(1010));
    assertThat(lifetime.remaining(now)).contains(Duration.ofSeconds(10));
    assertThat(lifetime.isExpired(now)).isFalse();
  }

  @Test
  public void expiredTokenHasZeroRemaining() {
    var lifetime = TokenLifetime.fromRawExp(Optional.of("990"));

    assertThat(lifetime.isExpired(now)).isTrue();
    assertThat(lifetime.remaining(now)).contains(Duration.ZERO);
  }

  @Test
  public void missingOrInvalidExpMeansNoExpiry() {
    assertThat(TokenLifetime.fromRawExp(Optional.empty()).expiresAt()).isEmpty();
    assertThat(TokenLifetime.fromRawExp(Optional.of("\"soon\"")).expiresAt()).isEmpty();
    assertThat(TokenLifetime.fromRawExp(Optional.empty()).isExpired(now)).isFalse();
  }
}
