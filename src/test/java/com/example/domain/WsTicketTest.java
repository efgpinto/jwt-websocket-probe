package com.example.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class WsTicketTest {

  private final Instant now = Instant.ofEpochSecond(1_000);
  private final Duration ttl = Duration.ofSeconds(30);

  @Test
  public void validUntilUsesTheTtlWhenTheTokenLivesLonger() {
    assertThat(WsTicket.validUntil(now, ttl, Optional.of(now.plusSeconds(600))))
      .isEqualTo(now.plusSeconds(30));
  }

  @Test
  public void validUntilUsesTokenExpWhenItComesFirst() {
    assertThat(WsTicket.validUntil(now, ttl, Optional.of(now.plusSeconds(5))))
      .isEqualTo(now.plusSeconds(5));
  }

  @Test
  public void validUntilUsesTheTtlWhenTheTokenHasNoExp() {
    assertThat(WsTicket.validUntil(now, ttl, Optional.empty())).isEqualTo(now.plusSeconds(30));
  }

  @Test
  public void timeToLiveIsTheTimeLeftUntilValidUntil() {
    var ticket = new WsTicket("alice", now.plusSeconds(30), Optional.empty(), Optional.empty());

    assertThat(ticket.timeToLive(now)).isEqualTo(Duration.ofSeconds(30));
  }

  @Test
  public void timeToLiveIsNeverZeroOrNegative() {
    var ticket = new WsTicket("alice", now.minusSeconds(5), Optional.empty(), Optional.empty());

    assertThat(ticket.timeToLive(now)).isEqualTo(Duration.ofSeconds(1));
  }

  @Test
  public void isIssuedForTheTokenWithTheStoredHash() {
    var ticket = new WsTicket("alice", now, Optional.empty(), Optional.of(TokenHash.of("jwt-a")));

    assertThat(ticket.isIssuedFor("jwt-a")).isTrue();
    assertThat(ticket.isIssuedFor("jwt-b")).isFalse();
  }

  @Test
  public void isNotIssuedForAnyTokenWithoutAHash() {
    var ticket = new WsTicket("alice", now, Optional.empty(), Optional.empty());

    assertThat(ticket.isIssuedFor("jwt-a")).isFalse();
  }
}
