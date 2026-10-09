package com.example.application;

import static org.assertj.core.api.Assertions.assertThat;

import akka.Done;
import akka.javasdk.testkit.KeyValueEntityTestKit;
import com.example.domain.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class WsTicketEntityTest {

  private static WsTicketEntity.Issue issue(Instant validUntil) {
    return new WsTicketEntity.Issue(
      "alice",
      validUntil,
      Optional.of(validUntil.plusSeconds(60)),
      Optional.of(TokenHash.of("the-jwt"))
    );
  }

  @Test
  public void issuedTicketExpiresAtValidUntil() {
    var testKit = KeyValueEntityTestKit.of("ticket-1", WsTicketEntity::new);

    var result = testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().plusSeconds(30)));

    assertThat(result.getReply()).isEqualTo(Done.getInstance());
    assertThat(result.getExpireAfter()).hasValueSatisfying(ttl ->
      assertThat(ttl).isBetween(Duration.ofSeconds(29), Duration.ofSeconds(30))
    );
  }

  @Test
  public void redeemingDeletesTheTicket() {
    var testKit = KeyValueEntityTestKit.of("ticket-2", WsTicketEntity::new);
    testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().plusSeconds(30)));

    var first = testKit.method(WsTicketEntity::redeem).invoke();

    assertThat(first.isError()).isFalse();
    assertThat(first.getReply().subject()).isEqualTo("alice");
    assertThat(first.getReply().isIssuedFor("the-jwt")).isTrue();
    assertThat(first.stateWasDeleted()).isTrue();
    assertThat(testKit.isDeleted()).isTrue();

    var second = testKit.method(WsTicketEntity::redeem).invoke();
    assertThat(second.isError()).isTrue();
    assertThat(second.getError()).isEqualTo("ticket no longer valid");
  }

  @Test
  public void rejectsAnExpiredTicketThatIsStillStored() {
    var testKit = KeyValueEntityTestKit.of("ticket-3", WsTicketEntity::new);
    testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().minusSeconds(1)));

    var result = testKit.method(WsTicketEntity::redeem).invoke();

    assertThat(result.isError()).isTrue();
    assertThat(result.getError()).isEqualTo("ticket expired");
  }

  @Test
  public void rejectsAnUnknownTicket() {
    var testKit = KeyValueEntityTestKit.of("ticket-4", WsTicketEntity::new);

    var result = testKit.method(WsTicketEntity::redeem).invoke();

    assertThat(result.isError()).isTrue();
    assertThat(result.getError()).isEqualTo("unknown ticket");
  }

  @Test
  public void doesNotIssueTheSameTicketTwice() {
    var testKit = KeyValueEntityTestKit.of("ticket-5", WsTicketEntity::new);
    testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().plusSeconds(30)));

    var result = testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().plusSeconds(30)));

    assertThat(result.isError()).isTrue();
  }
}
