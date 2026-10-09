package com.example.application;

import static org.assertj.core.api.Assertions.assertThat;

import akka.Done;
import akka.javasdk.testkit.KeyValueEntityTestKit;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class WsTicketEntityTest {

  private static WsTicketEntity.Issue issue(Instant validUntil) {
    return new WsTicketEntity.Issue("alice", validUntil, Optional.of(validUntil.plusSeconds(60)));
  }

  @Test
  public void redeemsAnIssuedTicketOnce() {
    var testKit = KeyValueEntityTestKit.of("ticket-1", WsTicketEntity::new);
    var issued = testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().plusSeconds(30)));
    assertThat(issued.getReply()).isEqualTo(Done.getInstance());

    var first = testKit.method(WsTicketEntity::redeem).invoke();
    assertThat(first.isError()).isFalse();
    assertThat(first.getReply().subject()).isEqualTo("alice");
    assertThat(first.getReply().isRedeemed()).isTrue();

    var second = testKit.method(WsTicketEntity::redeem).invoke();
    assertThat(second.isError()).isTrue();
    assertThat(second.getError()).isEqualTo("ticket already used");
  }

  @Test
  public void rejectsAnExpiredTicket() {
    var testKit = KeyValueEntityTestKit.of("ticket-2", WsTicketEntity::new);
    testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().minusSeconds(1)));

    var result = testKit.method(WsTicketEntity::redeem).invoke();

    assertThat(result.isError()).isTrue();
    assertThat(result.getError()).isEqualTo("ticket expired");
  }

  @Test
  public void rejectsAnUnknownTicket() {
    var testKit = KeyValueEntityTestKit.of("ticket-3", WsTicketEntity::new);

    var result = testKit.method(WsTicketEntity::redeem).invoke();

    assertThat(result.isError()).isTrue();
    assertThat(result.getError()).isEqualTo("unknown ticket");
  }

  @Test
  public void doesNotIssueTheSameTicketTwice() {
    var testKit = KeyValueEntityTestKit.of("ticket-4", WsTicketEntity::new);
    testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().plusSeconds(30)));

    var result = testKit.method(WsTicketEntity::issue).invoke(issue(Instant.now().plusSeconds(30)));

    assertThat(result.isError()).isTrue();
  }
}
