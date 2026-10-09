package com.example.api;

import static com.example.api.WsTestClient.claims;
import static com.example.api.WsTestClient.expectClosedAtExp;
import static com.example.api.WsTestClient.rawToken;
import static com.example.api.WsTestClient.sendAndReceive;
import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKit;
import akka.javasdk.testkit.TestKitSupport;
import com.example.api.WsTicketEndpoint.TicketResponse;
import com.example.domain.TokenHash;
import com.typesafe.config.ConfigFactory;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Ticket pattern when the WebSocket handler must forward the user's JWT downstream: the client
 * opens the socket with a ticket, then sends the JWT as the first message.
 */
public class WsTicketWithTokenIntegrationTest extends TestKitSupport {

  private static final String PATH = "/ws/ticket-with-token?ticket=";

  private WsTestClient ws;

  @Override
  protected TestKit.Settings testKitSettings() {
    return TestKit.Settings.DEFAULT.withAdditionalConfig(
      ConfigFactory.parseString("probe.ws-ticket.first-message-timeout = 1s")
    );
  }

  @BeforeEach
  public void setUp() {
    ws = new WsTestClient(testKit);
  }

  @Test
  public void tokenSentAsFirstMessageIsAvailableToTheHandler() {
    var token = rawToken(claims("alice", 60));
    var conn = ws.connect(PATH + issueTicket(token).ticket(), Optional.empty());

    conn.publisher().sendNext(token);
    var reply = sendAndReceive(conn, "hello");

    assertThat(reply.seq()).isEqualTo(1);
    assertThat(reply.subject()).isEqualTo("alice");
    assertThat(reply.message()).isEqualTo("hello");
    // The handler holds the same token that @JWT validated on POST /ws-ticket.
    assertThat(reply.claims()).containsEntry("forwardableTokenSha256", TokenHash.of(token));
    conn.publisher().sendComplete();
  }

  @Test
  public void differentTokenIsRejected() {
    var token = rawToken(claims("alice", 60));
    var otherToken = rawToken(claims("mallory", 60));
    var conn = ws.connect(PATH + issueTicket(token).ticket(), Optional.empty());

    conn.subscriber().request(2);
    conn.publisher().sendNext(otherToken);

    assertThat(conn.subscriber().expectNext())
      .isEqualTo(WsTicketEndpoint.REJECTED_PREFIX + WsTicketEndpoint.TOKEN_MISMATCH);
    conn.subscriber().expectComplete();
  }

  @Test
  public void missingFirstMessageIsRejectedAfterTheTimeout() {
    var token = rawToken(claims("alice", 60));
    var conn = ws.connect(PATH + issueTicket(token).ticket(), Optional.empty());

    conn.subscriber().request(2);

    assertThat(conn.subscriber().expectNext(scala.concurrent.duration.Duration.create(5, TimeUnit.SECONDS)))
      .isEqualTo(WsTicketEndpoint.REJECTED_PREFIX + WsTicketEndpoint.NO_TOKEN);
    conn.subscriber().expectComplete();
  }

  @Test
  public void ticketCannotBeReused() {
    var token = rawToken(claims("alice", 60));
    var ticket = issueTicket(token).ticket();
    var first = ws.connect(PATH + ticket, Optional.empty());

    var second = ws.connect(PATH + ticket, Optional.empty());
    second.subscriber().request(2);

    assertThat(second.subscriber().expectNext())
      .isEqualTo(WsTicketEndpoint.REJECTED_PREFIX + WsTicketEndpoint.INVALID_TICKET);
    second.subscriber().expectComplete();
    first.publisher().sendComplete();
  }

  @Test
  public void socketClosesAtTokenExp() {
    var token = rawToken(claims("alice", 3));
    var conn = ws.connect(PATH + issueTicket(token).ticket(), Optional.empty());

    conn.publisher().sendNext(token);
    var before = sendAndReceive(conn, "before exp");
    assertThat(before.tokenExpired()).isFalse();

    expectClosedAtExp(conn);
  }

  private TicketResponse issueTicket(String token) {
    var response = httpClient
      .POST("/ws-ticket")
      .addHeader("Authorization", "Bearer " + token)
      .responseBodyAs(TicketResponse.class)
      .invoke();
    assertThat(response.status().intValue()).isEqualTo(201);
    return response.body();
  }
}
