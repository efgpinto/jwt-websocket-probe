package com.example.api;

import static com.example.api.WsTestClient.bearer;
import static com.example.api.WsTestClient.claims;
import static com.example.api.WsTestClient.exp;
import static com.example.api.WsTestClient.expectClosedAtExp;
import static com.example.api.WsTestClient.sendAndReceive;
import static com.example.api.WsTestClient.sleepUntil;
import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.testkit.TestKitSupport;
import com.example.api.WsTicketEndpoint.TicketResponse;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Ticket pattern: the client gets a ticket with a normal {@code @JWT} request, then opens the
 * WebSocket with only the ticket in the URL, as a browser can.
 */
public class WsTicketIntegrationTest extends TestKitSupport {

  private WsTestClient ws;

  @BeforeEach
  public void setUp() {
    ws = new WsTestClient(testKit);
  }

  @Test
  public void issuingATicketRequiresAJwt() {
    var response = httpClient.POST("/ws-ticket").invoke();

    assertThat(response.status().intValue()).isEqualTo(400);
  }

  @Test
  public void ticketOpensSocketWithoutAuthorizationHeader() {
    var ticket = issueTicket(claims("alice", 60));

    var conn = ws.connect("/ws/ticket?ticket=" + ticket.ticket(), Optional.empty());
    var reply = sendAndReceive(conn, "hello");

    assertThat(reply.subject()).isEqualTo("alice");
    assertThat(reply.message()).isEqualTo("hello");
    assertThat(reply.tokenExpired()).isFalse();
    conn.publisher().sendComplete();
  }

  @Test
  public void ticketCanBeUsedOnlyOnce() {
    var ticket = issueTicket(claims("alice", 60));
    var conn = ws.connect("/ws/ticket?ticket=" + ticket.ticket(), Optional.empty());

    expectRejected("/ws/ticket?ticket=" + ticket.ticket(), WsTicketEndpoint.INVALID_TICKET);
    conn.publisher().sendComplete();
  }

  @Test
  public void unknownTicketIsRejected() {
    expectRejected("/ws/ticket?ticket=made-up", WsTicketEndpoint.INVALID_TICKET);
  }

  @Test
  public void missingTicketIsRejected() {
    expectRejected("/ws/ticket", WsTicketEndpoint.MISSING_TICKET);
  }

  @Test
  public void ticketExpiresWithTheToken() throws Exception {
    var claims = claims("alice", 2);
    var ticket = issueTicket(claims);
    assertThat(ticket.validUntil()).isEqualTo(exp(claims));

    sleepUntil(exp(claims).plusSeconds(1));

    expectRejected("/ws/ticket?ticket=" + ticket.ticket(), WsTicketEndpoint.INVALID_TICKET);
  }

  /** Documents a runtime gap: HttpException thrown from a WebSocket method is not mapped. */
  @Test
  public void httpExceptionFromWebSocketMethodBecomes500() {
    var upgrade = ws.handshake("/ws/ticket-throws", Optional.empty(), Optional.empty());

    assertThat(upgrade.isValid()).isFalse();
    assertThat(upgrade.response().status().intValue()).isEqualTo(500);
  }

  @Test
  public void socketClosesAtTokenExp() {
    var ticket = issueTicket(claims("alice", 3));
    var conn = ws.connect("/ws/ticket?ticket=" + ticket.ticket(), Optional.empty());

    var before = sendAndReceive(conn, "before exp");
    assertThat(before.tokenExpired()).isFalse();

    expectClosedAtExp(conn);
  }

  /** The upgrade succeeds, the server sends the reason, then closes. */
  private void expectRejected(String path, String reason) {
    var conn = ws.connect(path, Optional.empty());
    conn.subscriber().request(2);
    assertThat(conn.subscriber().expectNext()).isEqualTo(WsTicketEndpoint.REJECTED_PREFIX + reason);
    conn.subscriber().expectComplete();
  }

  private TicketResponse issueTicket(Map<String, Object> claims) {
    var response = httpClient
      .POST("/ws-ticket")
      .addHeader("Authorization", bearer(claims))
      .responseBodyAs(TicketResponse.class)
      .invoke();
    assertThat(response.status().intValue()).isEqualTo(201);
    return response.body();
  }
}
