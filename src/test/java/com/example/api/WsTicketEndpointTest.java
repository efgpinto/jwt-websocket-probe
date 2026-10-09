package com.example.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.javasdk.CommandException;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;

/** How the ticket endpoint classifies failures of its entity calls. */
public class WsTicketEndpointTest {

  @Test
  public void entityRejectionIsAnInvalidTicket() {
    var reason = WsTicketEndpoint.rejectionReason(new CommandException("ticket no longer valid"));

    assertThat(reason).isEqualTo(WsTicketEndpoint.INVALID_TICKET);
  }

  @Test
  public void otherFailuresAskTheClientToTryAgain() {
    var timeout = new RuntimeException(new TimeoutException("ask timed out"));

    assertThat(WsTicketEndpoint.rejectionReason(timeout)).isEqualTo(WsTicketEndpoint.TRY_AGAIN);
    assertThat(WsTicketEndpoint.rejectionReason(new IllegalStateException("entity failed")))
      .isEqualTo(WsTicketEndpoint.TRY_AGAIN);
  }

  @Test
  public void failedIssueReturns503() {
    var response = WsTicketEndpoint.tryAgainResponse();

    assertThat(response.status().intValue()).isEqualTo(503);
  }
}
