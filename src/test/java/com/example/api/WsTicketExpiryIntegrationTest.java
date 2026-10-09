package com.example.api;

import static com.example.api.WsTestClient.bearer;
import static com.example.api.WsTestClient.claims;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import akka.javasdk.testkit.TestKit;
import akka.javasdk.testkit.TestKitSupport;
import com.example.api.WsTicketEndpoint.TicketResponse;
import com.example.application.WsTicketEntity;
import com.typesafe.config.ConfigFactory;
import java.util.concurrent.TimeUnit;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;

/** Checks that the runtime removes unused tickets once their TTL has passed. */
public class WsTicketExpiryIntegrationTest extends TestKitSupport {

  @Override
  protected TestKit.Settings testKitSettings() {
    // The runtime sweeps TTL-expired entities every minute by default.
    return TestKit.Settings.DEFAULT.withAdditionalConfig(
      ConfigFactory.parseString("akka.runtime.delete-entity.ttl-cleanup-interval = 1s")
    );
  }

  @Test
  public void unusedTicketIsRemovedAfterItsTtl() {
    // The ticket is valid until the token's "exp", 2 seconds from now.
    var ticket = httpClient
      .POST("/ws-ticket")
      .addHeader("Authorization", bearer(claims("alice", 2)))
      .responseBodyAs(TicketResponse.class)
      .invoke()
      .body()
      .ticket();

    Awaitility.await()
      .atMost(20, TimeUnit.SECONDS)
      .pollInterval(1, TimeUnit.SECONDS)
      .untilAsserted(() ->
        // "ticket expired" while the state is still stored. Once the TTL sweep has run, the
        // entity is deleted. The ticket was never redeemed, so only the TTL can have deleted it.
        assertThatThrownBy(() ->
          componentClient.forKeyValueEntity(ticket).method(WsTicketEntity::redeem).invoke()
        ).hasMessageContaining("ticket no longer valid")
      );
  }

  @Test
  public void redeemedTicketIsDeleted() {
    var ticket = httpClient
      .POST("/ws-ticket")
      .addHeader("Authorization", bearer(claims("alice", 60)))
      .responseBodyAs(TicketResponse.class)
      .invoke()
      .body()
      .ticket();

    var redeemed = componentClient.forKeyValueEntity(ticket).method(WsTicketEntity::redeem).invoke();
    assertThat(redeemed.subject()).isEqualTo("alice");

    assertThatThrownBy(() ->
      componentClient.forKeyValueEntity(ticket).method(WsTicketEntity::redeem).invoke()
    ).hasMessageContaining("ticket no longer valid");
  }
}
