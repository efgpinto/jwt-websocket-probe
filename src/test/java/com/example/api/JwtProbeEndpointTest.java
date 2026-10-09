package com.example.api;

import static org.assertj.core.api.Assertions.assertThat;

import akka.actor.ActorSystem;
import akka.stream.javadsl.Flow;
import akka.stream.javadsl.Sink;
import akka.stream.javadsl.Source;
import akka.testkit.javadsl.TestKit;
import com.example.domain.TokenLifetime;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class JwtProbeEndpointTest {

  private static ActorSystem system;

  @BeforeAll
  public static void setUp() {
    system = ActorSystem.create("JwtProbeEndpointTest");
  }

  @AfterAll
  public static void tearDown() {
    TestKit.shutdownActorSystem(system);
  }

  private List<String> run(Flow<String, String, ?> flow, Source<String, ?> input) throws Exception {
    return input.via(flow).runWith(Sink.seq(), system).toCompletableFuture().get(3, TimeUnit.SECONDS);
  }

  @Test
  public void closesImmediatelyWhenTheTokenHasAlreadyExpired() throws Exception {
    var expired = new TokenLifetime(Optional.of(Instant.now().minusSeconds(5)));
    var flow = JwtProbeEndpoint.closeAtExp(Flow.of(String.class), expired);

    // The input never completes, so only the deadline can end the stream.
    var result = run(flow, Source.<String>never());

    assertThat(result).containsExactly(JwtProbeEndpoint.CLOSING_MESSAGE);
  }

  @Test
  public void passesMessagesThroughWithoutExp() throws Exception {
    var noExp = new TokenLifetime(Optional.empty());
    var flow = JwtProbeEndpoint.closeAtExp(Flow.of(String.class), noExp);

    var result = run(flow, Source.from(List.of("a", "b")));

    assertThat(result).containsExactly("a", "b");
  }
}
