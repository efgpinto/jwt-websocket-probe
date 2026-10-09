package com.example.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

public class TokenHashTest {

  @Test
  public void hashIsStableAndUrlSafe() {
    var hash = TokenHash.of("header.payload.signature");

    assertThat(hash).isEqualTo(TokenHash.of("header.payload.signature"));
    assertThat(hash).matches("[A-Za-z0-9_-]{43}");
  }

  @Test
  public void matchesOnlyTheSameToken() {
    var hash = TokenHash.of("token-1");

    assertThat(TokenHash.matches(hash, "token-1")).isTrue();
    assertThat(TokenHash.matches(hash, "token-2")).isFalse();
  }
}
