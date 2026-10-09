package com.example.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** SHA-256 of a JWT, so a ticket can identify a token without storing it. */
public final class TokenHash {

  private TokenHash() {}

  /** Base64url SHA-256 of the token, without padding. */
  public static String of(String token) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(token));
  }

  /** Compares in constant time, so the comparison does not leak how many characters matched. */
  public static boolean matches(String expectedHash, String token) {
    var expected = Base64.getUrlDecoder().decode(expectedHash);
    return MessageDigest.isEqual(expected, sha256(token));
  }

  private static byte[] sha256(String token) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }
}
