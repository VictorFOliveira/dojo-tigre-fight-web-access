package br.com.cactus.fight.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {
  private final SecretKey key;

  public JwtService(@Value("${security.jwt-secret}") String secret) {
    if (secret == null || secret.length() < 32) throw new IllegalStateException("JWT_SECRET must have at least 32 characters");
    this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }

  public String sign(String subject, Map<String,Object> claims, Duration duration) {
    Instant now = Instant.now();
    return Jwts.builder()
      .subject(subject)
      .claims(claims)
      .issuer("cactus-fight-api")
      .issuedAt(Date.from(now))
      .expiration(Date.from(now.plus(duration)))
      .signWith(key)
      .compact();
  }

  public Claims parse(String token) {
    return Jwts.parser().verifyWith(key).requireIssuer("cactus-fight-api").build()
      .parseSignedClaims(token).getPayload();
  }
}
