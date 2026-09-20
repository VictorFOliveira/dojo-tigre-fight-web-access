package br.com.cactus.fight.security;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {
  @Test
  void signsAndParsesScopedToken() {
    JwtService jwt=new JwtService("test-jwt-secret-with-at-least-32-characters");
    String token=jwt.sign("11111111-1111-4111-8111-111111111111",Map.of("scope","SESSION","av",3),Duration.ofMinutes(5));
    var claims=jwt.parse(token);

    assertEquals("SESSION",claims.get("scope",String.class));
    assertEquals(3,((Number)claims.get("av")).intValue());
    assertEquals("11111111-1111-4111-8111-111111111111",claims.getSubject());
  }
}
