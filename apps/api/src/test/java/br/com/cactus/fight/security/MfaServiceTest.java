package br.com.cactus.fight.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MfaServiceTest {
  @Test
  void totpAndEncryptionRoundTrip() throws Exception {
    MfaService service=new MfaService("test-mfa-key-with-at-least-32-characters");
    String secret=service.generateSecret();
    String encrypted=service.encrypt(secret);

    assertNotEquals(secret,encrypted);
    assertEquals(secret,service.decrypt(encrypted));
    assertTrue(service.verify(secret,currentCode(service,secret)));
    assertFalse(service.verify(secret,"123"));
  }

  private String currentCode(MfaService service,String secret) throws Exception {
    var method=MfaService.class.getDeclaredMethod("totp",String.class,long.class);
    method.setAccessible(true);
    return (String)method.invoke(service,secret,java.time.Instant.now().getEpochSecond());
  }
}
