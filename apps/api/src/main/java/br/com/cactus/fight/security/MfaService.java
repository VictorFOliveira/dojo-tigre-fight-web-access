package br.com.cactus.fight.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

@Service
public class MfaService {
  private static final String ALPHABET="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  private final byte[] encryptionKey;
  private final SecureRandom random=new SecureRandom();

  public MfaService(@Value("${security.mfa-encryption-key}") String raw) throws Exception {
    if(raw==null||raw.length()<32) throw new IllegalStateException("MFA_ENCRYPTION_KEY must have at least 32 characters");
    this.encryptionKey=MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
  }

  public String generateSecret() {
    byte[] raw=new byte[20];random.nextBytes(raw);return base32Encode(raw);
  }

  public boolean verify(String secret,String code) {
    if(code==null||!code.matches("\\d{6}")) return false;
    long now=Instant.now().getEpochSecond();
    for(int i=-1;i<=1;i++) if(MessageDigest.isEqual(totp(secret,now+i*30).getBytes(),code.getBytes())) return true;
    return false;
  }

  public String encrypt(String value) throws Exception {
    byte[] iv=new byte[12];random.nextBytes(iv);
    Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(encryptionKey,"AES"),new GCMParameterSpec(128,iv));
    byte[] enc=cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
    ByteBuffer out=ByteBuffer.allocate(iv.length+enc.length).put(iv).put(enc);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(out.array());
  }

  public String decrypt(String value) throws Exception {
    byte[] raw=Base64.getUrlDecoder().decode(value);
    byte[] iv=new byte[12];byte[] enc=new byte[raw.length-12];
    System.arraycopy(raw,0,iv,0,12);System.arraycopy(raw,12,enc,0,enc.length);
    Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(encryptionKey,"AES"),new GCMParameterSpec(128,iv));
    return new String(cipher.doFinal(enc),StandardCharsets.UTF_8);
  }

  public List<String> recoveryCodes(int count){
    List<String> out=new ArrayList<>();
    for(int i=0;i<count;i++){byte[] b=new byte[6];random.nextBytes(b);String h=hex(b).toUpperCase(Locale.ROOT);out.add(h.substring(0,6)+"-"+h.substring(6,12));}
    return out;
  }

  public String hash(String value) throws Exception {
    return hex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
  }

  private String totp(String secret,long epochSeconds){
    try{
      long counter=epochSeconds/30;
      ByteBuffer data=ByteBuffer.allocate(8).putLong(counter);
      Mac mac=Mac.getInstance("HmacSHA1");
      mac.init(new SecretKeySpec(base32Decode(secret),"HmacSHA1"));
      byte[] h=mac.doFinal(data.array());
      int offset=h[h.length-1]&0x0f;
      int bin=((h[offset]&0x7f)<<24)|((h[offset+1]&0xff)<<16)|((h[offset+2]&0xff)<<8)|(h[offset+3]&0xff);
      return String.format("%06d",bin%1_000_000);
    }catch(Exception e){throw new IllegalStateException(e);}
  }

  private String base32Encode(byte[] data){
    StringBuilder out=new StringBuilder();int buffer=0,bits=0;
    for(byte b:data){buffer=(buffer<<8)|(b&0xff);bits+=8;while(bits>=5){out.append(ALPHABET.charAt((buffer>>(bits-5))&31));bits-=5;}}
    if(bits>0)out.append(ALPHABET.charAt((buffer<<(5-bits))&31));return out.toString();
  }

  private byte[] base32Decode(String input){
    ByteBuffer out=ByteBuffer.allocate(input.length()*5/8+2);int buffer=0,bits=0;
    for(char c:input.toUpperCase(Locale.ROOT).toCharArray()){int v=ALPHABET.indexOf(c);if(v<0)continue;buffer=(buffer<<5)|v;bits+=5;if(bits>=8){out.put((byte)((buffer>>(bits-8))&0xff));bits-=8;}}
    byte[] r=new byte[out.position()];out.flip();out.get(r);return r;
  }

  private String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x));return s.toString();}
}
