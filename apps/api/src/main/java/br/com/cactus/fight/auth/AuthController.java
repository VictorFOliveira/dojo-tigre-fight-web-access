package br.com.cactus.fight.auth;

import br.com.cactus.fight.audit.AuditService;
import br.com.cactus.fight.security.CurrentUser;
import br.com.cactus.fight.security.JwtService;
import br.com.cactus.fight.security.MfaService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
  private static final Set<String> ADMIN_ROLES=Set.of("OWNER","ADMIN","FINANCE");
  private final JdbcTemplate jdbc;
  private final PasswordEncoder passwords;
  private final JwtService jwt;
  private final MfaService mfa;
  private final AuditService audit;
  private final ObjectMapper json;
  private final boolean requireAdminMfa;
  private final boolean production;
  private final String baseUrl;
  private final SecureRandom random=new SecureRandom();

  public AuthController(
    JdbcTemplate jdbc,
    PasswordEncoder passwords,
    JwtService jwt,
    MfaService mfa,
    AuditService audit,
    ObjectMapper json,
    @Value("${security.require-admin-mfa:false}") boolean requireAdminMfa,
    @Value("${spring.profiles.active:development}") String profile,
    @Value("${cactus.public-url:http://localhost:8080}") String baseUrl
  ){
    this.jdbc=jdbc;this.passwords=passwords;this.jwt=jwt;this.mfa=mfa;this.audit=audit;this.json=json;
    this.requireAdminMfa=requireAdminMfa;this.production="production".equalsIgnoreCase(profile);this.baseUrl=baseUrl.replaceAll("/$","");
  }

  public record LoginRequest(String academy,@Email @NotBlank String email,@NotBlank @Size(min=8,max=200) String password){}
  public record ChallengeRequest(@NotBlank String challengeToken,String code,String recoveryCode){}
  public record SetupRequest(@NotBlank String challengeToken){}
  public record ResetRequest(@NotBlank String academy,@Email @NotBlank String email){}
  public record ResetConfirmRequest(@NotBlank String token,@NotBlank @Size(min=10,max=200) String password){}

  @PostMapping("/login")
  public ResponseEntity<?> login(@Valid @RequestBody LoginRequest input,HttpServletRequest request){
    String academyId=academyFromHost(request);
    List<Map<String,Object>> rows;
    if(academyId!=null){
      rows=jdbc.queryForList("""
        select u.*,a.trade_name academy_name,a.slug academy_slug,a.status academy_status
        from users u join academies a on a.id=u.academy_id
        where u.academy_id=?::uuid and lower(u.email)=lower(?) and u.active=true
          and a.status in ('TRIAL','ACTIVE')
        limit 2
      """,academyId,input.email().trim());
    }else{
      if(input.academy()==null||input.academy().isBlank()) return ResponseEntity.badRequest().body(Map.of("error","academy_required"));
      rows=jdbc.queryForList("""
        select u.*,a.trade_name academy_name,a.slug academy_slug,a.status academy_status
        from users u join academies a on a.id=u.academy_id
        where lower(a.slug)=lower(?) and lower(u.email)=lower(?) and u.active=true
          and a.status in ('TRIAL','ACTIVE')
        limit 2
      """,input.academy().trim(),input.email().trim());
    }
    if(rows.size()!=1) return unauthorized();
    Map<String,Object> user=rows.getFirst();
    if(!passwords.matches(input.password(),String.valueOf(user.get("password_hash")))) return unauthorized();

    UUID userId=(UUID)user.get("id"),tenant=(UUID)user.get("academy_id");
    String role=String.valueOf(user.get("role"));
    if(Boolean.TRUE.equals(user.get("mfa_enabled"))){
      return ResponseEntity.ok(Map.of(
        "mfaRequired",true,
        "challengeToken",challenge(userId,tenant,"MFA"),
        "user",publicUser(user)
      ));
    }
    if((production||requireAdminMfa)&&ADMIN_ROLES.contains(role)){
      return ResponseEntity.ok(Map.of(
        "mfaSetupRequired",true,
        "challengeToken",challenge(userId,tenant,"MFA_SETUP"),
        "user",publicUser(user)
      ));
    }

    audit.user(tenant,userId,"AUTH_LOGIN","user",userId.toString(),Map.of());
    return ResponseEntity.ok(session(user));
  }

  @PostMapping("/mfa/setup")
  public ResponseEntity<?> setup(@Valid @RequestBody SetupRequest input) throws Exception {
    Map<String,Object> user=challengeUser(input.challengeToken(),"MFA_SETUP");
    String secret=mfa.generateSecret();
    jdbc.update("""
      update users set mfa_secret_enc=?,mfa_enabled=false,mfa_recovery_hashes='[]'::jsonb,mfa_enabled_at=null
      where id=? and academy_id=?
    """,mfa.encrypt(secret),user.get("id"),user.get("academy_id"));
    String label=url(String.valueOf(user.get("academy_name"))+":"+String.valueOf(user.get("email")));
    String uri="otpauth://totp/"+label+"?secret="+secret+"&issuer="+url("Cactus Fight")+"&algorithm=SHA1&digits=6&period=30";
    return ResponseEntity.ok(Map.of(
      "secret",secret,
      "otpauthUri",uri,
      "challengeToken",challenge((UUID)user.get("id"),(UUID)user.get("academy_id"),"MFA_SETUP")
    ));
  }

  @PostMapping("/mfa/confirm")
  @Transactional
  public ResponseEntity<?> confirm(@Valid @RequestBody ChallengeRequest input) throws Exception {
    Map<String,Object> user=challengeUser(input.challengeToken(),"MFA_SETUP");
    Object encrypted=user.get("mfa_secret_enc");
    if(encrypted==null||!mfa.verify(mfa.decrypt(String.valueOf(encrypted)),input.code())){
      return ResponseEntity.badRequest().body(Map.of("error","mfa_code_invalid"));
    }
    List<String> codes=mfa.recoveryCodes(8);
    List<String> hashes=new ArrayList<>();
    for(String code:codes) hashes.add(mfa.hash(code.toUpperCase(Locale.ROOT)));
    int version=((Number)user.get("auth_version")).intValue()+1;
    jdbc.update("""
      update users set mfa_enabled=true,mfa_enabled_at=now(),mfa_recovery_hashes=cast(? as jsonb),auth_version=?
      where id=? and academy_id=?
    """,json.writeValueAsString(hashes),version,user.get("id"),user.get("academy_id"));
    user.put("auth_version",version);user.put("mfa_enabled",true);
    audit.user((UUID)user.get("academy_id"),(UUID)user.get("id"),"MFA_ENABLED","user",String.valueOf(user.get("id")),Map.of());
    Map<String,Object> response=new LinkedHashMap<>(session(user));
    response.put("recoveryCodes",codes);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/mfa/verify")
  @Transactional
  public ResponseEntity<?> verify(@Valid @RequestBody ChallengeRequest input) throws Exception {
    Map<String,Object> user=challengeUser(input.challengeToken(),"MFA");
    if(!Boolean.TRUE.equals(user.get("mfa_enabled"))||user.get("mfa_secret_enc")==null) return unauthorized();

    boolean ok=false,usedRecovery=false;
    if(input.code()!=null&&!input.code().isBlank()){
      ok=mfa.verify(mfa.decrypt(String.valueOf(user.get("mfa_secret_enc"))),input.code());
    }
    if(!ok&&input.recoveryCode()!=null&&!input.recoveryCode().isBlank()){
      List<String> hashes=recoveryHashes(user.get("mfa_recovery_hashes_text"));
      String target=mfa.hash(input.recoveryCode().toUpperCase(Locale.ROOT));
      int index=-1;
      for(int i=0;i<hashes.size();i++) if(MessageDigestCompat.equalsHex(hashes.get(i),target)){index=i;break;}
      if(index>=0){
        hashes.remove(index);ok=true;usedRecovery=true;
        jdbc.update("update users set mfa_recovery_hashes=cast(? as jsonb) where id=? and academy_id=?",
          json.writeValueAsString(hashes),user.get("id"),user.get("academy_id"));
      }
    }
    if(!ok) return unauthorized();

    audit.user((UUID)user.get("academy_id"),(UUID)user.get("id"),"MFA_LOGIN","user",String.valueOf(user.get("id")),Map.of("usedRecovery",usedRecovery));
    Map<String,Object> response=new LinkedHashMap<>(session(user));response.put("usedRecovery",usedRecovery);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/forgot-password")
  @Transactional
  public ResponseEntity<?> forgot(@Valid @RequestBody ResetRequest input) throws Exception {
    List<Map<String,Object>> rows=jdbc.queryForList("""
      select u.id,u.academy_id,u.email,a.slug
      from users u join academies a on a.id=u.academy_id
      where lower(a.slug)=lower(?) and lower(u.email)=lower(?) and u.active=true
        and a.status in ('TRIAL','ACTIVE')
      limit 2
    """,input.academy().trim(),input.email().trim());
    if(rows.size()!=1) return ResponseEntity.accepted().body(Map.of("ok",true));
    Map<String,Object> user=rows.getFirst();
    byte[] bytes=new byte[32];random.nextBytes(bytes);
    String raw=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    String tokenHash=mfa.hash(raw);
    int minutes=30;
    jdbc.update("update password_reset_tokens set used_at=now() where academy_id=? and user_id=? and used_at is null",user.get("academy_id"),user.get("id"));
    jdbc.update("""
      insert into password_reset_tokens(academy_id,user_id,token_hash,expires_at)
      values (?,?,?,now()+(?::text||' minutes')::interval)
    """,user.get("academy_id"),user.get("id"),tokenHash,String.valueOf(minutes));
    String resetUrl=baseUrl+"/reset-password?token="+url(raw);
    jdbc.update("""
      insert into notification_outbox(academy_id,channel,template_key,destination,payload,idempotency_key)
      values (?,'EMAIL','PASSWORD_RESET',?,cast(? as jsonb),?)
    """,user.get("academy_id"),user.get("email"),json.writeValueAsString(Map.of("resetUrl",resetUrl,"expiresMinutes",minutes)),"password-reset:"+tokenHash);
    return ResponseEntity.accepted().body(Map.of("ok",true));
  }

  @PostMapping("/reset-password")
  @Transactional
  public ResponseEntity<?> reset(@Valid @RequestBody ResetConfirmRequest input) throws Exception {
    String tokenHash=mfa.hash(input.token());
    List<Map<String,Object>> rows=jdbc.queryForList("""
      select prt.id,prt.academy_id,prt.user_id
      from password_reset_tokens prt
      where prt.token_hash=? and prt.used_at is null and prt.expires_at>now()
      for update
    """,tokenHash);
    if(rows.size()!=1) return ResponseEntity.badRequest().body(Map.of("error","reset_token_invalid"));
    Map<String,Object> row=rows.getFirst();
    jdbc.update("update users set password_hash=?,auth_version=auth_version+1,updated_at=now() where id=? and academy_id=?",
      passwords.encode(input.password()),row.get("user_id"),row.get("academy_id"));
    jdbc.update("update password_reset_tokens set used_at=now() where academy_id=? and user_id=? and used_at is null",row.get("academy_id"),row.get("user_id"));
    audit.user((UUID)row.get("academy_id"),(UUID)row.get("user_id"),"PASSWORD_RESET","user",String.valueOf(row.get("user_id")),Map.of("selfService",true));
    return ResponseEntity.ok(Map.of("ok",true));
  }

  @PostMapping("/logout")
  public ResponseEntity<?> logout(@AuthenticationPrincipal CurrentUser user){
    jdbc.update("update users set auth_version=auth_version+1,updated_at=now() where id=? and academy_id=?",user.id(),user.academyId());
    audit.user(user.academyId(),user.id(),"AUTH_LOGOUT_ALL","user",user.id().toString(),Map.of());
    return ResponseEntity.noContent().build();
  }

  private String academyFromHost(HttpServletRequest request){
    String host=request.getHeader("X-Forwarded-Host");
    if(host==null||host.isBlank()) host=request.getHeader("Host");
    if(host==null) return null;
    host=host.split(":")[0].toLowerCase(Locale.ROOT);
    if(Set.of("localhost","127.0.0.1","::1").contains(host)) return null;
    List<Map<String,Object>> rows=jdbc.queryForList("select academy_id from academy_domains where lower(domain)=? and verified=true limit 1",host);
    return rows.isEmpty()?null:String.valueOf(rows.getFirst().get("academy_id"));
  }

  private Map<String,Object> challengeUser(String token,String expected) {
    Claims claims;
    try{claims=jwt.parse(token);}catch(Exception e){throw new UnauthorizedException();}
    if(!expected.equals(claims.get("scope",String.class))) throw new UnauthorizedException();
    UUID userId=UUID.fromString(claims.getSubject()),academyId=UUID.fromString(claims.get("academyId",String.class));
    List<Map<String,Object>> rows=jdbc.queryForList("""
      select u.*,u.mfa_recovery_hashes::text mfa_recovery_hashes_text,
             a.trade_name academy_name,a.slug academy_slug,a.status academy_status
      from users u join academies a on a.id=u.academy_id
      where u.id=? and u.academy_id=? and u.active=true and a.status in ('TRIAL','ACTIVE') limit 1
    """,userId,academyId);
    if(rows.size()!=1) throw new UnauthorizedException();
    return new HashMap<>(rows.getFirst());
  }

  private String challenge(UUID userId,UUID academyId,String scope){
    return jwt.sign(userId.toString(),Map.of("scope",scope,"academyId",academyId.toString()),Duration.ofMinutes(5));
  }

  private Map<String,Object> session(Map<String,Object> user){
    int av=((Number)user.get("auth_version")).intValue();
    String token=jwt.sign(String.valueOf(user.get("id")),Map.of("scope","SESSION","av",av),Duration.ofHours(8));
    return Map.of(
      "token",token,
      "user",publicUser(user),
      "academy",Map.of("id",user.get("academy_id"),"name",user.get("academy_name"),"slug",user.get("academy_slug"))
    );
  }

  private Map<String,Object> publicUser(Map<String,Object> user){
    return Map.of("id",user.get("id"),"name",user.get("name"),"email",user.get("email"),"role",user.get("role"));
  }

  private List<String> recoveryHashes(Object raw){
    if(raw==null) return new ArrayList<>();
    try{return new ArrayList<>(json.readValue(String.valueOf(raw),new TypeReference<List<String>>(){}));}
    catch(Exception e){return new ArrayList<>();}
  }

  private ResponseEntity<?> unauthorized(){return ResponseEntity.status(401).body(Map.of("error","invalid_credentials"));}

  private String url(String value){
    try{return java.net.URLEncoder.encode(value,java.nio.charset.StandardCharsets.UTF_8);}
    catch(Exception e){return value;}
  }

  @ResponseStatus(org.springframework.http.HttpStatus.UNAUTHORIZED)
  static class UnauthorizedException extends RuntimeException {}

  static class MessageDigestCompat {
    static boolean equalsHex(String a,String b){
      return java.security.MessageDigest.isEqual(String.valueOf(a).getBytes(java.nio.charset.StandardCharsets.UTF_8),String.valueOf(b).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
  }
}
