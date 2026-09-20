package br.com.cactus.fight.platform;

import br.com.cactus.fight.audit.AuditService;
import br.com.cactus.fight.security.JwtService;
import br.com.cactus.fight.security.MfaService;
import br.com.cactus.fight.security.PlatformUser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;

@RestController
@RequestMapping("/api/platform")
public class PlatformController {
  private final JdbcTemplate jdbc;
  private final PasswordEncoder passwords;
  private final JwtService jwt;
  private final MfaService mfa;
  private final AuditService audit;
  private final ObjectMapper json;
  private final boolean requireMfa;
  private final String baseDomain;

  public PlatformController(
    JdbcTemplate jdbc,PasswordEncoder passwords,JwtService jwt,MfaService mfa,AuditService audit,ObjectMapper json,
    @Value("${security.require-platform-mfa:true}") boolean requireMfa,
    @Value("${cactus.base-domain:fight.cactustecnologia.com.br}") String baseDomain
  ){
    this.jdbc=jdbc;this.passwords=passwords;this.jwt=jwt;this.mfa=mfa;this.audit=audit;this.json=json;
    this.requireMfa=requireMfa;this.baseDomain=baseDomain.toLowerCase(Locale.ROOT).replaceAll("\\.$","");
  }

  public record Login(@Email @NotBlank String email,@NotBlank @Size(min=8,max=200) String password){}
  public record Challenge(@NotBlank String challengeToken,String code,String recoveryCode){}
  public record Setup(@NotBlank String challengeToken){}
  public record Owner(@NotBlank @Size(min=2,max=120) String name,@Email @NotBlank String email,@NotBlank @Size(min=10,max=200) String password){}
  public record AcademyCreate(
    @NotBlank @Size(min=2,max=180) String legalName,
    @NotBlank @Size(min=2,max=160) String tradeName,
    @NotBlank @Pattern(regexp="^[a-z0-9-]{2,80}$") String slug,
    String planCode,
    Owner owner
  ){}
  public record AcademyUpdate(String status,String planCode){}

  @PostMapping("/auth/login")
  public ResponseEntity<?> login(@Valid @RequestBody Login input){
    List<Map<String,Object>> rows=jdbc.queryForList("""
      select id,name,email,password_hash,auth_version,mfa_enabled
      from platform_admins where lower(email)=lower(?) and active=true limit 1
    """,input.email().trim());
    if(rows.size()!=1||!passwords.matches(input.password(),String.valueOf(rows.getFirst().get("password_hash")))){
      return unauthorized();
    }
    Map<String,Object> admin=rows.getFirst();
    UUID id=(UUID)admin.get("id");
    if(Boolean.TRUE.equals(admin.get("mfa_enabled"))){
      return ResponseEntity.ok(Map.of("mfaRequired",true,"challengeToken",challenge(id,"PLATFORM_MFA"),"user",publicAdmin(admin)));
    }
    if(requireMfa){
      return ResponseEntity.ok(Map.of("mfaSetupRequired",true,"challengeToken",challenge(id,"PLATFORM_MFA_SETUP"),"user",publicAdmin(admin)));
    }
    jdbc.update("update platform_admins set last_login_at=now() where id=?",id);
    audit.platform(id,"PLATFORM_LOGIN","platform_admin",id.toString(),Map.of());
    return ResponseEntity.ok(session(admin));
  }

  @PostMapping("/auth/mfa/setup")
  public ResponseEntity<?> setup(@Valid @RequestBody Setup input) throws Exception {
    Map<String,Object> admin=challengeAdmin(input.challengeToken(),"PLATFORM_MFA_SETUP");
    String secret=mfa.generateSecret();
    jdbc.update("""
      update platform_admins set mfa_secret_enc=?,mfa_enabled=false,mfa_recovery_hashes='[]'::jsonb
      where id=?
    """,mfa.encrypt(secret),admin.get("id"));
    String label=url("Cactus Fight Platform:"+String.valueOf(admin.get("email")));
    return ResponseEntity.ok(Map.of(
      "secret",secret,
      "otpauthUri","otpauth://totp/"+label+"?secret="+secret+"&issuer="+url("Cactus Fight Platform")+"&algorithm=SHA1&digits=6&period=30",
      "challengeToken",challenge((UUID)admin.get("id"),"PLATFORM_MFA_SETUP")
    ));
  }

  @PostMapping("/auth/mfa/confirm")
  @Transactional
  public ResponseEntity<?> confirm(@Valid @RequestBody Challenge input) throws Exception {
    Map<String,Object> admin=challengeAdmin(input.challengeToken(),"PLATFORM_MFA_SETUP");
    if(admin.get("mfa_secret_enc")==null||!mfa.verify(mfa.decrypt(String.valueOf(admin.get("mfa_secret_enc"))),input.code())){
      return ResponseEntity.badRequest().body(Map.of("error","mfa_code_invalid"));
    }
    List<String> codes=mfa.recoveryCodes(10),hashes=new ArrayList<>();
    for(String code:codes)hashes.add(mfa.hash(code.toUpperCase(Locale.ROOT)));
    int av=((Number)admin.get("auth_version")).intValue()+1;
    jdbc.update("""
      update platform_admins set mfa_enabled=true,mfa_recovery_hashes=cast(? as jsonb),auth_version=?,last_login_at=now()
      where id=?
    """,json.writeValueAsString(hashes),av,admin.get("id"));
    admin.put("auth_version",av);admin.put("mfa_enabled",true);
    audit.platform((UUID)admin.get("id"),"PLATFORM_MFA_ENABLED","platform_admin",String.valueOf(admin.get("id")),Map.of());
    Map<String,Object> response=new LinkedHashMap<>(session(admin));response.put("recoveryCodes",codes);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/auth/mfa/verify")
  @Transactional
  public ResponseEntity<?> verify(@Valid @RequestBody Challenge input) throws Exception {
    Map<String,Object> admin=challengeAdmin(input.challengeToken(),"PLATFORM_MFA");
    if(!Boolean.TRUE.equals(admin.get("mfa_enabled"))||admin.get("mfa_secret_enc")==null)return unauthorized();
    boolean ok=false,usedRecovery=false;
    if(input.code()!=null&&!input.code().isBlank())ok=mfa.verify(mfa.decrypt(String.valueOf(admin.get("mfa_secret_enc"))),input.code());
    if(!ok&&input.recoveryCode()!=null&&!input.recoveryCode().isBlank()){
      List<String> hashes=recoveryHashes(admin.get("mfa_recovery_hashes_text"));
      String target=mfa.hash(input.recoveryCode().toUpperCase(Locale.ROOT));int found=-1;
      for(int i=0;i<hashes.size();i++)if(equal(hashes.get(i),target)){found=i;break;}
      if(found>=0){hashes.remove(found);ok=true;usedRecovery=true;jdbc.update("update platform_admins set mfa_recovery_hashes=cast(? as jsonb) where id=?",json.writeValueAsString(hashes),admin.get("id"));}
    }
    if(!ok)return unauthorized();
    jdbc.update("update platform_admins set last_login_at=now() where id=?",admin.get("id"));
    audit.platform((UUID)admin.get("id"),"PLATFORM_MFA_LOGIN","platform_admin",String.valueOf(admin.get("id")),Map.of("usedRecovery",usedRecovery));
    Map<String,Object> response=new LinkedHashMap<>(session(admin));response.put("usedRecovery",usedRecovery);
    return ResponseEntity.ok(response);
  }

  @GetMapping("/academies")
  @PreAuthorize("hasRole('PLATFORM_ADMIN')")
  public List<Map<String,Object>> academies(){
    return jdbc.queryForList("""
      select a.id,a.slug,a.legal_name,a.trade_name,a.status,a.plan_code,a.created_at,
        (select count(*)::int from students s where s.academy_id=a.id and s.active) active_students,
        (select count(*)::int from access_agents ag where ag.academy_id=a.id and ag.active) active_agents
      from academies a order by a.created_at desc limit 1000
    """);
  }

  @PostMapping("/academies")
  @PreAuthorize("hasRole('PLATFORM_ADMIN')")
  @Transactional
  public ResponseEntity<?> createAcademy(@AuthenticationPrincipal PlatformUser admin,@Valid @RequestBody AcademyCreate input){
    String plan=normalizePlan(input.planCode());
    Integer planExists=jdbc.queryForObject("select count(*) from saas_plans where code=? and active=true",Integer.class,plan);
    if(planExists==null||planExists==0)return ResponseEntity.badRequest().body(Map.of("error","invalid_plan"));
    if(input.owner()==null)return ResponseEntity.badRequest().body(Map.of("error","owner_required"));
    try{
      UUID academyId=jdbc.queryForObject("""
        insert into academies(slug,legal_name,trade_name,status,plan_code)
        values (?,?,?,'TRIAL',?) returning id
      """,UUID.class,input.slug(),input.legalName().trim(),input.tradeName().trim(),plan);
      UUID ownerId=jdbc.queryForObject("""
        insert into users(academy_id,name,email,password_hash,role)
        values (?,?,lower(?),?,'OWNER') returning id
      """,UUID.class,academyId,input.owner().name().trim(),input.owner().email().trim(),passwords.encode(input.owner().password()));
      String domain=input.slug()+"."+baseDomain;
      jdbc.update("""
        insert into academy_domains(academy_id,domain,kind,verified,is_primary,verified_at)
        values (?,?,'CACTUS',true,true,now())
      """,academyId,domain);
      audit.platform(admin.id(),"PLATFORM_ACADEMY_CREATE","academy",academyId.toString(),Map.of("slug",input.slug(),"plan",plan,"ownerId",ownerId.toString()));
      return ResponseEntity.status(201).body(Map.of("academyId",academyId,"ownerId",ownerId,"domain",domain,"status","TRIAL","plan",plan));
    }catch(Exception e){
      return ResponseEntity.status(409).body(Map.of("error","academy_or_owner_already_exists"));
    }
  }

  @PatchMapping("/academies/{id}")
  @PreAuthorize("hasRole('PLATFORM_ADMIN')")
  @Transactional
  public ResponseEntity<?> updateAcademy(@AuthenticationPrincipal PlatformUser admin,@PathVariable UUID id,@RequestBody AcademyUpdate input){
    String status=input.status()==null?null:input.status().toUpperCase(Locale.ROOT);
    String plan=input.planCode()==null?null:normalizePlan(input.planCode());
    if(status!=null&&!Set.of("TRIAL","ACTIVE","SUSPENDED","CANCELLED").contains(status))return ResponseEntity.badRequest().body(Map.of("error","invalid_status"));
    if(plan!=null){
      Integer exists=jdbc.queryForObject("select count(*) from saas_plans where code=? and active=true",Integer.class,plan);
      if(exists==null||exists==0)return ResponseEntity.badRequest().body(Map.of("error","invalid_plan"));
    }
    int changed=jdbc.update("""
      update academies set status=coalesce(?,status),plan_code=coalesce(?,plan_code),updated_at=now()
      where id=?
    """,status,plan,id);
    if(changed==0)return ResponseEntity.notFound().build();
    audit.platform(admin.id(),"PLATFORM_ACADEMY_UPDATE","academy",id.toString(),Map.of("status",String.valueOf(status),"plan",String.valueOf(plan)));
    return ResponseEntity.ok(Map.of("id",id,"updated",true));
  }

  @GetMapping("/plans")
  @PreAuthorize("hasRole('PLATFORM_ADMIN')")
  public List<Map<String,Object>> plans(){
    return jdbc.queryForList("select * from saas_plans order by monthly_price_cents");
  }

  private Map<String,Object> challengeAdmin(String token,String scope){
    Claims claims;try{claims=jwt.parse(token);}catch(Exception e){throw new UnauthorizedException();}
    if(!scope.equals(claims.get("scope",String.class)))throw new UnauthorizedException();
    UUID id=UUID.fromString(claims.getSubject());
    List<Map<String,Object>> rows=jdbc.queryForList("""
      select *,mfa_recovery_hashes::text mfa_recovery_hashes_text
      from platform_admins where id=? and active=true limit 1
    """,id);
    if(rows.size()!=1)throw new UnauthorizedException();
    return new HashMap<>(rows.getFirst());
  }

  private String challenge(UUID id,String scope){return jwt.sign(id.toString(),Map.of("scope",scope),Duration.ofMinutes(5));}
  private Map<String,Object> session(Map<String,Object> admin){
    int av=((Number)admin.get("auth_version")).intValue();
    return Map.of("token",jwt.sign(String.valueOf(admin.get("id")),Map.of("scope","PLATFORM","av",av),Duration.ofHours(8)),"user",publicAdmin(admin));
  }
  private Map<String,Object> publicAdmin(Map<String,Object> admin){return Map.of("id",admin.get("id"),"name",admin.get("name"),"email",admin.get("email"),"role","PLATFORM_ADMIN");}
  private List<String> recoveryHashes(Object raw){
    try{return new ArrayList<>(json.readValue(String.valueOf(raw),new TypeReference<List<String>>(){}));}catch(Exception e){return new ArrayList<>();}
  }
  private boolean equal(String a,String b){byte[] x=a.getBytes(StandardCharsets.UTF_8),y=b.getBytes(StandardCharsets.UTF_8);return x.length==y.length&&MessageDigest.isEqual(x,y);}
  private String normalizePlan(String plan){String value=plan==null?"STARTER":plan.trim().toUpperCase(Locale.ROOT);return Set.of("STARTER","PRO","ENTERPRISE").contains(value)?value:"INVALID";}
  private ResponseEntity<?> unauthorized(){return ResponseEntity.status(401).body(Map.of("error","invalid_credentials"));}
  private String url(String value){return java.net.URLEncoder.encode(value,StandardCharsets.UTF_8);}

  @org.springframework.web.bind.annotation.ResponseStatus(org.springframework.http.HttpStatus.UNAUTHORIZED)
  static class UnauthorizedException extends RuntimeException {}
}
