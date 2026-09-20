package br.com.cactus.fight.student;

import br.com.cactus.fight.audit.AuditService;
import br.com.cactus.fight.security.CurrentUser;
import br.com.cactus.fight.security.MfaService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.*;

@RestController
@RequestMapping("/api/students")
@PreAuthorize("hasAnyRole('OWNER','ADMIN','RECEPTION','COACH','FINANCE')")
public class StudentController {
  private final JdbcTemplate jdbc;
  private final AuditService audit;
  private final MfaService secrets;
  private final ObjectMapper json;
  private final SecureRandom random=new SecureRandom();

  public StudentController(JdbcTemplate jdbc,AuditService audit,MfaService secrets,ObjectMapper json){
    this.jdbc=jdbc;this.audit=audit;this.secrets=secrets;this.json=json;
  }

  public record StudentInput(String name,String document,String email,String phone,LocalDate birthDate,Map<String,Object> metadata){}
  public record MembershipInput(String modality,LocalDate startsOn,LocalDate endsOn,String provider,String providerMemberId){}
  public record CredentialInput(String type,String credential,java.time.OffsetDateTime expiresAt){}

  @GetMapping
  public List<Map<String,Object>> list(@AuthenticationPrincipal CurrentUser user){
    return jdbc.queryForList("""
      select s.id,s.name,s.document,s.email,s.phone,s.birth_date,s.active,s.created_at,s.updated_at,
        coalesce((
          select json_agg(json_build_object('id',m.id,'modality',m.modality,'status',m.status,'startsOn',m.starts_on,'endsOn',m.ends_on))
          from memberships m where m.academy_id=s.academy_id and m.student_id=s.id
        ),'[]'::json) memberships
      from students s where s.academy_id=?
      order by s.active desc,s.name limit 1000
    """,user.academyId());
  }

  @PostMapping
  @PreAuthorize("hasAnyRole('OWNER','ADMIN','RECEPTION')")
  @Transactional
  public ResponseEntity<?> create(@AuthenticationPrincipal CurrentUser user,@RequestBody StudentInput input) throws Exception {
    String name=clean(input.name(),160),document=blankToNull(input.document(),80),email=blankToNull(input.email(),320),phone=blankToNull(input.phone(),50);
    if(name.length()<2)return ResponseEntity.badRequest().body(Map.of("error","invalid_student_name"));
    try{
      UUID id=jdbc.queryForObject("""
        insert into students(academy_id,name,document,email,phone,birth_date,metadata)
        values (?,?,?,?,?,?,cast(? as jsonb)) returning id
      """,UUID.class,user.academyId(),name,document,email,phone,input.birthDate(),
        json.writeValueAsString(input.metadata()==null?Map.of():input.metadata()));
      audit.user(user.academyId(),user.id(),"STUDENT_CREATE","student",id.toString(),Map.of());
      return ResponseEntity.status(201).body(Map.of("id",id,"name",name));
    }catch(DataIntegrityViolationException e){
      return ResponseEntity.status(409).body(Map.of("error","student_identity_conflict"));
    }
  }

  @PostMapping("/{id}/memberships")
  @PreAuthorize("hasAnyRole('OWNER','ADMIN','RECEPTION','FINANCE')")
  @Transactional
  public ResponseEntity<?> membership(@AuthenticationPrincipal CurrentUser user,@PathVariable UUID id,@RequestBody MembershipInput input){
    String modality=clean(input.modality(),80);
    if(modality.length()<2)return ResponseEntity.badRequest().body(Map.of("error","invalid_modality"));
    Integer student=jdbc.queryForObject("select count(*) from students where id=? and academy_id=? and active=true",Integer.class,id,user.academyId());
    if(student==null||student==0)return ResponseEntity.notFound().build();
    LocalDate starts=input.startsOn()==null?LocalDate.now():input.startsOn();
    if(input.endsOn()!=null&&input.endsOn().isBefore(starts))return ResponseEntity.badRequest().body(Map.of("error","invalid_membership_dates"));
    try{
      UUID membershipId=jdbc.queryForObject("""
        insert into memberships(academy_id,student_id,modality,starts_on,ends_on,provider,provider_member_id)
        values (?,?,?,?,?,?,?) returning id
      """,UUID.class,user.academyId(),id,modality,starts,input.endsOn(),blankToNull(input.provider(),80),blankToNull(input.providerMemberId(),200));
      audit.user(user.academyId(),user.id(),"MEMBERSHIP_CREATE","membership",membershipId.toString(),Map.of("studentId",id.toString(),"modality",modality));
      return ResponseEntity.status(201).body(Map.of("id",membershipId,"status","ACTIVE"));
    }catch(DataIntegrityViolationException e){
      return ResponseEntity.status(409).body(Map.of("error","open_membership_already_exists"));
    }
  }

  @PostMapping("/{id}/credentials")
  @PreAuthorize("hasAnyRole('OWNER','ADMIN','RECEPTION')")
  @Transactional
  public ResponseEntity<?> credential(@AuthenticationPrincipal CurrentUser user,@PathVariable UUID id,@RequestBody CredentialInput input) throws Exception {
    String type=clean(input.type(),30).toUpperCase(Locale.ROOT);
    if(!Set.of("QR","RFID","BIOMETRIC","PIN").contains(type))return ResponseEntity.badRequest().body(Map.of("error","invalid_credential_type"));
    Integer student=jdbc.queryForObject("select count(*) from students where id=? and academy_id=? and active=true",Integer.class,id,user.academyId());
    if(student==null||student==0)return ResponseEntity.notFound().build();
    String raw=blankToNull(input.credential(),300);
    boolean generated=raw==null;
    if(raw==null)raw=randomKey();
    try{
      UUID credentialId=jdbc.queryForObject("""
        insert into access_credentials(academy_id,student_id,credential_type,credential_hash,expires_at)
        values (?,?,?,?,?) returning id
      """,UUID.class,user.academyId(),id,type,secrets.hash(raw),input.expiresAt());
      audit.user(user.academyId(),user.id(),"ACCESS_CREDENTIAL_CREATE","access_credential",credentialId.toString(),Map.of("studentId",id.toString(),"type",type));
      Map<String,Object> response=new LinkedHashMap<>();
      response.put("id",credentialId);response.put("type",type);response.put("generated",generated);
      if(generated)response.put("credential",raw);
      return ResponseEntity.status(201).body(response);
    }catch(DataIntegrityViolationException e){
      return ResponseEntity.status(409).body(Map.of("error","credential_already_exists"));
    }
  }

  @PatchMapping("/{id}/active")
  @PreAuthorize("hasAnyRole('OWNER','ADMIN')")
  public ResponseEntity<?> active(@AuthenticationPrincipal CurrentUser user,@PathVariable UUID id,@RequestParam boolean enabled){
    int changed=jdbc.update("update students set active=?,updated_at=now() where id=? and academy_id=?",enabled,id,user.academyId());
    if(changed==0)return ResponseEntity.notFound().build();
    audit.user(user.academyId(),user.id(),enabled?"STUDENT_ENABLE":"STUDENT_DISABLE","student",id.toString(),Map.of());
    return ResponseEntity.ok(Map.of("id",id,"active",enabled));
  }

  private String randomKey(){byte[] raw=new byte[24];random.nextBytes(raw);return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);}
  private String clean(String value,int max){String v=value==null?"":value.trim();return v.substring(0,Math.min(v.length(),max));}
  private String blankToNull(String value,int max){String v=clean(value,max);return v.isBlank()?null:v;}
}
