package br.com.cactus.fight.privacy;

import br.com.cactus.fight.audit.AuditService;
import br.com.cactus.fight.security.CurrentUser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/privacy")
public class PrivacyController {
  private static final Set<String> TYPES=Set.of(
    "ACCESS_EXPORT","CORRECTION","ANONYMIZATION","DELETION",
    "PORTABILITY","SHARING_INFO","OPPOSITION","OTHER"
  );
  private static final Set<String> REVIEW=Set.of("IN_REVIEW","COMPLETED","REJECTED");
  private static final Set<String> CONSENTS=Set.of("PRIVACY_POLICY","TERMS_OF_USE","COMMUNICATION");

  private final JdbcTemplate jdbc;
  private final AuditService audit;
  private final ObjectMapper json;

  public PrivacyController(JdbcTemplate jdbc,AuditService audit,ObjectMapper json){
    this.jdbc=jdbc;this.audit=audit;this.json=json;
  }

  public record PrivacyRequestInput(String type,String description){}
  public record PrivacyReviewInput(String status,String response,String decisionReason){}
  public record ConsentInput(String kind,String version,boolean accepted,Map<String,Object> metadata){}
  public record SettingsInput(String contactEmail,String dpoName,String policyUrl,String retentionNotice){}

  @GetMapping
  public Map<String,Object> center(@AuthenticationPrincipal CurrentUser user){
    List<Map<String,Object>> settings=jdbc.queryForList("""
      select a.trade_name,a.legal_name,ps.contact_email,ps.dpo_name,ps.policy_url,ps.retention_notice
      from academies a left join privacy_settings ps on ps.academy_id=a.id
      where a.id=?
    """,user.academyId());
    Map<String,Object> row=settings.isEmpty()?Map.of():settings.getFirst();
    List<Map<String,Object>> requests=jdbc.queryForList("""
      select id,type,status,description,response,decision_reason,reviewed_at,created_at,updated_at
      from privacy_requests where academy_id=? and user_id=?
      order by created_at desc limit 100
    """,user.academyId(),user.id());
    List<Map<String,Object>> consents=jdbc.queryForList("""
      select kind,version,accepted,accepted_at
      from privacy_consents where academy_id=? and user_id=?
      order by accepted_at desc
    """,user.academyId(),user.id());
    Map<String,Object> controller=new LinkedHashMap<>();
    controller.put("name",row.getOrDefault("trade_name",row.get("legal_name")));
    controller.put("contactEmail",row.get("contact_email"));
    controller.put("dpoName",row.get("dpo_name"));
    controller.put("policyUrl",row.get("policy_url"));

    Map<String,Object> result=new LinkedHashMap<>();
    result.put("controller",controller);
    result.put("retentionNotice",row.getOrDefault("retention_notice","Os prazos de retenção dependem da finalidade, obrigações aplicáveis e política do controlador."));
    result.put("requestTypes",TYPES);
    result.put("requests",requests);
    result.put("consents",consents);
    result.put("note","Pedidos de exclusão ou anonimização passam por análise e não removem automaticamente registros sujeitos a retenção.");
    return result;
  }

  @GetMapping("/export")
  public Map<String,Object> export(@AuthenticationPrincipal CurrentUser user){
    Map<String,Object> output=new LinkedHashMap<>();
    output.put("generatedAt",java.time.OffsetDateTime.now().toString());
    output.put("account",one("""
      select id,name,email,role,active,created_at from users where academy_id=? and id=?
    """,user.academyId(),user.id()));
    output.put("academy",one("""
      select id,trade_name,legal_name,slug from academies where id=?
    """,user.academyId()));

    Map<String,Object> student=one("""
      select id,name,document,email,phone,birth_date,active,metadata,created_at,updated_at
      from students where academy_id=? and portal_user_id=? limit 1
    """,user.academyId(),user.id());
    output.put("student",student.isEmpty()?null:student);
    if(!student.isEmpty()){
      UUID studentId=(UUID)student.get("id");
      output.put("memberships",jdbc.queryForList("""
        select modality,status,starts_on,ends_on,provider,created_at,updated_at
        from memberships where academy_id=? and student_id=? order by starts_on
      """,user.academyId(),studentId));
      output.put("accessEvents",jdbc.queryForList("""
        select occurred_at,decision,reason,credential_type,metadata,received_at
        from access_events where academy_id=? and student_id=? order by occurred_at
      """,user.academyId(),studentId));
    }else{
      output.put("memberships",List.of());
      output.put("accessEvents",List.of());
    }

    audit.user(user.academyId(),user.id(),"PRIVACY_EXPORT","user",user.id().toString(),Map.of("studentLinked",!student.isEmpty()));
    return output;
  }

  @PostMapping("/requests")
  @Transactional
  public ResponseEntity<?> createRequest(@AuthenticationPrincipal CurrentUser user,@RequestBody PrivacyRequestInput input){
    String type=clean(input.type(),50).toUpperCase(Locale.ROOT);
    if(!TYPES.contains(type)) return ResponseEntity.badRequest().body(Map.of("error","invalid_privacy_request_type"));
    Integer count=jdbc.queryForObject("""
      select count(*) from privacy_requests
      where academy_id=? and user_id=? and type=? and status in ('OPEN','IN_REVIEW')
        and created_at>now()-interval '24 hours'
    """,Integer.class,user.academyId(),user.id(),type);
    if(count!=null&&count>0) return ResponseEntity.status(409).body(Map.of("error","privacy_request_already_open"));

    UUID studentId=null;
    List<Map<String,Object>> students=jdbc.queryForList("select id from students where academy_id=? and portal_user_id=? limit 1",user.academyId(),user.id());
    if(!students.isEmpty()) studentId=(UUID)students.getFirst().get("id");

    UUID id=jdbc.queryForObject("""
      insert into privacy_requests(academy_id,user_id,student_id,type,description)
      values (?,?,?,?,?) returning id
    """,UUID.class,user.academyId(),user.id(),studentId,type,clean(input.description(),3000));
    audit.user(user.academyId(),user.id(),"PRIVACY_REQUEST_CREATE","privacy_request",String.valueOf(id),Map.of("type",type));
    return ResponseEntity.status(201).body(Map.of("id",id,"type",type,"status","OPEN"));
  }

  @PostMapping("/consents")
  @Transactional
  public ResponseEntity<?> consent(@AuthenticationPrincipal CurrentUser user,@RequestBody ConsentInput input) throws JsonProcessingException {
    String kind=clean(input.kind(),50).toUpperCase(Locale.ROOT),version=clean(input.version(),80);
    if(!CONSENTS.contains(kind)||version.isBlank()) return ResponseEntity.badRequest().body(Map.of("error","invalid_consent"));
    jdbc.update("""
      insert into privacy_consents(academy_id,user_id,kind,version,accepted,metadata)
      values (?,?,?,?,?,cast(? as jsonb))
      on conflict(academy_id,user_id,kind,version) do update
        set accepted=excluded.accepted,accepted_at=now(),metadata=excluded.metadata
    """,user.academyId(),user.id(),kind,version,input.accepted(),json.writeValueAsString(input.metadata()==null?Map.of():input.metadata()));
    audit.user(user.academyId(),user.id(),"PRIVACY_CONSENT","user",user.id().toString(),Map.of("kind",kind,"version",version,"accepted",input.accepted()));
    return ResponseEntity.ok(Map.of("kind",kind,"version",version,"accepted",input.accepted()));
  }

  @GetMapping("/admin/requests")
  @PreAuthorize("hasAnyRole('OWNER','ADMIN')")
  public List<Map<String,Object>> adminRequests(@AuthenticationPrincipal CurrentUser user){
    return jdbc.queryForList("""
      select pr.id,pr.type,pr.status,pr.description,pr.response,pr.decision_reason,
             pr.reviewed_at,pr.created_at,pr.updated_at,
             u.name requester_name,u.email requester_email,s.name student_name,rv.name reviewer_name
      from privacy_requests pr
      join users u on u.id=pr.user_id and u.academy_id=pr.academy_id
      left join students s on s.id=pr.student_id and s.academy_id=pr.academy_id
      left join users rv on rv.id=pr.reviewed_by and rv.academy_id=pr.academy_id
      where pr.academy_id=?
      order by case pr.status when 'OPEN' then 0 when 'IN_REVIEW' then 1 else 2 end,pr.created_at desc
      limit 500
    """,user.academyId());
  }

  @PatchMapping("/admin/requests/{id}")
  @PreAuthorize("hasAnyRole('OWNER','ADMIN')")
  @Transactional
  public ResponseEntity<?> review(
    @AuthenticationPrincipal CurrentUser user,
    @PathVariable UUID id,
    @RequestBody PrivacyReviewInput input
  ){
    String status=clean(input.status(),30).toUpperCase(Locale.ROOT);
    String response=clean(input.response(),5000),reason=clean(input.decisionReason(),3000);
    if(!REVIEW.contains(status)) return ResponseEntity.badRequest().body(Map.of("error","invalid_privacy_status"));
    if(Set.of("COMPLETED","REJECTED").contains(status)&&response.isBlank()){
      return ResponseEntity.badRequest().body(Map.of("error","privacy_response_required"));
    }
    int changed=jdbc.update("""
      update privacy_requests set
        status=?,response=coalesce(nullif(?,''),response),decision_reason=coalesce(nullif(?,''),decision_reason),
        reviewed_by=?,reviewed_at=case when ? in ('COMPLETED','REJECTED') then now() else reviewed_at end,
        updated_at=now()
      where id=? and academy_id=?
    """,status,response,reason,user.id(),status,id,user.academyId());
    if(changed==0) return ResponseEntity.notFound().build();
    audit.user(user.academyId(),user.id(),"PRIVACY_REQUEST_REVIEW","privacy_request",id.toString(),Map.of("status",status));
    return ResponseEntity.ok(Map.of("id",id,"status",status));
  }

  @GetMapping("/settings")
  @PreAuthorize("hasAnyRole('OWNER','ADMIN')")
  public Map<String,Object> settings(@AuthenticationPrincipal CurrentUser user){
    Map<String,Object> row=one("select * from privacy_settings where academy_id=?",user.academyId());
    return row.isEmpty()?Map.of("academyId",user.academyId()):row;
  }

  @PutMapping("/settings")
  @PreAuthorize("hasAnyRole('OWNER','ADMIN')")
  @Transactional
  public ResponseEntity<?> settings(
    @AuthenticationPrincipal CurrentUser user,
    @RequestBody SettingsInput input
  ){
    String policy=clean(input.policyUrl(),1000);
    if(!policy.isBlank()&&!policy.toLowerCase(Locale.ROOT).startsWith("https://")){
      return ResponseEntity.badRequest().body(Map.of("error","privacy_policy_url_must_use_https"));
    }
    jdbc.update("""
      insert into privacy_settings(academy_id,contact_email,dpo_name,policy_url,retention_notice,updated_at)
      values (?,?,?,?,?,now())
      on conflict(academy_id) do update set
        contact_email=excluded.contact_email,dpo_name=excluded.dpo_name,
        policy_url=excluded.policy_url,retention_notice=excluded.retention_notice,updated_at=now()
    """,user.academyId(),nullIfBlank(input.contactEmail()),nullIfBlank(input.dpoName()),nullIfBlank(policy),nullIfBlank(input.retentionNotice()));
    audit.user(user.academyId(),user.id(),"PRIVACY_SETTINGS_UPDATE","academy",user.academyId().toString(),Map.of());
    return ResponseEntity.ok(Map.of("ok",true));
  }

  private Map<String,Object> one(String sql,Object... args){
    List<Map<String,Object>> rows=jdbc.queryForList(sql,args);
    return rows.isEmpty()?Map.of():rows.getFirst();
  }

  private String clean(String value,int max){
    String v=value==null?"":value.trim();return v.substring(0,Math.min(v.length(),max));
  }

  private String nullIfBlank(String value){
    String v=clean(value,4000);return v.isBlank()?null:v;
  }
}
