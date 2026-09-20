package br.com.cactus.fight.domain;

import br.com.cactus.fight.audit.AuditService;
import br.com.cactus.fight.security.CurrentUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import java.security.SecureRandom;
import java.util.*;

@RestController
@RequestMapping("/api/domains")
@PreAuthorize("hasAnyRole('OWNER','ADMIN')")
public class DomainController {
  private final JdbcTemplate jdbc;
  private final AuditService audit;
  private final String baseDomain;
  private final String customCname;
  private final SecureRandom random=new SecureRandom();

  public DomainController(
    JdbcTemplate jdbc,
    AuditService audit,
    @Value("${cactus.base-domain:fight.cactustecnologia.com.br}") String baseDomain,
    @Value("${cactus.custom-cname:custom.fight.cactustecnologia.com.br}") String customCname
  ){
    this.jdbc=jdbc;this.audit=audit;
    this.baseDomain=normalize(baseDomain);this.customCname=normalize(customCname);
  }

  public record DomainRequest(String domain){}

  @GetMapping
  public Map<String,Object> list(@AuthenticationPrincipal CurrentUser user){
    ensureDefault(user.academyId());
    List<Map<String,Object>> domains=jdbc.queryForList("""
      select id,domain,kind,verified,is_primary,verified_at,created_at
      from academy_domains where academy_id=?
      order by is_primary desc,kind,created_at
    """,user.academyId());
    return Map.of("domains",domains,"config",Map.of("baseDomain",baseDomain,"customCname",customCname));
  }

  @PostMapping
  public ResponseEntity<?> create(@AuthenticationPrincipal CurrentUser user,@RequestBody DomainRequest input){
    String domain=normalize(input.domain());
    if(!valid(domain)||domain.equals(baseDomain)||domain.endsWith("."+baseDomain)){
      return ResponseEntity.badRequest().body(Map.of("error","invalid_domain"));
    }
    String token=randomHex(16);
    try{
      UUID id=jdbc.queryForObject("""
        insert into academy_domains(academy_id,domain,kind,verification_token)
        values (?,?,'CUSTOM',?) returning id
      """,UUID.class,user.academyId(),domain,token);
      audit.user(user.academyId(),user.id(),"DOMAIN_CREATE","academy_domain",String.valueOf(id),Map.of("domain",domain));
      return ResponseEntity.status(201).body(Map.of(
        "id",id,"domain",domain,
        "dns",Map.of("type","CNAME","name",domain,"value",customCname)
      ));
    }catch(Exception e){
      return ResponseEntity.status(409).body(Map.of("error","domain_in_use"));
    }
  }

  @PostMapping("/{id}/verify")
  public ResponseEntity<?> verify(@AuthenticationPrincipal CurrentUser user,@PathVariable UUID id){
    List<Map<String,Object>> rows=jdbc.queryForList("""
      select id,domain from academy_domains
      where id=? and academy_id=? and kind='CUSTOM'
    """,id,user.academyId());
    if(rows.isEmpty()) return ResponseEntity.notFound().build();
    String domain=String.valueOf(rows.getFirst().get("domain"));
    List<String> records=cnameRecords(domain);
    boolean verified=records.stream().map(DomainController::normalize).anyMatch(customCname::equals);
    if(!verified) return ResponseEntity.ok(Map.of("verified",false,"domain",domain,"expectedCname",customCname,"records",records));
    jdbc.update("update academy_domains set verified=true,verified_at=now() where id=? and academy_id=?",id,user.academyId());
    audit.user(user.academyId(),user.id(),"DOMAIN_VERIFY","academy_domain",id.toString(),Map.of("domain",domain));
    return ResponseEntity.ok(Map.of("verified",true,"domain",domain,"records",records));
  }

  @PostMapping("/{id}/primary")
  @org.springframework.transaction.annotation.Transactional
  public ResponseEntity<?> primary(@AuthenticationPrincipal CurrentUser user,@PathVariable UUID id){
    Integer found=jdbc.queryForObject("select count(*) from academy_domains where id=? and academy_id=? and verified=true",Integer.class,id,user.academyId());
    if(found==null||found==0) return ResponseEntity.status(409).body(Map.of("error","domain_not_verified"));
    jdbc.update("update academy_domains set is_primary=false where academy_id=?",user.academyId());
    jdbc.update("update academy_domains set is_primary=true where id=? and academy_id=?",id,user.academyId());
    audit.user(user.academyId(),user.id(),"DOMAIN_PRIMARY","academy_domain",id.toString(),Map.of());
    return ResponseEntity.ok(Map.of("ok",true));
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<?> delete(@AuthenticationPrincipal CurrentUser user,@PathVariable UUID id){
    int changed=jdbc.update("""
      delete from academy_domains where id=? and academy_id=? and kind='CUSTOM' and is_primary=false
    """,id,user.academyId());
    if(changed==0) return ResponseEntity.status(409).body(Map.of("error","domain_delete_blocked"));
    audit.user(user.academyId(),user.id(),"DOMAIN_DELETE","academy_domain",id.toString(),Map.of());
    return ResponseEntity.noContent().build();
  }

  private void ensureDefault(UUID academyId){
    List<Map<String,Object>> rows=jdbc.queryForList("select slug from academies where id=?",academyId);
    if(rows.isEmpty()) return;
    String domain=normalize(String.valueOf(rows.getFirst().get("slug"))+"."+baseDomain);
    jdbc.update("""
      insert into academy_domains(academy_id,domain,kind,verified,is_primary,verified_at)
      values (?,?,'CACTUS',true,not exists(select 1 from academy_domains where academy_id=? and is_primary),now())
      on conflict(domain) do nothing
    """,academyId,domain,academyId);
  }

  private List<String> cnameRecords(String domain){
    try{
      Record[] records=new Lookup(domain,Type.CNAME).run();
      if(records==null) return List.of();
      List<String> out=new ArrayList<>();
      for(Record record:records) if(record instanceof CNAMERecord cname) out.add(normalize(cname.getTarget().toString()));
      return out;
    }catch(Exception e){return List.of();}
  }

  static String normalize(String value){
    if(value==null) return "";
    String v=value.trim().toLowerCase(Locale.ROOT);
    if(v.startsWith("http://")||v.startsWith("https://")){
      try{v=java.net.URI.create(v).getHost();}catch(Exception ignored){}
    }
    if(v.contains("/"))v=v.substring(0,v.indexOf('/'));
    if(v.endsWith("."))v=v.substring(0,v.length()-1);
    return v;
  }

  private boolean valid(String domain){
    return domain.length()<=253&&domain.contains(".")&&!domain.matches("\\d+(?:\\.\\d+){3}")&&
      Arrays.stream(domain.split("\\.")).allMatch(x->x.matches("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"));
  }

  private String randomHex(int bytes){
    byte[] raw=new byte[bytes];random.nextBytes(raw);
    StringBuilder out=new StringBuilder();for(byte b:raw)out.append(String.format("%02x",b));return out.toString();
  }
}
