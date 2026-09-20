package br.com.cactus.fight.access;

import br.com.cactus.fight.audit.AuditService;
import br.com.cactus.fight.security.CurrentUser;
import br.com.cactus.fight.security.MfaService;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.*;

@RestController
@RequestMapping("/api/access/agents")
@PreAuthorize("hasAnyRole('OWNER','ADMIN')")
public class AccessAgentController {
  private final JdbcTemplate jdbc;
  private final MfaService secrets;
  private final AuditService audit;
  private final SecureRandom random=new SecureRandom();

  public AccessAgentController(JdbcTemplate jdbc,MfaService secrets,AuditService audit){
    this.jdbc=jdbc;this.secrets=secrets;this.audit=audit;
  }

  public record AgentRequest(String name){}

  @GetMapping
  public List<Map<String,Object>> list(@AuthenticationPrincipal CurrentUser user){
    return jdbc.queryForList("""
      select id,name,active,last_seen_at,created_at
      from access_agents where academy_id=? order by active desc,created_at desc
    """,user.academyId());
  }

  @PostMapping
  @Transactional
  public ResponseEntity<?> create(@AuthenticationPrincipal CurrentUser user,@RequestBody AgentRequest input) throws Exception {
    String name=clean(input.name(),120);
    if(name.length()<2) return ResponseEntity.badRequest().body(Map.of("error","invalid_agent_name"));
    String rawKey=key();
    UUID id=jdbc.queryForObject("""
      insert into access_agents(academy_id,name,key_hash)
      values (?,?,?) returning id
    """,UUID.class,user.academyId(),name,secrets.hash(rawKey));
    audit.user(user.academyId(),user.id(),"ACCESS_AGENT_CREATE","access_agent",id.toString(),Map.of("name",name));
    return ResponseEntity.status(201).body(Map.of(
      "id",id,"name",name,"agentKey",rawKey,
      "note","A chave é exibida uma única vez. Armazene-a no agente local e não a registre em logs."
    ));
  }

  @PostMapping("/{id}/rotate")
  @Transactional
  public ResponseEntity<?> rotate(@AuthenticationPrincipal CurrentUser user,@PathVariable UUID id) throws Exception {
    String rawKey=key();
    int changed=jdbc.update("""
      update access_agents set key_hash=? where id=? and academy_id=? and active=true
    """,secrets.hash(rawKey),id,user.academyId());
    if(changed==0) return ResponseEntity.notFound().build();
    audit.user(user.academyId(),user.id(),"ACCESS_AGENT_KEY_ROTATE","access_agent",id.toString(),Map.of());
    return ResponseEntity.ok(Map.of("id",id,"agentKey",rawKey));
  }

  @PatchMapping("/{id}/active")
  @Transactional
  public ResponseEntity<?> active(
    @AuthenticationPrincipal CurrentUser user,
    @PathVariable UUID id,
    @RequestParam boolean enabled
  ){
    int changed=jdbc.update("update access_agents set active=? where id=? and academy_id=?",enabled,id,user.academyId());
    if(changed==0) return ResponseEntity.notFound().build();
    audit.user(user.academyId(),user.id(),enabled?"ACCESS_AGENT_ENABLE":"ACCESS_AGENT_DISABLE","access_agent",id.toString(),Map.of());
    return ResponseEntity.ok(Map.of("id",id,"active",enabled));
  }

  private String key(){
    byte[] raw=new byte[32];random.nextBytes(raw);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
  }

  private String clean(String value,int max){
    String v=value==null?"":value.trim();
    return v.substring(0,Math.min(v.length(),max));
  }
}
