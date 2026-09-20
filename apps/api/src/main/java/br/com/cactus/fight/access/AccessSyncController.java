package br.com.cactus.fight.access;

import br.com.cactus.fight.security.MfaService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/access")
public class AccessSyncController {
  private final JdbcTemplate jdbc;
  private final MfaService secrets;
  private final ObjectMapper json;

  public AccessSyncController(JdbcTemplate jdbc,MfaService secrets,ObjectMapper json){
    this.jdbc=jdbc;this.secrets=secrets;this.json=json;
  }

  public record EventInput(
    UUID academyId,
    UUID agentId,
    String idempotencyKey,
    UUID studentId,
    OffsetDateTime occurredAt,
    String decision,
    String reason,
    String credentialType,
    Map<String,Object> metadata
  ){}

  @PostMapping("/sync")
  @Transactional
  public ResponseEntity<?> sync(@RequestHeader("X-Agent-Key") String agentKey,@RequestBody EventInput input) throws Exception {
    if(input.academyId()==null||input.agentId()==null||blank(input.idempotencyKey())||input.occurredAt()==null){
      return ResponseEntity.badRequest().body(Map.of("error","invalid_event"));
    }
    String decision=String.valueOf(input.decision()).toUpperCase(Locale.ROOT);
    if(!Set.of("ALLOW","DENY").contains(decision)||blank(input.reason())){
      return ResponseEntity.badRequest().body(Map.of("error","invalid_decision"));
    }

    List<Map<String,Object>> agents=jdbc.queryForList("""
      select id,key_hash from access_agents
      where id=? and academy_id=? and active=true
      limit 1
    """,input.agentId(),input.academyId());
    if(agents.size()!=1) return ResponseEntity.status(401).body(Map.of("error","agent_unauthorized"));

    String expected=String.valueOf(agents.getFirst().get("key_hash"));
    String actual=secrets.hash(agentKey);
    if(!constantTime(expected,actual)) return ResponseEntity.status(401).body(Map.of("error","agent_unauthorized"));

    if(input.studentId()!=null){
      Integer student=jdbc.queryForObject("""
        select count(*) from students where id=? and academy_id=?
      """,Integer.class,input.studentId(),input.academyId());
      if(student==null||student==0) return ResponseEntity.badRequest().body(Map.of("error","student_not_found"));
    }

    String metadata=json.writeValueAsString(input.metadata()==null?Map.of():input.metadata());
    List<Map<String,Object>> inserted=jdbc.queryForList("""
      insert into access_events(
        academy_id,agent_id,student_id,idempotency_key,occurred_at,decision,reason,credential_type,metadata
      ) values (?,?,?,?,?,?,?,?,cast(? as jsonb))
      on conflict(academy_id,idempotency_key) do nothing
      returning id,received_at
    """,input.academyId(),input.agentId(),input.studentId(),input.idempotencyKey().trim(),
      input.occurredAt(),decision,clean(input.reason(),500),clean(input.credentialType(),40),metadata);

    jdbc.update("update access_agents set last_seen_at=now() where id=? and academy_id=?",input.agentId(),input.academyId());

    if(inserted.isEmpty()){
      Map<String,Object> existing=jdbc.queryForMap("""
        select id,decision,reason,received_at from access_events
        where academy_id=? and idempotency_key=?
      """,input.academyId(),input.idempotencyKey().trim());
      return ResponseEntity.ok(Map.of("ok",true,"duplicate",true,"event",existing));
    }
    return ResponseEntity.status(201).body(Map.of("ok",true,"duplicate",false,"event",inserted.getFirst()));
  }

  private boolean constantTime(String a,String b){
    byte[] x=String.valueOf(a).getBytes(StandardCharsets.UTF_8);
    byte[] y=String.valueOf(b).getBytes(StandardCharsets.UTF_8);
    return x.length==y.length&&MessageDigest.isEqual(x,y);
  }

  private boolean blank(String value){return value==null||value.isBlank();}
  private String clean(String value,int max){
    String v=value==null?"":value.trim();return v.substring(0,Math.min(v.length(),max));
  }
}
