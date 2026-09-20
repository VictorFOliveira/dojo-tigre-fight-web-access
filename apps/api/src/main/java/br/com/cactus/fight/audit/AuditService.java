package br.com.cactus.fight.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Service
public class AuditService {
  private final JdbcTemplate jdbc;
  private final ObjectMapper json;

  public AuditService(JdbcTemplate jdbc,ObjectMapper json){
    this.jdbc=jdbc;
    this.json=json;
  }

  public void user(UUID academyId,UUID userId,String action,String entityType,String entityId,Map<String,Object> metadata){
    jdbc.update("""
      insert into audit_logs(academy_id,user_id,action,entity_type,entity_id,metadata)
      values (?,?,?,?,?,cast(? as jsonb))
    """,academyId,userId,action,entityType,entityId,toJson(metadata));
  }

  public void platform(UUID platformAdminId,String action,String entityType,String entityId,Map<String,Object> metadata){
    jdbc.update("""
      insert into platform_audit_logs(platform_admin_id,action,entity_type,entity_id,metadata)
      values (?,?,?,?,cast(? as jsonb))
    """,platformAdminId,action,entityType,entityId,toJson(metadata));
  }

  private String toJson(Map<String,Object> metadata){
    try{return json.writeValueAsString(metadata==null?Map.of():metadata);}
    catch(JsonProcessingException e){return "{}";}
  }
}
