package br.com.cactus.fight.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class JwtTenantFilter extends OncePerRequestFilter {
  private final JwtService jwt;
  private final JdbcTemplate jdbc;

  public JwtTenantFilter(JwtService jwt,JdbcTemplate jdbc){this.jwt=jwt;this.jdbc=jdbc;}

  @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain) throws ServletException,IOException {
    String auth=req.getHeader("Authorization");
    if(auth==null||!auth.startsWith("Bearer ")){chain.doFilter(req,res);return;}
    try{
      Claims c=jwt.parse(auth.substring(7));
      if(!"SESSION".equals(c.get("scope",String.class))) throw new IllegalArgumentException();
      UUID userId=UUID.fromString(c.getSubject());
      int av=((Number)c.get("av")).intValue();
      List<Map<String,Object>> rows=jdbc.queryForList("""
        select u.id,u.academy_id,u.name,u.email,u.role,u.auth_version
        from users u join academies a on a.id=u.academy_id
        where u.id=? and u.active=true and a.status in ('TRIAL','ACTIVE')
      """,userId);
      if(rows.size()!=1||((Number)rows.getFirst().get("auth_version")).intValue()!=av) throw new IllegalArgumentException();
      Map<String,Object> row=rows.getFirst();
      UUID academyId=(UUID)row.get("academy_id");
      String host=req.getHeader("X-Forwarded-Host");
      if(host==null||host.isBlank())host=req.getHeader("Host");
      if(host!=null){
        host=host.split(":")[0].toLowerCase();
        List<Map<String,Object>> domains=jdbc.queryForList("select academy_id from academy_domains where lower(domain)=? and verified=true limit 1",host);
        if(!domains.isEmpty()&&!academyId.equals(domains.getFirst().get("academy_id"))) throw new IllegalArgumentException();
      }
      CurrentUser user=new CurrentUser(userId,academyId,String.valueOf(row.get("name")),String.valueOf(row.get("email")),String.valueOf(row.get("role")),av);
      var token=new UsernamePasswordAuthenticationToken(user,null,List.of(new SimpleGrantedAuthority("ROLE_"+user.role())));
      SecurityContextHolder.getContext().setAuthentication(token);
      chain.doFilter(req,res);
    }catch(Exception e){
      SecurityContextHolder.clearContext();res.setStatus(401);res.setContentType("application/json");res.getWriter().write("{\"error\":\"session_invalid\"}");
    }
  }
}
