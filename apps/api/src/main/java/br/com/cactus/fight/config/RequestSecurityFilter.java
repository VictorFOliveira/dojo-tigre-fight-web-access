package br.com.cactus.fight.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RequestSecurityFilter extends OncePerRequestFilter {
  private record Bucket(long resetAt,int count){}
  private final Map<String,Bucket> buckets=new ConcurrentHashMap<>();
  private final int apiLimit;
  private final int loginLimit;
  private final int accessLimit;

  public RequestSecurityFilter(
    @Value("${security.rate-limit-api:600}") int apiLimit,
    @Value("${security.rate-limit-login:20}") int loginLimit,
    @Value("${security.rate-limit-access:300}") int accessLimit
  ){
    this.apiLimit=apiLimit;this.loginLimit=loginLimit;this.accessLimit=accessLimit;
  }

  @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain) throws ServletException,IOException {
    String requestId=req.getHeader("X-Request-Id");
    if(requestId==null||requestId.isBlank()||requestId.length()>100) requestId=UUID.randomUUID().toString();
    res.setHeader("X-Request-Id",requestId);
    res.setHeader("X-Content-Type-Options","nosniff");
    if(req.getRequestURI().startsWith("/api/")){
      res.setHeader("Cache-Control","no-store, private");
      res.setHeader("Pragma","no-cache");
    }

    String path=req.getRequestURI();
    int limit=apiLimit;String scope="api";
    if(path.equals("/api/auth/login")||path.equals("/api/platform/auth/login")||path.contains("forgot-password")){
      limit=loginLimit;scope="login";
    }else if(path.equals("/api/access/sync")){
      limit=accessLimit;scope="access";
    }

    String ip=req.getRemoteAddr()==null?"unknown":req.getRemoteAddr();
    String key=scope+":"+ip;
    long now=Instant.now().toEpochMilli(),window=60_000L;
    Bucket hit=buckets.compute(key,(k,old)->old==null||old.resetAt<=now?new Bucket(now+window,1):new Bucket(old.resetAt,old.count+1));
    res.setHeader("X-RateLimit-Limit",String.valueOf(limit));
    res.setHeader("X-RateLimit-Remaining",String.valueOf(Math.max(0,limit-hit.count)));
    if(hit.count>limit){
      long retry=Math.max(1,(hit.resetAt-now+999)/1000);
      res.setHeader("Retry-After",String.valueOf(retry));
      res.setStatus(429);res.setContentType("application/json");
      res.getWriter().write("{\"error\":\"rate_limited\"}");
      return;
    }
    if(buckets.size()>10_000) buckets.entrySet().removeIf(e->e.getValue().resetAt<=now);
    chain.doFilter(req,res);
  }
}
