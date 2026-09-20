package br.com.cactus.fight.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;

@Configuration
public class RuntimeConfig {
  @Bean
  ApplicationRunner validateAndBootstrap(Environment env,JdbcTemplate jdbc,PasswordEncoder passwords){
    return args->{
      boolean production=env.acceptsProfiles(Profiles.of("production"));
      String jwt=env.getProperty("JWT_SECRET",env.getProperty("security.jwt-secret",""));
      String mfa=env.getProperty("MFA_ENCRYPTION_KEY",env.getProperty("security.mfa-encryption-key",""));
      String cors=env.getProperty("CORS_ORIGINS",env.getProperty("security.cors-origins",""));
      String database=env.getProperty("DATABASE_URL","");
      if(production){
        if(jwt.length()<32||jwt.toLowerCase().contains("change-this")) throw new IllegalStateException("JWT_SECRET forte é obrigatório em produção");
        if(mfa.length()<32||mfa.toLowerCase().contains("change-this")) throw new IllegalStateException("MFA_ENCRYPTION_KEY forte é obrigatória em produção");
        if(database.isBlank()) throw new IllegalStateException("DATABASE_URL é obrigatória em produção");
        if(cors.isBlank()||Arrays.stream(cors.split(",")).map(String::trim).anyMatch(v->v.equals("*")||v.contains("localhost")||v.contains("127.0.0.1"))){
          throw new IllegalStateException("CORS_ORIGINS deve conter somente origens reais em produção");
        }
      }

      Integer count=jdbc.queryForObject("select count(*) from platform_admins where active=true",Integer.class);
      if(count!=null&&count>0) return;

      String email=env.getProperty("PLATFORM_ADMIN_EMAIL","");
      String password=env.getProperty("PLATFORM_ADMIN_PASSWORD","");
      String name=env.getProperty("PLATFORM_ADMIN_NAME","Cactus Superadmin");
      if(email.isBlank()||password.isBlank()){
        if(production) throw new IllegalStateException("Defina PLATFORM_ADMIN_EMAIL e PLATFORM_ADMIN_PASSWORD no primeiro boot");
        return;
      }
      if(password.length()<12) throw new IllegalStateException("PLATFORM_ADMIN_PASSWORD deve ter pelo menos 12 caracteres");
      jdbc.update("""
        insert into platform_admins(name,email,password_hash)
        values (?,lower(?),?)
        on conflict(email) do nothing
      """,name,email,passwords.encode(password));
    };
  }
}
