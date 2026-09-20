package br.com.cactus.fight.config;

import br.com.cactus.fight.security.JwtService;
import br.com.cactus.fight.security.JwtTenantFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
  @Bean PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder(12);}
  @Bean JwtTenantFilter jwtTenantFilter(JwtService jwt,JdbcTemplate jdbc){return new JwtTenantFilter(jwt,jdbc);}

  @Bean SecurityFilterChain filterChain(HttpSecurity http,JwtTenantFilter jwtFilter) throws Exception {
    return http
      .csrf(csrf->csrf.disable())
      .headers(h->h.frameOptions(f->f.deny()).contentTypeOptions(c->{})
        .referrerPolicy(r->r.policy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)))
      .authorizeHttpRequests(a->a
        .requestMatchers("/api/auth/**","/actuator/health","/actuator/info","/api/access/sync").permitAll()
        .anyRequest().authenticated())
      .addFilterBefore(jwtFilter,UsernamePasswordAuthenticationFilter.class)
      .build();
  }
}
