package br.com.cactus.fight.config;

import br.com.cactus.fight.security.JwtService;
import br.com.cactus.fight.security.JwtTenantFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
  @Bean PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder(12);}
  @Bean JwtTenantFilter jwtTenantFilter(JwtService jwt,JdbcTemplate jdbc){return new JwtTenantFilter(jwt,jdbc);}

  @Bean
  CorsConfigurationSource corsConfigurationSource(@Value("${security.cors-origins:http://localhost:5173}") String origins){
    CorsConfiguration config=new CorsConfiguration();
    config.setAllowedOrigins(Arrays.stream(origins.split(",")).map(String::trim).filter(v->!v.isBlank()).toList());
    config.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization","Content-Type","Idempotency-Key","X-Agent-Key","X-Request-Id"));
    config.setExposedHeaders(List.of("X-Request-Id"));
    config.setAllowCredentials(false);
    config.setMaxAge(600L);
    UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**",config);
    return source;
  }

  @Bean SecurityFilterChain filterChain(HttpSecurity http,JwtTenantFilter jwtFilter,RequestSecurityFilter requestFilter) throws Exception {
    return http
      .csrf(csrf->csrf.disable())
      .cors(Customizer.withDefaults())
      .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .headers(h->h
        .frameOptions(f->f.deny())
        .contentTypeOptions(c->{})
        .referrerPolicy(r->r.policy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
        .permissionsPolicy(p->p.policy("camera=(), microphone=(), geolocation=(), payment=()")))
      .authorizeHttpRequests(a->a
        .requestMatchers("/api/auth/**","/api/platform/auth/**","/actuator/health","/actuator/info","/api/access/sync").permitAll()
        .anyRequest().authenticated())
      .addFilterBefore(requestFilter,JwtTenantFilter.class)
      .addFilterBefore(jwtFilter,UsernamePasswordAuthenticationFilter.class)
      .build();
  }
}
