package dev.secureops;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import javax.sql.DataSource;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import java.util.List;

@Configuration
public class SecurityConfig {
  @Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
  @Bean UserDetailsService users(DataSource dataSource) {
    var users = new JdbcUserDetailsManager(dataSource);
    users.setUsersByUsernameQuery("select email,password_hash,enabled from app_user where email=?");
    users.setAuthoritiesByUsernameQuery("select email, 'ROLE_' || role from app_user where email=?");
    return users;
  }
  @Bean SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.cors(c -> c.configurationSource(r -> { var cors = new CorsConfiguration(); cors.setAllowedOrigins(List.of("http://localhost:5173","http://127.0.0.1:5173")); cors.setAllowedMethods(List.of("GET","POST","PATCH","DELETE","OPTIONS")); cors.setAllowedHeaders(List.of("Content-Type","X-XSRF-TOKEN")); cors.setAllowCredentials(true); return cors; }))
      .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
      .authorizeHttpRequests(a -> a.requestMatchers("/api/v1/auth/csrf", "/api/v1/auth/login", "/actuator/health", "/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
        .requestMatchers(HttpMethod.POST, "/api/v1/events/demo").hasAnyRole("ADMIN","ANALYST")
        .requestMatchers("/api/v1/admin/**").access((authentication, context) -> new org.springframework.security.authorization.AuthorizationDecision(RolePolicy.isAdmin(authentication.get().getAuthorities()))).anyRequest().authenticated())
      .formLogin(f -> f.loginProcessingUrl("/api/v1/auth/login").successHandler((req,res,auth) -> {res.setStatus(204);}).failureHandler((req,res,e) -> res.sendError(401)))
      .logout(l -> l.logoutUrl("/api/v1/auth/logout").logoutSuccessHandler((req,res,auth) -> res.setStatus(204))).build();
  }
}
