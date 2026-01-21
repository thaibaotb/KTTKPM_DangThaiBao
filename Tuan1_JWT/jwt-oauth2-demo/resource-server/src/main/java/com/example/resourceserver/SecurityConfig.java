
package com.example.resourceserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
          .authorizeHttpRequests(auth -> auth
              .requestMatchers("/public").permitAll()
              .requestMatchers("/api/**").hasAuthority("SCOPE_read")
              .anyRequest().authenticated()
          )
          .oauth2ResourceServer(oauth -> oauth.jwt());
        return http.build();
    }
}
