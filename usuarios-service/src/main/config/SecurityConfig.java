package com.enseniamelo.usuarios.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {
    
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Profile("!test") // No aplicar en tests
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(exchanges -> exchanges
                // Endpoints públicos
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/openapi/**").permitAll()
                .pathMatchers("/v3/api-docs/**").permitAll()
                .pathMatchers("/swagger-ui/**").permitAll()
                .pathMatchers("/webjars/**").permitAll()
                
                // Endpoints de autenticación (tu sistema actual)
                .pathMatchers("/v1/auth/register", "/v1/auth/login").permitAll()
                
                // Endpoints protegidos - requieren autenticación
                .pathMatchers("/v1/usuario/**").hasAnyAuthority("SCOPE_usuarios:read", "SCOPE_usuarios:write", "ROLE_ADMIN")
                .pathMatchers("/v1/tutores/**").hasAnyAuthority("SCOPE_tutores:read", "SCOPE_tutores:write", "ROLE_ADMIN")
                .pathMatchers("/v1/verificacion/**").hasAnyAuthority("SCOPE_verificacion:write", "ROLE_ADMIN")
                
                // Cualquier otra petición requiere autenticación
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})
            )
            .build();
    }

    /**
     * Configuración para tests - sin seguridad
     */
    @Bean
    @Profile("test")
    public SecurityWebFilterChain testSecurityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(exchanges -> exchanges
                .anyExchange().permitAll()
            )
            .build();
    }
}