package com.enseniamelo.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(exchanges -> exchanges
                // ============ ENDPOINTS PÚBLICOS ============
                // Actuator y health checks
                .pathMatchers("/actuator/**").permitAll()
                
                // Swagger/OpenAPI
                .pathMatchers("/openapi/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                .pathMatchers("/v3/api-docs/**", "/webjars/**").permitAll()
                
                // Autenticación (tu sistema actual de login/register)
                .pathMatchers("/v1/auth/register", "/v1/auth/login", "/v1/auth/logout").permitAll()
                .pathMatchers("/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/logout").permitAll()
                
                // ============ ENDPOINTS PROTEGIDOS ============
                // Usuarios - requiere scope usuarios:read o rol ADMIN
                .pathMatchers("/v1/usuario/**", "/api/v1/usuario/**")
                    .hasAnyAuthority("SCOPE_usuarios:read", "SCOPE_usuarios:write", "ROLE_ADMIN")
                
                // Tutores - requiere scope tutores:read o rol ADMIN
                .pathMatchers("/v1/tutores/**", "/api/v1/tutores/**")
                    .hasAnyAuthority("SCOPE_tutores:read", "SCOPE_tutores:write", "ROLE_ADMIN")
                
                // Verificación - solo ADMIN
                .pathMatchers("/v1/verificacion/**", "/api/v1/verificacion/**")
                    .hasAnyAuthority("SCOPE_verificacion:write", "ROLE_ADMIN")
                
                // Cualquier otra petición requiere autenticación
                .anyExchange().authenticated()
            )
            // Configuración como Resource Server (valida JWT)
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})
            )
            // Configuración como Client (para login flow - opcional)
            .oauth2Client(oauth2 -> {})
            .build();
    }
}