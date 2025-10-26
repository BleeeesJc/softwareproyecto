package bo.edu.ucb.microservices.core.ms_product_composite.config;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import reactor.core.publisher.Flux;

@Configuration
@EnableReactiveMethodSecurity()
public class SecurityConfig {	

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) throws Exception {
    	// Solicitar autenticación para todos los requests del controller 
    	http
            .authorizeExchange(auth -> auth
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/openapi/**").permitAll()
                .pathMatchers(HttpMethod.POST,"/v1/product-composite/**").hasAnyAuthority("ROLE_PRODUCT_COMPOSITE_WRITE")
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                        .jwtAuthenticationConverter(jwtAuthenticationConverter()))
            );
        return http.build();
    }
    
   
    @Bean
	public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
    	ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");

            if (realmAccess == null || realmAccess.get("roles") == null) {
                return Flux.empty();
            }

            @SuppressWarnings("unchecked")
            Collection<String> roles = (Collection<String>) realmAccess.get("roles");

            Collection<GrantedAuthority> authorities = roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toSet());

            return Flux.fromIterable(authorities);
        });

        return converter;
	}
}