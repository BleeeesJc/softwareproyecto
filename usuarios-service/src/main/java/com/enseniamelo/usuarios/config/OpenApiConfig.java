package com.enseniamelo.usuarios.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;

import java.util.List;

@Configuration
public class OpenApiConfig {
    @Value("${api.common.version}")
    String apiVersion;
    @Value("${api.common.title}")
    String apiTitle;
    @Value("${api.common.description}")
    String apiDescription;
    @Value("${api.common.termsOfService}")
    String apiTermsOfService;
    @Value("${api.common.license}")
    String apiLicense;
    @Value("${api.common.licenseUrl}")
    String apiLicenseUrl;
    @Value("${api.common.externalDocDesc}")
    String apiExternalDocDesc;
    @Value("${api.common.externalDocUrl}")
    String apiExternalDocUrl;
    @Value("${api.common.contact.name}")
    String apiContactName;
    @Value("${api.common.contact.url}")
    String apiContactUrl;
    @Value("${api.common.contact.email}")
    String apiContactEmail;

    /**
     * Will exposed on $HOST:$PORT/swagger-ui.html
     *
     * @return the common OpenAPI documentation
     */
    @Bean
    public OpenAPI getOpenApiDocumentation() {
        Server gatewayServer = new Server();
        gatewayServer.setUrl("https://localhost:8443");
        gatewayServer.setDescription("API Gateway (HTTPS)");

        Server directServer = new Server();
        directServer.setUrl("http://localhost:8081");
        directServer.setDescription("Usuarios Service (Direct Access)");

        return new OpenAPI()
                .info(new Info()
                    .title(apiTitle)
                    .description(apiDescription)
                    .version(apiVersion)
                    .contact(new Contact()
                        .name(apiContactName)
                        .url(apiContactUrl)
                        .email(apiContactEmail))
                    .termsOfService(apiTermsOfService)
                    .license(new License()
                        .name(apiLicense)
                        .url(apiLicenseUrl)))
                .externalDocs(new ExternalDocumentation()
                    .description(apiExternalDocDesc)
                    .url(apiExternalDocUrl))
                .servers(List.of(gatewayServer, directServer));
    }
}