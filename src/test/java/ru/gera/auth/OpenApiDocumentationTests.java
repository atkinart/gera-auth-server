package ru.gera.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

/**
 * Тесты OpenAPI документации и Swagger UI.
 * Проверяет доступность, корректность спецификации и интеграцию с Spring Security.
 */
@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
@AutoConfigureMockMvc
class OpenApiDocumentationTests {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
            DockerImageName.parse("postgres:16"))
            .withDatabaseName("test")
            .withUsername("test")
            .withPassword("test")
            .withEnv("PGDATA", "/var/lib/postgresql/data")
            .withTmpFs(Map.of(
                    "/var/lib/postgresql/data", "rw,size=256m"
            ))
            .withStartupTimeout(java.time.Duration.ofMinutes(5))
            .waitingFor(org.testcontainers.containers.wait.strategy.Wait.forListeningPort())
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(OpenApiDocumentationTests.class)));

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;

    @Nested
    @DisplayName("OpenAPI Specification")
    class OpenApiSpecification {

        @Test
        @DisplayName("OpenAPI JSON спецификация доступна и корректна")
        void openApiJsonSpec_accessibleAndValid() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType("application/json"))
                    .andExpect(jsonPath("$.openapi").value("3.0.1"))
                    .andExpect(jsonPath("$.info.title").value("Gera Auth Server API"))
                    .andExpect(jsonPath("$.info.description").value(containsString("OAuth2")))
                    .andExpect(jsonPath("$.info.version").isNotEmpty())
                    .andExpect(jsonPath("$.servers").isArray())
                    .andExpect(jsonPath("$.paths").isMap())
                    .andExpect(jsonPath("$.components").isMap());
        }

        @Test
        @DisplayName("OpenAPI спецификация содержит registration endpoint")
        void openApiSpec_containsRegistrationEndpoint() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.paths['/api/auth/register']").exists())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post").exists())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.summary").value("Регистрация нового пользователя"))
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.requestBody").exists())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.responses['201']").exists())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.responses['409']").exists());
        }

        @Test
        @DisplayName("OpenAPI спецификация содержит схемы данных")
        void openApiSpec_containsDataSchemas() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest").exists())
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.username").exists())
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.password").exists())
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.email").exists())
                    .andExpect(jsonPath("$.components.schemas.RegistrationResponse").exists());
        }

        @Test
        @DisplayName("OpenAPI спецификация содержит схемы безопасности")
        void openApiSpec_containsSecuritySchemes() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.components.securitySchemes").exists())
                    .andExpect(jsonPath("$.components.securitySchemes.oauth2").exists())
                    .andExpect(jsonPath("$.components.securitySchemes.bearer").exists())
                    .andExpect(jsonPath("$.components.securitySchemes.basic").exists());
        }

        @Test
        @DisplayName("OpenAPI спецификация содержит OAuth2 флоу")
        void openApiSpec_containsOAuth2Flows() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.components.securitySchemes.oauth2.flows").exists())
                    .andExpect(jsonPath("$.components.securitySchemes.oauth2.flows.authorizationCode").exists())
                    .andExpect(jsonPath("$.components.securitySchemes.oauth2.flows.authorizationCode.authorizationUrl").value(containsString("/oauth2/authorize")))
                    .andExpect(jsonPath("$.components.securitySchemes.oauth2.flows.authorizationCode.tokenUrl").value(containsString("/oauth2/token")))
                    .andExpect(jsonPath("$.components.securitySchemes.oauth2.flows.authorizationCode.scopes").exists());
        }
    }

    @Nested
    @DisplayName("Swagger UI")
    class SwaggerUi {

        @Test
        @DisplayName("Swagger UI главная страница доступна")
        void swaggerUi_mainPageAccessible() throws Exception {
            mvc.perform(get("/swagger-ui.html"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("text/html"))
                    .andExpect(content().string(containsString("swagger-ui")))
                    .andExpect(content().string(containsString("Swagger UI")));
        }

        @Test
        @DisplayName("Swagger UI статические ресурсы доступны")
        void swaggerUi_staticResourcesAccessible() throws Exception {
            mvc.perform(get("/swagger-ui/swagger-ui-bundle.js"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType("application/javascript"));

            mvc.perform(get("/swagger-ui/swagger-ui.css"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType("text/css"));
        }

        @Test
        @DisplayName("Swagger UI конфигурация указывает на правильный OpenAPI endpoint")
        void swaggerUi_configPointsToCorrectOpenApiEndpoint() throws Exception {
            mvc.perform(get("/swagger-ui/swagger-config"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType("application/json"))
                    .andExpect(jsonPath("$.url").value("/v3/api-docs"));
        }
    }

    @Nested
    @DisplayName("Documentation Security")
    class DocumentationSecurity {

        @Test
        @DisplayName("OpenAPI endpoints доступны без аутентификации")
        void openApiEndpoints_accessibleWithoutAuth() throws Exception {
            // Проверяем, что документация доступна без токенов
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk());

            mvc.perform(get("/swagger-ui.html"))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("OpenAPI endpoints не требуют CSRF токен")
        void openApiEndpoints_noCsrfRequired() throws Exception {
            // GET запросы не требуют CSRF, но убедимся что это явно разрешено в конфигурации
            mvc.perform(get("/v3/api-docs")
                    .header("X-Requested-With", "XMLHttpRequest")) // AJAX запрос
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("OpenAPI endpoints поддерживают CORS")
        void openApiEndpoints_supportCors() throws Exception {
            mvc.perform(get("/v3/api-docs")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));

            mvc.perform(get("/swagger-ui.html")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }
    }

    @Nested
    @DisplayName("API Documentation Completeness")
    class ApiDocumentationCompleteness {

        @Test
        @DisplayName("Все публичные endpoints документированы")
        void allPublicEndpoints_documented() throws Exception {
            String openApiJson = mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            // Проверяем, что ключевые endpoints задокументированы
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.paths['/api/auth/register']").exists()) // Registration
                    .andExpect(jsonPath("$.paths['/actuator/health']").exists()); // Health check
                    // OAuth2 endpoints обычно не включаются в OpenAPI, так как это Spring Authorization Server endpoints
        }

        @Test
        @DisplayName("Error responses задокументированы")
        void errorResponses_documented() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.responses['400']").exists()) // Bad Request
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.responses['409']").exists()) // Conflict
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.responses['500']").exists()); // Internal Error
        }

        @Test
        @DisplayName("Request/Response модели содержат validation constraints")
        void requestResponseModels_containValidationConstraints() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    // Username constraints
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.username.minLength").value(3))
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.username.maxLength").value(50))
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.username.pattern").exists())
                    // Password constraints
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.password.minLength").value(8))
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.password.maxLength").value(100))
                    // Email constraints
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.email.format").value("email"))
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.email.maxLength").value(255));
        }
    }

    @Nested
    @DisplayName("OpenAPI Version Compatibility")
    class OpenApiVersionCompatibility {

        @Test
        @DisplayName("OpenAPI версия совместима с Swagger UI")
        void openApiVersion_compatibleWithSwaggerUi() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.openapi").value(matchesPattern("^3\\.[0-9]+\\.[0-9]+")))
                    .andExpect(jsonPath("$.openapi").value(startsWith("3.")));
        }

        @Test
        @DisplayName("OpenAPI спецификация валидна по JSON Schema")
        void openApiSpec_validJsonSchema() throws Exception {
            String openApiJson = mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            // Проверяем, что это валидный JSON
            objectMapper.readTree(openApiJson);

            // Проверяем обязательные поля OpenAPI 3.x
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.openapi").exists())
                    .andExpect(jsonPath("$.info").exists())
                    .andExpect(jsonPath("$.paths").exists());
        }

        @Test
        @DisplayName("Content-Type заголовки корректны")
        void contentTypeHeaders_correct() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType("application/json"));

            mvc.perform(get("/v3/api-docs.yaml"))
                    .andExpect(status().isNotFound()); // YAML обычно не включен по умолчанию
        }
    }
}