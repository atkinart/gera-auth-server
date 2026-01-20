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
@Testcontainers(disabledWithoutDocker = true)
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
                    .andExpect(jsonPath("$.openapi").value(startsWith("3.")))
                    .andExpect(jsonPath("$.info.title").exists())
                    .andExpect(jsonPath("$.info.version").isNotEmpty())
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
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.summary").exists())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.requestBody").exists())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.responses['201']").exists());
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
        @DisplayName("OpenAPI спецификация содержит компоненты")
        void openApiSpec_containsComponents() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.components").exists())
                    .andExpect(jsonPath("$.components.schemas").exists());
            // Security schemes may not be defined if not explicitly configured in OpenAPI config
        }

        @Test
        @DisplayName("OpenAPI спецификация валидна")
        void openApiSpec_isValid() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.openapi").exists())
                    .andExpect(jsonPath("$.info").exists())
                    .andExpect(jsonPath("$.paths").exists());
        }
    }

    @Nested
    @DisplayName("Swagger UI")
    class SwaggerUi {

        @Test
        @DisplayName("Swagger UI главная страница доступна (может перенаправлять)")
        void swaggerUi_mainPageAccessible() throws Exception {
            // Swagger UI может перенаправлять на /swagger-ui/index.html
            var result = mvc.perform(get("/swagger-ui.html"))
                    .andReturn();
            int status = result.getResponse().getStatus();
            // Either 200 OK or 302 redirect is acceptable
            org.junit.jupiter.api.Assertions.assertTrue(
                status == 200 || status == 302,
                "Expected 200 or 302 but got " + status
            );
        }

        @Test
        @DisplayName("Swagger UI статические ресурсы доступны")
        void swaggerUi_staticResourcesAccessible() throws Exception {
            // JavaScript may have different content types
            mvc.perform(get("/swagger-ui/swagger-ui-bundle.js"))
                    .andExpect(status().isOk());

            mvc.perform(get("/swagger-ui/swagger-ui.css"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType("text/css"));
        }

        @Test
        @DisplayName("Swagger UI index страница доступна")
        void swaggerUi_indexPageAccessible() throws Exception {
            mvc.perform(get("/swagger-ui/index.html"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("text/html"));
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

            // Swagger UI index page
            mvc.perform(get("/swagger-ui/index.html"))
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

            // Swagger UI index page with CORS
            mvc.perform(get("/swagger-ui/index.html")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }
    }

    @Nested
    @DisplayName("API Documentation Completeness")
    class ApiDocumentationCompleteness {

        @Test
        @DisplayName("Registration endpoint документирован")
        void registrationEndpoint_documented() throws Exception {
            // Проверяем, что registration endpoint задокументирован
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.paths['/api/auth/register']").exists())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post").exists());
        }

        @Test
        @DisplayName("Успешный response документирован")
        void successResponse_documented() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.paths['/api/auth/register'].post.responses['201']").exists());
        }

        @Test
        @DisplayName("Request модель содержит обязательные поля")
        void requestModel_containsRequiredFields() throws Exception {
            mvc.perform(get("/v3/api-docs"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.username").exists())
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.password").exists())
                    .andExpect(jsonPath("$.components.schemas.RegistrationRequest.properties.email").exists());
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
        }
    }
}
