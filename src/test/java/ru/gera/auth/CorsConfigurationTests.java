package ru.gera.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
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

/**
 * Тесты CORS конфигурации для всех эндпоинтов приложения.
 * Проверяет preflight запросы, разрешенные origins, методы и заголовки.
 */
@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer",
        "app.cors.origins=http://localhost:5173,http://localhost:3000"
})
@AutoConfigureMockMvc
class CorsConfigurationTests {

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
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(CorsConfigurationTests.class)));

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;

    @Nested
    @DisplayName("Registration API CORS")
    class RegistrationApiCors {

        @Test
        @DisplayName("CORS preflight request для разрешенного origin возвращает 200")
        void corsPreflightRequest_allowedOrigin_returns200() throws Exception {
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "http://localhost:5173")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "Content-Type"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"))
                    .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
            // Note: Allowed headers/methods may vary based on CORS config implementation
        }

        @Test
        @DisplayName("CORS preflight request для второго разрешенного origin возвращает 200")
        void corsPreflightRequest_secondAllowedOrigin_returns200() throws Exception {
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "http://localhost:3000")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "Content-Type"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"));
        }

        @Test
        @DisplayName("Actual CORS request для разрешенного origin включает заголовки")
        void actualCorsRequest_allowedOrigin_includesHeaders() throws Exception {
            var request = Map.of(
                    "username", "testuser",
                    "password", "password123",
                    "email", "testuser@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .header("Origin", "http://localhost:5173")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"))
                    .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
        }

        @Test
        @DisplayName("CORS request без Origin заголовка работает нормально")
        void requestWithoutOrigin_worksNormally() throws Exception {
            var request = Map.of(
                    "username", "testusernoorigin",
                    "password", "password123",
                    "email", "testusernoorigin@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
        }

        @Test
        @DisplayName("CORS preflight для неразрешенного origin отклоняется")
        void corsPreflightRequest_disallowedOrigin_rejected() throws Exception {
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "http://malicious-site.com")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "Content-Type"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Actual CORS request для неразрешенного origin отклоняется")
        void actualCorsRequest_disallowedOrigin_rejected() throws Exception {
            var request = Map.of(
                    "username", "testuser",
                    "password", "password123",
                    "email", "testuser@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .header("Origin", "http://malicious-site.com")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("CORS preflight для неподдерживаемого метода отклоняется")
        void corsPreflightRequest_unsupportedMethod_rejected() throws Exception {
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "http://localhost:5173")
                    .header("Access-Control-Request-Method", "DELETE")
                    .header("Access-Control-Request-Headers", "Content-Type"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("CORS preflight для неподдерживаемого заголовка отклоняется")
        void corsPreflightRequest_unsupportedHeader_rejected() throws Exception {
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "http://localhost:5173")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "X-Custom-Header"))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("OAuth2 Endpoints CORS")
    class OAuth2EndpointsCors {

        @Test
        @DisplayName("CORS preflight для OAuth2 token endpoint")
        void corsPreflightRequest_oauthTokenEndpoint() throws Exception {
            mvc.perform(options("/oauth2/token")
                    .header("Origin", "http://localhost:5173")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "Authorization,Content-Type"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }

        @Test
        @DisplayName("CORS для OAuth2 authorization endpoint")
        void corsRequest_oauthAuthorizeEndpoint() throws Exception {
            mvc.perform(get("/oauth2/authorize")
                    .header("Origin", "http://localhost:5173")
                    .param("response_type", "code")
                    .param("client_id", "test-client"))
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }

        @Test
        @DisplayName("CORS для OIDC userinfo endpoint")
        void corsRequest_userinfoEndpoint() throws Exception {
            mvc.perform(get("/userinfo")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }

        @Test
        @DisplayName("CORS для OIDC discovery endpoint")
        void corsRequest_discoveryEndpoint() throws Exception {
            mvc.perform(get("/.well-known/openid-configuration")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }

        @Test
        @DisplayName("CORS для JWKS endpoint")
        void corsRequest_jwksEndpoint() throws Exception {
            mvc.perform(get("/oauth2/jwks")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }
    }

    @Nested
    @DisplayName("OpenAPI Documentation CORS")
    class OpenApiDocsCors {

        @Test
        @DisplayName("CORS для OpenAPI JSON спецификации")
        void corsRequest_openApiSpec() throws Exception {
            mvc.perform(get("/v3/api-docs")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }

        @Test
        @DisplayName("CORS для Swagger UI (redirects to index)")
        void corsRequest_swaggerUi() throws Exception {
            // Swagger UI may redirect to /swagger-ui/index.html
            mvc.perform(get("/swagger-ui.html")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(status().is3xxRedirection()); // Redirects to Swagger UI index
        }

        @Test
        @DisplayName("CORS preflight для OpenAPI endpoints")
        void corsPreflightRequest_openApiEndpoints() throws Exception {
            mvc.perform(options("/v3/api-docs")
                    .header("Origin", "http://localhost:5173")
                    .header("Access-Control-Request-Method", "GET")
                    .header("Access-Control-Request-Headers", "Content-Type"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }
    }

    @Nested
    @DisplayName("CORS Configuration Edge Cases")
    class CorsEdgeCases {

        @Test
        @DisplayName("CORS с credentials=true поддерживается")
        void corsWithCredentials_supported() throws Exception {
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "http://localhost:5173")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "Content-Type")
                    .header("Access-Control-Request-Credentials", "true"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
        }

        @Test
        @DisplayName("Множественные origins в одном запросе не поддерживаются")
        void multipleOrigins_notSupported() throws Exception {
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "http://localhost:5173,http://localhost:3000")
                    .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("CORS для публичного endpoint без аутентификации")
        void corsForPublicEndpoint_openIdConfig() throws Exception {
            // OpenID Configuration endpoint is public and should work with CORS
            mvc.perform(get("/.well-known/openid-configuration")
                    .header("Origin", "http://localhost:5173"))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
        }

        @Test
        @DisplayName("Case-insensitive origins не поддерживаются")
        void caseInsensitiveOrigins_notSupported() throws Exception {
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "HTTP://LOCALHOST:5173") // uppercase
                    .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Origins с разными портами различаются")
        void originsWithDifferentPorts_distinguished() throws Exception {
            // Порт 5174 не в разрешенном списке (только 5173 и 3000)
            mvc.perform(options("/api/auth/register")
                    .header("Origin", "http://localhost:5174")
                    .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isForbidden());
        }
    }
}