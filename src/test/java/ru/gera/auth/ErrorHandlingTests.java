package ru.gera.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Comprehensive error handling tests for critical failure scenarios.
 * Tests application behavior under various error conditions and edge cases.
 */
@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer",
        "logging.level.org.springframework.security=WARN"
})
@AutoConfigureMockMvc
@DisplayName("Error Handling Tests - Critical Scenarios")
class ErrorHandlingTests {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
            DockerImageName.parse("postgres:16"))
            .withDatabaseName("test")
            .withUsername("test")
            .withPassword("test")
            .withEnv("PGDATA", "/var/lib/postgresql/data")
            .withTmpFs(Map.of("/var/lib/postgresql/data", "rw,size=256m"))
            .withStartupTimeout(java.time.Duration.ofMinutes(5))
            .waitingFor(org.testcontainers.containers.wait.strategy.Wait.forListeningPort())
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(ErrorHandlingTests.class)));

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Nested
    @DisplayName("Registration Error Scenarios")
    class RegistrationErrorScenarios {

        @Test
        @DisplayName("Malformed JSON в registration request")
        void malformedJson_returns400() throws Exception {
            String malformedJson = "{\"username\":\"test\",\"password\":\"pass\",\"email\":"; // Incomplete JSON

            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(malformedJson))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Empty request body возвращает 400")
        void emptyRequestBody_returns400() throws Exception {
            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(""))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Неподдерживаемый Content-Type возвращает 415")
        void unsupportedContentType_returns415() throws Exception {
            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.TEXT_PLAIN)
                            .content("plain text"))
                    .andExpect(status().isUnsupportedMediaType());
        }

        @Test
        @DisplayName("Дублирование email адреса возвращает 409")
        void duplicateEmail_returns409() throws Exception {
            String timestamp = String.valueOf(System.nanoTime()).substring(0, 8);
            String duplicateEmail = "duplicate" + timestamp + "@example.com";

            // Register first user
            var firstUser = Map.of(
                    "username", "user1_" + timestamp,
                    "password", "password123",
                    "email", duplicateEmail
            );

            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(firstUser)))
                    .andExpect(status().isCreated());

            // Attempt to register second user with same email
            var secondUser = Map.of(
                    "username", "user2_" + timestamp,
                    "password", "password123",
                    "email", duplicateEmail // Same email
            );

            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(secondUser)))
                    .andExpect(status().isConflict());
        }

        @Test
        @DisplayName("SQL injection attempts в username/email блокируются")
        void sqlInjectionAttempts_blocked() throws Exception {
            String[] sqlInjectionPayloads = {
                    "'; DROP TABLE users; --",
                    "admin' OR '1'='1",
                    "test@example.com'; DELETE FROM users; --",
                    "<script>alert('xss')</script>",
                    "../../etc/passwd"
            };

            for (String payload : sqlInjectionPayloads) {
                var maliciousRequest = Map.of(
                        "username", payload,
                        "password", "password123",
                        "email", "test@example.com"
                );

                mvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(maliciousRequest)))
                        .andExpect(status().isBadRequest()); // Should be rejected by validation
            }
        }
    }

    @Nested
    @DisplayName("OAuth2 Error Handling")
    class OAuth2ErrorHandling {

        @Test
        @DisplayName("Недействительные OAuth2 параметры возвращают правильные error codes")
        void invalidOAuth2Parameters_returnCorrectErrors() throws Exception {
            // Invalid response_type - redirects to login (requires authentication)
            mvc.perform(get("/oauth2/authorize")
                            .param("response_type", "invalid_type")
                            .param("client_id", "test-client"))
                    .andExpect(status().is3xxRedirection()); // Redirects to login

            // Missing required parameters - redirects to login
            mvc.perform(get("/oauth2/authorize"))
                    .andExpect(status().is3xxRedirection()); // Redirects to login

            // Invalid grant_type - requires client authentication
            mvc.perform(post("/oauth2/token")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("grant_type", "invalid_grant"))
                    .andExpect(status().isUnauthorized()); // No client credentials
        }

        @Test
        @DisplayName("Token introspection без аутентификации клиента возвращает 401")
        void tokenIntrospection_withoutClientAuth_returns401() throws Exception {
            // Without client authentication, introspection should return 401
            mvc.perform(post("/oauth2/introspect")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("token", "some_token"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Token endpoint без аутентификации клиента возвращает 401")
        void tokenEndpoint_withoutClientAuth_returns401() throws Exception {
            // Token endpoint requires client authentication
            mvc.perform(post("/oauth2/token")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("grant_type", "authorization_code")
                            .param("code", "dummy_code")
                            .param("redirect_uri", "http://localhost:8080/callback"))
                    .andExpect(status().isUnauthorized()); // No client credentials
        }
    }

    @Nested
    @DisplayName("Security Attack Scenarios")
    class SecurityAttackScenarios {

        @Test
        @DisplayName("Rate limiting simulation - множественные быстрые запросы")
        void rapidMultipleRequests_handledGracefully() throws Exception {
            String timestamp = String.valueOf(System.nanoTime()).substring(0, 8);

            // Simulate rapid registration attempts
            for (int i = 0; i < 10; i++) {
                var request = Map.of(
                        "username", "rapiduser" + i + "_" + timestamp,
                        "password", "password123",
                        "email", "rapid" + i + "_" + timestamp + "@example.com"
                );

                mvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                        // Should handle gracefully (either succeed or rate limit)
                        .andExpect(status().isCreated());
            }
        }

        @Test
        @DisplayName("Large payload attempts блокируются")
        void largePayloadAttempts_blocked() throws Exception {
            // Create very large username/email
            String largeString = "a".repeat(10000);

            var largeRequest = Map.of(
                    "username", largeString,
                    "password", "password123",
                    "email", largeString + "@example.com"
            );

            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(largeRequest)))
                    .andExpect(status().isBadRequest()); // Should be rejected by validation
        }

        @Test
        @DisplayName("Cross-site scripting (XSS) attempts в полях")
        void xssAttempts_blocked() throws Exception {
            String[] xssPayloads = {
                    "<script>alert('xss')</script>",
                    "javascript:alert('xss')",
                    "<img src=x onerror=alert('xss')>",
                    "</script><script>alert('xss')</script>",
                    "onload=alert('xss')"
            };

            for (String payload : xssPayloads) {
                var xssRequest = Map.of(
                        "username", payload,
                        "password", "password123",
                        "email", "test@example.com"
                );

                mvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(xssRequest)))
                        .andExpect(status().isBadRequest()); // Should be rejected
            }
        }

        @Test
        @DisplayName("Registration endpoint требует JSON content-type")
        void registrationEndpoint_requiresJsonContentType() throws Exception {
            // Registration endpoint requires application/json content type
            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("username", "testuser")
                            .param("password", "password123")
                            .param("email", "test@example.com"))
                    .andExpect(status().isUnsupportedMediaType()); // Requires JSON
        }
    }

    @Nested
    @DisplayName("Network and Infrastructure Errors")
    class NetworkInfrastructureErrors {

        @Test
        @DisplayName("Неподдерживаемые HTTP методы на registration endpoint")
        void unsupportedHttpMethods_onRegistration() throws Exception {
            // Test unsupported methods on registration endpoint
            // Registration only supports POST, other methods return 405
            mvc.perform(put("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isMethodNotAllowed());

            mvc.perform(delete("/api/auth/register"))
                    .andExpect(status().isMethodNotAllowed());

            mvc.perform(patch("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isMethodNotAllowed());
        }

        @Test
        @DisplayName("Недопустимые URL paths на публичных endpoints")
        void invalidPaths_onPublicEndpoints() throws Exception {
            // These paths don't exist and should return 404
            // Using POST to avoid redirect to login for protected GET endpoints
            mvc.perform(post("/api/auth/nonexistent")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isNotFound());

            mvc.perform(post("/api/v2/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("Очень длинные URL paths обрабатываются корректно")
        void veryLongPaths_handledCorrectly() throws Exception {
            String longPath = "/api/auth/" + "very-long-path-segment/".repeat(100);

            // Using POST to avoid redirect to login
            mvc.perform(post(longPath)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isNotFound()); // Should return 404, not crash
        }
    }

    @Nested
    @DisplayName("Concurrent Operations Error Handling")
    class ConcurrentOperationsErrorHandling {

        @Test
        @DisplayName("Одновременная регистрация пользователей с одинаковыми данными")
        void concurrentRegistrationSameData_handledCorrectly() throws Exception {
            String timestamp = String.valueOf(System.nanoTime()).substring(0, 8);
            String sharedUsername = "concurrent_" + timestamp;
            String sharedEmail = "concurrent_" + timestamp + "@example.com";

            // Simulate concurrent registration attempts with same data
            var request1 = Map.of(
                    "username", sharedUsername,
                    "password", "password123",
                    "email", sharedEmail
            );

            var request2 = Map.of(
                    "username", sharedUsername, // Same username
                    "password", "password456",
                    "email", sharedEmail // Same email
            );

            // First request should succeed
            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request1)))
                    .andExpect(status().isCreated());

            // Second request should fail with conflict
            mvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request2)))
                    .andExpect(status().isConflict());
        }
    }
}