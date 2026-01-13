package ru.gera.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Простые негативные тесты для OAuth2 без Testcontainers.
 * Проверяют валидацию параметров и базовую обработку ошибок.
 */
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:testdb",
        "spring.datasource.username=test",
        "spring.datasource.password=test",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.liquibase.enabled=false",
        "logging.level.org.springframework.security=DEBUG"
})
class OAuth2NegativeSimpleTests {

    @Autowired
    MockMvc mvc;

    // =========================== Token Exchange Negative Tests ===========================

    @Test
    @DisplayName("Обмен недействительного authorization code возвращает ошибку")
    void exchangeToken_invalidAuthorizationCode_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", "invalid-code-12345")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("client_id", "test-client")
                        .param("code_verifier", "test-verifier"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Отсутствующий grant_type возвращает ошибку")
    void exchangeToken_missingGrantType_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("code", "some-code")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("client_id", "test-client"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    @DisplayName("Отсутствующий код авторизации возвращает ошибку")
    void exchangeToken_missingCode_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("client_id", "test-client"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    @DisplayName("Отсутствующий client_id возвращает ошибку")
    void exchangeToken_missingClientId_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", "some-code")
                        .param("redirect_uri", "http://127.0.0.1/callback"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    // =========================== UserInfo Endpoint Tests ===========================

    @Test
    @DisplayName("UserInfo с недействительным токеном возвращает 401")
    void userinfo_invalidToken_returns401() throws Exception {
        mvc.perform(post("/userinfo")
                        .header("Authorization", "Bearer invalid-token-12345"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("UserInfo без токена возвращает 401")
    void userinfo_missingToken_returns401() throws Exception {
        mvc.perform(post("/userinfo"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("UserInfo с неправильным форматом Authorization header")
    void userinfo_malformedAuthHeader_returns401() throws Exception {
        mvc.perform(post("/userinfo")
                        .header("Authorization", "InvalidFormat token123"))
                .andExpect(status().isUnauthorized());
    }

    // =========================== Introspection Tests ===========================

    @Test
    @DisplayName("Introspection без аутентификации клиента возвращает 401")
    void introspect_noClientAuth_returns401() throws Exception {
        mvc.perform(post("/oauth2/introspect")
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", "some-token"))
                .andExpect(status().isUnauthorized());
    }

    // =========================== Revoke Tests ===========================

    @Test
    @DisplayName("Revoke без аутентификации возвращает ошибку")
    void revoke_noAuth_returnsError() throws Exception {
        mvc.perform(post("/oauth2/revoke")
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", "some-token"))
                .andExpect(status().isUnauthorized());
    }
}