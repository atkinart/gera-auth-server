package ru.gera.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Негативные тесты для OAuth2/OIDC функциональности.
 * Покрывают различные виды ошибок: неправильные параметры, недействительные токены,
 * неправильные клиенты, PKCE ошибки и другие security-related сценарии.
 */
@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
@org.springframework.context.annotation.Import(TestClientConfig.class)
@AutoConfigureMockMvc
class OAuth2NegativeTests {

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
            .waitingFor(org.testcontainers.containers.wait.strategy.Wait.forListeningPort());

    @Autowired
    MockMvc mvc;

    @Autowired
    RegisteredClientRepository clients;

    @Autowired
    ObjectMapper objectMapper;

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String codeVerifier() {
        byte[] code = new byte[32];
        new SecureRandom().nextBytes(code);
        return base64Url(code);
    }

    private static String s256(String verifier) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return base64Url(md.digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    private MvcResult loginAsAdmin() throws Exception {
        return mvc.perform(formLogin().user("admin").password("admin"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
    }

    private String[] pkcePair() throws Exception {
        String verifier = codeVerifier();
        String challenge = s256(verifier);
        return new String[]{verifier, challenge};
    }

    private String extractCodeFromLocation(String location) {
        URI redirect = URI.create(location);
        String query = redirect.getQuery();
        for (String p : query.split("&")) {
            if (p.startsWith("code=")) return p.substring("code=".length());
        }
        throw new IllegalStateException("No code in redirect: " + location);
    }

    @BeforeEach
    void ensureTestClient() {
        assertThat(clients.findByClientId("test-client")).as("test-client должен существовать").isNotNull();
    }

    // =========================== Token Exchange Negative Tests ===========================

    @Test
    @DisplayName("Обмен недействительного authorization code возвращает ошибку")
    void exchangeToken_invalidAuthorizationCode_returnsError() throws Exception {
        String[] pkce = pkcePair();

        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", "invalid-code-12345")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("client_id", "test-client")
                        .param("code_verifier", pkce[0]))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Обмен кода с неправильным client_id возвращает ошибку")
    void exchangeToken_wrongClientId_returnsError() throws Exception {
        // Получаем валидный код для test-client
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);
        String[] pkce = pkcePair();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid profile")
                        .param("code_challenge", pkce[1])
                        .param("code_challenge_method", "S256")
                        .param("state", UUID.randomUUID().toString()))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String code = extractCodeFromLocation(auth.getResponse().getHeader("Location"));

        // Пытаемся обменять с другим client_id
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("client_id", "wrong-client-id")
                        .param("code_verifier", pkce[0]))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    @DisplayName("Обмен кода с неправильным redirect_uri возвращает ошибку")
    void exchangeToken_wrongRedirectUri_returnsError() throws Exception {
        // Получаем валидный код
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);
        String[] pkce = pkcePair();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid profile")
                        .param("code_challenge", pkce[1])
                        .param("code_challenge_method", "S256")
                        .param("state", UUID.randomUUID().toString()))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String code = extractCodeFromLocation(auth.getResponse().getHeader("Location"));

        // Пытаемся обменять с другим redirect_uri
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", "http://evil-site.com/callback")
                        .param("client_id", "test-client")
                        .param("code_verifier", pkce[0]))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Обмен кода с неправильным PKCE verifier возвращает ошибку")
    void exchangeToken_wrongPkceVerifier_returnsError() throws Exception {
        // Получаем валидный код с одним verifier
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);
        String[] pkce = pkcePair();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid profile")
                        .param("code_challenge", pkce[1])
                        .param("code_challenge_method", "S256")
                        .param("state", UUID.randomUUID().toString()))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String code = extractCodeFromLocation(auth.getResponse().getHeader("Location"));

        // Пытаемся обменять с другим verifier
        String wrongVerifier = codeVerifier();

        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("client_id", "test-client")
                        .param("code_verifier", wrongVerifier))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Повторное использование authorization code возвращает ошибку")
    void exchangeToken_reusedAuthorizationCode_returnsError() throws Exception {
        // Получаем валидный код
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);
        String[] pkce = pkcePair();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid profile")
                        .param("code_challenge", pkce[1])
                        .param("code_challenge_method", "S256")
                        .param("state", UUID.randomUUID().toString()))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String code = extractCodeFromLocation(auth.getResponse().getHeader("Location"));

        // Первый обмен - успешный
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("client_id", "test-client")
                        .param("code_verifier", pkce[0]))
                .andExpect(status().isOk());

        // Второй обмен того же кода - должен провалиться
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("client_id", "test-client")
                        .param("code_verifier", pkce[0]))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    // =========================== Missing Parameters Tests ===========================

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
        mvc.perform(get("/userinfo")
                        .header("Authorization", "Bearer invalid-token-12345"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("UserInfo без токена возвращает 401")
    void userinfo_missingToken_returns401() throws Exception {
        mvc.perform(get("/userinfo"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("UserInfo с неправильным форматом Authorization header")
    void userinfo_malformedAuthHeader_returns401() throws Exception {
        mvc.perform(get("/userinfo")
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

    @Test
    @DisplayName("Introspection с неправильными credentials возвращает 401")
    void introspect_wrongCredentials_returns401() throws Exception {
        String wrongBasic = "Basic " + Base64.getEncoder()
                .encodeToString("wrong-client:wrong-secret".getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/oauth2/introspect")
                        .header("Authorization", wrongBasic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", "some-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Introspection недействительного токена возвращает active=false")
    void introspect_invalidToken_returnsInactive() throws Exception {
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("conf-client:secret".getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/oauth2/introspect")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", "invalid-token-12345"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }

    // =========================== Refresh Token Tests ===========================

    @Test
    @DisplayName("Refresh с недействительным refresh_token возвращает ошибку")
    void refresh_invalidRefreshToken_returnsError() throws Exception {
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("code-client:secret2".getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", "invalid-refresh-token-12345"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Refresh без аутентификации клиента возвращает ошибку")
    void refresh_noClientAuth_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", "some-refresh-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    // =========================== Authorization Endpoint Tests ===========================

    @Test
    @DisplayName("Авторизация с несуществующим client_id возвращает ошибку")
    void authorize_nonExistentClient_returnsError() throws Exception {
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);

        mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "non-existent-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("error"));
    }

    @Test
    @DisplayName("Авторизация с неправильным redirect_uri возвращает ошибку")
    void authorize_invalidRedirectUri_returnsError() throws Exception {
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);

        mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://evil-site.com/callback")
                        .param("scope", "openid"))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("error"));
    }

    @Test
    @DisplayName("Авторизация без PKCE для публичного клиента возвращает ошибку")
    void authorize_missingPkceForPublicClient_returnsError() throws Exception {
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);

        mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("error=invalid_request")));
    }

    @Test
    @DisplayName("Авторизация с неподдерживаемым response_type возвращает ошибку")
    void authorize_unsupportedResponseType_returnsError() throws Exception {
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);

        mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "token")  // Implicit flow не поддерживается
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("error=unsupported_response_type")));
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

    @Test
    @DisplayName("Revoke с неправильными credentials возвращает ошибку")
    void revoke_wrongCredentials_returnsError() throws Exception {
        String wrongBasic = "Basic " + Base64.getEncoder()
                .encodeToString("wrong:secret".getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/oauth2/revoke")
                        .header("Authorization", wrongBasic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", "some-token"))
                .andExpect(status().isUnauthorized());
    }
}