package ru.gera.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.MongoDBContainer;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Негативные тесты безопасности OAuth2/OIDC флоуов.
 * Проверяют защиту от атак: code replay, PKCE bypass, client impersonation,
 * неправильные redirect_uri, недействительные токены и другие уязвимости.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer",
        "logging.level.org.springframework.security=WARN"
})
@org.springframework.context.annotation.Import(TestClientConfig.class)
@AutoConfigureMockMvc
class OAuth2SecurityTests {

    @Container
    @ServiceConnection
    static MongoDBContainer mongo = new MongoDBContainer(
            DockerImageName.parse("mongo:7"))
            .withStartupTimeout(java.time.Duration.ofMinutes(5))
            .waitingFor(org.testcontainers.containers.wait.strategy.Wait.forListeningPort())
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(OAuth2SecurityTests.class)));

    @Autowired MockMvc mvc;
    @Autowired RegisteredClientRepository clients;
    @Autowired ObjectMapper objectMapper;

    // Helper methods
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
        return mvc.perform(formLogin().user("admin").password("Admin123!"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
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

    private record PkceAuthCode(String code, String verifier) {}

    private PkceAuthCode obtainAuthorizationCodeForTestClient() throws Exception {
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);

        String verifier = codeVerifier();
        String challenge = s256(verifier);
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid profile")
                        .param("nonce", nonce)
                        .param("code_challenge", challenge)
                        .param("code_challenge_method", "S256")
                        .param("state", state))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String code = extractCodeFromLocation(auth.getResponse().getHeader("Location"));
        return new PkceAuthCode(code, verifier);
    }

    // ============ НЕГАТИВНЫЕ ТЕСТЫ =============

    @Test
    @DisplayName("Обмен недействительного authorization code возвращает ошибку")
    void exchangeToken_invalidAuthorizationCode_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                .contentType("application/x-www-form-urlencoded")
                .param("grant_type", "authorization_code")
                .param("code", "invalid-code-12345")
                .param("client_id", "test-client")
                .param("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                .param("redirect_uri", "http://127.0.0.1/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Обмен токена с неправильным client_id возвращает ошибку")
    void exchangeToken_wrongClientId_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                .contentType("application/x-www-form-urlencoded")
                .param("grant_type", "authorization_code")
                .param("code", "valid-code")
                .param("client_id", "malicious-client-id")
                .param("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                .param("redirect_uri", "http://127.0.0.1/callback"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    @DisplayName("Обмен токена без code_verifier для PKCE клиента возвращает ошибку")
    void exchangeToken_missingCodeVerifier_returnsError() throws Exception {
        PkceAuthCode authCode = obtainAuthorizationCodeForTestClient();
        mvc.perform(post("/oauth2/token")
                .contentType("application/x-www-form-urlencoded")
                .accept(MediaType.APPLICATION_JSON)
                .param("grant_type", "authorization_code")
                .param("code", authCode.code())
                .param("client_id", "test-client")
                .param("redirect_uri", "http://127.0.0.1/callback"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("Обмен токена с неправильным code_verifier возвращает ошибку")
    void exchangeToken_wrongCodeVerifier_returnsError() throws Exception {
        PkceAuthCode authCode = obtainAuthorizationCodeForTestClient();
        mvc.perform(post("/oauth2/token")
                .contentType("application/x-www-form-urlencoded")
                .param("grant_type", "authorization_code")
                .param("code", authCode.code())
                .param("client_id", "test-client")
                .param("code_verifier", "wrong-verifier-value-attack")
                .param("redirect_uri", "http://127.0.0.1/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Обмен токена с неправильным redirect_uri возвращает ошибку")
    void exchangeToken_wrongRedirectUri_returnsError() throws Exception {
        PkceAuthCode authCode = obtainAuthorizationCodeForTestClient();
        mvc.perform(post("/oauth2/token")
                .contentType("application/x-www-form-urlencoded")
                .param("grant_type", "authorization_code")
                .param("code", authCode.code())
                .param("client_id", "test-client")
                .param("code_verifier", authCode.verifier())
                .param("redirect_uri", "http://malicious-site.com/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Повторное использование authorization code (replay attack) блокируется")
    void codeReplayAttack_blocked() throws Exception {
        // 1) Логин и получение валидного кода
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);

        String verifier = codeVerifier();
        String challenge = s256(verifier);
        String state = UUID.randomUUID().toString();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                .session((org.springframework.mock.web.MockHttpSession) session)
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("redirect_uri", "http://127.0.0.1/callback")
                .param("scope", "openid profile")
                .param("code_challenge", challenge)
                .param("code_challenge_method", "S256")
                .param("state", state))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String code = extractCodeFromLocation(auth.getResponse().getHeader("Location"));

        // 2) Первое использование кода (успешно)
        mvc.perform(post("/oauth2/token")
                .contentType("application/x-www-form-urlencoded")
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("client_id", "test-client")
                .param("code_verifier", verifier)
                .param("redirect_uri", "http://127.0.0.1/callback"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());

        // 3) Повторное использование того же кода (replay attack)
        mvc.perform(post("/oauth2/token")
                .contentType("application/x-www-form-urlencoded")
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("client_id", "test-client")
                .param("code_verifier", verifier)
                .param("redirect_uri", "http://127.0.0.1/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Запрос авторизации без обязательных параметров возвращает ошибку")
    void authorize_missingRequiredParams_returnsError() throws Exception {
        mvc.perform(get("/oauth2/authorize")
                .param("response_type", "code"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("Запрос авторизации с неподдерживаемым response_type возвращает ошибку")
    void authorize_unsupportedResponseType_returnsError() throws Exception {
        mvc.perform(get("/oauth2/authorize")
                .param("response_type", "token") // implicit flow не поддерживается
                .param("client_id", "test-client")
                .param("redirect_uri", "http://127.0.0.1/callback"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("Запрос авторизации с неразрешенным redirect_uri возвращает ошибку")
    void authorize_unauthorizedRedirectUri_returnsError() throws Exception {
        mvc.perform(get("/oauth2/authorize")
                .param("response_type", "code")
                .param("client_id", "test-client")
                .param("redirect_uri", "http://evil-site.com/steal-codes"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("Аутентификация с неправильными клиентскими данными возвращает ошибку")
    void tokenRequest_invalidClientCredentials_returnsError() throws Exception {
        String wrongBasic = "Basic " + Base64.getEncoder()
                .encodeToString("conf-client:wrong-secret".getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/oauth2/token")
                .header("Authorization", wrongBasic)
                .contentType("application/x-www-form-urlencoded")
                .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    @DisplayName("Интроспекция с недействительным токеном возвращает неактивный статус")
    void introspectToken_invalidToken_returnsInactive() throws Exception {
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("conf-client:secret".getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/oauth2/introspect")
                .header("Authorization", basic)
                .contentType("application/x-www-form-urlencoded")
                .param("token", "invalid-token-value-123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }

    @Test
    @DisplayName("Интроспекция без аутентификации клиента возвращает ошибку")
    void introspectToken_noClientAuth_returnsError() throws Exception {
        mvc.perform(post("/oauth2/introspect")
                .contentType("application/x-www-form-urlencoded")
                .accept(MediaType.APPLICATION_JSON)
                .param("token", "some-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Отзыв токена без аутентификации клиента возвращает ошибку")
    void revokeToken_noClientAuth_returnsError() throws Exception {
        mvc.perform(post("/oauth2/revoke")
                .contentType("application/x-www-form-urlencoded")
                .accept(MediaType.APPLICATION_JSON)
                .param("token", "some-token")
                .param("token_type_hint", "access_token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Использование недействительного refresh_token возвращает ошибку")
    void refreshToken_invalidToken_returnsError() throws Exception {
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("code-client:secret2".getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/oauth2/token")
                .header("Authorization", basic)
                .contentType("application/x-www-form-urlencoded")
                .param("grant_type", "refresh_token")
                .param("refresh_token", "invalid-refresh-token"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Доступ к /userinfo без токена возвращает ошибку")
    void userinfo_noToken_returnsError() throws Exception {
        mvc.perform(get("/userinfo").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Доступ к /userinfo с недействительным токеном возвращает ошибку")
    void userinfo_invalidToken_returnsError() throws Exception {
        mvc.perform(get("/userinfo")
                .header("Authorization", "Bearer invalid-token-value"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Запрос с неподдерживаемым grant_type возвращает ошибку")
    void tokenRequest_unsupportedGrantType_returnsError() throws Exception {
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("conf-client:secret".getBytes(StandardCharsets.UTF_8));
        mvc.perform(post("/oauth2/token")
                .header("Authorization", basic)
                .contentType("application/x-www-form-urlencoded")
                .accept(MediaType.APPLICATION_JSON)
                .param("grant_type", "password") // Resource Owner Password не поддерживается
                .param("username", "admin")
                .param("password", "admin")
                .param("client_id", "conf-client"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    @DisplayName("Запрос токена без grant_type возвращает ошибку")
    void tokenRequest_missingGrantType_returnsError() throws Exception {
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("conf-client:secret".getBytes(StandardCharsets.UTF_8));
        mvc.perform(post("/oauth2/token")
                .header("Authorization", basic)
                .contentType("application/x-www-form-urlencoded")
                .accept(MediaType.APPLICATION_JSON)
                .param("client_id", "conf-client"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    @DisplayName("PKCE без code_challenge в запросе авторизации работает для публичного клиента")
    void authorize_missingCodeChallenge_allowedForPublicClient() throws Exception {
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);

        // test-client требует PKCE: запрос без code_challenge должен завершаться ошибкой (через redirect с error=...)
        MvcResult res = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = res.getResponse().getHeader("Location");
        assertThat(location).contains("error=");
        assertThat(location).doesNotContain("code=");
    }

    @Test
    @DisplayName("Межклиентская атака: попытка использования чужого кода возвращает ошибку")
    void crossClientCodeAttack_blocked() throws Exception {
        // Получаем реальный code для public test-client и пытаемся обменять его другим клиентом (code-client).
        PkceAuthCode authCode = obtainAuthorizationCodeForTestClient();
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString("code-client:secret2".getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", authCode.code())
                        .param("redirect_uri", "http://127.0.0.1/callback2"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }
}
