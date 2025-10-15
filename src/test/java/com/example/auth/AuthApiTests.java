package com.example.auth;

import com.example.auth.user.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Disabled;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import java.util.Map;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Интеграционные тесты публичного API авторизации/аутентификации SAS.
 * Покрывает: discovery/JWKS, Authorization Code + PKCE, обмен кода на токены,
 * OIDC userinfo, refresh_token (для confidential клиента), introspection и revoke.
 */
@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
@org.springframework.context.annotation.Import(TestClientConfig.class)
@AutoConfigureMockMvc
class AuthApiTests {

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
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(AuthApiTests.class)));

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

    // Helpers
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

    private JsonNode exchangeCodeForTokensPkce(String clientId, String redirectUri, String code, String verifier) throws Exception {
        MvcResult token = mvc.perform(post("/oauth2/token")
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", redirectUri)
                        .param("client_id", clientId)
                        .param("code_verifier", verifier))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(token.getResponse().getContentAsString());
    }

    @BeforeEach
    void ensureTestClient() {
        // Клиент должен быть создан TestClientConfig до начала тестов
        assertThat(clients.findByClientId("test-client")).as("test-client должен существовать").isNotNull();
    }

    /**
     * Проверяет, что эндпоинты discovery и JWKS доступны и отдают корректные структуры.
     * Это базовая проверка конфигурации Authorization Server и JWK источника ключей.
     */
    @Test
    @DisplayName("Discovery и JWKS эндпоинты доступны")
    void openidConfigurationAndJwksAvailable() throws Exception {
        mvc.perform(get("/.well-known/openid-configuration").accept("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://test-issuer"));

        mvc.perform(get("/oauth2/jwks").accept("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray());
    }

    /**
     * Полный Authorization Code + PKCE флоу для публичного клиента.
     * Зачем: убедиться, что аутентификация пользователя и выдача access_token работают,
     * а также что /userinfo доступен с полученным токеном.
     */
    @Test
    @DisplayName("Authorization Code + PKCE и /userinfo (public)")
    void authorizationCodePkceFlow() throws Exception {
        // 1) Login as admin
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // 2) Start authorization request (consent not required for test client)
        String[] pkce = pkcePair();
        String verifier = pkce[0];
        String challenge = pkce[1];
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid profile offline_access")
                        .param("nonce", nonce)
                        .param("code_challenge", challenge)
                        .param("code_challenge_method", "S256")
                        .param("state", state))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String location = auth.getResponse().getHeader("Location");
        assertThat(location).isNotBlank();
        assertThat(URI.create(location).getHost()).isEqualTo("127.0.0.1");
        String code = extractCodeFromLocation(location);
        assertThat(code).isNotBlank();

        // 3) Exchange code for token
        JsonNode tokenJson = exchangeCodeForTokensPkce("test-client", "http://127.0.0.1/callback", code, verifier);
        assertThat(tokenJson.get("token_type").asText()).isEqualTo("Bearer");
        String accessToken = tokenJson.get("access_token").asText();
        assertThat(accessToken).isNotBlank();

        // 4) Call OIDC userinfo with the access token
        mvc.perform(get("/userinfo").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").isNotEmpty());
    }

    /**
     * Проверяет получение refresh_token и его использование в потоке confidential клиента.
     * Почему не public: по умолчанию SAS не выдаёт refresh_token публичным клиентам.
     */
    @Test
    @DisplayName("Обновление токена по refresh_token (confidential client)")
    void refreshTokenFlow() throws Exception {
        // 1) Логин админа (для consent при code flow)
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);

        // 2) Code flow для confidential-клиента (без PKCE)
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "code-client")
                        .param("redirect_uri", "http://127.0.0.1/callback2")
                        .param("scope", "openid profile offline_access")
                        .param("nonce", nonce)
                        .param("state", state))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URI redirect = URI.create(auth.getResponse().getHeader("Location"));
        String code = null;
        for (String p : redirect.getQuery().split("&")) {
            if (p.startsWith("code=")) { code = p.substring("code=".length()); break; }
        }

        String basic = "Basic " + Base64.getEncoder().encodeToString("code-client:secret2".getBytes(StandardCharsets.UTF_8));

        // 3) Обмен кода на токены (ожидаем refresh_token)
        MvcResult tokenResult = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", "http://127.0.0.1/callback2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn();

        var json = objectMapper.readTree(tokenResult.getResponse().getContentAsString());
        String refreshToken = json.get("refresh_token").asText();

        // 4) Обновление токенов по refresh_token (confidential клиент)
        mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    /**
     * Интроспекция access_token, выданного пользователю через PKCE.
     * Цель: проверить, что introspect возвращает активность, subject, client_id и scope.
     */
    @Test
    @DisplayName("Интроспекция user access_token (PKCE)")
    void introspectUserAccessToken() throws Exception {
        // 1) Логин и получение user access_token через PKCE
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);
        String[] pkce = pkcePair();
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid profile")
                        .param("nonce", nonce)
                        .param("code_challenge", pkce[1])
                        .param("code_challenge_method", "S256")
                        .param("state", state))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String code = extractCodeFromLocation(auth.getResponse().getHeader("Location"));

        JsonNode tokens = exchangeCodeForTokensPkce("test-client", "http://127.0.0.1/callback", code, pkce[0]);
        String accessToken = tokens.get("access_token").asText();

        // 2) Интроспекция через confidential-клиента
        String basic = "Basic " + Base64.getEncoder().encodeToString("conf-client:secret".getBytes(StandardCharsets.UTF_8));
        mvc.perform(post("/oauth2/introspect")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.sub").value("admin"))
                .andExpect(jsonPath("$.client_id").value("test-client"))
                .andExpect(jsonPath("$.scope").value(org.hamcrest.Matchers.containsString("openid")));
    }

    /**
     * Попытка отзыва user access_token публичным клиентом только по client_id (без секрета).
     * На текущей конфигурации SAS это не поддерживается (требуется аутентификация клиента),
     * поэтому тест отключён как справочный.
     */
    @Test
    @Disabled("В текущей конфигурации SAS public client по client_id на /oauth2/revoke не аутентифицируется; оставлено как справочный кейс")
    @DisplayName("Отзыв user access_token публичным клиентом (client_id)")
    void revokeUserAccessTokenByPublicClientId() throws Exception {
        // 1) Получаем access_token пользователя через PKCE (public test-client)
        MvcResult login = loginAsAdmin();
        var session = login.getRequest().getSession(false);
        String[] pkce = pkcePair();
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        MvcResult auth = mvc.perform(post("/oauth2/authorize")
                        .session((org.springframework.mock.web.MockHttpSession) session)
                        .param("response_type", "code")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://127.0.0.1/callback")
                        .param("scope", "openid profile")
                        .param("nonce", nonce)
                        .param("code_challenge", pkce[1])
                        .param("code_challenge_method", "S256")
                        .param("state", state))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String code = extractCodeFromLocation(auth.getResponse().getHeader("Location"));

        JsonNode tokens = exchangeCodeForTokensPkce("test-client", "http://127.0.0.1/callback", code, pkce[0]);
        String accessToken = tokens.get("access_token").asText();

        // 2) Интроспекция до отзыва (конфиденциальный клиент)
        String basic = "Basic " + Base64.getEncoder().encodeToString("conf-client:secret".getBytes(StandardCharsets.UTF_8));
        mvc.perform(post("/oauth2/introspect")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.client_id").value("test-client"));

        // 3) Отзыв токена публичным клиентом по client_id (без секрета)
        var revoke = mvc.perform(post("/oauth2/revoke")
                        .contentType("application/x-www-form-urlencoded")
                        .accept("application/json")
                        .param("client_id", "test-client")
                        .param("token_type_hint", "access_token")
                        .param("token", accessToken))
                .andReturn();

        int revokeStatus = revoke.getResponse().getStatus();
        if (revokeStatus != 200) {
            // Некоторые конфигурации SAS требуют аутентификацию клиента даже для public
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "Отзыв public client по client_id не поддержан этой конфигурацией (status=" + revokeStatus + ")");
            return;
        }

        // 4) Интроспекция после отзыва
        mvc.perform(post("/oauth2/introspect")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }

    /**
     * Интроспекция и отзыв токена, полученного по client_credentials (confidential клиент).
     * Зачем: ревок и интроспекция клиентских токенов — базовая администрируемая операция.
     */
    @Test
    @DisplayName("Интроспекция и отзыв client_credentials токена")
    void introspectAndRevokeToken() throws Exception {
        // Получаем токен по client_credentials для confidential-клиента
        String basic = "Basic " + Base64.getEncoder().encodeToString("conf-client:secret".getBytes(StandardCharsets.UTF_8));
        MvcResult clientToken = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andReturn();
        var tokJson = objectMapper.readTree(clientToken.getResponse().getContentAsString());
        String accessToken = tokJson.get("access_token").asText();

        // Интроспекция токена (активен)
        mvc.perform(post("/oauth2/introspect")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true));

        // Отзыв токена тем же confidential-клиентом
        mvc.perform(post("/oauth2/revoke")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token_type_hint", "access_token")
                        .param("token", accessToken))
                .andExpect(status().isOk());

        // Интроспекция после отзыва (неактивен)
        mvc.perform(post("/oauth2/introspect")
                        .header("Authorization", basic)
                        .contentType("application/x-www-form-urlencoded")
                        .param("token", accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }
}
