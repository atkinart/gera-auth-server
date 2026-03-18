package ru.gera.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import ru.gera.auth.user.UserRepository;

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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Сквозные интеграционные тесты, которые реально прогоняют Auth Server:
 * регистрация → логин пользователем → OAuth2 Authorization Code + PKCE → token → userinfo.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer",
        "logging.level.org.springframework.security=WARN"
})
@org.springframework.context.annotation.Import(TestClientConfig.class)
@AutoConfigureMockMvc
class OAuth2IntegrationTests {

    @Container
    @ServiceConnection
    static MongoDBContainer mongo = new MongoDBContainer(DockerImageName.parse("mongo:7"))
            .withStartupTimeout(java.time.Duration.ofMinutes(5))
            .waitingFor(org.testcontainers.containers.wait.strategy.Wait.forListeningPort())
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(OAuth2IntegrationTests.class)));

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository users;

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

    private static String extractCodeFromLocation(String location) {
        URI redirect = URI.create(location);
        String query = redirect.getQuery();
        for (String p : query.split("&")) {
            if (p.startsWith("code=")) return p.substring("code=".length());
        }
        throw new IllegalStateException("No code in redirect: " + location);
    }

    private JsonNode exchangeCodeForTokensPkce(String clientId, String redirectUri, String code, String verifier) throws Exception {
        MvcResult token = mvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("client_id", clientId)
                        .param("redirect_uri", redirectUri)
                        .param("code", code)
                        .param("code_verifier", verifier))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andReturn();

        return objectMapper.readTree(token.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("Регистрация создаёт пользователя с зашифрованным паролем")
    void registration_createsUserWithEncodedPassword() throws Exception {
        String unique = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String username = "u_" + unique;
        String rawPassword = "Password1!";
        String email = "u_" + unique + "@example.com";

        var registrationRequest = Map.of(
                "username", username,
                "password", rawPassword,
                "email", email
        );

        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(email));

        var user = users.findById(username).orElseThrow();
        assertThat(passwordEncoder.matches(rawPassword, user.getPassword())).isTrue();
        assertThat(user.getEmail()).isEqualTo(email);
    }

    @Test
    @DisplayName("Сквозной флоу: регистрация → логин → auth code + PKCE → token → userinfo")
    void registrationToOauth2PkceFlow_success() throws Exception {
        String unique = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String username = "pkce_" + unique;
        String rawPassword = "Password1!";
        String email = "pkce_" + unique + "@example.com";

        // 1) Регистрация
        var registrationRequest = Map.of(
                "username", username,
                "password", rawPassword,
                "email", email
        );
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest)))
                .andExpect(status().isCreated());

        // 2) Логин этим пользователем
        MvcResult login = mvc.perform(formLogin().user(username).password(rawPassword))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        var session = login.getRequest().getSession(false);

        // 3) /oauth2/authorize с PKCE (consent отключён для test-client)
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

        String location = auth.getResponse().getHeader("Location");
        assertThat(location).isNotBlank();
        String code = extractCodeFromLocation(location);

        // 4) /oauth2/token (public client)
        JsonNode tokens = exchangeCodeForTokensPkce("test-client", "http://127.0.0.1/callback", code, verifier);
        String accessToken = tokens.get("access_token").asText();

        // 5) /userinfo
        mvc.perform(get("/userinfo")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(username));
    }
}
