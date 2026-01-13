package ru.gera.auth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * OAuth2 негативные тесты с использованием H2 in-memory базы данных.
 * Эти тесты проверяют безопасность OAuth2 потоков.
 */
@SpringBootTest(
    classes = {OAuth2NegativeH2Tests.TestConfig.class},
    properties = {
        "spring.datasource.url=jdbc:h2:mem:testdb",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.liquibase.enabled=false",
        "spring.main.allow-bean-definition-overriding=true",
        "app.issuer=http://test-issuer",
        "logging.level.org.springframework.security=DEBUG"
    }
)
@AutoConfigureMockMvc
class OAuth2NegativeH2Tests {

    @Autowired MockMvc mvc;
    @Autowired PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("Обмен недействительного authorization code возвращает ошибку")
    void exchangeToken_invalidAuthorizationCode_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("code", "invalid-code-12345")
                .param("client_id", "test-client")
                .param("code_verifier", "test-verifier")
                .param("redirect_uri", "http://localhost:3000/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Обмен токена с неправильным client_id возвращает ошибку")
    void exchangeToken_wrongClientId_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("code", "valid-code")
                .param("client_id", "wrong-client-id")
                .param("code_verifier", "test-verifier")
                .param("redirect_uri", "http://localhost:3000/callback"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    @DisplayName("Обмен токена без code_verifier для PKCE клиента возвращает ошибку")
    void exchangeToken_missingCodeVerifier_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("code", "valid-code")
                .param("client_id", "test-client")
                .param("redirect_uri", "http://localhost:3000/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    @DisplayName("Обмен токена с неправильным redirect_uri возвращает ошибку")
    void exchangeToken_wrongRedirectUri_returnsError() throws Exception {
        mvc.perform(post("/oauth2/token")
                .param("grant_type", "authorization_code")
                .param("code", "valid-code")
                .param("client_id", "test-client")
                .param("code_verifier", "test-verifier")
                .param("redirect_uri", "http://malicious-site.com/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Запрос авторизации без обязательных параметров возвращает ошибку")
    void authorize_missingRequiredParams_returnsError() throws Exception {
        mvc.perform(post("/oauth2/authorize")
                .param("response_type", "code"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("Запрос авторизации с неподдерживаемым response_type возвращает ошибку")
    void authorize_unsupportedResponseType_returnsError() throws Exception {
        mvc.perform(post("/oauth2/authorize")
                .param("response_type", "token")
                .param("client_id", "test-client")
                .param("redirect_uri", "http://localhost:3000/callback"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("Проверка токена с недействительным токеном возвращает ошибку")
    void introspectToken_invalidToken_returnsInactive() throws Exception {
        mvc.perform(post("/oauth2/introspect")
                .param("token", "invalid-token-value")
                .param("client_id", "test-client"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }

    @Configuration
    @EnableWebSecurity
    static class TestConfig {

        @Bean
        SecurityFilterChain asFilterChain(HttpSecurity http) throws Exception {
            OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

            http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, config -> config.oidc(configurer -> {}))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());

            return http.build();
        }

        @Bean
        @Primary
        SecurityFilterChain appFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests(auth -> auth
                    .requestMatchers("/oauth2/**", "/login", "/error").permitAll()
                    .anyRequest().authenticated())
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.permitAll());
            return http.build();
        }

        @Bean
        @Primary
        RegisteredClientRepository registeredClientRepository() {
            RegisteredClient testClient = RegisteredClient.withId("test-client-id")
                    .clientId("test-client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:3000/callback")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("api.read")
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                            .refreshTokenTimeToLive(Duration.ofDays(30))
                            .build())
                    .build();

            return new InMemoryRegisteredClientRepository(testClient);
        }

        @Bean
        @Primary
        UserDetailsManager userDetailsManager(PasswordEncoder passwordEncoder) {
            var user = User.withUsername("testuser")
                    .password(passwordEncoder.encode("password"))
                    .authorities("ROLE_USER")
                    .build();
            return new InMemoryUserDetailsManager(user);
        }

        @Bean
        AuthorizationServerSettings authorizationServerSettings() {
            return AuthorizationServerSettings.builder()
                    .issuer("http://test-issuer")
                    .build();
        }

        @Bean
        JWKSource<SecurityContext> jwkSource() {
            RSAKey rsa = generateRsa();
            JWKSet jwkSet = new JWKSet(rsa);
            return (selector, ctx) -> selector.select(jwkSet);
        }

        private static RSAKey generateRsa() {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
                RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
                return new RSAKey.Builder(pub)
                        .privateKey(priv)
                        .keyID(UUID.randomUUID().toString())
                        .build();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}