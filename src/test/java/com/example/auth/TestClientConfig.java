package com.example.auth;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@TestConfiguration
public class TestClientConfig {

    @Bean
    ApplicationRunner testClientInitializer(RegisteredClientRepository clients) {
        return args -> {
            if (clients.findByClientId("test-client") == null) {
                RegisteredClient rc = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("test-client")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://127.0.0.1/callback")
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .scope("offline_access")
                        .clientSettings(ClientSettings.builder()
                                .requireProofKey(true)
                                .requireAuthorizationConsent(false)
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(15))
                                .reuseRefreshTokens(false)
                                .refreshTokenTimeToLive(Duration.ofHours(8))
                                .build())
                        .build();
                clients.save(rc);
            }

            if (clients.findByClientId("conf-client") == null) {
                RegisteredClient conf = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("conf-client")
                        .clientSecret("{noop}secret")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        // introspect/revoke допускают аутентифицированного клиента; грант не обязателен
                        .build();
                clients.save(conf);
            }

            if (clients.findByClientId("code-client") == null) {
                RegisteredClient code = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("code-client")
                        .clientSecret("{noop}secret2")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://127.0.0.1/callback2")
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .scope("offline_access")
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(15))
                                .reuseRefreshTokens(false)
                                .refreshTokenTimeToLive(Duration.ofHours(8))
                                .build())
                        .build();
                clients.save(code);
            }
        };
    }
}
