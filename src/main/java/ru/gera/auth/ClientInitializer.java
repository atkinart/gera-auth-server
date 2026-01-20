package ru.gera.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

@Component
public class ClientInitializer implements CommandLineRunner {

    private final RegisteredClientRepository clients;

    public ClientInitializer(RegisteredClientRepository clients) {
        this.clients = clients;
    }

    @Value("${app.spa.client-id:spa}") String spaClientId;
    @Value("${app.spa.redirect-uri:http://localhost:5173/callback}") String spaRedirect;
    @Value("${app.spa.post-logout-uri:http://localhost:5173/}") String spaPostLogout;

    @Value("${app.e2e.enabled:false}") boolean e2eEnabled;
    @Value("${app.e2e.client-id:e2e-client}") String e2eClientId;
    @Value("${app.e2e.client-secret:e2e-secret}") String e2eClientSecret;
    @Value("${app.e2e.scope:api.read}") String e2eScope;

    @Override public void run(String... args) {
        if (clients.findByClientId(spaClientId) == null) {
            var rc = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(spaClientId)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(spaRedirect)
                    .postLogoutRedirectUri(spaPostLogout)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("api.read")
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(true)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                            .build())
                    .build();
            clients.save(rc);
        }

        if (e2eEnabled && clients.findByClientId(e2eClientId) == null) {
            var e2e = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(e2eClientId)
                    .clientSecret("{noop}" + e2eClientSecret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope(e2eScope)
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                            .build())
                    .build();
            clients.save(e2e);
        }
    }
}
