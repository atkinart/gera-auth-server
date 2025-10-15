package com.example.auth;

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
    }
}

