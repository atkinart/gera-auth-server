package ru.gera.auth.oauth.mongo;

import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public class MongoAuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final StoredAuthorizationConsentRepository repository;

    public MongoAuthorizationConsentService(StoredAuthorizationConsentRepository repository) {
        this.repository = repository;
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        String key = key(authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
        String payload = SerializedObjectCodec.serialize(authorizationConsent);
        repository.save(new StoredAuthorizationConsent(
                key,
                authorizationConsent.getRegisteredClientId(),
                authorizationConsent.getPrincipalName(),
                payload
        ));
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        repository.deleteById(key(authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName()));
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        return repository.findById(key(registeredClientId, principalName))
                .map(StoredAuthorizationConsent::getPayload)
                .map(payload -> SerializedObjectCodec.deserialize(payload, OAuth2AuthorizationConsent.class))
                .orElse(null);
    }

    private String key(String registeredClientId, String principalName) {
        return registeredClientId + ":" + principalName;
    }
}
