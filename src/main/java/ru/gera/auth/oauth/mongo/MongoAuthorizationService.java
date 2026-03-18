package ru.gera.auth.oauth.mongo;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public class MongoAuthorizationService implements OAuth2AuthorizationService {

    private final StoredAuthorizationRepository repository;

    public MongoAuthorizationService(StoredAuthorizationRepository repository) {
        this.repository = repository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");

        StoredAuthorization stored = new StoredAuthorization();
        stored.setId(authorization.getId());
        stored.setPayload(SerializedObjectCodec.serialize(authorization));
        stored.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));
        stored.setAuthorizationCodeValue(tokenValue(authorization.getToken(OAuth2AuthorizationCode.class)));
        stored.setAccessTokenValue(tokenValue(authorization.getAccessToken()));
        stored.setRefreshTokenValue(tokenValue(authorization.getRefreshToken()));
        stored.setOidcIdTokenValue(tokenValue(authorization.getToken(OidcIdToken.class)));
        stored.setUserCodeValue(tokenValue(authorization.getToken(OAuth2UserCode.class)));
        stored.setDeviceCodeValue(tokenValue(authorization.getToken(OAuth2DeviceCode.class)));

        repository.save(stored);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        repository.deleteById(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return repository.findById(id)
                .map(StoredAuthorization::getPayload)
                .map(payload -> SerializedObjectCodec.deserialize(payload, OAuth2Authorization.class))
                .orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (token == null || token.isBlank()) {
            return null;
        }

        if (tokenType == null) {
            return firstByAnyToken(token);
        }

        String type = tokenType.getValue();
        if (OAuth2ParameterNames.STATE.equals(type)) {
            return decode(repository.findByState(token).orElse(null));
        }
        if (OAuth2ParameterNames.CODE.equals(type)) {
            return decode(repository.findByAuthorizationCodeValue(token).orElse(null));
        }
        if (OAuth2TokenType.ACCESS_TOKEN.getValue().equals(type)) {
            return decode(repository.findByAccessTokenValue(token).orElse(null));
        }
        if (OAuth2TokenType.REFRESH_TOKEN.getValue().equals(type)) {
            return decode(repository.findByRefreshTokenValue(token).orElse(null));
        }
        if (OidcParameterNames.ID_TOKEN.equals(type)) {
            return decode(repository.findByOidcIdTokenValue(token).orElse(null));
        }
        if (OAuth2ParameterNames.USER_CODE.equals(type)) {
            return decode(repository.findByUserCodeValue(token).orElse(null));
        }
        if (OAuth2ParameterNames.DEVICE_CODE.equals(type)) {
            return decode(repository.findByDeviceCodeValue(token).orElse(null));
        }

        return null;
    }

    private OAuth2Authorization firstByAnyToken(String token) {
        OAuth2Authorization authorization = decode(repository.findByState(token).orElse(null));
        if (authorization != null) {
            return authorization;
        }

        authorization = decode(repository.findByAuthorizationCodeValue(token).orElse(null));
        if (authorization != null) {
            return authorization;
        }

        authorization = decode(repository.findByAccessTokenValue(token).orElse(null));
        if (authorization != null) {
            return authorization;
        }

        authorization = decode(repository.findByRefreshTokenValue(token).orElse(null));
        if (authorization != null) {
            return authorization;
        }

        authorization = decode(repository.findByOidcIdTokenValue(token).orElse(null));
        if (authorization != null) {
            return authorization;
        }

        authorization = decode(repository.findByUserCodeValue(token).orElse(null));
        if (authorization != null) {
            return authorization;
        }

        return decode(repository.findByDeviceCodeValue(token).orElse(null));
    }

    private OAuth2Authorization decode(StoredAuthorization storedAuthorization) {
        if (storedAuthorization == null || storedAuthorization.getPayload() == null) {
            return null;
        }
        return SerializedObjectCodec.deserialize(storedAuthorization.getPayload(), OAuth2Authorization.class);
    }

    private <T extends OAuth2Token> String tokenValue(OAuth2Authorization.Token<T> token) {
        if (token == null || token.getToken() == null) {
            return null;
        }
        return token.getToken().getTokenValue();
    }
}
