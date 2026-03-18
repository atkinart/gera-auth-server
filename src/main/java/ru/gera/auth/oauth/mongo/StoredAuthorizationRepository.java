package ru.gera.auth.oauth.mongo;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface StoredAuthorizationRepository extends MongoRepository<StoredAuthorization, String> {
    Optional<StoredAuthorization> findByState(String state);

    Optional<StoredAuthorization> findByAuthorizationCodeValue(String authorizationCodeValue);

    Optional<StoredAuthorization> findByAccessTokenValue(String accessTokenValue);

    Optional<StoredAuthorization> findByRefreshTokenValue(String refreshTokenValue);

    Optional<StoredAuthorization> findByOidcIdTokenValue(String oidcIdTokenValue);

    Optional<StoredAuthorization> findByUserCodeValue(String userCodeValue);

    Optional<StoredAuthorization> findByDeviceCodeValue(String deviceCodeValue);
}
