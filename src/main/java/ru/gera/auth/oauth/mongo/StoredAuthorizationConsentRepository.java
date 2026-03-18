package ru.gera.auth.oauth.mongo;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface StoredAuthorizationConsentRepository extends MongoRepository<StoredAuthorizationConsent, String> {
}
