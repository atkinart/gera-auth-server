package ru.gera.auth.oauth.mongo;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface StoredRegisteredClientRepository extends MongoRepository<StoredRegisteredClient, String> {
    Optional<StoredRegisteredClient> findByClientId(String clientId);
}
