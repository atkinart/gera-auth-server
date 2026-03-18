package ru.gera.auth.user;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<UserEntity, String> {
    boolean existsByEmail(String email);

    Optional<UserEntity> findByUsername(String username);
}
