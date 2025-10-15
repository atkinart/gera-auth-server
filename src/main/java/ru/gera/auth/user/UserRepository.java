package ru.gera.auth.user;

import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<UserEntity, String> {
    boolean existsByEmail(String email);
}
