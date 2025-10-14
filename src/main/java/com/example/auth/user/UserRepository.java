package com.example.auth.user;

import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<UserEntity, String> {
}

