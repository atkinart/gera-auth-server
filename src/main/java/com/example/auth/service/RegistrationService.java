package com.example.auth.service;

import com.example.auth.api.RegistrationRequest;
import com.example.auth.api.RegistrationResponse;
import com.example.auth.user.UserRepository;
import jakarta.validation.Valid;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class RegistrationService {

    private final UserDetailsManager userDetailsManager;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository users;

    public RegistrationService(UserDetailsManager userDetailsManager,
                               PasswordEncoder passwordEncoder,
                               UserRepository users) {
        this.userDetailsManager = userDetailsManager;
        this.passwordEncoder = passwordEncoder;
        this.users = users;
    }

    @Transactional
    public RegistrationResponse register(@Valid RegistrationRequest req) {
        if (userDetailsManager.userExists(req.getUsername())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "username already exists");
        }
        if (users.existsByEmail(req.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "email already exists");
        }

        UserDetails user = User.withUsername(req.getUsername())
                .password(passwordEncoder.encode(req.getPassword()))
                .roles("USER")
                .build();
        try {
            userDetailsManager.createUser(user);
        } catch (DuplicateKeyException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "username already exists");
        }

        users.findById(req.getUsername()).ifPresent(u -> {
            u.setEmail(req.getEmail());
            users.save(u);
        });

        return new RegistrationResponse(req.getUsername(), req.getEmail());
    }
}

