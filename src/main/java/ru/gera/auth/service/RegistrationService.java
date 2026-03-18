package ru.gera.auth.service;

import ru.gera.auth.api.RegistrationRequest;
import ru.gera.auth.api.RegistrationResponse;
import ru.gera.auth.user.UserRepository;
import jakarta.validation.Valid;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashSet;
import java.util.Set;

@Service
public class RegistrationService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository users;

    public RegistrationService(PasswordEncoder passwordEncoder,
                               UserRepository users) {
        this.passwordEncoder = passwordEncoder;
        this.users = users;
    }

    public RegistrationResponse register(@Valid RegistrationRequest req) {
        if (users.existsById(req.getUsername())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "username already exists");
        }
        if (users.existsByEmail(req.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "email already exists");
        }

        var user = new ru.gera.auth.user.UserEntity();
        user.setUsername(req.getUsername());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setEnabled(true);
        user.setEmail(req.getEmail());
        user.setRoles(new LinkedHashSet<>(Set.of("ROLE_USER")));

        try {
            users.save(user);
        } catch (DuplicateKeyException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "username/email already exists");
        }

        return new RegistrationResponse(req.getUsername(), req.getEmail());
    }
}
