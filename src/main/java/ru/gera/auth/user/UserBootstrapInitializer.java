package ru.gera.auth.user;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class UserBootstrapInitializer implements CommandLineRunner {

    private final BootstrapUsersProperties bootstrapUsers;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository users;

    public UserBootstrapInitializer(BootstrapUsersProperties bootstrapUsers,
                                   PasswordEncoder passwordEncoder,
                                   UserRepository users) {
        this.bootstrapUsers = bootstrapUsers;
        this.passwordEncoder = passwordEncoder;
        this.users = users;
    }

    @Override
    public void run(String... args) {
        for (BootstrapUsersProperties.BootstrapUser config : bootstrapUsers.getUsers()) {
            if (config.getUsername() == null || config.getUsername().isBlank()) {
                continue;
            }

            if (users.existsById(config.getUsername())) {
                continue;
            }

            UserEntity user = new UserEntity();
            user.setUsername(config.getUsername().trim());
            user.setPassword(passwordEncoder.encode(defaultString(config.getPassword(), "ChangeMe123!")));
            user.setEnabled(true);
            user.setEmail(defaultString(config.getEmail(), config.getUsername().trim() + "@example.com"));
            user.setRoles(parseRoles(config.getRoles()));
            users.save(user);
        }
    }

    private String defaultString(String value, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value.trim();
    }

    private Set<String> parseRoles(String rolesCsv) {
        if (rolesCsv == null || rolesCsv.isBlank()) {
            return new LinkedHashSet<>(Set.of("ROLE_USER"));
        }

        Set<String> roles = Arrays.stream(rolesCsv.split(","))
                .map(String::trim)
                .filter(role -> !role.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        if (roles.isEmpty()) {
            roles.add("ROLE_USER");
        }
        return roles;
    }
}
