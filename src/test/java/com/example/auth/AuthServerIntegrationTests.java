package com.example.auth;

import com.example.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.containers.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
class AuthServerIntegrationTests {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
            DockerImageName.parse("postgres:16"));

    @Autowired
    UserRepository users;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    RegisteredClientRepository clients;

    @Test
    void adminUserIsInitialized() {
        var admin = users.findById("admin");
        assertThat(admin).isPresent();
        assertThat(admin.get().isEnabled()).isTrue();
        // Password is encoded (bcrypt starts with $2)
        assertThat(admin.get().getPassword()).startsWith("$2");
    }

    @Test
    void spaClientIsRegistered() {
        assertThat(clients.findByClientId("spa")).isNotNull();
    }
}

