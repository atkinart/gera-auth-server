package com.example.auth;

import com.example.auth.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Тесты API регистрации пользователей.
 */
@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
@AutoConfigureMockMvc
class RegistrationApiTests {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
            DockerImageName.parse("postgres:16"))
            .withDatabaseName("test")
            .withUsername("test")
            .withPassword("test")
            .withEnv("PGDATA", "/var/lib/postgresql/data")
            .withTmpFs(Map.of("/var/lib/postgresql/data", "rw,size=256m"))
            .withStartupTimeout(java.time.Duration.ofMinutes(5))
            .waitingFor(org.testcontainers.containers.wait.strategy.Wait.forListeningPort());

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository users;
    @Autowired UserDetailsManager userDetailsManager;

    private String json(Object o) throws Exception { return objectMapper.writeValueAsString(o); }

    @Test
    @DisplayName("Регистрация нового пользователя возвращает 201 и создаёт запись")
    void registerUser_success() throws Exception {
        var req = Map.of(
                "username", "alice",
                "password", "Password1!",
                "email", "alice@example.com"
        );

        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(req)))
                .andExpect(status().isCreated());

        assertThat(users.findById("alice")).isPresent();
        // Пользователь может аутентифицироваться (пароль зашифрован, проверяем наличие в менеджере)
        assertThat(userDetailsManager.userExists("alice")).isTrue();
    }

    @Test
    @DisplayName("Дублирование username возвращает 409")
    void registerUser_duplicateUsername_conflict() throws Exception {
        var req = Map.of(
                "username", "bob",
                "password", "Password1!",
                "email", "bob@example.com"
        );
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(json(req)))
                .andExpect(status().isCreated());

        var dup = Map.of(
                "username", "bob",
                "password", "Password2!",
                "email", "bob2@example.com"
        );
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(json(dup)))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("Дублирование email возвращает 409")
    void registerUser_duplicateEmail_conflict() throws Exception {
        var first = Map.of(
                "username", "charlie",
                "password", "Password1!",
                "email", "charlie@example.com"
        );
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(json(first)))
                .andExpect(status().isCreated());

        var dupEmail = Map.of(
                "username", "charlie2",
                "password", "Password2!",
                "email", "charlie@example.com"
        );
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(json(dupEmail)))
                .andExpect(status().isConflict());
    }
}

