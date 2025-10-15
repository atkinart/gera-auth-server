package ru.gera.auth;

import ru.gera.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import java.util.Map;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.containers.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Базовые интеграционные проверки инициализации приложения:
 * - наличие пользователя admin, созданного миграциями Liquibase,
 * - наличие преднастроенного SPA-клиента, создаваемого при старте.
 */
@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
class AuthServerIntegrationTests {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
            DockerImageName.parse("postgres:16"))
            .withDatabaseName("test")
            .withUsername("test")
            .withPassword("test")
            .withEnv("PGDATA", "/var/lib/postgresql/data")
            .withTmpFs(Map.of(
                    "/var/lib/postgresql/data", "rw,size=256m"
            ))
            .withStartupTimeout(java.time.Duration.ofMinutes(5))
            .waitingFor(org.testcontainers.containers.wait.strategy.Wait.forListeningPort())
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(AuthServerIntegrationTests.class)));

    @Autowired
    UserRepository users;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    RegisteredClientRepository clients;

    /**
     * Проверяет, что пользователь admin создан и пароль соответствует настройкам энкодера.
     * Это подтверждает корректную работу Liquibase и схемы security таблиц.
     */
    @Test
    @DisplayName("Инициализация пользователя admin (Liquibase)")
    void adminUserIsInitialized() {
        var admin = users.findById("admin");
        assertThat(admin).isPresent();
        assertThat(admin.get().isEnabled()).isTrue();
        // Password matches encoder configuration
        assertThat(passwordEncoder.matches("admin", admin.get().getPassword())).isTrue();
    }

    /**
     * Проверяет, что SPA-клиент зарегистрирован при старте (через ClientInitializer).
     * Это гарантирует наличие клиента для PKCE флоу в UI.
     */
    @Test
    @DisplayName("Регистрация SPA‑клиента при старте (ClientInitializer)")
    void spaClientIsRegistered() {
        assertThat(clients.findByClientId("spa")).isNotNull();
    }
}
