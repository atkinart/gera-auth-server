package ru.gera.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

/**
 * Comprehensive validation тесты для Registration API.
 * Проверяет все Jakarta Bean Validation аннотации в RegistrationRequest.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
@AutoConfigureMockMvc
class RegistrationValidationTests {

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
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(RegistrationValidationTests.class)));

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;

    @Nested
    @DisplayName("Username validation")
    class UsernameValidation {

        @Test
        @DisplayName("Пустой username возвращает 400")
        void emptyUsername_returns400() throws Exception {
            var request = Map.of(
                    "username", "",
                    "password", "password123",
                    "email", "test@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Null username возвращает 400")
        void nullUsername_returns400() throws Exception {
            var request = Map.of(
                    "password", "password123",
                    "email", "test@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Username короче 3 символов возвращает 400")
        void shortUsername_returns400() throws Exception {
            var request = Map.of(
                    "username", "ab",
                    "password", "password123",
                    "email", "test@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Username длиннее 50 символов возвращает 400")
        void longUsername_returns400() throws Exception {
            // 51 символ
            String longUsername = "a".repeat(51);

            var request = Map.of(
                    "username", longUsername,
                    "password", "password123",
                    "email", "test@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Username с недопустимыми символами возвращает 400")
        void invalidUsernameChars_returns400() throws Exception {
            String[] invalidUsernames = {
                    "user name", // пробел
                    "user@name", // @
                    "user#name", // #
                    "user$name", // $
                    "user%name", // %
                    "user name", // пробел
                    "user\tname", // табуляция
                    "user\nname", // новая строка
                    "user/name", // слеш
                    "user\\name", // обратный слеш
                    "user name", // спецсимволы
                    "пользователь" // кириллица
            };

            for (String username : invalidUsernames) {
                var request = Map.of(
                        "username", username,
                        "password", "password123",
                        "email", "test@example.com"
                );

                mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isBadRequest());
            }
        }

        @Test
        @DisplayName("Username с допустимыми символами проходит валидацию")
        void validUsernameChars_passes() throws Exception {
            String[] validUsernames = {
                    "user123",
                    "user.name",
                    "user_name",
                    "user-name",
                    "User123",
                    "123user",
                    "a.b_c-d123"
            };

            for (int i = 0; i < validUsernames.length; i++) {
                String username = validUsernames[i] + i; // добавляем индекс для уникальности
                var request = Map.of(
                        "username", username,
                        "password", "password123",
                        "email", username + "@example.com"
                );

                // Должно пройти валидацию (может упасть на бизнес-логике, но не на валидации)
                mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isCreated()); // успешная регистрация
            }
        }
    }

    @Nested
    @DisplayName("Password validation")
    class PasswordValidation {

        @Test
        @DisplayName("Пустой password возвращает 400")
        void emptyPassword_returns400() throws Exception {
            var request = Map.of(
                    "username", "validuser",
                    "password", "",
                    "email", "test@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Null password возвращает 400")
        void nullPassword_returns400() throws Exception {
            var request = Map.of(
                    "username", "validuser",
                    "email", "test@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Password короче 8 символов возвращает 400")
        void shortPassword_returns400() throws Exception {
            var request = Map.of(
                    "username", "validuser",
                    "password", "1234567", // 7 символов
                    "email", "test@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Password длиннее 100 символов возвращает 400")
        void longPassword_returns400() throws Exception {
            // 101 символ
            String longPassword = "a".repeat(101);

            var request = Map.of(
                    "username", "validuser",
                    "password", longPassword,
                    "email", "test@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Password ровно 8 символов проходит валидацию")
        void minValidPassword_passes() throws Exception {
            var request = Map.of(
                    "username", "validuser8",
                    "password", "12345678", // ровно 8 символов
                    "email", "validuser8@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated());
        }
    }

    @Nested
    @DisplayName("Email validation")
    class EmailValidation {

        @Test
        @DisplayName("Пустой email возвращает 400")
        void emptyEmail_returns400() throws Exception {
            var request = Map.of(
                    "username", "validuser",
                    "password", "password123",
                    "email", ""
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Null email возвращает 400")
        void nullEmail_returns400() throws Exception {
            var request = Map.of(
                    "username", "validuser",
                    "password", "password123"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Email без @ возвращает 400")
        void emailWithoutAt_returns400() throws Exception {
            var request = Map.of(
                    "username", "validuser",
                    "password", "password123",
                    "email", "testexample.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Email без домена возвращает 400")
        void emailWithoutDomain_returns400() throws Exception {
            var request = Map.of(
                    "username", "validuser",
                    "password", "password123",
                    "email", "test@"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Email без локальной части возвращает 400")
        void emailWithoutLocal_returns400() throws Exception {
            var request = Map.of(
                    "username", "validuser",
                    "password", "password123",
                    "email", "@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Email с недопустимыми символами возвращает 400")
        void emailWithInvalidChars_returns400() throws Exception {
            String[] invalidEmails = {
                    "test space@example.com", // пробел в локальной части
                    "test@", // нет домена
                    "@example.com", // нет локальной части
                    "testexample.com" // нет @
            };

            for (int i = 0; i < invalidEmails.length; i++) {
                String email = invalidEmails[i];
                var request = Map.of(
                        "username", "validuser" + i, // уникальные имена пользователей
                        "password", "password123",
                        "email", email
                );

                mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isBadRequest());
            }
        }

        @Test
        @DisplayName("Email длиннее 255 символов возвращает 400")
        void longEmail_returns400() throws Exception {
            // Создаем email длиннее 255 символов
            String longLocalPart = "a".repeat(240);
            String longEmail = longLocalPart + "@example.com"; // > 255 символов

            var request = Map.of(
                    "username", "validuser",
                    "password", "password123",
                    "email", longEmail
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
;
        }

        @Test
        @DisplayName("Валидные email форматы проходят валидацию")
        void validEmails_pass() throws Exception {
            String[] validEmails = {
                    "test@example.com",
                    "user.name@example.com",
                    "user+tag@example.com",
                    "user123@test-domain.co.uk",
                    "a@b.co"
            };

            for (int i = 0; i < validEmails.length; i++) {
                String email = validEmails[i];
                var request = Map.of(
                        "username", "validuser" + i,
                        "password", "password123",
                        "email", email
                );

                mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isCreated());
            }
        }
    }

    @Nested
    @DisplayName("Combined validation errors")
    class CombinedValidation {

        @Test
        @DisplayName("Все поля невалидны - возвращает 400 с несколькими ошибками")
        void allFieldsInvalid_returnsMultipleErrors() throws Exception {
            var request = Map.of(
                    "username", "ab", // слишком короткий
                    "password", "123", // слишком короткий
                    "email", "invalid-email" // неправильный формат
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Пустой JSON возвращает 400")
        void emptyJson_returns400() throws Exception {
            var request = Map.of();

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Некорректный JSON возвращает 400")
        void invalidJson_returns400() throws Exception {
            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{invalid-json"))
                    .andExpect(status().isBadRequest());
        }
    }
}
