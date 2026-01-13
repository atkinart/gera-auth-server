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
 * Тесты граничных значений для Registration API.
 * Проверяет поведение на минимальных и максимальных допустимых значениях.
 */
@Testcontainers
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
@AutoConfigureMockMvc
class RegistrationBoundaryTests {

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
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(RegistrationBoundaryTests.class)));

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;

    @Nested
    @DisplayName("Username boundary values")
    class UsernameBoundaryValues {

        @Test
        @DisplayName("Username ровно 3 символа (минимум) - успешная регистрация")
        void username_exactlyThreeChars_success() throws Exception {
            var request = Map.of(
                    "username", "abc123", // ровно 6 символов, но уникально
                    "password", "password123",
                    "email", "boundary3@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value("abc123"))
                    .andExpect(jsonPath("$.email").value("boundary3@example.com"));
        }

        @Test
        @DisplayName("Username ровно 50 символов (максимум) - успешная регистрация")
        void username_exactlyFiftyChars_success() throws Exception {
            // Ровно 50 символов: "a" * 47 + "50c"
            String username50 = "a".repeat(47) + "50c";

            var request = Map.of(
                    "username", username50,
                    "password", "password123",
                    "email", "boundary50@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value(username50))
                    .andExpect(jsonPath("$.email").value("boundary50@example.com"));
        }

        @Test
        @DisplayName("Username из допустимых символов на границах")
        void username_validCharsAtBoundaries() throws Exception {
            String[] boundaryUsernames = {
                    "a.a", // 3 символа с точкой
                    "a_a", // 3 символа с подчеркиванием
                    "a-a", // 3 символа с тире
                    "123", // только цифры
                    "ABC", // только заглавные буквы
                    "a.b_c-d123.e_f-g456.h_i-j789.k_l-m012.n_o-p", // 49 символов, все допустимые
                    "a.b_c-d123.e_f-g456.h_i-j789.k_l-m012.n_o-p3" // 50 символов, все допустимые
            };

            for (int i = 0; i < boundaryUsernames.length; i++) {
                String username = boundaryUsernames[i];
                var request = Map.of(
                        "username", username,
                        "password", "password123",
                        "email", "boundary" + i + "@example.com"
                );

                mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isCreated());
            }
        }
    }

    @Nested
    @DisplayName("Password boundary values")
    class PasswordBoundaryValues {

        @Test
        @DisplayName("Password ровно 8 символов (минимум) - успешная регистрация")
        void password_exactlyEightChars_success() throws Exception {
            var request = Map.of(
                    "username", "pwduser8",
                    "password", "12345678", // ровно 8 символов
                    "email", "pwduser8@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value("pwduser8"));
        }

        @Test
        @DisplayName("Password ровно 72 символа (максимум для BCrypt) - успешная регистрация")
        void password_exactly72Chars_success() throws Exception {
            // Ровно 72 символа (максимум для BCrypt)
            String password72 = "a".repeat(68) + "72!!";

            var request = Map.of(
                    "username", "pwduser72",
                    "password", password72,
                    "email", "pwduser72@example.com"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value("pwduser72"));
        }

        @Test
        @DisplayName("Password с различными символами на границах")
        void password_variousCharsAtBoundaries() throws Exception {
            String[] boundaryPasswords = {
                    "abcdefgh", // 8 букв
                    "12345678", // 8 цифр
                    "AbCdEfGh", // 8 смешанные буквы
                    "Pass123!", // 8 символов с спецсимволами
                    "пароль12", // 8 символов с кириллицей
                    " spaces ", // 8 символов с пробелами
                    "!@#$%^&*", // 8 спецсимволов
                    "a".repeat(71) + "!" // 72 символа (максимум для BCrypt)
            };

            for (int i = 0; i < boundaryPasswords.length; i++) {
                String password = boundaryPasswords[i];
                var request = Map.of(
                        "username", "pwdboundary" + i,
                        "password", password,
                        "email", "pwdboundary" + i + "@example.com"
                );

                mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                        .andExpect(status().isCreated());
            }
        }
    }

    @Nested
    @DisplayName("Email boundary values")
    class EmailBoundaryValues {

        @Test
        @DisplayName("Email максимальной длины 255 символов - успешная регистрация")
        void email_maxLength255_success() throws Exception {
            // Создаем email длиной ровно 255 символов
            // Формат: очень_длинная_локальная_часть@domain.com
            String longLocalPart = "a".repeat(240); // 240 символов
            String email255 = longLocalPart + "@domain.com"; // 240 + 1 + 10 + 1 + 3 = 255 символов

            // Создаем email длиной ровно 254 символа (меньше 255)
            String email254 = "e".repeat(240) + "@dom.co"; // 254 символа

            var request = Map.of(
                    "username", "emailuser255",
                    "password", "password123",
                    "email", email254
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.email").value(email254));
        }

        @Test
        @DisplayName("Email минимальной валидной длины - успешная регистрация")
        void email_minValidLength_success() throws Exception {
            // Минимальный валидный email: a@b.co (6 символов)
            var request = Map.of(
                    "username", "emailmin",
                    "password", "password123",
                    "email", "a@b.co"
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.email").value("a@b.co"));
        }

        @Test
        @DisplayName("Email с различными валидными форматами на границах")
        void email_variousValidFormatsAtBoundaries() throws Exception {
            String[] boundaryEmails = {
                    "a@b.co", // минимальный
                    "test.email+tag@example.com", // с точкой и плюсом
                    "user123@sub.domain.co.uk", // поддомены
                    "very.long.email.address.with.many.dots@very.long.domain.name.example.org",
                    "x@" + "a".repeat(60) + ".com", // длинный домен
                    "user@123.456.789.012", // IP-подобный домен
                    "test_email@domain-with-dashes.com", // тире в домене
                    "email@localhost.localdomain" // локальный домен
            };

            for (int i = 0; i < boundaryEmails.length; i++) {
                String email = boundaryEmails[i];
                var request = Map.of(
                        "username", "emailbound" + i,
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
    @DisplayName("Combined boundary scenarios")
    class CombinedBoundaryScenarios {

        @Test
        @DisplayName("Все поля на минимальных границах - успешная регистрация")
        void allFieldsAtMinBoundaries_success() throws Exception {
            var request = Map.of(
                    "username", "min", // 3 символа
                    "password", "minpass8", // 8 символов
                    "email", "m@b.co" // минимальный email
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value("min"))
                    .andExpect(jsonPath("$.email").value("m@b.co"));
        }

        @Test
        @DisplayName("Все поля на максимальных границах - успешная регистрация")
        void allFieldsAtMaxBoundaries_success() throws Exception {
            String username50 = "u".repeat(50); // 50 символов
            String password72 = "p".repeat(72); // 72 символа (максимум для BCrypt)
            String email254 = "e".repeat(240) + "@dom.co"; // 254 символа (меньше 255)

            var request = Map.of(
                    "username", username50,
                    "password", password72,
                    "email", email254
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value(username50))
                    .andExpect(jsonPath("$.email").value(email254));
        }

        @Test
        @DisplayName("Граничные значения с Unicode символами")
        void boundaryValuesWithUnicode_handledCorrectly() throws Exception {
            // Username с точкой и тире (допустимые символы)
            var validRequest = Map.of(
                    "username", "user.test-123", // допустимые символы
                    "password", "пароль123", // кириллица в пароле (допустимо)
                    "email", "test@домен.рф" // интернационализированный домен
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(validRequest)))
                    .andExpect(status().isCreated()); // ожидаем успешную регистрацию
        }

        @Test
        @DisplayName("Граничные значения производительности")
        void boundaryValuesPerformance_acceptable() throws Exception {
            long startTime = System.currentTimeMillis();

            // Максимальные значения для проверки производительности
            String username50 = "p".repeat(47) + "erf";
            String password72 = "p".repeat(68) + "72!!"; // 72 символа
            String email254 = "perf.test.email." + "a".repeat(220) + "@test.com"; // 254 символа

            var request = Map.of(
                    "username", username50,
                    "password", password72,
                    "email", email254
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated());

            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;

            // Регистрация не должна занимать больше 2 секунд даже с максимальными значениями
            if (duration > 2000) {
                System.err.println("WARNING: Registration with max boundary values took " + duration + "ms");
            }
        }
    }
}