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
import org.testcontainers.containers.MongoDBContainer;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

/**
 * Тесты граничных значений для Registration API.
 * Проверяет поведение на минимальных и максимальных допустимых значениях.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer"
})
@AutoConfigureMockMvc
class RegistrationBoundaryTests {

    @Container
    @ServiceConnection
    static MongoDBContainer mongo = new MongoDBContainer(
            DockerImageName.parse("mongo:7"))
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
            String username = UUID.randomUUID().toString().replace("-", "").substring(0, 3);
            String email = "boundary3_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8) + "@example.com";

            var request = Map.of(
                    "username", username,
                    "password", "password123",
                    "email", email
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value(username))
                    .andExpect(jsonPath("$.email").value(email));
        }

        @Test
        @DisplayName("Username ровно 50 символов (максимум) - успешная регистрация")
        void username_exactlyFiftyChars_success() throws Exception {
            // Ровно 50 символов: "a" * 47 + "50c"
            String username50 = "a".repeat(47) + "50c";
            String email = "boundary50_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8) + "@example.com";

            var request = Map.of(
                    "username", username50,
                    "password", "password123",
                    "email", email
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value(username50))
                    .andExpect(jsonPath("$.email").value(email));
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
            String uniquePrefix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
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
                        "username", "pwdboundary_" + uniquePrefix + "_" + i,
                        "password", password,
                        "email", "pwdboundary_" + uniquePrefix + "_" + i + "@example.com"
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
        @DisplayName("Email с длинным доменом - успешная регистрация")
        void email_longDomain_success() throws Exception {
            // RFC 5321 ограничивает локальную часть до 64 символов
            // Используем нормальную локальную часть и длинный домен
            String uniqueId = String.valueOf(System.nanoTime()).substring(0, 8);
            String email = "user" + uniqueId + "@" + "a".repeat(50) + ".example.com";

            var request = Map.of(
                    "username", "emailuser255" + uniqueId,
                    "password", "password123",
                    "email", email
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.email").value(email));
        }

        @Test
        @DisplayName("Email минимальной валидной длины - успешная регистрация")
        void email_minValidLength_success() throws Exception {
            String uniqueId = String.valueOf(System.nanoTime()).substring(0, 8);
            String email = "m" + uniqueId + "@b.co";

            var request = Map.of(
                    "username", "emailmin" + uniqueId,
                    "password", "password123",
                    "email", email
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.email").value(email));
        }

        @Test
        @DisplayName("Email с точкой и плюсом - успешная регистрация")
        void email_withDotAndPlus_success() throws Exception {
            String uniqueId = String.valueOf(System.nanoTime()).substring(0, 8);
            String email = "test.email+tag" + uniqueId + "@example.com";

            var request = Map.of(
                    "username", "emailbound" + uniqueId,
                    "password", "password123",
                    "email", email
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated());
        }
    }

    @Nested
    @DisplayName("Combined boundary scenarios")
    class CombinedBoundaryScenarios {

        @Test
        @DisplayName("Все поля на минимальных границах - успешная регистрация")
        void allFieldsAtMinBoundaries_success() throws Exception {
            String username3 = UUID.randomUUID().toString().replace("-", "").substring(0, 3);
            var request = Map.of(
                    "username", username3, // 3 символа
                    "password", "minpass8", // 8 символов
                    "email", "m@b.co" // минимальный email
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value(username3))
                    .andExpect(jsonPath("$.email").value("m@b.co"));
        }

        @Test
        @DisplayName("Все поля на максимальных границах - успешная регистрация")
        void allFieldsAtMaxBoundaries_success() throws Exception {
            String uniqueId = String.valueOf(System.nanoTime()).substring(0, 8);
            String username50 = "u".repeat(42) + uniqueId; // 42 + 8 = 50 символов
            String password72 = "p".repeat(72); // 72 символа (максимум для BCrypt)
            // RFC 5321: локальная часть до 64 символов
            String email = "max" + uniqueId + "@" + "a".repeat(50) + ".example.com";

            var request = Map.of(
                    "username", username50,
                    "password", password72,
                    "email", email
            );

            mvc.perform(post("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value(username50))
                    .andExpect(jsonPath("$.email").value(email));
        }

    }
}
