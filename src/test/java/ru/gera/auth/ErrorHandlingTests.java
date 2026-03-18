package ru.gera.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(properties = {
        "app.issuer=http://test-issuer",
        "logging.level.org.springframework.security=WARN"
})
@AutoConfigureMockMvc
class ErrorHandlingTests {

    @Container
    @ServiceConnection
    static MongoDBContainer mongo = new MongoDBContainer(DockerImageName.parse("mongo:7"))
            .withStartupTimeout(java.time.Duration.ofMinutes(5))
            .waitingFor(org.testcontainers.containers.wait.strategy.Wait.forListeningPort())
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(ErrorHandlingTests.class)));

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    @DisplayName("Registration: некорректный JSON возвращает 400")
    void registration_malformedJson_returns400() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"test\",\"password\":\"pass\",\"email\":"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Registration: неподдерживаемый Content-Type возвращает 415")
    void registration_unsupportedContentType_returns415() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("plain text"))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    @DisplayName("Registration: дублирование email возвращает 409")
    void registration_duplicateEmail_returns409() throws Exception {
        String unique = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String duplicateEmail = "duplicate_" + unique + "@example.com";

        var firstUser = Map.of(
                "username", "u1_" + unique,
                "password", "Password1!",
                "email", duplicateEmail
        );
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(firstUser)))
                .andExpect(status().isCreated());

        var secondUser = Map.of(
                "username", "u2_" + unique,
                "password", "Password1!",
                "email", duplicateEmail
        );
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secondUser)))
                .andExpect(status().isConflict());
    }
}
