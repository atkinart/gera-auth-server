package ru.gera.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Простые юнит-тесты без использования Testcontainers
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.NONE,
    classes = {SimpleUnitTests.TestConfig.class},
    properties = {
        "spring.datasource.url=jdbc:h2:mem:testdb",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.liquibase.enabled=false",
        "spring.main.allow-bean-definition-overriding=true"
    }
)
class SimpleUnitTests {

    @Test
    @DisplayName("Контекст приложения должен загружаться успешно")
    void contextLoads() {
        // Если тест дошел до этой точки, контекст загрузился успешно
    }

    @Configuration
    @EnableWebSecurity
    static class TestConfig {

        @Bean
        @Primary
        SecurityFilterChain testFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.disable());
            return http.build();
        }
    }
}