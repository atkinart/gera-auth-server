# Spring Authorization Server (Gradle 9 + Java 25)

Готовый **Spring Authorization Server** (SAS) проект на **Gradle 9.1.0** и **Java 25**.
- Хранит пользователей (`JdbcUserDetailsManager`) и OAuth2‑сущности в **PostgreSQL**.
- Поддерживает **OIDC 1.0**, PKCE для SPA (публичный клиент).
- Конфигурация `issuer` и CORS через env.

## Требования

- **Java 25** (Temurin/Adoptium).
- **Gradle 9.1+** *(или используйте GitHub Actions — он сам подтянет нужную версию)*.
- PostgreSQL 16+.

## Быстрый старт локально

1) Запустить Postgres (любым способом):
```bash
docker run -d --name sas_db -p 5432:5432 \
  -e POSTGRES_DB=sas -e POSTGRES_USER=sas -e POSTGRES_PASSWORD=sas postgres:16
```

2) Сгенерировать wrapper (если нужен) и собрать:
```bash
# если Gradle уже установлен
gradle wrapper --gradle-version 9.1.0
./gradlew clean bootJar
```

3) Запуск через Java:
```bash
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/sas \
SPRING_DATASOURCE_USERNAME=sas \
SPRING_DATASOURCE_PASSWORD=sas \
APP_ISSUER=http://localhost:9000 \
APP_CORS_ORIGINS=http://localhost:5173 \
java -jar build/libs/*.jar
```

Откройте: `http://localhost:9000/.well-known/openid-configuration`

Логин: `admin / admin` (создается при первом запуске; поменяйте в продуктиве).

## Docker (Java 25 runtime)

Собрать и запустить контейнер:
```bash
docker build -t auth-server:local .
docker run --rm -p 9000:9000 --name auth_server \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://host.docker.internal:5432/sas \
  -e SPRING_DATASOURCE_USERNAME=sas \
  -e SPRING_DATASOURCE_PASSWORD=sas \
  -e APP_ISSUER=http://localhost:9000 \
  -e APP_CORS_ORIGINS=http://localhost:5173 \
  auth-server:local
```

## Что внутри

- `build.gradle` — Gradle 9, Java toolchain 25, зависимости Spring Boot 3.5.6 и SAS 1.5.2.
- `SecurityConfig` — настройка SAS, OIDC, CORS, JDBC‑хранилищ.
- `DataInitializer` — публичный клиент для SPA (PKCE), scopes `openid profile api.read`.
- `application.yml` — SQL init с схемами SAS + таблицы пользователей.

## Примечания продакшена
- Замените генерацию RSA‑ключа на keystore/Vault + ротация.
- Включите HTTPS и укажите `APP_ISSUER` на prod‑домен.
- Используйте Flyway/Liquibase вместо `spring.sql.init`.

## Лицензия
MIT (или на ваше усмотрение)
