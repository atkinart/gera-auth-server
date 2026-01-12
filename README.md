# Gera Auth Server (Gradle 9 + Java 25)

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

- `groupId`: `ru.gera`, базовый пакет: `ru.gera.auth`.
- `build.gradle` — Gradle 9, Java toolchain 25, Spring Boot 3.5.6, SAS 1.5.x, springdoc-openapi.
- `SecurityConfig` — настройка SAS, OIDC, CORS, JDBC‑хранилищ; доступ открыт к `/api/auth/register`, Swagger UI.
- `ClientInitializer` — регистрирует SPA‑клиент (PKCE) и служебных клиентов для тестов.
- `Liquibase` — миграции схем SAS и `users/authorities` (см. `db/changelog`).
- `RegistrationController`/`RegistrationService` — REST‑регистрация пользователей `POST /api/auth/register`.
- `banner.txt` — баннер в логах, берёт имя приложения и issuer из конфигурации.

## Примечания продакшена
- Замените генерацию RSA‑ключа на keystore/Vault + ротация.
- Включите HTTPS и укажите `APP_ISSUER` на prod‑домен.
- Управляйте схемой через Liquibase (см. changelog). 
  В changelog добавлено согласование типов под SAS 1.5.x (token/metadata/attributes как `text`).

## OpenAPI / Swagger UI

- UI: `http://localhost:9000/swagger-ui.html`
- JSON: `http://localhost:9000/v3/api-docs`

Описание включает ключевые точки интеграции для SPA и backend‑сервисов:
- `/oauth2/authorize` — Authorization Code (+PKCE) с редиректом на `redirect_uri`.
- `/oauth2/token` — обмен кода/refresh на токены.
- `/userinfo` — OIDC профиль по `Bearer` токену.
- `/oauth2/introspect` — интроспекция (Basic auth: confidential‑клиент).
- `/oauth2/revoke` — отзыв токена (Basic/confidential или `client_id` для public, если разрешено).

### Регистрация пользователей

- Эндпоинт: `POST /api/auth/register`
- Доступ: открыт (`permitAll`), CSRF отключён для этого пути.
- Тело запроса (JSON):

```json
{
  "username": "alice",
  "password": "Password1!",
  "email": "alice@example.com"
}
```

- Ограничения:
  - `username`: [a-zA-Z0-9._-], 3..50
  - `password`: 8..100
  - `email`: валидный email, уникален

- Ответы:
  - 201 Created: `{ "username": "alice", "email": "alice@example.com" }`
  - 409 Conflict: username/email заняты
  - 400 Bad Request: ошибка валидации

- Пример cURL:

```bash
curl -i -X POST http://localhost:9000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Password1!","email":"alice@example.com"}'
```

- Пример из React (fetch):

```ts
await fetch('/api/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password, email })
});
```

Эндпоинт описан также в Swagger UI.

## Интеграция React (PKCE)

1) Создайте публичный клиент в AS (ClientInitializer уже добавляет `spa` по умолчанию).
2) На фронте выполните PKCE‑флоу:

```ts
// Пример: старт авторизации
const authz = new URL('http://localhost:9000/oauth2/authorize');
authz.searchParams.set('response_type', 'code');
authz.searchParams.set('client_id', 'spa');
authz.searchParams.set('redirect_uri', 'http://localhost:5173/callback');
authz.searchParams.set('scope', 'openid profile');
authz.searchParams.set('code_challenge', pkceChallenge);
authz.searchParams.set('code_challenge_method', 'S256');
window.location.assign(authz.toString());
```

`/callback` в приложении принимает `code`, обменивает на токены:

```ts
// POST x-www-form-urlencoded на /oauth2/token
grant_type=authorization_code&code=...&redirect_uri=...&client_id=spa&code_verifier=...
```

Для профиля: `GET /userinfo` с заголовком `Authorization: Bearer <access_token>`.

## Backend на Spring: проверка токенов

Вариант 1 — Resource Server (рекомендуется, JWT):

```groovy
dependencies {
  implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
}
```

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${APP_ISSUER:http://localhost:9000}
```

Вариант 2 — Интроспекция (opaque/централизованная проверка):

```groovy
dependencies {
  implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
}
```

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          introspection-uri: http://localhost:9000/oauth2/introspect
          client-id: conf-client
          client-secret: secret
```

## Метаданные и баннер

- Имя приложения: `spring.application.name=gera-auth-server` (banнер и логи).
- `/actuator/info` содержит build‑информацию (версия, имя, группа) — включено через Gradle `springBoot { buildInfo() }`.
- Баннер (`src/main/resources/banner.txt`) выводит имя и issuer.

## Лицензия
MIT (или на ваше усмотрение)
