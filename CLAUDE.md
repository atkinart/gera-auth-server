# CLAUDE.md - AI Assistant Context

## Project Overview

**Gera Auth Server** is a Spring Authorization Server (SAS) project built with Gradle 9.1.0 and Java 25. It provides OAuth2/OIDC authentication services with PostgreSQL backend storage.

## Key Technologies

- **Language**: Java 25
- **Build Tool**: Gradle 9.1.0
- **Framework**: Spring Boot 3.5.6
- **Security**: Spring Security OAuth2 Authorization Server 1.5.2
- **Database**: PostgreSQL 16+
- **Migration**: Liquibase
- **Documentation**: OpenAPI 3 (springdoc-openapi)
- **Testing**: JUnit 5, Testcontainers

## Project Structure

```
src/main/java/ru/gera/auth/
├── config/          # Security and application configuration
├── controller/      # REST endpoints (registration, etc.)
├── service/         # Business logic
├── model/           # DTOs and domain models
└── GeraAuthServerApplication.java

src/main/resources/
├── db/changelog/    # Liquibase database migrations
├── application.yml  # Main configuration
└── banner.txt       # Custom startup banner

src/test/java/
└── ru/gera/auth/    # Test classes
```

## Core Features

1. **OAuth2/OIDC Support**: Full OAuth2 Authorization Server with OIDC 1.0
2. **PKCE for SPAs**: Support for public clients (Single Page Applications)
3. **User Registration**: REST API for user registration (`POST /api/auth/register`)
4. **JDBC User Management**: Users stored in PostgreSQL via JdbcUserDetailsManager
5. **CORS Configuration**: Configurable CORS origins via environment variables
6. **Database Migrations**: Liquibase-managed schema evolution
7. **OpenAPI Documentation**: Swagger UI available at `/swagger-ui.html`

## Environment Configuration

Key environment variables:
- `SPRING_DATASOURCE_URL`: PostgreSQL connection URL
- `SPRING_DATASOURCE_USERNAME`: Database username
- `SPRING_DATASOURCE_PASSWORD`: Database password
- `APP_ISSUER`: OAuth2 issuer URL (e.g., http://localhost:9000)
- `APP_CORS_ORIGINS`: Allowed CORS origins (e.g., http://localhost:5173)

## Default Endpoints

- Authorization: `/oauth2/authorize`
- Token: `/oauth2/token`
- User Info: `/userinfo`
- Introspection: `/oauth2/introspect`
- Token Revocation: `/oauth2/revoke`
- Registration: `/api/auth/register`
- OpenAPI: `/v3/api-docs`
- Swagger UI: `/swagger-ui.html`
- Health: `/actuator/health`
- Build Info: `/actuator/info`

## Default Credentials

- **Username**: admin
- **Password**: admin
- **Note**: Change in production!

## Development Workflow

1. **Database**: Run PostgreSQL locally or via Docker
2. **Build**: `./gradlew clean bootJar`
3. **Run**: Set environment variables and run JAR
4. **Test**: `./gradlew test` (uses Testcontainers)

## Security Configuration

- **Public endpoints**: `/api/auth/register`, Swagger UI, actuator health
- **CSRF**: Disabled for API paths
- **CORS**: Configurable via `APP_CORS_ORIGINS`
- **JWT**: Self-contained tokens with RSA signing
- **Client Types**: Both confidential and public clients supported

## Database Schema

Managed by Liquibase with changesets for:
- SAS standard tables (oauth2_authorization, oauth2_client, etc.)
- Users and authorities tables
- Custom indexes and constraints
- Type adjustments for SAS 1.5.x compatibility

## Testing

- **Unit Tests**: Standard Spring Boot test slices
- **Integration Tests**: Testcontainers for PostgreSQL
- **OAuth2 Flows**: PKCE, refresh token, introspection, revocation

## Common AI Assistant Tasks

When working on this project, you might be asked to:

1. **Add new OAuth2 clients**: Modify ClientInitializer
2. **Extend user registration**: Update RegistrationController/Service
3. **Add custom endpoints**: Create new controllers
4. **Database changes**: Create new Liquibase changesets
5. **Security modifications**: Adjust SecurityConfig
6. **Testing**: Add or modify test cases
7. **Configuration**: Update application.yml or environment handling

## Important Notes

- Always use the existing package structure (`ru.gera.auth`)
- Follow Spring Security best practices
- Use Liquibase for any database schema changes
- Maintain backward compatibility when possible
- Include appropriate tests for new functionality
- Update OpenAPI documentation for new endpoints

## Build Commands

```bash
# Clean and build
./gradlew clean bootJar

# Run tests
./gradlew test

# Generate Gradle wrapper
gradle wrapper --gradle-version 9.1.0

# Run with profile
./gradlew bootRun --args='--spring.profiles.active=dev'
```

## Docker Support

The project includes a Dockerfile for containerized deployment using Java 25 runtime.

## Documentation

- README.md: Comprehensive setup and usage guide
- OpenAPI/Swagger: Available at runtime for API documentation
- This file: AI assistant context and development guidance