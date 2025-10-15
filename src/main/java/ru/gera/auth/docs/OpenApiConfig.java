package ru.gera.auth.docs;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI(@Value("${app.issuer:http://localhost:9000}") String issuer) {
        // Security schemes
        SecurityScheme oauth2 = new SecurityScheme()
                .type(SecurityScheme.Type.OAUTH2)
                .flows(new OAuthFlows().authorizationCode(new OAuthFlow()
                        .authorizationUrl(issuer + "/oauth2/authorize")
                        .tokenUrl(issuer + "/oauth2/token")
                        .scopes(new Scopes()
                                .addString("openid", "OpenID Connect")
                                .addString("profile", "Basic profile")
                                .addString("offline_access", "Refresh tokens")
                                .addString("api.read", "Example API read")
                        )));

        SecurityScheme basic = new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("basic");
        SecurityScheme bearer = new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT");

        Components components = new Components()
                .addSecuritySchemes("OAuth2", oauth2)
                .addSecuritySchemes("BasicAuth", basic)
                .addSecuritySchemes("BearerAuth", bearer)
                .addSchemas("TokenResponse", tokenResponseSchema())
                .addSchemas("IntrospectionResponse", introspectionResponseSchema())
                .addSchemas("RegistrationRequest", registrationRequestSchema())
                .addSchemas("RegistrationResponse", registrationResponseSchema());

        // Paths (основные точки интеграции)
        Paths paths = new Paths()
                .addPathItem("/oauth2/authorize", new PathItem().get(new Operation()
                        .summary("OAuth2 Authorization Endpoint (Auth Code + PKCE)")
                        .addParametersItem(param("response_type", "code", true))
                        .addParametersItem(param("client_id", "Client ID", true))
                        .addParametersItem(param("redirect_uri", "Redirect URI", true))
                        .addParametersItem(param("scope", "Scopes (space delimited)", true))
                        .addParametersItem(param("state", "CSRF protection", false))
                        .addParametersItem(param("code_challenge", "PKCE challenge", false))
                        .addParametersItem(param("code_challenge_method", "S256", false))
                        .addParametersItem(param("nonce", "OIDC nonce", false))
                        .responses(resp(Map.of("302", new ApiResponse().description("Redirect to client with code"))))
                ))
                .addPathItem("/oauth2/token", new PathItem().post(new Operation()
                        .summary("OAuth2 Token Endpoint")
                        .requestBody(formRB("grant_type, code, redirect_uri, client_id, code_verifier"))
                        .responses(resp(Map.of("200", new ApiResponse().description("Token response")
                                .content(new Content().addMediaType("application/json", new MediaType().schema(ref("TokenResponse")))))
                        ))
                ))
                .addPathItem("/oauth2/introspect", new PathItem().post(new Operation()
                        .summary("OAuth2 Token Introspection")
                        .addSecurityItem(new SecurityRequirement().addList("BasicAuth"))
                        .requestBody(formRB("token"))
                        .responses(resp(Map.of("200", new ApiResponse().description("Introspection response")
                                .content(new Content().addMediaType("application/json", new MediaType().schema(ref("IntrospectionResponse")))))
                        ))
                ))
                .addPathItem("/oauth2/revoke", new PathItem().post(new Operation()
                        .summary("OAuth2 Token Revocation")
                        .requestBody(formRB("token, token_type_hint, client_id (for public)"))
                        .responses(resp(Map.of("200", new ApiResponse().description("Revoked"))))
                ))
                .addPathItem("/api/auth/register", new PathItem().post(new Operation()
                        .summary("User registration")
                        .description("Creates a new user with role USER; CSRF is disabled for this endpoint.")
                        .requestBody(jsonRB(ref("RegistrationRequest")))
                        .responses(resp(Map.of(
                                "201", new ApiResponse().description("Created").content(new Content().addMediaType("application/json", new MediaType().schema(ref("RegistrationResponse")))) ,
                                "400", new ApiResponse().description("Validation error"),
                                "409", new ApiResponse().description("Conflict: username or email exists")
                        )))
                ))
                .addPathItem("/userinfo", new PathItem().get(new Operation()
                        .summary("OIDC UserInfo")
                        .addSecurityItem(new SecurityRequirement().addList("BearerAuth"))
                        .responses(resp(Map.of("200", new ApiResponse().description("User claims (JSON)"))))
                ));

        return new OpenAPI()
                .info(new Info().title("Gera Auth Server").version("v1"))
                .servers(List.of(new Server().url(issuer).description("Issuer")))
                .components(components)
                .paths(paths)
                .addSecurityItem(new SecurityRequirement().addList("OAuth2"));
    }

    private static Schema<?> tokenResponseSchema() {
        return new Schema<>()
                .type("object")
                .addProperties("access_token", new Schema<>().type("string"))
                .addProperties("token_type", new Schema<>().type("string").example("Bearer"))
                .addProperties("expires_in", new Schema<>().type("integer"))
                .addProperties("refresh_token", new Schema<>().type("string"))
                .addProperties("id_token", new Schema<>().type("string"))
                .addProperties("scope", new Schema<>().type("string"));
    }

    private static Schema<?> introspectionResponseSchema() {
        return new Schema<>()
                .type("object")
                .addProperties("active", new Schema<>().type("boolean"))
                .addProperties("sub", new Schema<>().type("string"))
                .addProperties("client_id", new Schema<>().type("string"))
                .addProperties("scope", new Schema<>().type("string"))
                .addProperties("iss", new Schema<>().type("string"))
                .addProperties("exp", new Schema<>().type("integer"))
                .addProperties("iat", new Schema<>().type("integer"));
    }

    private static Parameter param(String name, String desc, boolean required) {
        return new Parameter().name(name).in("query").required(required).description(desc).schema(new Schema<>().type("string"));
    }

    private static RequestBody formRB(String fields) {
        return new RequestBody().required(true)
                .content(new Content().addMediaType("application/x-www-form-urlencoded",
                        new MediaType().schema(new Schema<>().type("object").description("Fields: " + fields))));
    }

    private static RequestBody jsonRB(Schema<?> schema) {
        return new RequestBody().required(true)
                .content(new Content().addMediaType("application/json", new MediaType().schema(schema)));
    }

    private static ApiResponses resp(Map<String, ApiResponse> map) {
        ApiResponses rs = new ApiResponses();
        map.forEach(rs::addApiResponse);
        return rs;
    }

    private static Schema<?> ref(String name) {
        return new Schema<>().$ref("#/components/schemas/" + name);
    }

    private static Schema<?> registrationRequestSchema() {
        return new Schema<>()
                .type("object")
                .addProperties("username", new Schema<>().type("string").minLength(3).maxLength(50))
                .addProperties("password", new Schema<>().type("string").minLength(8))
                .addProperties("email", new Schema<>().type("string").format("email"))
                .required(List.of("username", "password", "email"));
    }

    private static Schema<?> registrationResponseSchema() {
        return new Schema<>()
                .type("object")
                .addProperties("username", new Schema<>().type("string"))
                .addProperties("email", new Schema<>().type("string"));
    }
}
