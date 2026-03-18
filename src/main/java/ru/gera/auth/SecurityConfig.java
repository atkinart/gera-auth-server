package ru.gera.auth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.authentication.PublicClientAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain asFilterChain(HttpSecurity http) throws Exception {
        var as = OAuth2AuthorizationServerConfigurer.authorizationServer();
        http.securityMatcher(as.getEndpointsMatcher())
                .with(as, config -> config
                        .oidc(Customizer.withDefaults())
                        .clientAuthentication(ca -> ca.authenticationConverter(new PublicClientAuthenticationConverter()))
                )
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .addFilterBefore(
                        stripContinueParameterFilter(),
                        org.springframework.security.web.context.SecurityContextHolderFilter.class
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.cors(Customizer.withDefaults()).build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain appFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.GET, "/login", "/signup", "/auth-ui.css", "/auth-signup.js").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                        .requestMatchers(
                                "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**"
                        ).permitAll()
                        .anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/auth/register", "/v3/api-docs/**"))
                .formLogin(form -> form.loginPage("/login").permitAll())
                .logout(logout -> logout.logoutSuccessUrl("/login?logout").permitAll());
        return http.cors(Customizer.withDefaults()).build();
    }

    @Bean
    OncePerRequestFilter stripContinueParameterFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain filterChain) throws ServletException, IOException {
                if (!"/oauth2/authorize".equals(request.getServletPath()) || request.getParameter("continue") == null) {
                    filterChain.doFilter(request, response);
                    return;
                }

                var wrapped = new HttpServletRequestWrapper(request) {
                    @Override
                    public String getParameter(String name) {
                        if ("continue".equals(name)) {
                            return null;
                        }
                        return super.getParameter(name);
                    }

                    @Override
                    public Map<String, String[]> getParameterMap() {
                        Map<String, String[]> source = super.getParameterMap();
                        Map<String, String[]> filtered = new LinkedHashMap<>(source);
                        filtered.remove("continue");
                        return Collections.unmodifiableMap(filtered);
                    }

                    @Override
                    public Enumeration<String> getParameterNames() {
                        return Collections.enumeration(getParameterMap().keySet());
                    }

                    @Override
                    public String[] getParameterValues(String name) {
                        if ("continue".equals(name)) {
                            return null;
                        }
                        return super.getParameterValues(name);
                    }

                    @Override
                    public String getQueryString() {
                        String query = super.getQueryString();
                        if (query == null || query.isBlank()) {
                            return query;
                        }
                        return Arrays.stream(query.split("&"))
                                .filter(part -> !"continue".equals(part) && !part.startsWith("continue="))
                                .collect(Collectors.joining("&"));
                    }
                };

                filterChain.doFilter(wrapped, response);
            }
        };
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.origins:http://localhost:5173}") String origins) {
        var config = new CorsConfiguration();
        config.setAllowedOriginPatterns(Arrays.asList(origins.split(",")));
        config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(true);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean PasswordEncoder passwordEncoder() {
        return org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(@Value("${app.issuer}") String issuer) {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        RSAKey rsa = generateRsa();
        JWKSet jwkSet = new JWKSet(rsa);
        return (selector, ctx) -> selector.select(jwkSet);
    }

    private static RSAKey generateRsa() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
            return new RSAKey.Builder(pub).privateKey(priv).keyID(UUID.randomUUID().toString()).build();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
