package io.bloodhound.responder.security;

import io.bloodhound.responder.config.ResponderProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * Authentication for the responder API, in one of three modes.
 *
 * <ul>
 *   <li>{@code oidc} — validate JWTs issued by Keycloak. What a real deployment does.</li>
 *   <li>{@code apikey} — the Week 18 shared keys. Kept so the platform still runs without an
 *       identity provider, and so the two can be compared side by side.</li>
 *   <li>{@code none} — everything open. Acceptable on a laptop, nowhere else.</li>
 * </ul>
 *
 * <p><b>Why OIDC replaced the API keys.</b> The keys were strings in a config file. They never
 * expired, could not be rotated without a restart, were shared between everyone holding them,
 * and — worst for a platform that can disable accounts — made the audit trail say
 * {@code responder@apikey} rather than naming a person. "Who locked this account out at 3am"
 * had no answer. Tokens carry a subject, a short lifetime, and revocable sessions.
 */
@Configuration
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private final ResponderProperties props;

    public SecurityConfig(ResponderProperties props) {
        this.props = props;
    }

    /**
     * Stops Spring Boot from registering the API key filter with the servlet container.
     *
     * <p>Any bean that implements {@code Filter} is auto-registered for every request, entirely
     * independent of the security filter chain. Without this, the API key filter ran even in
     * {@code oidc} mode and rejected perfectly valid bearer tokens with
     * {@code missing or invalid X-Api-Key header} — before Spring Security ever saw them.
     *
     * <p>The symptom is a 401 whose body names the wrong mechanism entirely, which is a
     * memorably confusing hour. Disabling auto-registration leaves the filter available to be
     * added to the chain deliberately, in the one mode that wants it.
     */
    @Bean
    public FilterRegistrationBean<ApiKeyAuthFilter> disableApiKeyAutoRegistration(
            ApiKeyAuthFilter filter) {
        FilterRegistrationBean<ApiKeyAuthFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ApiKeyAuthFilter apiKeyFilter)
            throws Exception {

        // Stateless API with bearer tokens: there is no session to fix and no browser form to
        // forge from, so CSRF protection guards nothing and would reject every curl.
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Health and metrics stay open so Prometheus and Docker health checks work without
        // being handed a credential. They expose no security data.
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health/**", "/actuator/prometheus", "/actuator/info")
                .permitAll()
                .anyRequest().permitAll());

        String mode = props.getAuth().getMode();
        switch (mode) {
            case "oidc" -> {
                http.oauth2ResourceServer(oauth -> oauth.jwt(jwt ->
                        jwt.jwtAuthenticationConverter(new KeycloakRoleConverter())));
                // Authorisation is enforced per-endpoint by RequestContext.require(), not here.
                // Keeping it in one place means the role a given action needs is visible next to
                // the action rather than in a URL pattern list that drifts out of date.
                http.exceptionHandling(e -> e.authenticationEntryPoint(
                        (request, response, ex) -> {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType("application/json");
                            response.getWriter().write(
                                    "{\"error\":\"a valid bearer token is required\"}");
                        }));
                log.info("Auth mode: OIDC, issuer {}", props.getAuth().getIssuerUri());
            }
            case "apikey" -> {
                http.addFilterBefore(apiKeyFilter,
                        org.springframework.security.web.authentication
                                .UsernamePasswordAuthenticationFilter.class);
                log.warn("Auth mode: API key. Shared, non-expiring credentials — lab only.");
            }
            case "none" -> log.warn("Auth mode: NONE. Every endpoint is open.");
            default -> throw new IllegalStateException(
                    "Unknown auth mode '" + mode + "'. Expected oidc, apikey or none.");
        }

        return http.build();
    }

    /**
     * JWT decoder with issuer <em>and</em> audience validation.
     *
     * <p>Spring validates the issuer and signature out of the box. Audience it does not, and
     * skipping it means accepting any token this realm ever issued — including one minted for a
     * different application by a user who never intended it to be used here. That is the
     * confused-deputy problem, and the audience claim is the fix.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        if (!"oidc".equals(props.getAuth().getMode())) {
            // Spring Boot would otherwise fail startup trying to reach an issuer that is not
            // running, which would make `apikey` and `none` modes depend on Keycloak.
            return token -> {
                throw new UnsupportedOperationException("JWT decoding is disabled outside oidc mode");
            };
        }

        String issuer = props.getAuth().getIssuerUri();
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();

        OAuth2TokenValidator<Jwt> audience = jwt -> {
            List<String> aud = jwt.getAudience();
            if (aud != null && aud.contains(props.getAuth().getAudience())) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "Token audience " + aud + " does not include "
                            + props.getAuth().getAudience(),
                    null));
        };

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer), audience));
        return decoder;
    }

    /** Lets a browser-based console call the API during development. */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOriginPatterns("http://localhost:*")
                        .allowedMethods("GET", "POST")
                        .allowedHeaders("*");
            }
        };
    }
}
