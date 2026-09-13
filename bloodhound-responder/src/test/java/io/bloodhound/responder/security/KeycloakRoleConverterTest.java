package io.bloodhound.responder.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakRoleConverterTest {

    private final KeycloakRoleConverter converter = new KeycloakRoleConverter();

    private static Jwt token(String username, List<String> realmRoles) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("f7c3-uuid")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("preferred_username", username)
                .audience(List.of("bloodhound-responder"));
        if (realmRoles != null) {
            builder.claim("realm_access", Map.of("roles", realmRoles));
        }
        return builder.build();
    }

    private static List<String> authorities(AbstractAuthenticationToken auth) {
        return auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList();
    }

    @Test
    void mapsRealmRolesToAuthorities() {
        AbstractAuthenticationToken auth = converter.convert(token("rae", List.of("RESPONDER")));
        assertThat(authorities(auth)).containsExactly("ROLE_RESPONDER");
    }

    /**
     * Keycloak attaches offline_access, uma_authorization and default-roles-* to every user.
     * Admitting them would let the identity provider's own bookkeeping shape this platform's
     * authorisation model.
     */
    @Test
    void ignoresRolesThisPlatformDoesNotModel() {
        AbstractAuthenticationToken auth = converter.convert(token("ana", List.of(
                "ANALYST", "offline_access", "uma_authorization", "default-roles-bloodhound")));

        assertThat(authorities(auth)).containsExactly("ROLE_ANALYST");
    }

    /**
     * The case the `nobody` user in the realm exists to hold open: a token that verifies
     * perfectly and grants nothing. Authentication is not authorisation.
     */
    @Test
    void aTokenWithNoRecognisedRolesGrantsNoAuthorities() {
        assertThat(authorities(converter.convert(token("nobody", List.of("offline_access")))))
                .isEmpty();
        assertThat(authorities(converter.convert(token("nobody", List.of())))).isEmpty();
    }

    /** A token with no realm_access claim at all must not blow up the filter chain. */
    @Test
    void toleratesAMissingRealmAccessClaim() {
        AbstractAuthenticationToken auth = converter.convert(token("stranger", null));
        assertThat(authorities(auth)).isEmpty();
        assertThat(auth.getName()).isEqualTo("stranger");
    }

    /**
     * The principal becomes the actor in the audit log, so it must be the human-readable
     * username rather than the subject UUID. "Who disabled this account" needs a name.
     */
    @Test
    void principalIsTheUsernameNotTheSubjectUuid() {
        AbstractAuthenticationToken auth = converter.convert(token("rae", List.of("RESPONDER")));
        assertThat(auth.getName()).isEqualTo("rae");
        assertThat(auth.getName()).isNotEqualTo("f7c3-uuid");
    }

    @Test
    void roleHierarchyOrdersCapabilities() {
        assertThat(ApiKeyAuthFilter.Role.RESPONDER.canAtLeast(ApiKeyAuthFilter.Role.ANALYST)).isTrue();
        assertThat(ApiKeyAuthFilter.Role.RESPONDER.canAtLeast(ApiKeyAuthFilter.Role.VIEWER)).isTrue();
        assertThat(ApiKeyAuthFilter.Role.ANALYST.canAtLeast(ApiKeyAuthFilter.Role.RESPONDER)).isFalse();
        assertThat(ApiKeyAuthFilter.Role.VIEWER.canAtLeast(ApiKeyAuthFilter.Role.ANALYST)).isFalse();
    }
}
