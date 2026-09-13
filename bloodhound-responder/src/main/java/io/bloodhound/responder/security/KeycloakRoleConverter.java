package io.bloodhound.responder.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns Keycloak's {@code realm_access.roles} claim into Spring Security authorities.
 *
 * <p>Spring's default converter reads the {@code scope} claim, which Keycloak does not use for
 * roles — so without this every authenticated user arrives with no authorities at all and every
 * request is refused. The symptom is a 403 for a user who visibly has the right role in Keycloak,
 * which is a confusing morning.
 *
 * <p>Only the three roles this platform defines are mapped. A realm may carry dozens of unrelated
 * roles (Keycloak adds {@code offline_access}, {@code uma_authorization} and a
 * {@code default-roles-*} to every user); admitting them as authorities would mean an
 * authorisation model shaped by whatever the identity provider happens to include.
 */
public class KeycloakRoleConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final Set<String> RECOGNISED = Set.of("VIEWER", "ANALYST", "RESPONDER");

    @Override
    @SuppressWarnings("unchecked")
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");

        List<String> roles = realmAccess == null
                ? List.of()
                : (List<String>) realmAccess.getOrDefault("roles", List.of());

        Collection<GrantedAuthority> authorities = roles.stream()
                .filter(RECOGNISED::contains)
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                .toList();

        // The principal name becomes the actor in the audit log. `preferred_username` rather
        // than `sub` because a human reading "who disabled this account" needs a name, not a
        // UUID — and unlike the shared API keys, this one identifies a person.
        return new JwtAuthenticationToken(jwt, authorities, jwt.getClaimAsString("preferred_username"));
    }
}
