package io.bloodhound.responder.security;

import io.bloodhound.responder.config.ResponderProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

/**
 * Resolves the caller's role and identity, whichever authentication mode is in use, and
 * enforces the role an endpoint requires.
 *
 * <p>Authorisation lives here — called explicitly from each endpoint — rather than in a list of
 * URL patterns in the security configuration. The role an action needs is then visible next to
 * the action itself, instead of in a separate file that drifts out of date the moment somebody
 * adds a route. For a platform whose endpoints can disable user accounts, that proximity is
 * worth more than the tidiness of centralising it.
 */
@Component
public class RequestContext {

    private final ResponderProperties props;

    public RequestContext(ResponderProperties props) {
        this.props = props;
    }

    public ApiKeyAuthFilter.Role role(HttpServletRequest request) {
        return switch (props.getAuth().getMode()) {
            case "oidc" -> oidcRole();
            case "apikey" -> apiKeyRole(request);
            // No authentication configured: everything is permitted, and the startup log says so.
            default -> ApiKeyAuthFilter.Role.RESPONDER;
        };
    }

    public String actor(HttpServletRequest request) {
        return switch (props.getAuth().getMode()) {
            case "oidc" -> Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                    .map(Authentication::getName)
                    .orElse("unauthenticated");
            case "apikey" -> {
                Object actor = request.getAttribute(ApiKeyAuthFilter.ACTOR_ATTRIBUTE);
                yield actor == null ? "unknown" : actor.toString();
            }
            default -> "anonymous";
        };
    }

    /**
     * @return the actor, for the audit log
     * @throws ResponseStatusException 401 if the caller presented no credentials at all,
     *         403 if they authenticated but lack the required role
     */
    public String require(HttpServletRequest request, ApiKeyAuthFilter.Role required) {
        // The distinction matters to whoever is calling. 401 means "authenticate and try
        // again"; 403 means "you did authenticate, and the answer is still no". Collapsing
        // both into 403 sends a client with an expired token off to debug its permissions,
        // and a client with no token off to request a role it already has.
        if (!isAuthenticated(request)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Authentication required: present a bearer token"
                            + ("apikey".equals(props.getAuth().getMode()) ? " or X-Api-Key" : ""));
        }

        ApiKeyAuthFilter.Role actual = role(request);
        if (actual == null || !actual.canAtLeast(required)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "This action requires the " + required + " role; you have "
                            + (actual == null ? "none" : actual));
        }
        return actor(request);
    }

    /**
     * Did the caller present credentials that checked out?
     *
     * <p>Separate from {@link #role}, because "authenticated with no roles" is a real and
     * important state — the {@code nobody} user in the Keycloak realm exists to hold this
     * open. Authentication answers who you are; it does not answer what you may do.
     */
    private boolean isAuthenticated(HttpServletRequest request) {
        return switch (props.getAuth().getMode()) {
            case "oidc" -> {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                yield auth != null && auth.isAuthenticated()
                        && !(auth instanceof AnonymousAuthenticationToken);
            }
            case "apikey" -> request.getAttribute(ApiKeyAuthFilter.ROLE_ATTRIBUTE) != null;
            default -> true;
        };
    }

    /**
     * Highest role granted by the token.
     *
     * <p>Returns null rather than a default when the token carries none of the three roles. That
     * case is real — an account can authenticate perfectly and be authorised for nothing — and
     * defaulting it to VIEWER would silently grant read access to every user in the realm.
     * Authentication answers "who are you"; it does not answer "what may you do".
     */
    private ApiKeyAuthFilter.Role oidcRole() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }
        ApiKeyAuthFilter.Role highest = null;
        for (GrantedAuthority authority : auth.getAuthorities()) {
            String name = authority.getAuthority().replaceFirst("^ROLE_", "");
            try {
                ApiKeyAuthFilter.Role role = ApiKeyAuthFilter.Role.valueOf(name);
                if (highest == null || role.canAtLeast(highest)) {
                    highest = role;
                }
            } catch (IllegalArgumentException ignored) {
                // An authority this platform does not model. Keycloak attaches several.
            }
        }
        return highest;
    }

    private ApiKeyAuthFilter.Role apiKeyRole(HttpServletRequest request) {
        Object role = request.getAttribute(ApiKeyAuthFilter.ROLE_ATTRIBUTE);
        return role instanceof ApiKeyAuthFilter.Role r ? r : null;
    }
}
