package io.bloodhound.responder.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/** Reads the authenticated role and actor off the request, and enforces the required role. */
@Component
public class RequestContext {

    public ApiKeyAuthFilter.Role role(HttpServletRequest request) {
        Object role = request.getAttribute(ApiKeyAuthFilter.ROLE_ATTRIBUTE);
        return role instanceof ApiKeyAuthFilter.Role r ? r : ApiKeyAuthFilter.Role.VIEWER;
    }

    public String actor(HttpServletRequest request) {
        Object actor = request.getAttribute(ApiKeyAuthFilter.ACTOR_ATTRIBUTE);
        return actor == null ? "unknown" : actor.toString();
    }

    /** @throws ResponseStatusException 403 if the caller's role is insufficient. */
    public String require(HttpServletRequest request, ApiKeyAuthFilter.Role required) {
        ApiKeyAuthFilter.Role actual = role(request);
        if (!actual.canAtLeast(required)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "This action requires the " + required + " role; you have " + actual);
        }
        return actor(request);
    }
}
