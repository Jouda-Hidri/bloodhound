package io.bloodhound.responder.security;

import io.bloodhound.responder.config.ResponderProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/**
 * API key authentication with three roles.
 *
 * <p>This is lab-grade and says so: keys live in configuration, never expire, and cannot be
 * rotated without a restart. Proper OIDC against Keycloak is the remaining Week 19 work.
 *
 * <p>What it does get right is the part worth learning — <b>least privilege</b>. Reading alerts
 * and disabling an account are different capabilities:
 *
 * <ul>
 *   <li>{@code VIEWER} — read alerts, incidents, risk</li>
 *   <li>{@code ANALYST} — the above, plus triage verdicts and incident state changes</li>
 *   <li>{@code RESPONDER} — the above, plus approving and executing containment</li>
 * </ul>
 *
 * <p>The role that can lock users out is deliberately the hardest to hold. On a real platform the
 * response role is the one an attacker most wants, because it turns your own security tooling into
 * their denial-of-service.
 */
@Component
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String ROLE_ATTRIBUTE = "bloodhound.role";
    public static final String ACTOR_ATTRIBUTE = "bloodhound.actor";
    private static final String HEADER = "X-Api-Key";

    private final ResponderProperties props;

    public ApiKeyAuthFilter(ResponderProperties props) {
        this.props = props;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Health and metrics stay open so Prometheus and Docker health checks work without
        // handing a scraper a credential.
        return path.startsWith("/actuator");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!props.getAuth().isEnabled()) {
            request.setAttribute(ROLE_ATTRIBUTE, Role.RESPONDER);
            request.setAttribute(ACTOR_ATTRIBUTE, "anonymous");
            chain.doFilter(request, response);
            return;
        }

        String presented = request.getHeader(HEADER);
        String role = presented == null ? null : lookup(presented);

        if (role == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"error\":\"missing or invalid " + HEADER + " header\"}");
            return;
        }

        request.setAttribute(ROLE_ATTRIBUTE, Role.valueOf(role));
        // The actor recorded in the audit log. A shared key means the audit trail can only say
        // "someone holding the responder key" — another reason real deployments need real identity.
        request.setAttribute(ACTOR_ATTRIBUTE, role.toLowerCase() + "@apikey");
        chain.doFilter(request, response);
    }

    /**
     * Compares in constant time against every configured key.
     *
     * <p>A short-circuiting comparison leaks key material through timing. It is a small risk for a
     * lab, and getting it right costs three lines.
     */
    private String lookup(String presented) {
        byte[] presentedBytes = presented.getBytes(StandardCharsets.UTF_8);
        String match = null;
        for (Map.Entry<String, String> entry : props.getAuth().getKeys().entrySet()) {
            if (MessageDigest.isEqual(presentedBytes, entry.getKey().getBytes(StandardCharsets.UTF_8))) {
                match = entry.getValue();
            }
        }
        return match;
    }

    public enum Role {
        VIEWER, ANALYST, RESPONDER;

        public boolean canAtLeast(Role required) {
            return ordinal() >= required.ordinal();
        }
    }
}
