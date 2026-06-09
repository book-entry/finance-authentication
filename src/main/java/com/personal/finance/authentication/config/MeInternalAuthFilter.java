package com.personal.finance.authentication.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Lightweight gateway-envelope check for {@code /v1/me/**}.
 *
 * <p>Deliberately does NOT use finance-common's Spring-Security
 * {@code InternalRequestFilter}: it does not populate the {@code SecurityContext}
 * and does not validate the secret at application startup. Instead it performs a
 * plain per-request check that the gateway-injected envelope is present and the
 * shared secret matches, returning {@code 401} otherwise.
 *
 * <p>The configured secret is supplied with a blank default, so a missing
 * {@code INTERNAL_SERVICE_SECRET} no longer prevents the service from booting —
 * every {@code /v1/me} call is simply rejected with 401 until the secret is set
 * (and matches the gateway's value).
 */
@Slf4j
public class MeInternalAuthFilter extends OncePerRequestFilter {

    static final String SECRET_HEADER = "X-Internal-Secret";
    static final String USER_ID_HEADER = "X-User-Id";

    private final String configuredSecret;

    public MeInternalAuthFilter(String configuredSecret) {
        this.configuredSecret = configuredSecret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // Secret not configured on this service → cannot trust anything; reject.
        if (!StringUtils.hasText(configuredSecret)) {
            log.warn("/v1/me called but finance.security.internal.secret is not configured — rejecting");
            writeUnauthorized(response, "Internal authentication is not configured");
            return;
        }

        String incomingSecret = request.getHeader(SECRET_HEADER);
        if (!StringUtils.hasText(incomingSecret) || !constantTimeEquals(incomingSecret, configuredSecret)) {
            log.warn("/v1/me request with missing/invalid {} header", SECRET_HEADER);
            writeUnauthorized(response, "Invalid or missing internal secret");
            return;
        }

        String uid = request.getHeader(USER_ID_HEADER);
        if (!StringUtils.hasText(uid)) {
            log.warn("/v1/me request missing {} header", USER_ID_HEADER);
            writeUnauthorized(response, "User identity header is required");
            return;
        }

        chain.doFilter(request, response);
    }

    /** Constant-time comparison to avoid leaking the secret via response timing. */
    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"success\":false,\"error\":{\"code\":\"AUTH_001\",\"message\":\"" + message + "\"}}");
    }
}
