package com.personal.finance.authentication.util;

import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;

/**
 * HS256 JWT helper for the short-lived tokens defined in spec §4 (sessionToken,
 * actionToken, resetToken, confirmedToken).
 *
 * <p>Claims include {@code uid}, {@code email}, {@code ctx}, {@code phase}
 * (nullable), {@code iat}, {@code exp}.
 */
@Component
@Slf4j
public class JwtUtil {

    public static final String CLAIM_UID = "uid";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_CTX = "ctx";
    public static final String CLAIM_PHASE = "phase";

    private final SecretKey signingKey;

    public JwtUtil(AuthProperties props) {
        String secret = props.getJwt().getSecret();
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException(
                    "app.jwt.secret must be configured and at least 32 characters long");
        }
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Sign and serialise a new token. {@code phase} may be {@code null} for
     * tokens that do not carry a phase claim (sessionToken/actionToken).
     */
    public String generateToken(String uid, String email, String ctx, String phase, Duration ttl) {
        return generateTokenWithExtraClaim(uid, email, ctx, phase, ttl, null, null);
    }

    /**
     * Variant that bakes an additional named claim into the token — used by
     * the register flow to carry {@code name} across the OTP boundary.
     */
    public String generateTokenWithExtraClaim(String uid, String email, String ctx, String phase,
                                              Duration ttl, String extraClaimName, Object extraClaimValue) {
        long nowMs = System.currentTimeMillis();
        var builder = Jwts.builder()
                .claim(CLAIM_UID, uid)
                .claim(CLAIM_EMAIL, email)
                .claim(CLAIM_CTX, ctx)
                .issuedAt(new Date(nowMs))
                .expiration(new Date(nowMs + ttl.toMillis()))
                .signWith(signingKey);
        if (phase != null) {
            builder.claim(CLAIM_PHASE, phase);
        }
        if (extraClaimName != null && extraClaimValue != null) {
            builder.claim(extraClaimName, extraClaimValue);
        }
        return builder.compact();
    }

    /**
     * Verify signature, expiry, and structure. Throws
     * {@link AuthException} with {@code INVALID_TOKEN} on any failure.
     */
    public Claims validateAndParse(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.BAD_REQUEST,
                    "Token is missing");
        }
        try {
            return Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("JWT validation failed: {}", ex.getMessage());
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.BAD_REQUEST,
                    "Token is invalid or expired");
        }
    }

    /**
     * Assert that the token's {@code ctx} claim equals {@code expectedCtx}.
     * Throws {@link AuthException} with {@code WRONG_CONTEXT} otherwise.
     */
    public void assertContext(Claims claims, String expectedCtx) {
        String actual = claims.get(CLAIM_CTX, String.class);
        if (!expectedCtx.equals(actual)) {
            throw new AuthException(ErrorCode.WRONG_CONTEXT, HttpStatus.BAD_REQUEST,
                    "Expected ctx '" + expectedCtx + "' but token carries '" + actual + "'");
        }
    }

    /**
     * Assert that the token's {@code phase} claim equals {@code expectedPhase}.
     * Throws {@link AuthException} with {@code INVALID_TOKEN} otherwise — phase
     * skipping is reported with the same code as a malformed token to avoid
     * leaking internal state to callers.
     */
    public void assertPhase(Claims claims, String expectedPhase) {
        String actual = claims.get(CLAIM_PHASE, String.class);
        if (!expectedPhase.equals(actual)) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.BAD_REQUEST,
                    "Expected phase '" + expectedPhase + "' but token carries '" + actual + "'");
        }
    }
}
