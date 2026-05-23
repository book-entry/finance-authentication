package com.personal.finance.authentication.util;

import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtUtilTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String OTHER_SECRET = "ffffffffffffffffffffffffffffffffffffffffffffffff";

    private JwtUtil jwt;

    @BeforeEach
    void setUp() {
        jwt = buildUtil(SECRET);
    }

    @Test
    void generate_then_parse_roundtrips_all_claims() {
        String token = jwt.generateToken("uid-1", "u@example.com",
                TokenContext.CTX_PWD_RESET, TokenContext.PHASE_OTP, Duration.ofMinutes(10));

        Claims claims = jwt.validateAndParse(token);

        assertThat(claims.get(JwtUtil.CLAIM_UID, String.class)).isEqualTo("uid-1");
        assertThat(claims.get(JwtUtil.CLAIM_EMAIL, String.class)).isEqualTo("u@example.com");
        assertThat(claims.get(JwtUtil.CLAIM_CTX, String.class)).isEqualTo(TokenContext.CTX_PWD_RESET);
        assertThat(claims.get(JwtUtil.CLAIM_PHASE, String.class)).isEqualTo(TokenContext.PHASE_OTP);
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull().isAfter(claims.getIssuedAt());
    }

    @Test
    void expired_token_throws_invalid_token() {
        // TTL of -1s — already expired at issue.
        String token = jwt.generateToken("uid-2", "u@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofSeconds(-1));

        assertThatThrownBy(() -> jwt.validateAndParse(token))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> {
                    AuthException ae = (AuthException) ex;
                    assertThat(ae.getErrorCode()).isEqualTo(ErrorCode.INVALID_TOKEN);
                });
    }

    @Test
    void token_signed_with_wrong_secret_throws_invalid_token() {
        JwtUtil other = buildUtil(OTHER_SECRET);
        String token = other.generateToken("uid-3", "u@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));

        assertThatThrownBy(() -> jwt.validateAndParse(token))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
    }

    @Test
    void malformed_token_throws_invalid_token() {
        assertThatThrownBy(() -> jwt.validateAndParse("not-a-jwt"))
                .isInstanceOf(AuthException.class);
        assertThatThrownBy(() -> jwt.validateAndParse(null))
                .isInstanceOf(AuthException.class);
        assertThatThrownBy(() -> jwt.validateAndParse(""))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void assertContext_passes_when_ctx_matches() {
        String token = jwt.generateToken("uid", "e@x.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));
        Claims claims = jwt.validateAndParse(token);

        jwt.assertContext(claims, TokenContext.CTX_LOGIN); // does not throw
    }

    @Test
    void assertContext_throws_wrong_context_on_mismatch() {
        String token = jwt.generateToken("uid", "e@x.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));
        Claims claims = jwt.validateAndParse(token);

        assertThatThrownBy(() -> jwt.assertContext(claims, TokenContext.CTX_REGISTER))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.WRONG_CONTEXT));
    }

    @Test
    void assertPhase_throws_invalid_token_on_mismatch() {
        String token = jwt.generateToken("uid", "e@x.com",
                TokenContext.CTX_PWD_RESET, TokenContext.PHASE_OTP, Duration.ofMinutes(5));
        Claims claims = jwt.validateAndParse(token);

        assertThatThrownBy(() -> jwt.assertPhase(claims, TokenContext.PHASE_CONFIRMED))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
    }

    @Test
    void short_secret_rejected_at_construction() {
        AuthProperties props = new AuthProperties();
        props.getJwt().setSecret("tooshort");
        assertThatThrownBy(() -> new JwtUtil(props))
                .isInstanceOf(IllegalStateException.class);
    }

    private static JwtUtil buildUtil(String secret) {
        AuthProperties props = new AuthProperties();
        props.getJwt().setSecret(secret);
        return new JwtUtil(props);
    }
}
