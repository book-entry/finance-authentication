package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.twilio.TwilioVerifyClient;
import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.dto.request.ResendOtpRequest;
import com.personal.finance.authentication.dto.response.ResendOtpResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.exception.RedisUnavailableException;
import com.personal.finance.authentication.exception.ResendCooldownException;
import com.personal.finance.authentication.util.JwtUtil;
import com.personal.finance.authentication.util.TokenContext;
import com.personal.finance.common.exception.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OtpServiceImplTest {

    @Mock TwilioVerifyClient twilioClient;
    @Mock RedisTemplate<String, String> redisTemplate;
    @Mock ValueOperations<String, String> valueOps;

    OtpServiceImpl service;
    JwtUtil jwtUtil;
    AuthProperties props;

    @BeforeEach
    void setUp() {
        props = new AuthProperties();
        props.getJwt().setSecret("0123456789abcdef0123456789abcdef0123456789abcdef");
        props.getOtp().setResendCooldownSeconds(60L);
        jwtUtil = new JwtUtil(props);
        service = new OtpServiceImpl(twilioClient, jwtUtil, redisTemplate, props);
    }

    @Test
    void resend_happy_path_sets_cooldown_and_dispatches_otp() {
        String token = jwtUtil.generateToken("uid-1", "u@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get("resend-cooldown:uid-1")).thenReturn(null);

        ResendOtpResponse resp = service.resend(req(token));

        verify(valueOps).set(eq("resend-cooldown:uid-1"), eq("1"), eq(Duration.ofSeconds(60)));
        verify(twilioClient).sendVerification("u@example.com");
        assertThat(resp.getMessage()).isEqualTo("OTP resent");
        assertThat(resp.getRetryAfter()).isEqualTo(60L);
    }

    @Test
    void resend_with_cooldown_active_throws_resend_too_soon() {
        String token = jwtUtil.generateToken("uid-1", "u@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get("resend-cooldown:uid-1")).thenReturn("1");
        when(redisTemplate.getExpire("resend-cooldown:uid-1", TimeUnit.SECONDS)).thenReturn(42L);

        assertThatThrownBy(() -> service.resend(req(token)))
                .isInstanceOf(ResendCooldownException.class)
                .satisfies(ex -> assertThat(((ResendCooldownException) ex).getRetryAfterSeconds())
                        .isEqualTo(42L));
        verify(twilioClient, never()).sendVerification(anyString());
    }

    @Test
    void resend_when_redis_unavailable_translates_to_redis_unavailable_exception() {
        String token = jwtUtil.generateToken("uid-1", "u@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString()))
                .thenThrow(new RedisConnectionFailureException("down"));

        assertThatThrownBy(() -> service.resend(req(token)))
                .isInstanceOf(RedisUnavailableException.class);
        verify(twilioClient, never()).sendVerification(anyString());
    }

    @Test
    void resend_with_confirmed_phase_token_throws_invalid_token() {
        String confirmed = jwtUtil.generateToken("uid-1", "u@example.com",
                TokenContext.CTX_PWD_RESET, TokenContext.PHASE_CONFIRMED, Duration.ofMinutes(5));

        assertThatThrownBy(() -> service.resend(req(confirmed)))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
        verify(twilioClient, never()).sendVerification(anyString());
    }

    @Test
    void resend_with_expired_token_throws_invalid_token() {
        String expired = jwtUtil.generateToken("uid-1", "u@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofSeconds(-1));

        assertThatThrownBy(() -> service.resend(req(expired)))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
    }

    private ResendOtpRequest req(String token) {
        ResendOtpRequest r = new ResendOtpRequest();
        r.setToken(token);
        return r;
    }
}
