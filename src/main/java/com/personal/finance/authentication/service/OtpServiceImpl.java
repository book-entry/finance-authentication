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
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class OtpServiceImpl implements OtpService {

    private static final String COOLDOWN_KEY_PREFIX = "resend-cooldown:";

    private final TwilioVerifyClient twilioClient;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;
    private final AuthProperties properties;

    /**
     * Spec §3.11 — High-Level Logic:
     * <ol>
     *   <li>Verify + decode the submitted token (any ctx). Reject expired
     *       or {@code phase === 'confirmed'} tokens with INVALID_TOKEN.</li>
     *   <li>Extract uid from token claims.</li>
     *   <li>Redis GET resend-cooldown:{uid}; if present, 429 RESEND_TOO_SOON
     *       with remaining TTL as retryAfter.</li>
     *   <li>SET resend-cooldown:{uid} = 1 with 60s TTL.</li>
     *   <li>Twilio dispatch new OTP.</li>
     *   <li>Return 200 { message: 'OTP resent', retryAfter: 60 }.</li>
     * </ol>
     * Any Redis failure surfaces as {@link RedisUnavailableException} (503).
     */
    @Override
    public ResendOtpResponse resend(ResendOtpRequest request) {
        Claims claims = jwtUtil.validateAndParse(request.getToken());
        rejectConfirmedPhase(claims);
        String uid = claims.get(JwtUtil.CLAIM_UID, String.class);
        String email = claims.get(JwtUtil.CLAIM_EMAIL, String.class);
        if (uid == null || email == null) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.BAD_REQUEST,
                    "Token is missing required claims");
        }
        String key = COOLDOWN_KEY_PREFIX + uid;
        enforceCooldownAndSet(key);
        twilioClient.sendVerification(email);
        long cooldown = properties.getOtp().getResendCooldownSeconds();
        log.info("OTP resent for uid [{}] — cooldown [{}s]", uid, cooldown);
        return ResendOtpResponse.builder()
                .message("OTP resent")
                .retryAfter(cooldown)
                .build();
    }

    /**
     * Per spec §3.11: confirmedToken (phase=confirmed) is past the OTP step and
     * must be rejected here with INVALID_TOKEN.
     */
    private void rejectConfirmedPhase(Claims claims) {
        String phase = claims.get(JwtUtil.CLAIM_PHASE, String.class);
        if (TokenContext.PHASE_CONFIRMED.equals(phase)) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.BAD_REQUEST,
                    "Token cannot be used for resend");
        }
    }

    /**
     * GETs the cooldown key; throws ResendCooldownException if still alive.
     * Otherwise atomically sets the key with TTL. Any Redis exception is
     * translated into RedisUnavailableException to fail closed per spec §6.2.
     */
    private void enforceCooldownAndSet(String key) {
        try {
            String existing = redisTemplate.opsForValue().get(key);
            if (existing != null) {
                Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
                long retryAfter = ttl != null && ttl > 0 ? ttl : properties.getOtp().getResendCooldownSeconds();
                throw new ResendCooldownException(retryAfter);
            }
            Duration ttl = Duration.ofSeconds(properties.getOtp().getResendCooldownSeconds());
            redisTemplate.opsForValue().set(key, "1", ttl);
        } catch (ResendCooldownException ex) {
            throw ex;
        } catch (DataAccessException ex) {
            log.error("Redis unavailable while enforcing resend cooldown", ex);
            throw new RedisUnavailableException(ex);
        } catch (Exception ex) {
            log.error("Unexpected Redis failure while enforcing resend cooldown", ex);
            throw new RedisUnavailableException(ex);
        }
    }
}
