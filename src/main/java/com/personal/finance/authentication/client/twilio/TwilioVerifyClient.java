package com.personal.finance.authentication.client.twilio;

import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.exception.TwilioMaxAttemptsException;
import com.personal.finance.common.exception.ErrorCode;
import com.twilio.exception.ApiException;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/**
 * Wrapper around Twilio Verify {@code Verification} and {@code VerificationCheck}
 * endpoints. Translates Twilio statuses into spec-aligned exceptions so service
 * code never imports {@code com.twilio.*}.
 *
 * <p>Status mapping (spec §3.2 step 4 / §6.2):
 * <ul>
 *   <li>{@code approved} → silent success</li>
 *   <li>{@code max-attempts-reached} → {@link TwilioMaxAttemptsException}</li>
 *   <li>any other → {@link AuthException} with {@code INVALID_OTP}</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TwilioVerifyClient {

    public static final String STATUS_APPROVED = "approved";
    public static final String STATUS_MAX_ATTEMPTS = "max-attempts-reached";

    /**
     * Fixed code accepted when {@code app.twilio.bypass=true}. Local-testing
     * only — used so the full OTP flow (send → verify) can be exercised
     * without a configured Twilio account.
     */
    public static final String BYPASS_OTP_CODE = "123456";

    private final AuthProperties properties;

    /**
     * Implements spec §3.1 step 5 / §3.4 step 5 / §3.6 step 4 / §3.8 step 4 /
     * §3.11 step 5 — dispatch a new OTP via Twilio Verify.
     */
    public void sendVerification(String to) {
        if (properties.getTwilio().isBypass()) {
            log.warn("Twilio bypass enabled — skipping Verification dispatch for [{}]", maskEmail(to));
            return;
        }
        try {
            Verification.creator(properties.getTwilio().getVerifySid(), to,
                            properties.getTwilio().getChannel())
                    .create();
        } catch (ApiException ex) {
            log.warn("Twilio Verification creation failed for [{}]: {}", maskEmail(to), ex.getMessage());
            translateRateLimit(ex);
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    /**
     * Implements spec §3.2 step 3 / §3.5 step 2 / §3.7 step 3 / §3.9 step 2 —
     * check a submitted code against Twilio.
     */
    public void checkVerification(String to, String code) {
        if (properties.getTwilio().isBypass()) {
            // Bypass mode: only the fixed code is accepted; everything else is
            // rejected with the same INVALID_OTP path used in real operation.
            if (BYPASS_OTP_CODE.equals(code)) {
                log.warn("Twilio bypass enabled — accepting fixed OTP for [{}]", maskEmail(to));
                return;
            }
            throw new AuthException(ErrorCode.INVALID_OTP, HttpStatus.UNAUTHORIZED,
                    "The OTP provided is incorrect");
        }
        String status;
        try {
            VerificationCheck check = VerificationCheck.creator(properties.getTwilio().getVerifySid())
                    .setTo(to)
                    .setCode(code)
                    .create();
            status = check.getStatus();
        } catch (ApiException ex) {
            log.debug("Twilio VerificationCheck failed for [{}]: {}", maskEmail(to), ex.getMessage());
            translateRateLimit(ex);
            // Per spec §3.2: anything other than 'approved' is INVALID_OTP.
            throw new AuthException(ErrorCode.INVALID_OTP, HttpStatus.UNAUTHORIZED,
                    "The OTP provided is incorrect");
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
        if (STATUS_MAX_ATTEMPTS.equals(status)) {
            throw new TwilioMaxAttemptsException();
        }
        if (!STATUS_APPROVED.equals(status)) {
            throw new AuthException(ErrorCode.INVALID_OTP, HttpStatus.UNAUTHORIZED,
                    "The OTP provided is incorrect");
        }
    }

    private void translateRateLimit(ApiException ex) {
        Integer statusCode = ex.getStatusCode();
        if (statusCode != null && statusCode == HttpStatus.TOO_MANY_REQUESTS.value()) {
            throw new AuthException(ErrorCode.TOO_MANY_REQUESTS, HttpStatus.TOO_MANY_REQUESTS,
                    "Twilio rate limit exceeded");
        }
    }

    private static String maskEmail(String to) {
        if (to == null) return "<null>";
        int at = to.indexOf('@');
        if (at <= 1) return "***" + to.substring(Math.max(0, to.length() - 4));
        return to.charAt(0) + "***" + to.substring(at);
    }
}
