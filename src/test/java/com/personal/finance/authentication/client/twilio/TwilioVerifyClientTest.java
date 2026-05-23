package com.personal.finance.authentication.client.twilio;

import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.exception.TwilioMaxAttemptsException;
import com.personal.finance.common.exception.ErrorCode;
import com.twilio.exception.ApiException;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import com.twilio.rest.verify.v2.service.VerificationCheckCreator;
import com.twilio.rest.verify.v2.service.VerificationCreator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class TwilioVerifyClientTest {

    private static final String VERIFY_SID = "VA-test";

    TwilioVerifyClient client;
    AuthProperties props;

    @BeforeEach
    void setUp() {
        props = new AuthProperties();
        props.getTwilio().setVerifySid(VERIFY_SID);
        props.getTwilio().setChannel("email");
        client = new TwilioVerifyClient(props);
    }

    // ── sendVerification ──────────────────────────────────────────────────

    @Test
    void sendVerification_happy_path_creates_verification() {
        try (MockedStatic<Verification> mocked = mockStatic(Verification.class)) {
            VerificationCreator creator = mock(VerificationCreator.class);
            Verification verification = mock(Verification.class);
            mocked.when(() -> Verification.creator(VERIFY_SID, "u@example.com", "email"))
                    .thenReturn(creator);
            when(creator.create()).thenReturn(verification);

            assertThatCode(() -> client.sendVerification("u@example.com"))
                    .doesNotThrowAnyException();
        }
    }

    @Test
    void sendVerification_translates_twilio_429_to_too_many_requests() {
        try (MockedStatic<Verification> mocked = mockStatic(Verification.class)) {
            VerificationCreator creator = mock(VerificationCreator.class);
            ApiException apiEx = new ApiException("rate limit", 429, null, 429, null);
            mocked.when(() -> Verification.creator(any(), any(), any())).thenReturn(creator);
            when(creator.create()).thenThrow(apiEx);

            assertThatThrownBy(() -> client.sendVerification("u@example.com"))
                    .isInstanceOf(AuthException.class)
                    .satisfies(ex -> org.assertj.core.api.Assertions
                            .assertThat(((AuthException) ex).getErrorCode())
                            .isEqualTo(ErrorCode.TOO_MANY_REQUESTS));
        }
    }

    @Test
    void sendVerification_translates_unknown_twilio_failure_to_internal_error() {
        try (MockedStatic<Verification> mocked = mockStatic(Verification.class)) {
            VerificationCreator creator = mock(VerificationCreator.class);
            ApiException apiEx = new ApiException("oops", 500, null, 500, null);
            mocked.when(() -> Verification.creator(any(), any(), any())).thenReturn(creator);
            when(creator.create()).thenThrow(apiEx);

            assertThatThrownBy(() -> client.sendVerification("u@example.com"))
                    .isInstanceOf(AuthException.class)
                    .satisfies(ex -> org.assertj.core.api.Assertions
                            .assertThat(((AuthException) ex).getErrorCode())
                            .isEqualTo(ErrorCode.INTERNAL_ERROR));
        }
    }

    // ── checkVerification ─────────────────────────────────────────────────

    @Test
    void checkVerification_approved_returns_silently() {
        try (MockedStatic<VerificationCheck> mocked = mockStatic(VerificationCheck.class)) {
            VerificationCheckCreator creator =
                    mock(VerificationCheckCreator.class);
            VerificationCheck check = mock(VerificationCheck.class);
            mocked.when(() -> VerificationCheck.creator(VERIFY_SID)).thenReturn(creator);
            when(creator.setTo(any())).thenReturn(creator);
            when(creator.setCode(any())).thenReturn(creator);
            when(creator.create()).thenReturn(check);
            when(check.getStatus()).thenReturn("approved");

            assertThatCode(() -> client.checkVerification("u@example.com", "123456"))
                    .doesNotThrowAnyException();
        }
    }

    @Test
    void checkVerification_max_attempts_throws_TwilioMaxAttemptsException() {
        try (MockedStatic<VerificationCheck> mocked = mockStatic(VerificationCheck.class)) {
            VerificationCheckCreator creator =
                    mock(VerificationCheckCreator.class);
            VerificationCheck check = mock(VerificationCheck.class);
            mocked.when(() -> VerificationCheck.creator(VERIFY_SID)).thenReturn(creator);
            when(creator.setTo(any())).thenReturn(creator);
            when(creator.setCode(any())).thenReturn(creator);
            when(creator.create()).thenReturn(check);
            when(check.getStatus()).thenReturn("max-attempts-reached");

            assertThatThrownBy(() -> client.checkVerification("u@example.com", "000000"))
                    .isInstanceOf(TwilioMaxAttemptsException.class);
        }
    }

    @Test
    void checkVerification_pending_status_throws_invalid_otp() {
        try (MockedStatic<VerificationCheck> mocked = mockStatic(VerificationCheck.class)) {
            VerificationCheckCreator creator =
                    mock(VerificationCheckCreator.class);
            VerificationCheck check = mock(VerificationCheck.class);
            mocked.when(() -> VerificationCheck.creator(VERIFY_SID)).thenReturn(creator);
            when(creator.setTo(any())).thenReturn(creator);
            when(creator.setCode(any())).thenReturn(creator);
            when(creator.create()).thenReturn(check);
            when(check.getStatus()).thenReturn("pending");

            assertThatThrownBy(() -> client.checkVerification("u@example.com", "999999"))
                    .isInstanceOf(AuthException.class)
                    .satisfies(ex -> org.assertj.core.api.Assertions
                            .assertThat(((AuthException) ex).getErrorCode())
                            .isEqualTo(ErrorCode.INVALID_OTP));
        }
    }

    @Test
    void checkVerification_api_exception_translates_to_invalid_otp() {
        try (MockedStatic<VerificationCheck> mocked = mockStatic(VerificationCheck.class)) {
            VerificationCheckCreator creator =
                    mock(VerificationCheckCreator.class);
            ApiException apiEx = new ApiException("invalid", 404, null, 404, null);
            mocked.when(() -> VerificationCheck.creator(VERIFY_SID)).thenReturn(creator);
            when(creator.setTo(any())).thenReturn(creator);
            when(creator.setCode(any())).thenReturn(creator);
            when(creator.create()).thenThrow(apiEx);

            assertThatThrownBy(() -> client.checkVerification("u@example.com", "000000"))
                    .isInstanceOf(AuthException.class)
                    .satisfies(ex -> org.assertj.core.api.Assertions
                            .assertThat(((AuthException) ex).getErrorCode())
                            .isEqualTo(ErrorCode.INVALID_OTP));
        }
    }

    // ── bypass mode ───────────────────────────────────────────────────────

    @Test
    void sendVerification_in_bypass_mode_makes_no_twilio_call() {
        props.getTwilio().setBypass(true);
        try (MockedStatic<Verification> mocked = mockStatic(Verification.class)) {
            assertThatCode(() -> client.sendVerification("u@example.com"))
                    .doesNotThrowAnyException();
            // Static factory must not be touched at all.
            mocked.verifyNoInteractions();
        }
    }

    @Test
    void checkVerification_in_bypass_mode_accepts_fixed_code_silently() {
        props.getTwilio().setBypass(true);
        try (MockedStatic<VerificationCheck> mocked = mockStatic(VerificationCheck.class)) {
            assertThatCode(() -> client.checkVerification("u@example.com",
                    TwilioVerifyClient.BYPASS_OTP_CODE)).doesNotThrowAnyException();
            mocked.verifyNoInteractions();
        }
    }

    @Test
    void checkVerification_in_bypass_mode_rejects_other_codes_as_invalid_otp() {
        props.getTwilio().setBypass(true);
        try (MockedStatic<VerificationCheck> mocked = mockStatic(VerificationCheck.class)) {
            assertThatThrownBy(() -> client.checkVerification("u@example.com", "000000"))
                    .isInstanceOf(AuthException.class)
                    .satisfies(ex -> org.assertj.core.api.Assertions
                            .assertThat(((AuthException) ex).getErrorCode())
                            .isEqualTo(ErrorCode.INVALID_OTP));
            mocked.verifyNoInteractions();
        }
    }
}
