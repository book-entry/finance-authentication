package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseUserRecord;
import com.personal.finance.authentication.client.twilio.TwilioVerifyClient;
import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.dto.request.PasswordResetRequest;
import com.personal.finance.authentication.dto.request.PasswordResetSubmitRequest;
import com.personal.finance.authentication.dto.request.PasswordResetVerifyRequest;
import com.personal.finance.authentication.dto.request.PasswordUpdateRequest;
import com.personal.finance.authentication.dto.response.MessageResponse;
import com.personal.finance.authentication.dto.response.PasswordResetRequestResponse;
import com.personal.finance.authentication.dto.response.PasswordResetVerifyResponse;
import com.personal.finance.authentication.dto.response.PasswordUpdateRequestResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.util.JwtUtil;
import com.personal.finance.authentication.util.TokenContext;
import com.personal.finance.common.exception.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordServiceImplTest {

    @Mock FirebaseAuthClient firebaseClient;
    @Mock TwilioVerifyClient twilioClient;

    PasswordServiceImpl service;
    JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        AuthProperties props = new AuthProperties();
        props.getJwt().setSecret("0123456789abcdef0123456789abcdef0123456789abcdef");
        jwtUtil = new JwtUtil(props);
        service = new PasswordServiceImpl(firebaseClient, twilioClient, jwtUtil);
    }

    // ── §3.6 update-request ───────────────────────────────────────────────

    @Test
    void requestUpdate_happy_path_verifies_id_token_signs_action_token_dispatches_otp() {
        when(firebaseClient.verifyIdToken("id-token-A"))
                .thenReturn(new FirebaseUserRecord("uid-U", "u@example.com"));

        PasswordUpdateRequestResponse resp = service.requestUpdate("Bearer id-token-A");

        assertThat(resp.isRequiresOtp()).isTrue();
        assertThat(resp.getExpiresIn()).isEqualTo(300L);
        var claims = jwtUtil.validateAndParse(resp.getActionToken());
        assertThat(claims.get(JwtUtil.CLAIM_CTX, String.class)).isEqualTo(TokenContext.CTX_PWD_UPDATE);
        verify(twilioClient).sendVerification("u@example.com");
    }

    @Test
    void requestUpdate_without_bearer_prefix_throws_invalid_token() {
        assertThatThrownBy(() -> service.requestUpdate("id-token-A"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
    }

    @Test
    void requestUpdate_when_firebase_rejects_propagates() {
        when(firebaseClient.verifyIdToken(anyString()))
                .thenThrow(new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED));

        assertThatThrownBy(() -> service.requestUpdate("Bearer bad"))
                .isInstanceOf(AuthException.class);
    }

    // ── §3.7 submit-update ────────────────────────────────────────────────

    @Test
    void submitUpdate_happy_path_updates_password_returns_message() {
        String action = jwtUtil.generateToken("uid-U", "u@example.com",
                TokenContext.CTX_PWD_UPDATE, null, Duration.ofMinutes(5));

        MessageResponse resp = service.submitUpdate(submit(action, "123456", "NewPass1!"));

        verify(twilioClient).checkVerification("u@example.com", "123456");
        verify(firebaseClient).updatePassword("uid-U", "NewPass1!");
        assertThat(resp.getMessage()).isEqualTo("Password updated successfully");
    }

    @Test
    void submitUpdate_with_weak_password_throws_before_calling_twilio() {
        String action = jwtUtil.generateToken("uid-U", "u@example.com",
                TokenContext.CTX_PWD_UPDATE, null, Duration.ofMinutes(5));

        assertThatThrownBy(() -> service.submitUpdate(submit(action, "123456", "weak")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.WEAK_PASSWORD));
        verify(twilioClient, never()).checkVerification(anyString(), anyString());
    }

    @Test
    void submitUpdate_wrong_context_throws_wrong_context() {
        String wrongCtx = jwtUtil.generateToken("uid-U", "u@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));

        assertThatThrownBy(() -> service.submitUpdate(submit(wrongCtx, "123456", "NewPass1!")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.WRONG_CONTEXT));
    }

    // ── §3.8 reset-request ────────────────────────────────────────────────

    @Test
    void requestReset_known_email_signs_reset_token_and_dispatches_otp() {
        PasswordResetRequest req = resetReq("KNOWN@Example.com ");
        when(firebaseClient.getUserByEmailOrNull("known@example.com"))
                .thenReturn(new FirebaseUserRecord("uid-K", "known@example.com"));

        PasswordResetRequestResponse resp = service.requestReset(req);

        assertThat(resp.getRequiresOtp()).isTrue();
        assertThat(resp.getResetToken()).isNotBlank();
        var claims = jwtUtil.validateAndParse(resp.getResetToken());
        assertThat(claims.get(JwtUtil.CLAIM_CTX, String.class)).isEqualTo(TokenContext.CTX_PWD_RESET);
        assertThat(claims.get(JwtUtil.CLAIM_PHASE, String.class)).isEqualTo(TokenContext.PHASE_OTP);
        verify(twilioClient).sendVerification("known@example.com");
    }

    @Test
    void requestReset_unknown_email_returns_silent_anti_enumeration_response() {
        PasswordResetRequest req = resetReq("ghost@example.com");
        when(firebaseClient.getUserByEmailOrNull("ghost@example.com")).thenReturn(null);

        PasswordResetRequestResponse resp = service.requestReset(req);

        assertThat(resp.getRequiresOtp()).isFalse();
        assertThat(resp.getResetToken()).isNull();
        verify(twilioClient, never()).sendVerification(anyString());
    }

    // ── §3.9 reset-verify ─────────────────────────────────────────────────

    @Test
    void verifyReset_happy_path_returns_confirmed_token() {
        String resetToken = jwtUtil.generateToken("uid-K", "known@example.com",
                TokenContext.CTX_PWD_RESET, TokenContext.PHASE_OTP, Duration.ofMinutes(10));

        PasswordResetVerifyResponse resp = service.verifyReset(verifyReq(resetToken, "123456"));

        assertThat(resp.isOtpVerified()).isTrue();
        var claims = jwtUtil.validateAndParse(resp.getConfirmedToken());
        assertThat(claims.get(JwtUtil.CLAIM_PHASE, String.class)).isEqualTo(TokenContext.PHASE_CONFIRMED);
        verify(twilioClient).checkVerification("known@example.com", "123456");
    }

    @Test
    void verifyReset_token_with_wrong_phase_throws_invalid_token() {
        String confirmedAlready = jwtUtil.generateToken("uid-K", "known@example.com",
                TokenContext.CTX_PWD_RESET, TokenContext.PHASE_CONFIRMED, Duration.ofMinutes(10));

        assertThatThrownBy(() -> service.verifyReset(verifyReq(confirmedAlready, "123456")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
    }

    // ── §3.10 reset submit ────────────────────────────────────────────────

    @Test
    void submitReset_happy_path_updates_password() {
        String confirmed = jwtUtil.generateToken("uid-K", "known@example.com",
                TokenContext.CTX_PWD_RESET, TokenContext.PHASE_CONFIRMED, Duration.ofMinutes(5));

        MessageResponse resp = service.submitReset(resetSubmit(confirmed, "NewPass1!"));

        verify(firebaseClient).updatePassword("uid-K", "NewPass1!");
        assertThat(resp.getMessage()).isEqualTo("Password reset successfully");
    }

    @Test
    void submitReset_with_otp_phase_token_throws_invalid_token() {
        String otpPhase = jwtUtil.generateToken("uid-K", "known@example.com",
                TokenContext.CTX_PWD_RESET, TokenContext.PHASE_OTP, Duration.ofMinutes(5));

        assertThatThrownBy(() -> service.submitReset(resetSubmit(otpPhase, "NewPass1!")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
    }

    @Test
    void submitReset_with_weak_password_throws_weak_password() {
        String confirmed = jwtUtil.generateToken("uid-K", "known@example.com",
                TokenContext.CTX_PWD_RESET, TokenContext.PHASE_CONFIRMED, Duration.ofMinutes(5));

        assertThatThrownBy(() -> service.submitReset(resetSubmit(confirmed, "weak")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.WEAK_PASSWORD));
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private PasswordUpdateRequest submit(String token, String otp, String newPassword) {
        PasswordUpdateRequest r = new PasswordUpdateRequest();
        r.setActionToken(token);
        r.setOtp(otp);
        r.setNewPassword(newPassword);
        return r;
    }

    private PasswordResetRequest resetReq(String email) {
        PasswordResetRequest r = new PasswordResetRequest();
        r.setEmail(email);
        return r;
    }

    private PasswordResetVerifyRequest verifyReq(String token, String otp) {
        PasswordResetVerifyRequest r = new PasswordResetVerifyRequest();
        r.setResetToken(token);
        r.setOtp(otp);
        return r;
    }

    private PasswordResetSubmitRequest resetSubmit(String token, String newPassword) {
        PasswordResetSubmitRequest r = new PasswordResetSubmitRequest();
        r.setConfirmedToken(token);
        r.setNewPassword(newPassword);
        return r;
    }
}
