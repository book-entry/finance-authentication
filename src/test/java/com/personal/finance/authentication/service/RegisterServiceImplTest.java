package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseSignInResult;
import com.personal.finance.authentication.client.twilio.TwilioVerifyClient;
import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.dto.request.RegisterRequest;
import com.personal.finance.authentication.dto.request.RegisterVerifyOtpRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.RegisterResponse;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegisterServiceImplTest {

    @Mock FirebaseAuthClient firebaseClient;
    @Mock TwilioVerifyClient twilioClient;

    RegisterServiceImpl service;
    JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        AuthProperties props = new AuthProperties();
        props.getJwt().setSecret("0123456789abcdef0123456789abcdef0123456789abcdef");
        jwtUtil = new JwtUtil(props);
        service = new RegisterServiceImpl(firebaseClient, twilioClient, jwtUtil);
    }

    // ── §3.4 register ─────────────────────────────────────────────────────

    @Test
    void register_happy_path_normalises_email_creates_user_signs_token_dispatches_otp() {
        RegisterRequest req = req(" NEW@Example.com ", "Passw0rd!", "Alice");
        when(firebaseClient.createUser("new@example.com", "Passw0rd!", "Alice")).thenReturn("uid-N");

        RegisterResponse resp = service.register(req);

        assertThat(resp.isRequiresOtp()).isTrue();
        assertThat(resp.getExpiresIn()).isEqualTo(600L);
        assertThat(resp.getSessionToken()).isNotBlank();
        var claims = jwtUtil.validateAndParse(resp.getSessionToken());
        assertThat(claims.get(JwtUtil.CLAIM_CTX, String.class)).isEqualTo(TokenContext.CTX_REGISTER);
        assertThat(claims.get(JwtUtil.CLAIM_UID, String.class)).isEqualTo("uid-N");
        assertThat(claims.get(JwtUtil.CLAIM_EMAIL, String.class)).isEqualTo("new@example.com");
        assertThat(claims.get(RegisterServiceImpl.CLAIM_NAME, String.class)).isEqualTo("Alice");
        verify(twilioClient).sendVerification("new@example.com");
    }

    @Test
    void register_with_weak_password_throws_before_calling_firebase() {
        RegisterRequest req = req("new@example.com", "weak", "Alice");

        assertThatThrownBy(() -> service.register(req))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.WEAK_PASSWORD));
    }

    @Test
    void register_when_firebase_reports_email_in_use_bubbles_up() {
        RegisterRequest req = req("dupe@example.com", "Passw0rd!", "Alice");
        when(firebaseClient.createUser(anyString(), anyString(), anyString()))
                .thenThrow(new AuthException(ErrorCode.EMAIL_IN_USE, HttpStatus.CONFLICT));

        assertThatThrownBy(() -> service.register(req))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.EMAIL_IN_USE));
    }

    // ── §3.5 verify-otp ───────────────────────────────────────────────────

    @Test
    void verifyOtp_happy_path_marks_verified_then_issues_tokens() {
        String session = jwtUtil.generateTokenWithExtraClaim("uid-N", "new@example.com",
                TokenContext.CTX_REGISTER, null, Duration.ofMinutes(10),
                RegisterServiceImpl.CLAIM_NAME, "Alice");
        when(firebaseClient.issueTokensForUid("uid-N"))
                .thenReturn(FirebaseSignInResult.builder()
                        .accessToken("a").refreshToken("r").uid("uid-N").build());

        AccessTokenResponse resp = service.verifyOtp(otpReq(session, "123456"));

        verify(twilioClient).checkVerification("new@example.com", "123456");
        verify(firebaseClient).markEmailVerified("uid-N", "Alice");
        assertThat(resp.getAccessToken()).isEqualTo("a");
        assertThat(resp.getRefreshToken()).isEqualTo("r");
        assertThat(resp.getUid()).isEqualTo("uid-N");
    }

    @Test
    void verifyOtp_wrong_context_throws_wrong_context() {
        String wrongCtx = jwtUtil.generateToken("uid-N", "new@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(10));

        assertThatThrownBy(() -> service.verifyOtp(otpReq(wrongCtx, "123456")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.WRONG_CONTEXT));
    }

    @Test
    void verifyOtp_twilio_invalid_otp_propagates() {
        String session = jwtUtil.generateToken("uid-N", "new@example.com",
                TokenContext.CTX_REGISTER, null, Duration.ofMinutes(10));
        org.mockito.Mockito.doThrow(new AuthException(
                        ErrorCode.INVALID_OTP, HttpStatus.UNAUTHORIZED))
                .when(twilioClient).checkVerification(any(), any());

        assertThatThrownBy(() -> service.verifyOtp(otpReq(session, "000000")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_OTP));
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private RegisterRequest req(String email, String password, String name) {
        RegisterRequest r = new RegisterRequest();
        r.setEmail(email);
        r.setPassword(password);
        r.setName(name);
        return r;
    }

    private RegisterVerifyOtpRequest otpReq(String session, String otp) {
        RegisterVerifyOtpRequest r = new RegisterVerifyOtpRequest();
        r.setSessionToken(session);
        r.setOtp(otp);
        return r;
    }
}
