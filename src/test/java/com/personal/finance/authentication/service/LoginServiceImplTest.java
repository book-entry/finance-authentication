package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseSignInResult;
import com.personal.finance.authentication.client.twilio.TwilioVerifyClient;
import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.dto.request.LoginRequest;
import com.personal.finance.authentication.dto.request.LoginVerifyOtpRequest;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.LoginResponse;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.exception.TwilioMaxAttemptsException;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginServiceImplTest {

    @Mock FirebaseAuthClient firebaseClient;
    @Mock TwilioVerifyClient twilioClient;

    LoginServiceImpl service;
    JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        AuthProperties props = new AuthProperties();
        props.getJwt().setSecret("0123456789abcdef0123456789abcdef0123456789abcdef");
        jwtUtil = new JwtUtil(props);
        service = new LoginServiceImpl(firebaseClient, twilioClient, jwtUtil);
    }

    // ── §3.1 login ────────────────────────────────────────────────────────

    @Test
    void login_happy_path_normalises_email_signs_token_dispatches_otp() {
        LoginRequest request = req("USER@Example.COM ", "Passw0rd!");
        when(firebaseClient.signInWithEmailAndPassword("user@example.com", "Passw0rd!"))
                .thenReturn(FirebaseSignInResult.builder().uid("uid-1").build());

        LoginResponse resp = service.login(request);

        assertThat(resp.isRequiresOtp()).isTrue();
        assertThat(resp.getExpiresIn()).isEqualTo(300L);
        assertThat(resp.getSessionToken()).isNotBlank();
        // Token is for ctx=login per spec §3.1 step 4
        var claims = jwtUtil.validateAndParse(resp.getSessionToken());
        assertThat(claims.get(JwtUtil.CLAIM_CTX, String.class)).isEqualTo(TokenContext.CTX_LOGIN);
        assertThat(claims.get(JwtUtil.CLAIM_UID, String.class)).isEqualTo("uid-1");
        assertThat(claims.get(JwtUtil.CLAIM_EMAIL, String.class)).isEqualTo("user@example.com");
        verify(twilioClient).sendVerification("user@example.com");
    }

    @Test
    void login_when_firebase_rejects_propagates_invalid_credentials() {
        LoginRequest request = req("user@example.com", "wrong");
        when(firebaseClient.signInWithEmailAndPassword(anyString(), anyString()))
                .thenThrow(new AuthException(ErrorCode.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED));

        assertThatThrownBy(() -> service.login(request))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_CREDENTIALS));
    }

    // ── §3.2 verify-otp ───────────────────────────────────────────────────

    @Test
    void verifyOtp_happy_path_returns_access_and_refresh_tokens() {
        String session = jwtUtil.generateToken("uid-1", "user@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));
        when(firebaseClient.issueTokensForUid("uid-1"))
                .thenReturn(FirebaseSignInResult.builder()
                        .accessToken("access").refreshToken("refresh").uid("uid-1")
                        .displayName("Alice").build());

        AccessTokenResponse resp = service.verifyOtp(otpReq(session, "123456"));

        verify(twilioClient).checkVerification("user@example.com", "123456");
        assertThat(resp.getAccessToken()).isEqualTo("access");
        assertThat(resp.getRefreshToken()).isEqualTo("refresh");
        assertThat(resp.getUid()).isEqualTo("uid-1");
        assertThat(resp.getDisplayName()).isEqualTo("Alice");
    }

    @Test
    void verifyOtp_wrong_context_token_throws_wrong_context() {
        String wrongCtx = jwtUtil.generateToken("uid-1", "user@example.com",
                TokenContext.CTX_REGISTER, null, Duration.ofMinutes(5));

        assertThatThrownBy(() -> service.verifyOtp(otpReq(wrongCtx, "123456")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.WRONG_CONTEXT));
    }

    @Test
    void verifyOtp_expired_token_throws_invalid_token() {
        String expired = jwtUtil.generateToken("uid-1", "user@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofSeconds(-1));

        assertThatThrownBy(() -> service.verifyOtp(otpReq(expired, "123456")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
    }

    @Test
    void verifyOtp_twilio_max_attempts_bubbles_up() {
        String session = jwtUtil.generateToken("uid-1", "user@example.com",
                TokenContext.CTX_LOGIN, null, Duration.ofMinutes(5));
        doThrow(new TwilioMaxAttemptsException())
                .when(twilioClient).checkVerification(eq("user@example.com"), anyString());

        assertThatThrownBy(() -> service.verifyOtp(otpReq(session, "000000")))
                .isInstanceOf(TwilioMaxAttemptsException.class);
    }

    // ── §3.3 oauth ────────────────────────────────────────────────────────

    @Test
    void oauthLogin_happy_path_maps_google_to_firebase_provider() {
        when(firebaseClient.signInWithIdpCredential(eq("google.com"), anyString()))
                .thenReturn(FirebaseSignInResult.builder()
                        .accessToken("a").refreshToken("r").uid("u")
                        .displayName("Alice").isNewUser(true).build());

        OAuthLoginResponse resp = service.oauthLogin(oauth("google", "id-token"));

        assertThat(resp.getUid()).isEqualTo("u");
        assertThat(resp.isNewUser()).isTrue();
        assertThat(resp.getDisplayName()).isEqualTo("Alice");
    }

    @Test
    void oauthLogin_unknown_provider_throws_invalid_provider() {
        assertThatThrownBy(() -> service.oauthLogin(oauth("facebook", "id-token")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_PROVIDER));
    }

    @Test
    void oauthLogin_firebase_rejection_translates_to_invalid_id_token() {
        when(firebaseClient.signInWithIdpCredential(any(), any()))
                .thenThrow(new AuthException(ErrorCode.INVALID_ID_TOKEN, HttpStatus.UNAUTHORIZED));

        assertThatThrownBy(() -> service.oauthLogin(oauth("apple", "bad")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_ID_TOKEN));
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private LoginRequest req(String email, String password) {
        LoginRequest r = new LoginRequest();
        r.setEmail(email);
        r.setPassword(password);
        return r;
    }

    private LoginVerifyOtpRequest otpReq(String session, String otp) {
        LoginVerifyOtpRequest r = new LoginVerifyOtpRequest();
        r.setSessionToken(session);
        r.setOtp(otp);
        return r;
    }

    private OAuthLoginRequest oauth(String provider, String idToken) {
        OAuthLoginRequest r = new OAuthLoginRequest();
        r.setProvider(provider);
        r.setIdToken(idToken);
        return r;
    }
}
