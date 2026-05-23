package com.personal.finance.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.personal.finance.authentication.dto.request.LoginRequest;
import com.personal.finance.authentication.dto.request.LoginVerifyOtpRequest;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.LoginResponse;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.exception.TwilioMaxAttemptsException;
import com.personal.finance.authentication.service.LoginService;
import com.personal.finance.common.exception.ErrorCode;
import com.personal.finance.common.web.ApiResponseBodyAdvice;
import com.personal.finance.common.web.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(LoginController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({GlobalExceptionHandler.class, ApiResponseBodyAdvice.class})
class LoginControllerTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @MockitoBean LoginService loginService;

    // ── §3.1 /v1/login ────────────────────────────────────────────────────

    @Test
    void login_happy_path_returns_202_and_wrapped_response() throws Exception {
        when(loginService.login(any())).thenReturn(LoginResponse.builder()
                .sessionToken("sess").requiresOtp(true).expiresIn(300L).build());
        LoginRequest req = new LoginRequest();
        req.setEmail("u@example.com");
        req.setPassword("Passw0rd!");

        mvc.perform(post("/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.sessionToken").value("sess"))
                .andExpect(jsonPath("$.data.requiresOtp").value(true))
                .andExpect(jsonPath("$.data.expiresIn").value(300));
    }

    @Test
    void login_with_missing_email_returns_400() throws Exception {
        LoginRequest req = new LoginRequest();
        req.setPassword("Passw0rd!");

        mvc.perform(post("/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("VAL_001"));
    }

    @Test
    void login_with_invalid_credentials_returns_401_invalid_credentials() throws Exception {
        when(loginService.login(any())).thenThrow(
                new AuthException(ErrorCode.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED));
        LoginRequest req = new LoginRequest();
        req.setEmail("u@example.com");
        req.setPassword("wrong");

        mvc.perform(post("/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_CREDENTIALS"));
    }

    // ── §3.2 /v1/login/verify-otp ─────────────────────────────────────────

    @Test
    void verifyOtp_happy_path_returns_200_with_tokens() throws Exception {
        when(loginService.verifyOtp(any())).thenReturn(AccessTokenResponse.builder()
                .accessToken("a").refreshToken("r").uid("u").build());
        LoginVerifyOtpRequest req = new LoginVerifyOtpRequest();
        req.setSessionToken("sess");
        req.setOtp("123456");

        mvc.perform(post("/v1/login/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("a"))
                .andExpect(jsonPath("$.data.refreshToken").value("r"))
                .andExpect(jsonPath("$.data.uid").value("u"));
    }

    @Test
    void verifyOtp_wrong_context_returns_400_wrong_context() throws Exception {
        when(loginService.verifyOtp(any())).thenThrow(
                new AuthException(ErrorCode.WRONG_CONTEXT, HttpStatus.BAD_REQUEST));
        LoginVerifyOtpRequest req = new LoginVerifyOtpRequest();
        req.setSessionToken("sess");
        req.setOtp("123456");

        mvc.perform(post("/v1/login/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("WRONG_CONTEXT"));
    }

    @Test
    void verifyOtp_twilio_max_attempts_returns_429() throws Exception {
        when(loginService.verifyOtp(any())).thenThrow(new TwilioMaxAttemptsException());
        LoginVerifyOtpRequest req = new LoginVerifyOtpRequest();
        req.setSessionToken("sess");
        req.setOtp("000000");

        mvc.perform(post("/v1/login/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("MAX_ATTEMPTS"));
    }

    // ── §3.3 /v1/login/oauth ──────────────────────────────────────────────

    @Test
    void oauthLogin_happy_path_returns_200_with_isNewUser() throws Exception {
        when(loginService.oauthLogin(any())).thenReturn(OAuthLoginResponse.builder()
                .accessToken("a").refreshToken("r").uid("u").isNewUser(true).build());
        OAuthLoginRequest req = new OAuthLoginRequest();
        req.setProvider("google");
        req.setIdToken("id-token");

        mvc.perform(post("/v1/login/oauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.isNewUser").value(true));
    }

    @Test
    void oauthLogin_invalid_provider_returns_400_invalid_provider() throws Exception {
        when(loginService.oauthLogin(any())).thenThrow(
                new AuthException(ErrorCode.INVALID_PROVIDER, HttpStatus.BAD_REQUEST));
        OAuthLoginRequest req = new OAuthLoginRequest();
        req.setProvider("facebook");
        req.setIdToken("id-token");

        mvc.perform(post("/v1/login/oauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("INVALID_PROVIDER"));
    }
}
