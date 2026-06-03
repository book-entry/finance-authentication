package com.personal.finance.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.personal.finance.authentication.dto.request.RegisterRequest;
import com.personal.finance.authentication.dto.request.RegisterVerifyOtpRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.RegisterResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.exception.TwilioMaxAttemptsException;
import com.personal.finance.authentication.service.RegisterService;
import com.personal.finance.common.exception.ErrorCode;
import com.personal.finance.common.web.ApiResponseBodyAdvice;
import com.personal.finance.common.web.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(RegisterController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({GlobalExceptionHandler.class, ApiResponseBodyAdvice.class})
class RegisterControllerTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @MockitoBean RegisterService registerService;

    @Test
    void register_happy_path_returns_202() throws Exception {
        when(registerService.register(any())).thenReturn(RegisterResponse.builder()
                .sessionToken("sess").requiresOtp(true).expiresIn(600L).build());

        mvc.perform(post("/v1/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req("u@example.com", "Passw0rd!", "Alice"))))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.sessionToken").value("sess"))
                .andExpect(jsonPath("$.data.expiresIn").value(600));
    }

    @Test
    void register_missing_name_returns_400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("u@example.com");
        req.setPassword("Passw0rd!");

        mvc.perform(post("/v1/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VAL_001"));
    }

    @Test
    void register_weak_password_from_service_returns_400_weak_password() throws Exception {
        when(registerService.register(any())).thenThrow(
                new AuthException(ErrorCode.WEAK_PASSWORD, HttpStatus.BAD_REQUEST));

        mvc.perform(post("/v1/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req("u@example.com", "weak", "Alice"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("WEAK_PASSWORD"));
    }

    @Test
    void register_email_in_use_returns_409() throws Exception {
        when(registerService.register(any())).thenThrow(
                new AuthException(ErrorCode.EMAIL_IN_USE, HttpStatus.CONFLICT));

        mvc.perform(post("/v1/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req("u@example.com", "Passw0rd!", "Alice"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("EMAIL_IN_USE"));
    }

    @Test
    void verifyOtp_happy_path_returns_201() throws Exception {
        when(registerService.verifyOtp(any())).thenReturn(AccessTokenResponse.builder()
                .accessToken("a").refreshToken("r").uid("u").displayName("Alice").build());
        RegisterVerifyOtpRequest req = new RegisterVerifyOtpRequest();
        req.setSessionToken("sess");
        req.setOtp("123456");

        mvc.perform(post("/v1/register/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.accessToken").value("a"))
                .andExpect(jsonPath("$.data.uid").value("u"))
                .andExpect(jsonPath("$.data.displayName").value("Alice"));
    }

    @Test
    void verifyOtp_invalid_otp_returns_401() throws Exception {
        when(registerService.verifyOtp(any())).thenThrow(
                new AuthException(ErrorCode.INVALID_OTP, HttpStatus.UNAUTHORIZED));
        RegisterVerifyOtpRequest req = new RegisterVerifyOtpRequest();
        req.setSessionToken("sess");
        req.setOtp("000000");

        mvc.perform(post("/v1/register/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_OTP"));
    }

    @Test
    void verifyOtp_max_attempts_returns_429() throws Exception {
        when(registerService.verifyOtp(any())).thenThrow(new TwilioMaxAttemptsException());
        RegisterVerifyOtpRequest req = new RegisterVerifyOtpRequest();
        req.setSessionToken("sess");
        req.setOtp("000000");

        mvc.perform(post("/v1/register/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("MAX_ATTEMPTS"));
    }

    private RegisterRequest req(String email, String password, String name) {
        RegisterRequest r = new RegisterRequest();
        r.setEmail(email);
        r.setPassword(password);
        r.setName(name);
        return r;
    }
}
