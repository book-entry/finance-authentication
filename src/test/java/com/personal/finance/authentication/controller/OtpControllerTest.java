package com.personal.finance.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.personal.finance.authentication.dto.request.ResendOtpRequest;
import com.personal.finance.authentication.dto.response.ResendOtpResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.exception.RedisUnavailableException;
import com.personal.finance.authentication.exception.ResendCooldownException;
import com.personal.finance.authentication.service.OtpService;
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

@WebMvcTest(OtpController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({GlobalExceptionHandler.class, ApiResponseBodyAdvice.class})
class OtpControllerTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @MockitoBean OtpService otpService;

    @Test
    void resend_happy_path_returns_200() throws Exception {
        when(otpService.resend(any())).thenReturn(ResendOtpResponse.builder()
                .message("OTP resent").retryAfter(60L).build());
        ResendOtpRequest req = new ResendOtpRequest();
        req.setToken("session-token");

        mvc.perform(post("/v1/otp/resend")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.message").value("OTP resent"))
                .andExpect(jsonPath("$.data.retryAfter").value(60));
    }

    @Test
    void resend_missing_token_returns_400() throws Exception {
        ResendOtpRequest req = new ResendOtpRequest();

        mvc.perform(post("/v1/otp/resend")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VAL_001"));
    }

    @Test
    void resend_invalid_token_returns_400_invalid_token() throws Exception {
        when(otpService.resend(any())).thenThrow(
                new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.BAD_REQUEST));
        ResendOtpRequest req = new ResendOtpRequest();
        req.setToken("bad");

        mvc.perform(post("/v1/otp/resend")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("INVALID_TOKEN"));
    }

    @Test
    void resend_cooldown_active_returns_429_resend_too_soon() throws Exception {
        when(otpService.resend(any())).thenThrow(new ResendCooldownException(42L));
        ResendOtpRequest req = new ResendOtpRequest();
        req.setToken("session-token");

        mvc.perform(post("/v1/otp/resend")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("RESEND_TOO_SOON"));
    }

    @Test
    void resend_redis_unavailable_returns_503() throws Exception {
        when(otpService.resend(any())).thenThrow(new RedisUnavailableException(new RuntimeException("down")));
        ResendOtpRequest req = new ResendOtpRequest();
        req.setToken("session-token");

        mvc.perform(post("/v1/otp/resend")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error.code").value("REDIS_UNAVAILABLE"));
    }
}
