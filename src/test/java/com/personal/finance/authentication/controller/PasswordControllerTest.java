package com.personal.finance.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.personal.finance.authentication.dto.request.PasswordResetRequest;
import com.personal.finance.authentication.dto.request.PasswordResetSubmitRequest;
import com.personal.finance.authentication.dto.request.PasswordResetVerifyRequest;
import com.personal.finance.authentication.dto.request.PasswordUpdateRequest;
import com.personal.finance.authentication.dto.response.MessageResponse;
import com.personal.finance.authentication.dto.response.PasswordResetRequestResponse;
import com.personal.finance.authentication.dto.response.PasswordResetVerifyResponse;
import com.personal.finance.authentication.dto.response.PasswordUpdateRequestResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.service.PasswordService;
import com.personal.finance.common.exception.ErrorCode;
import com.personal.finance.common.web.ApiResponseBodyAdvice;
import com.personal.finance.common.web.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(PasswordController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({GlobalExceptionHandler.class, ApiResponseBodyAdvice.class})
class PasswordControllerTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @MockitoBean PasswordService passwordService;

    // ── §3.6 update-request ───────────────────────────────────────────────

    @Test
    void updateRequest_happy_path_returns_202() throws Exception {
        when(passwordService.requestUpdate(anyString())).thenReturn(PasswordUpdateRequestResponse.builder()
                .actionToken("act").requiresOtp(true).expiresIn(300L).build());

        mvc.perform(post("/v1/password/update-request")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer id-token"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.actionToken").value("act"));
    }

    @Test
    void updateRequest_missing_bearer_header_returns_401_invalid_token() throws Exception {
        // Spec §3.6: missing accessToken → 401 INVALID_TOKEN.
        // The real PasswordServiceImpl throws AuthException(INVALID_TOKEN, 401)
        // for null/blank Authorization headers; mirror that here on the mock.
        when(passwordService.requestUpdate(null)).thenThrow(
                new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED));

        mvc.perform(post("/v1/password/update-request"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_TOKEN"));
    }

    @Test
    void updateRequest_invalid_token_returns_401() throws Exception {
        when(passwordService.requestUpdate(anyString())).thenThrow(
                new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED));

        mvc.perform(post("/v1/password/update-request")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer bad"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_TOKEN"));
    }

    // ── §3.7 update ───────────────────────────────────────────────────────

    @Test
    void update_happy_path_returns_200_with_message() throws Exception {
        when(passwordService.submitUpdate(any())).thenReturn(new MessageResponse("Password updated successfully"));
        PasswordUpdateRequest req = new PasswordUpdateRequest();
        req.setActionToken("act");
        req.setOtp("123456");
        req.setNewPassword("NewPass1!");

        mvc.perform(post("/v1/password/update")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.message").value("Password updated successfully"));
    }

    @Test
    void update_weak_password_returns_400() throws Exception {
        when(passwordService.submitUpdate(any())).thenThrow(
                new AuthException(ErrorCode.WEAK_PASSWORD, HttpStatus.BAD_REQUEST));
        PasswordUpdateRequest req = new PasswordUpdateRequest();
        req.setActionToken("act");
        req.setOtp("123456");
        req.setNewPassword("weak");

        mvc.perform(post("/v1/password/update")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("WEAK_PASSWORD"));
    }

    // ── §3.8 reset-request ────────────────────────────────────────────────

    @Test
    void resetRequest_known_email_returns_202_with_reset_token() throws Exception {
        when(passwordService.requestReset(any())).thenReturn(PasswordResetRequestResponse.builder()
                .resetToken("reset").requiresOtp(true).expiresIn(600L).build());
        PasswordResetRequest req = new PasswordResetRequest();
        req.setEmail("u@example.com");

        mvc.perform(post("/v1/password/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.resetToken").value("reset"))
                .andExpect(jsonPath("$.data.requiresOtp").value(true));
    }

    @Test
    void resetRequest_unknown_email_returns_202_with_requiresOtp_false_only() throws Exception {
        // Anti-enumeration: even unknown emails return 202 — service yields
        // requiresOtp:false, no resetToken.
        when(passwordService.requestReset(any())).thenReturn(PasswordResetRequestResponse.builder()
                .requiresOtp(false).build());
        PasswordResetRequest req = new PasswordResetRequest();
        req.setEmail("ghost@example.com");

        mvc.perform(post("/v1/password/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.requiresOtp").value(false))
                .andExpect(jsonPath("$.data.resetToken").doesNotExist());
    }

    @Test
    void resetRequest_missing_email_returns_400() throws Exception {
        PasswordResetRequest req = new PasswordResetRequest();

        mvc.perform(post("/v1/password/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    // ── §3.9 reset-verify ─────────────────────────────────────────────────

    @Test
    void resetVerify_happy_path_returns_200_with_confirmed_token() throws Exception {
        when(passwordService.verifyReset(any())).thenReturn(PasswordResetVerifyResponse.builder()
                .confirmedToken("conf").otpVerified(true).build());
        PasswordResetVerifyRequest req = new PasswordResetVerifyRequest();
        req.setResetToken("reset");
        req.setOtp("123456");

        mvc.perform(post("/v1/password/reset-verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.confirmedToken").value("conf"));
    }

    @Test
    void resetVerify_wrong_phase_returns_400_invalid_token() throws Exception {
        when(passwordService.verifyReset(any())).thenThrow(
                new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.BAD_REQUEST));
        PasswordResetVerifyRequest req = new PasswordResetVerifyRequest();
        req.setResetToken("reset");
        req.setOtp("123456");

        mvc.perform(post("/v1/password/reset-verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("INVALID_TOKEN"));
    }

    // ── §3.10 reset submit ────────────────────────────────────────────────

    @Test
    void resetSubmit_happy_path_returns_200_with_message() throws Exception {
        when(passwordService.submitReset(any())).thenReturn(new MessageResponse("Password reset successfully"));
        PasswordResetSubmitRequest req = new PasswordResetSubmitRequest();
        req.setConfirmedToken("conf");
        req.setNewPassword("NewPass1!");

        mvc.perform(post("/v1/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.message").value("Password reset successfully"));
    }
}
