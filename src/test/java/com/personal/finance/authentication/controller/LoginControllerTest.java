package com.personal.finance.authentication.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.exception.AuthException;
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

    // ── /v1/login/oauth ───────────────────────────────────────────────────

    @Test
    void oauthLogin_happy_path_returns_200_with_isNewUser() throws Exception {
        when(loginService.oauthLogin(any())).thenReturn(OAuthLoginResponse.builder()
                .accessToken("a").refreshToken("r").uid("u")
                .displayName("Alice").isNewUser(true).build());
        OAuthLoginRequest req = new OAuthLoginRequest();
        req.setProvider("google");
        req.setIdToken("id-token");

        mvc.perform(post("/v1/login/oauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessToken").value("a"))
                .andExpect(jsonPath("$.data.refreshToken").value("r"))
                .andExpect(jsonPath("$.data.uid").value("u"))
                .andExpect(jsonPath("$.data.isNewUser").value(true))
                .andExpect(jsonPath("$.data.displayName").value("Alice"));
    }

    @Test
    void oauthLogin_missing_idToken_returns_400() throws Exception {
        OAuthLoginRequest req = new OAuthLoginRequest();
        req.setProvider("google");

        mvc.perform(post("/v1/login/oauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("VAL_001"));
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

    @Test
    void oauthLogin_invalid_id_token_returns_401() throws Exception {
        when(loginService.oauthLogin(any())).thenThrow(
                new AuthException(ErrorCode.INVALID_ID_TOKEN, HttpStatus.UNAUTHORIZED));
        OAuthLoginRequest req = new OAuthLoginRequest();
        req.setProvider("apple");
        req.setIdToken("bad");

        mvc.perform(post("/v1/login/oauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_ID_TOKEN"));
    }
}
