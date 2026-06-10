package com.personal.finance.authentication.config;

import com.personal.finance.authentication.controller.LoginController;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.service.LoginService;
import com.personal.finance.common.web.ApiResponseBodyAdvice;
import com.personal.finance.common.web.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression test: with the Spring Security filter chain active (filters NOT
 * disabled), {@code POST /v1/login/oauth} must succeed without any
 * {@code Authorization} header. Without
 * {@link AuthServiceSecurityConfig}, Spring Boot's default
 * {@code SecurityAutoConfiguration} (or finance-common's catch-all chain in
 * production) gates every request with 401 and an empty body.
 */
@WebMvcTest(LoginController.class)
@Import({
        AuthServiceSecurityConfig.class,
        GlobalExceptionHandler.class,
        ApiResponseBodyAdvice.class
})
class AuthServiceSecurityConfigTest {

    @Autowired MockMvc mvc;
    @MockitoBean LoginService loginService;

    @Test
    void post_login_oauth_is_permitted_without_any_bearer_token() throws Exception {
        when(loginService.oauthLogin(any())).thenReturn(OAuthLoginResponse.builder()
                .accessToken("a").refreshToken("r").uid("u").isNewUser(false).build());

        mvc.perform(post("/v1/login/oauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"provider\":\"google\",\"idToken\":\"id-token\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessToken").value("a"));
    }
}
