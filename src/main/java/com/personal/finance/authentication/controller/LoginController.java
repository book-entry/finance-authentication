package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.LoginRequest;
import com.personal.finance.authentication.dto.request.LoginVerifyOtpRequest;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.LoginResponse;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.service.LoginService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/**
 * REST entry points for the login flows defined in spec §3.1, §3.2, §3.3.
 * Routing only — all logic lives in {@link LoginService}.
 */
@RestController
@RequestMapping("/v1/login")
@RequiredArgsConstructor
public class LoginController {

    private final LoginService loginService;

    /**
     * Spec §3.1 — {@code POST /v1/login}. Returns 202.
     */
    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return loginService.login(request);
    }

    /**
     * Spec §3.2 — {@code POST /v1/login/verify-otp}. Returns 200.
     */
    @PostMapping("/verify-otp")
    public AccessTokenResponse verifyOtp(@Valid @RequestBody LoginVerifyOtpRequest request) {
        return loginService.verifyOtp(request);
    }

    /**
     * Spec §3.3 — {@code POST /v1/login/oauth}. Returns 200.
     */
    @PostMapping("/oauth")
    public OAuthLoginResponse oauthLogin(@Valid @RequestBody OAuthLoginRequest request) {
        return loginService.oauthLogin(request);
    }
}
