package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.RegisterRequest;
import com.personal.finance.authentication.dto.request.RegisterVerifyOtpRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.RegisterResponse;
import com.personal.finance.authentication.service.RegisterService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST entry points for the registration flow defined in spec §3.4, §3.5.
 * Routing only — all logic lives in {@link RegisterService}.
 */
@RestController
@RequestMapping("/v1/register")
@RequiredArgsConstructor
public class RegisterController {

    private final RegisterService registerService;

    /** Spec §3.4 — {@code POST /v1/register}. Returns 202. */
    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        return registerService.register(request);
    }

    /** Spec §3.5 — {@code POST /v1/register/verify-otp}. Returns 201. */
    @PostMapping("/verify-otp")
    @ResponseStatus(HttpStatus.CREATED)
    public AccessTokenResponse verifyOtp(@Valid @RequestBody RegisterVerifyOtpRequest request) {
        return registerService.verifyOtp(request);
    }
}
