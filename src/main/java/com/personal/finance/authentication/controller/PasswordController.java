package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.PasswordResetRequest;
import com.personal.finance.authentication.dto.request.PasswordResetSubmitRequest;
import com.personal.finance.authentication.dto.request.PasswordResetVerifyRequest;
import com.personal.finance.authentication.dto.request.PasswordUpdateRequest;
import com.personal.finance.authentication.dto.response.MessageResponse;
import com.personal.finance.authentication.dto.response.PasswordResetRequestResponse;
import com.personal.finance.authentication.dto.response.PasswordResetVerifyResponse;
import com.personal.finance.authentication.dto.response.PasswordUpdateRequestResponse;
import com.personal.finance.authentication.service.PasswordService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST entry points for the password-change flows defined in spec §3.6–§3.10.
 * Routing only — all logic lives in {@link PasswordService}.
 */
@RestController
@RequestMapping("/v1/password")
@RequiredArgsConstructor
public class PasswordController {

    private final PasswordService passwordService;

    /**
     * Spec §3.6 — {@code POST /v1/password/update-request}. Authenticated;
     * Bearer token validated in the service layer. Returns 202.
     */
    @PostMapping("/update-request")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public PasswordUpdateRequestResponse requestUpdate(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        // Header optionality is intentional — the service maps null/blank to
        // INVALID_TOKEN/401 per spec §3.6 rather than letting Spring throw a
        // generic MissingRequestHeaderException (which would surface as 500).
        return passwordService.requestUpdate(authorization);
    }

    /** Spec §3.7 — {@code POST /v1/password/update}. Returns 200. */
    @PostMapping("/update")
    public MessageResponse submitUpdate(@Valid @RequestBody PasswordUpdateRequest request) {
        return passwordService.submitUpdate(request);
    }

    /** Spec §3.8 — {@code POST /v1/password/reset-request}. Returns 202 (always). */
    @PostMapping("/reset-request")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public PasswordResetRequestResponse requestReset(@Valid @RequestBody PasswordResetRequest request) {
        return passwordService.requestReset(request);
    }

    /** Spec §3.9 — {@code POST /v1/password/reset-verify}. Returns 200. */
    @PostMapping("/reset-verify")
    public PasswordResetVerifyResponse verifyReset(@Valid @RequestBody PasswordResetVerifyRequest request) {
        return passwordService.verifyReset(request);
    }

    /** Spec §3.10 — {@code POST /v1/password/reset}. Returns 200. */
    @PostMapping("/reset")
    public MessageResponse submitReset(@Valid @RequestBody PasswordResetSubmitRequest request) {
        return passwordService.submitReset(request);
    }
}
