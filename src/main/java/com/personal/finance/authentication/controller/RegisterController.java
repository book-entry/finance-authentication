package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.RegisterRequest;
import com.personal.finance.authentication.dto.request.RegisterVerifyOtpRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.RegisterResponse;
import com.personal.finance.authentication.service.RegisterService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Register", description = "New-user registration. Pre-token endpoints — no Authorization required.")
@SecurityRequirements
public class RegisterController {

    private final RegisterService registerService;

    /** Spec §3.4 — {@code POST /v1/register}. Returns 202. */
    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(
            summary = "Start registration",
            description = "Creates a pending account and dispatches an OTP. Returns a short-lived "
                    + "sessionToken that must be presented to /v1/register/verify-otp.")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Account staged; OTP dispatched."),
            @ApiResponse(responseCode = "400", description = "Validation error.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "409", description = "Email already registered.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "429", description = "Rate-limited.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        return registerService.register(request);
    }

    /** Spec §3.5 — {@code POST /v1/register/verify-otp}. Returns 201. */
    @PostMapping("/verify-otp")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Complete registration by verifying OTP",
            description = "Promotes the pending account to a real Firebase user and returns "
                    + "Firebase ID/refresh tokens.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Account created; Firebase tokens returned."),
            @ApiResponse(responseCode = "400", description = "Validation error.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "sessionToken invalid/expired or OTP wrong.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "429", description = "Too many OTP attempts.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public AccessTokenResponse verifyOtp(@Valid @RequestBody RegisterVerifyOtpRequest request) {
        return registerService.verifyOtp(request);
    }
}
