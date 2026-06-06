package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.LoginRequest;
import com.personal.finance.authentication.dto.request.LoginVerifyOtpRequest;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.LoginResponse;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.service.LoginService;
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
import org.springframework.web.bind.annotation.*;

/**
 * REST entry points for the login flows defined in spec §3.1, §3.2, §3.3.
 * Routing only — all logic lives in {@link LoginService}.
 */
@RestController
@RequestMapping("/v1/login")
@RequiredArgsConstructor
@Tag(name = "Login", description = "Password and OAuth login flows. All endpoints are pre-token "
        + "and do not require an Authorization header.")
@SecurityRequirements
public class LoginController {

    private final LoginService loginService;

    /**
     * Spec §3.1 — {@code POST /v1/login}. Returns 202.
     */
    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(
            summary = "Start password login",
            description = "Validates the email/password pair and, on success, issues a short-lived "
                    + "sessionToken bound to an SMS OTP challenge. Pre-token endpoint — no Authorization required.")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Credentials valid; OTP dispatched."),
            @ApiResponse(responseCode = "400", description = "Validation error (missing/invalid fields).",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "Email or password is incorrect.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "429", description = "Too many login attempts; back off.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return loginService.login(request);
    }

    /**
     * Spec §3.2 — {@code POST /v1/login/verify-otp}. Returns 200.
     */
    @PostMapping("/verify-otp")
    @Operation(
            summary = "Complete password login by verifying OTP",
            description = "Exchanges a valid sessionToken + OTP for Firebase ID/refresh tokens. "
                    + "On success, the returned accessToken is a Firebase ID token suitable for "
                    + "the Authorization header on every downstream service.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OTP verified; Firebase tokens returned."),
            @ApiResponse(responseCode = "400", description = "Validation error (missing fields).",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "sessionToken invalid/expired or OTP wrong.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "429", description = "Too many OTP attempts.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public AccessTokenResponse verifyOtp(@Valid @RequestBody LoginVerifyOtpRequest request) {
        return loginService.verifyOtp(request);
    }

    /**
     * Spec §3.3 — {@code POST /v1/login/oauth}. Returns 200.
     */
    @PostMapping("/oauth")
    @Operation(
            summary = "OAuth login (Google / Apple)",
            description = "Exchanges a provider ID token for Firebase ID/refresh tokens. "
                    + "Creates the Firebase user record on first sign-in (isNewUser=true).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Provider token accepted; Firebase tokens returned."),
            @ApiResponse(responseCode = "400", description = "Provider not supported or idToken missing.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "Provider ID token invalid or expired.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public OAuthLoginResponse oauthLogin(@Valid @RequestBody OAuthLoginRequest request) {
        return loginService.oauthLogin(request);
    }
}
