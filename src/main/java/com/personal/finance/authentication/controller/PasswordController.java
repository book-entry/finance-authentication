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
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Password", description = "Password update (Bearer-authenticated) and password reset "
        + "(internal-JWT-authenticated) flows.")
public class PasswordController {

    private final PasswordService passwordService;

    /**
     * Spec §3.6 — {@code POST /v1/password/update-request}. Authenticated;
     * Bearer token validated in the service layer. Returns 202.
     */
    @PostMapping("/update-request")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Operation(
            summary = "Start password update for the signed-in user",
            description = "Bearer-authenticated. Issues an actionToken bound to an OTP that must "
                    + "be submitted to /v1/password/update. The Bearer token is validated by the "
                    + "service layer (not Spring Security) so a null/blank header maps to 401 "
                    + "instead of 500.",
            security = @SecurityRequirement(name = "firebaseBearer"))
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "actionToken issued; OTP dispatched."),
            @ApiResponse(responseCode = "401", description = "Bearer token missing, invalid, or expired.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "429", description = "Rate-limited.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public PasswordUpdateRequestResponse requestUpdate(
            @Parameter(in = ParameterIn.HEADER, name = HttpHeaders.AUTHORIZATION, required = true,
                    description = "Firebase ID token as `Bearer <token>`.")
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        // Header optionality is intentional — the service maps null/blank to
        // INVALID_TOKEN/401 per spec §3.6 rather than letting Spring throw a
        // generic MissingRequestHeaderException (which would surface as 500).
        return passwordService.requestUpdate(authorization);
    }

    /** Spec §3.7 — {@code POST /v1/password/update}. Returns 200. */
    @PostMapping("/update")
    @SecurityRequirements
    @Operation(
            summary = "Complete password update by verifying OTP",
            description = "Pre-token endpoint — actionToken from /update-request authenticates the "
                    + "request; no Authorization header.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Password updated."),
            @ApiResponse(responseCode = "400", description = "Validation error.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "actionToken invalid/expired or OTP wrong.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public MessageResponse submitUpdate(@Valid @RequestBody PasswordUpdateRequest request) {
        return passwordService.submitUpdate(request);
    }

    /** Spec §3.8 — {@code POST /v1/password/reset-request}. Returns 202 (always). */
    @PostMapping("/reset-request")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @SecurityRequirements
    @Operation(
            summary = "Start password reset by email",
            description = "Always returns 202 to prevent account enumeration. When the email matches "
                    + "an account, a resetToken is included; otherwise only `requiresOtp:false` is returned.")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Reset request accepted (resetToken may be null)."),
            @ApiResponse(responseCode = "400", description = "Validation error.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "429", description = "Rate-limited.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public PasswordResetRequestResponse requestReset(@Valid @RequestBody PasswordResetRequest request) {
        return passwordService.requestReset(request);
    }

    /** Spec §3.9 — {@code POST /v1/password/reset-verify}. Returns 200. */
    @PostMapping("/reset-verify")
    @SecurityRequirements
    @Operation(
            summary = "Verify the reset OTP",
            description = "Exchanges a resetToken + OTP for a confirmedToken usable on /v1/password/reset.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OTP verified; confirmedToken returned."),
            @ApiResponse(responseCode = "400", description = "Validation error.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "resetToken invalid/expired or OTP wrong.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public PasswordResetVerifyResponse verifyReset(@Valid @RequestBody PasswordResetVerifyRequest request) {
        return passwordService.verifyReset(request);
    }

    /** Spec §3.10 — {@code POST /v1/password/reset}. Returns 200. */
    @PostMapping("/reset")
    @SecurityRequirements
    @Operation(
            summary = "Submit the new password",
            description = "Pre-token endpoint — confirmedToken from /reset-verify authenticates the request.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Password reset."),
            @ApiResponse(responseCode = "400", description = "Validation error.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "confirmedToken invalid or expired.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public MessageResponse submitReset(@Valid @RequestBody PasswordResetSubmitRequest request) {
        return passwordService.submitReset(request);
    }
}
