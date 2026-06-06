package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.ResendOtpRequest;
import com.personal.finance.authentication.dto.response.ResendOtpResponse;
import com.personal.finance.authentication.service.OtpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST entry point for the resend OTP flow defined in spec §3.11. Routing only.
 */
@RestController
@RequestMapping("/v1/otp")
@RequiredArgsConstructor
@Tag(name = "OTP", description = "OTP resend across the login, register and password-reset flows. "
        + "The internal JWT (sessionToken / actionToken / resetToken) is passed in the request body, "
        + "not in the Authorization header.")
@SecurityRequirements
public class OtpController {

    private final OtpService otpService;

    /** Spec §3.11 — {@code POST /v1/otp/resend}. Returns 200. */
    @PostMapping("/resend")
    @Operation(
            summary = "Resend OTP",
            description = "Re-dispatches the SMS OTP bound to the supplied internal JWT. "
                    + "Token kind is detected from the token's claims.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OTP redispatched; retryAfter window returned."),
            @ApiResponse(responseCode = "400", description = "Token missing or malformed.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "Token invalid or expired.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "429", description = "Resend rate limit hit.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public ResendOtpResponse resend(@Valid @RequestBody ResendOtpRequest request) {
        return otpService.resend(request);
    }
}
