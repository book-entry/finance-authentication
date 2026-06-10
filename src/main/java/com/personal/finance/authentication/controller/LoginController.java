package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
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
import org.springframework.web.bind.annotation.*;

/**
 * REST entry point for OAuth login. Routing only — all logic lives in
 * {@link LoginService}. The app authenticates exclusively through Google /
 * Apple OAuth; the first successful sign-in also provisions the account.
 */
@RestController
@RequestMapping("/v1/login")
@RequiredArgsConstructor
@Tag(name = "Login", description = "OAuth login (Google / Apple). Pre-token endpoint — "
        + "does not require an Authorization header.")
@SecurityRequirements
public class LoginController {

    private final LoginService loginService;

    /**
     * {@code POST /v1/login/oauth}. Exchanges a provider ID token for Firebase
     * tokens; creates the Firebase user record on first sign-in.
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
