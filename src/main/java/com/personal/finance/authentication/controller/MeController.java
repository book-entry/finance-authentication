package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.UpdateMeRequest;
import com.personal.finance.authentication.dto.response.MeResponse;
import com.personal.finance.authentication.service.MeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Profile read/update for the Settings screen — REQ-settings-backend §3 (P1).
 * Routing only; all logic (Bearer validation, Firebase calls, validation) lives
 * in {@link MeService}.
 *
 * <p>Bearer-authenticated like {@code /v1/password/update-request}: the token is
 * validated in the service layer (not Spring Security), so the {@code Authorization}
 * header is declared {@code required = false} and a null/blank header maps to a
 * clean 401 instead of a generic 500.
 */
@RestController
@RequestMapping("/v1/me")
@RequiredArgsConstructor
@Tag(name = "Profile", description = "Authenticated user's profile (REQ-settings-backend §3, P1). "
        + "Firebase Bearer token required.")
public class MeController {

    private final MeService meService;

    /** REQ-settings-backend §3.2 — {@code GET /v1/me}. */
    @GetMapping
    @Operation(
            summary = "Get the signed-in user's profile",
            description = "Bearer-authenticated. Returns Firebase-sourced profile fields. Timestamps "
                    + "are UTC ISO-8601; the client renders local time.",
            security = @SecurityRequirement(name = "firebaseBearer"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile returned."),
            @ApiResponse(responseCode = "401", description = "Bearer token missing, invalid, or expired.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public MeResponse getMe(
            @Parameter(in = ParameterIn.HEADER, name = HttpHeaders.AUTHORIZATION, required = true,
                    description = "Firebase ID token as `Bearer <token>`.")
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return meService.getMe(authorization);
    }

    /** REQ-settings-backend §3.3 — {@code PATCH /v1/me}. */
    @PatchMapping
    @Operation(
            summary = "Update the signed-in user's profile",
            description = "Bearer-authenticated. P1 accepts displayName only; returns the hydrated "
                    + "profile shape on success.",
            security = @SecurityRequirement(name = "firebaseBearer"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile updated."),
            @ApiResponse(responseCode = "400", description = "displayName missing or out of range.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "Bearer token missing, invalid, or expired.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public MeResponse updateMe(
            @Parameter(in = ParameterIn.HEADER, name = HttpHeaders.AUTHORIZATION, required = true,
                    description = "Firebase ID token as `Bearer <token>`.")
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestBody(required = false) UpdateMeRequest request) {
        return meService.updateMe(authorization, request);
    }
}
