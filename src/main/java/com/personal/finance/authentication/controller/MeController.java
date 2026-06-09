package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.UpdateMeRequest;
import com.personal.finance.authentication.dto.response.MeResponse;
import com.personal.finance.authentication.service.MeService;
import com.personal.finance.common.security.annotation.CurrentUser;
import com.personal.finance.common.security.model.AuthenticatedUser;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Profile read/update for the Settings screen — REQ-settings-backend §3 (P1).
 *
 * <p>Routing only; all logic lives in {@link MeService}. The principal is
 * populated by {@code com.personal.finance.authentication.config.MeSecurityConfig}'s
 * filter chain via finance-common's {@code InternalRequestFilter}: it
 * validates the gateway-injected {@code X-Internal-Secret} and reads
 * {@code X-User-Id} into the {@link AuthenticatedUser}. The frontend keeps
 * sending {@code Authorization: Bearer …}; the gateway validates it at the
 * edge and forwards the trusted envelope — same model as every other
 * downstream service.
 */
@RestController
@RequestMapping("/v1/me")
@RequiredArgsConstructor
@Tag(name = "Profile", description = "Authenticated user's profile (REQ-settings-backend §3, P1). "
        + "Gateway forwards X-User-Id after validating the user's Firebase Bearer.")
public class MeController {

    private final MeService meService;

    /** REQ-settings-backend §3.2 — {@code GET /v1/me}. */
    @GetMapping
    @Operation(
            summary = "Get the signed-in user's profile",
            description = "Returns Firebase-sourced profile fields. Timestamps are UTC ISO-8601; "
                    + "the client renders local time.",
            security = @SecurityRequirement(name = "firebaseBearer"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile returned."),
            @ApiResponse(responseCode = "401", description = "Gateway envelope missing or invalid.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public MeResponse getMe(@CurrentUser AuthenticatedUser user) {
        return meService.getMe(user.getUid());
    }

    /** REQ-settings-backend §3.3 — {@code PATCH /v1/me}. */
    @PatchMapping
    @Operation(
            summary = "Update the signed-in user's profile",
            description = "P1 accepts displayName only; returns the hydrated profile shape on success.",
            security = @SecurityRequirement(name = "firebaseBearer"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile updated."),
            @ApiResponse(responseCode = "400", description = "displayName missing or out of range.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class))),
            @ApiResponse(responseCode = "401", description = "Gateway envelope missing or invalid.",
                    content = @Content(schema = @Schema(implementation = com.personal.finance.common.web.ApiResponse.class)))
    })
    public MeResponse updateMe(@CurrentUser AuthenticatedUser user,
                               @RequestBody(required = false) UpdateMeRequest request) {
        return meService.updateMe(user.getUid(), request);
    }
}
