package com.personal.finance.authentication.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

import java.time.OffsetDateTime;

/**
 * Response for {@code GET /v1/me} and {@code PATCH /v1/me}
 * (REQ-settings-backend §3.2 / §3.3, P1 scope).
 *
 * <p>All fields are sourced live from Firebase — there is no profile table in
 * P1. {@code timezone}/{@code locale}/{@code photoUrl} are intentionally
 * omitted: timestamps are emitted as UTC ISO-8601 and the client renders local
 * time itself, so the server never needs the user's zone.
 */
@Value
@Builder
@Schema(description = "Authenticated user's profile, hydrated from Firebase (REQ-settings-backend §3.2).")
public class MeResponse {

    @Schema(description = "Firebase UID of the authenticated user.", example = "user_abc123")
    String uid;

    @Schema(description = "Primary email address.", example = "alice@home.hk")
    String email;

    @Schema(description = "Whether the email address has been verified.", example = "true")
    boolean emailVerified;

    @Schema(description = "Display name, or null if never set.", example = "Alice Wong")
    String displayName;

    @Schema(description = "Account creation instant (UTC, ISO-8601).", example = "2025-08-12T03:14:21Z")
    OffsetDateTime createdAt;

    @Schema(description = "Last sign-in instant (UTC, ISO-8601), or null if never signed in.",
            example = "2026-06-04T01:02:03Z")
    OffsetDateTime lastSignInAt;
}
