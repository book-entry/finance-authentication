package com.personal.finance.authentication.client.firebase;

import lombok.Builder;
import lombok.Value;

import java.time.OffsetDateTime;

/**
 * Richer projection of a Firebase {@code UserRecord} used by the Settings
 * Profile endpoints (REQ-settings-backend §3). Keeps Firebase SDK types out of
 * the service layer and converts the SDK's epoch-millis metadata into UTC
 * {@link OffsetDateTime} instants at the boundary — every other service emits
 * ISO-8601 UTC, so {@code /me} stays consistent.
 */
@Value
@Builder
public class FirebaseUserProfile {

    String uid;
    String email;
    boolean emailVerified;
    String displayName;

    /** Account creation instant (UTC). Always present for a real account. */
    OffsetDateTime createdAt;

    /** Last sign-in instant (UTC), or {@code null} if the user has never signed in. */
    OffsetDateTime lastSignInAt;
}
