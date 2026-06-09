package com.personal.finance.authentication.service;

import com.personal.finance.authentication.dto.request.UpdateMeRequest;
import com.personal.finance.authentication.dto.response.MeResponse;

/**
 * Profile read/update for the Settings screen (REQ-settings-backend §3, P1).
 *
 * <p>Authentication is handled at the edge by the gateway: it validates the
 * user's Firebase Bearer, then forwards an {@code X-Internal-Secret} +
 * {@code X-User-Id} envelope. The service-side filter chain
 * ({@code MeSecurityConfig}) reads that envelope into the security context;
 * by the time these methods are called the {@code uid} has already been
 * authenticated, so the service takes it as a plain parameter.
 */
public interface MeService {

    /** REQ-settings-backend §3.2 — {@code GET /v1/me}. */
    MeResponse getMe(String uid);

    /** REQ-settings-backend §3.3 — {@code PATCH /v1/me}. */
    MeResponse updateMe(String uid, UpdateMeRequest request);
}
