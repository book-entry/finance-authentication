package com.personal.finance.authentication.service;

import com.personal.finance.authentication.dto.request.UpdateMeRequest;
import com.personal.finance.authentication.dto.response.MeResponse;

/**
 * Profile read/update for the Settings screen (REQ-settings-backend §3, P1).
 *
 * <p>Authentication is by Firebase Bearer token validated in the service layer
 * — the auth service deliberately excludes finance-common's inbound security
 * filters (see {@code FinanceAuthenticationApplication}), so there is no
 * SecurityContext / {@code @CurrentUser} to read from. The caller passes the
 * raw {@code Authorization} header, mirroring the password-update flow.
 */
public interface MeService {

    /** REQ-settings-backend §3.2 — {@code GET /v1/me}. */
    MeResponse getMe(String authorizationHeader);

    /** REQ-settings-backend §3.3 — {@code PATCH /v1/me}. */
    MeResponse updateMe(String authorizationHeader, UpdateMeRequest request);
}
