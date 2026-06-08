package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseUserProfile;
import com.personal.finance.authentication.dto.request.UpdateMeRequest;
import com.personal.finance.authentication.dto.response.MeResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * REQ-settings-backend §3 (P1) — Profile read/update.
 *
 * <p>P1 is a pure Firebase passthrough: no profile table, no timezone/locale.
 * The uid is resolved by verifying the Bearer ID token (same pattern as
 * {@link PasswordServiceImpl#requestUpdate}); the full record is then read from
 * the Admin SDK so the response carries creation / last-sign-in metadata.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class MeServiceImpl implements MeService {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final int DISPLAY_NAME_MAX = 60;

    private final FirebaseAuthClient firebaseClient;

    @Override
    public MeResponse getMe(String authorizationHeader) {
        String uid = resolveUid(authorizationHeader);
        return toResponse(firebaseClient.getUser(uid));
    }

    @Override
    public MeResponse updateMe(String authorizationHeader, UpdateMeRequest request) {
        String uid = resolveUid(authorizationHeader);
        String displayName = validateDisplayName(request);
        FirebaseUserProfile updated = firebaseClient.updateDisplayName(uid, displayName);
        log.info("Profile updated uid=[{}]", uid);
        return toResponse(updated);
    }

    /** Verify the Bearer ID token and return its uid. 401 on any rejection. */
    private String resolveUid(String authorizationHeader) {
        String idToken = extractBearer(authorizationHeader);
        return firebaseClient.verifyIdToken(idToken).getUid();
    }

    /**
     * P1 accepts {@code displayName} only and treats it as required (it is the
     * sole editable field, so an empty body is an empty patch). Reuses the
     * existing {@code INVALID_INPUT} code rather than minting per-field codes.
     */
    private String validateDisplayName(UpdateMeRequest request) {
        if (request == null || request.getDisplayName() == null) {
            throw new AuthException(ErrorCode.INVALID_INPUT, HttpStatus.BAD_REQUEST,
                    "Request body must include displayName");
        }
        String trimmed = request.getDisplayName().trim();
        if (trimmed.isEmpty() || trimmed.length() > DISPLAY_NAME_MAX) {
            throw new AuthException(ErrorCode.INVALID_INPUT, HttpStatus.BAD_REQUEST,
                    "displayName must be 1–" + DISPLAY_NAME_MAX + " characters");
        }
        return trimmed;
    }

    private static MeResponse toResponse(FirebaseUserProfile p) {
        return MeResponse.builder()
                .uid(p.getUid())
                .email(p.getEmail())
                .emailVerified(p.isEmailVerified())
                .displayName(p.getDisplayName())
                .createdAt(p.getCreatedAt())
                .lastSignInAt(p.getLastSignInAt())
                .build();
    }

    private static String extractBearer(String header) {
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
                    "Authorization Bearer header is required");
        }
        String value = header.substring(BEARER_PREFIX.length()).trim();
        if (value.isEmpty()) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
                    "Authorization Bearer header is empty");
        }
        return value;
    }
}
