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
 * The {@code uid} is supplied by {@code MeSecurityConfig}'s filter chain,
 * which validates the gateway's {@code X-Internal-Secret} and reads
 * {@code X-User-Id} into the {@link com.personal.finance.common.security.model.AuthenticatedUser}.
 * The token is verified at the gateway edge; this service no longer
 * re-verifies the Bearer here.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class MeServiceImpl implements MeService {

    private static final int DISPLAY_NAME_MAX = 60;

    private final FirebaseAuthClient firebaseClient;

    @Override
    public MeResponse getMe(String uid) {
        return toResponse(firebaseClient.getUser(uid));
    }

    @Override
    public MeResponse updateMe(String uid, UpdateMeRequest request) {
        String displayName = validateDisplayName(request);
        FirebaseUserProfile updated = firebaseClient.updateDisplayName(uid, displayName);
        log.info("Profile updated uid=[{}]", uid);
        return toResponse(updated);
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
}
