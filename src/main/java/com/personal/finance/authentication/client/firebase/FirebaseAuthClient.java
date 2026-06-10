package com.personal.finance.authentication.client.firebase;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;

/**
 * Single point of contact with Firebase. Combines:
 * <ul>
 *   <li>{@link FirebaseAuth} Admin SDK calls (getUser, updateUser) for the
 *       {@code /v1/me} profile endpoints</li>
 *   <li>Firebase REST {@code signInWithIdp} for Google / Apple OAuth federation
 *       (not exposed by the Admin SDK)</li>
 * </ul>
 *
 * <p>Translates every Firebase failure into an
 * {@link AuthException} carrying the spec-mandated error code and HTTP status,
 * so raw SDK / REST errors never reach the service layer.
 */
@Component
@Slf4j
public class FirebaseAuthClient {

    private static final String REST_BASE = "https://identitytoolkit.googleapis.com/v1/accounts:";

    private final FirebaseAuth firebaseAuth;
    private final AuthProperties properties;
    private final RestTemplate restTemplate;

    public FirebaseAuthClient(FirebaseAuth firebaseAuth, AuthProperties properties,
                              @Qualifier("firebaseRestTemplate") RestTemplate restTemplate) {
        this.firebaseAuth = firebaseAuth;
        this.properties = properties;
        this.restTemplate = restTemplate;
    }

    // ── OAuth / IDP sign-in (REST) ────────────────────────────────────────

    /**
     * OAuth federation — {@code signInWithIdp}. Provider must be
     * {@code google.com} or {@code apple.com}. Creates the Firebase user record
     * on first sign-in (reflected in {@code isNewUser}).
     */
    public FirebaseSignInResult signInWithIdpCredential(String providerId, String idToken) {
        String postBody = "id_token=" + idToken + "&providerId=" + providerId;
        Map<String, Object> body = Map.of("postBody", postBody, "requestUri", "http://localhost",
                "returnIdpCredential", true, "returnSecureToken", true);
        try {
            ResponseEntity<Map> resp = postIdentityToolkit("signInWithIdp", body);
            return mapSignInResponse(resp.getBody());
        } catch (HttpStatusCodeException ex) {
            log.debug("Firebase signInWithIdp rejected: {}", ex.getStatusCode());
            throw new AuthException(ErrorCode.INVALID_ID_TOKEN, HttpStatus.UNAUTHORIZED, "OAuth credential rejected");
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    // ── Admin: getUser / profile (REQ-settings-backend §3) ────────────────

    /**
     * REQ-settings-backend §3.2 — fetch the full profile projection for
     * {@code GET /v1/me}. The {@code uid} comes from an already-verified Firebase
     * ID token, so a NOT_FOUND here means the account was deleted after the token
     * was minted — surfaced as 401 to force re-authentication.
     */
    public FirebaseUserProfile getUser(String uid) {
        try {
            return toProfile(firebaseAuth.getUser(uid));
        } catch (FirebaseAuthException ex) {
            String code = ex.getErrorCode() == null ? "" : ex.getErrorCode().name();
            if ("USER_NOT_FOUND".equals(code) || "NOT_FOUND".equals(code)
                    || (ex.getMessage() != null && ex.getMessage().toUpperCase().contains("NOT_FOUND"))) {
                throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
                        "User no longer exists");
            }
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    /**
     * REQ-settings-backend §3.3 — set the display name for {@code PATCH /v1/me}.
     * Returns the updated profile (the Admin SDK echoes the full record) so the
     * caller can return the hydrated shape without a second round-trip.
     */
    public FirebaseUserProfile updateDisplayName(String uid, String displayName) {
        try {
            UserRecord record = firebaseAuth.updateUser(
                    new UserRecord.UpdateRequest(uid).setDisplayName(displayName));
            return toProfile(record);
        } catch (FirebaseAuthException ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    private static FirebaseUserProfile toProfile(UserRecord record) {
        var meta = record.getUserMetadata();
        return FirebaseUserProfile.builder()
                .uid(record.getUid())
                .email(record.getEmail())
                .emailVerified(record.isEmailVerified())
                .displayName(record.getDisplayName())
                .createdAt(meta == null ? null : toUtc(meta.getCreationTimestamp()))
                .lastSignInAt(meta == null ? null : toUtc(meta.getLastSignInTimestamp()))
                .build();
    }

    /** Firebase metadata uses epoch-millis with 0 meaning "never". Map that to null. */
    private static OffsetDateTime toUtc(long epochMillis) {
        return epochMillis <= 0 ? null
                : OffsetDateTime.ofInstant(Instant.ofEpochMilli(epochMillis), ZoneOffset.UTC);
    }

    // ── Internals ─────────────────────────────────────────────────────────

    private static String stringOf(Map<?, ?> body, String key) {
        Object v = body.get(key);
        return v == null ? null : v.toString();
    }

    private ResponseEntity<Map> postIdentityToolkit(String endpoint, Map<String, Object> body) {
        String apiKey = properties.getFirebase().getApiKey();
        if (apiKey == null || apiKey.isBlank()) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR,
                    "Firebase API key not configured");
        }
        String url = REST_BASE + endpoint + "?key=" + apiKey;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
        return restTemplate.exchange(url, HttpMethod.POST, entity, Map.class);
    }

    private FirebaseSignInResult mapSignInResponse(Map<?, ?> body) {
        if (body == null) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR,
                    "Empty Firebase response");
        }
        return FirebaseSignInResult.builder()
                .accessToken(stringOf(body, "idToken"))
                .refreshToken(stringOf(body, "refreshToken"))
                .uid(stringOf(body, "localId"))
                .displayName(stringOf(body, "displayName"))
                .isNewUser(Boolean.TRUE.equals(body.get("isNewUser")))
                .build();
    }
}
