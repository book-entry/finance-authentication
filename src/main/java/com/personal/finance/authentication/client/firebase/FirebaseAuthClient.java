package com.personal.finance.authentication.client.firebase;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
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

import java.util.Map;

/**
 * Single point of contact with Firebase. Combines:
 * <ul>
 *   <li>{@link FirebaseAuth} Admin SDK calls (createUser, updateUser, getUser,
 *       verifyIdToken, createCustomToken)</li>
 *   <li>Firebase REST API calls for password and IDP sign-in plus custom-token
 *       exchange (not exposed by the Admin SDK)</li>
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

    // ── Email / password sign-in (REST) ───────────────────────────────────

    private static String stringOf(Map<?, ?> body, String key) {
        Object v = body.get(key);
        return v == null ? null : v.toString();
    }

    // ── OAuth / IDP sign-in (REST) ────────────────────────────────────────

    /**
     * Implements spec §3.1 step 2 — {@code signInWithEmailAndPassword}. Hits the
     * Identity Toolkit REST endpoint because the Admin SDK does not expose this.
     */
    public FirebaseSignInResult signInWithEmailAndPassword(String email, String password) {
        Map<String, Object> body = Map.of("email", email, "password", password, "returnSecureToken", true);
        try {
            ResponseEntity<Map> resp = postIdentityToolkit("signInWithPassword", body);
            return mapSignInResponse(resp.getBody(), false);
        } catch (HttpStatusCodeException ex) {
            log.info("Firebase signInWithPassword rejected: {}", ex.getStatusCode());
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED, "Invalid email or " +
                    "password");
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    // ── Admin: createUser ─────────────────────────────────────────────────

    /**
     * Implements spec §3.3 step 2 — {@code signInWithCredential}. Provider must
     * be {@code google.com} or {@code apple.com}.
     */
    public FirebaseSignInResult signInWithIdpCredential(String providerId, String idToken) {
        String postBody = "id_token=" + idToken + "&providerId=" + providerId;
        Map<String, Object> body = Map.of("postBody", postBody, "requestUri", "http://localhost",
                "returnIdpCredential", true, "returnSecureToken", true);
        try {
            ResponseEntity<Map> resp = postIdentityToolkit("signInWithIdp", body);
            return mapSignInResponse(resp.getBody(), true);
        } catch (HttpStatusCodeException ex) {
            log.debug("Firebase signInWithIdp rejected: {}", ex.getStatusCode());
            throw new AuthException(ErrorCode.INVALID_ID_TOKEN, HttpStatus.UNAUTHORIZED, "OAuth credential rejected");
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    // ── Admin: verifyIdToken ──────────────────────────────────────────────

    /**
     * Implements spec §3.4 step 2 — {@code createUserWithEmailAndPassword}.
     */
    public String createUser(String email, String password, String displayName) {
        try {
            UserRecord.CreateRequest req = new UserRecord.CreateRequest().setEmail(email)
                    .setEmailVerified(false)
                    .setPassword(password);
            if (displayName != null && !displayName.isBlank()) {
                req.setDisplayName(displayName);
            }
            UserRecord record = firebaseAuth.createUser(req);
            return record.getUid();
        } catch (FirebaseAuthException ex) {
            if ("EMAIL_EXISTS".equals(ex.getErrorCode().name()) || (ex.getMessage() != null && ex.getMessage()
                    .contains("EMAIL_EXISTS")) || (ex.getMessage() != null && ex.getMessage()
                    .toLowerCase()
                    .contains("already in use"))) {
                throw new AuthException(ErrorCode.EMAIL_IN_USE, HttpStatus.CONFLICT, "Email is already registered");
            }
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    // ── Admin: getUserByEmail ─────────────────────────────────────────────

    /**
     * Implements spec §3.6 step 2 — {@code verifyIdToken}. Returns the decoded
     * uid / email. {@link AuthException} on rejection.
     */
    public FirebaseUserRecord verifyIdToken(String idToken) {
        try {
            FirebaseToken token = firebaseAuth.verifyIdToken(idToken);
            return new FirebaseUserRecord(token.getUid(), token.getEmail());
        } catch (FirebaseAuthException ex) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
                    "Access token is invalid or " + "expired");
        }
    }

    // ── Admin: updateUser ─────────────────────────────────────────────────

    /**
     * Implements spec §3.8 step 2. Returns {@code null} on NOT_FOUND to support
     * the anti-enumeration response — caller decides what to do.
     */
    public FirebaseUserRecord getUserByEmailOrNull(String email) {
        try {
            UserRecord record = firebaseAuth.getUserByEmail(email);
            return new FirebaseUserRecord(record.getUid(), record.getEmail());
        } catch (FirebaseAuthException ex) {
            String code = ex.getErrorCode() == null ? "" : ex.getErrorCode().name();
            if ("USER_NOT_FOUND".equals(code) || "NOT_FOUND".equals(code) || (ex.getMessage() != null && ex.getMessage()
                    .toUpperCase()
                    .contains("NOT_FOUND"))) {
                return null;
            }
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    /**
     * Implements spec §3.5 step 3 — mark email verified and set display name.
     */
    public void markEmailVerified(String uid, String displayName) {
        try {
            UserRecord.UpdateRequest req = new UserRecord.UpdateRequest(uid).setEmailVerified(true);
            if (displayName != null && !displayName.isBlank()) {
                req.setDisplayName(displayName);
            }
            firebaseAuth.updateUser(req);
        } catch (FirebaseAuthException ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    // ── Admin: createCustomToken + exchange ───────────────────────────────

    /**
     * Implements spec §3.7 / §3.10 — change the user's password.
     */
    public void updatePassword(String uid, String newPassword) {
        try {
            UserRecord.UpdateRequest req = new UserRecord.UpdateRequest(uid).setPassword(newPassword);
            firebaseAuth.updateUser(req);
        } catch (FirebaseAuthException ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    // ── Internals ─────────────────────────────────────────────────────────

    /**
     * Implements spec §3.2 step 5 / §3.5 step 4 — produce
     * accessToken/refreshToken for {@code uid}. Two-step process:
     * Admin SDK creates a custom token; Identity Toolkit REST exchanges it.
     */
    public FirebaseSignInResult issueTokensForUid(String uid) {
        String customToken;
        try {
            customToken = firebaseAuth.createCustomToken(uid);
        } catch (FirebaseAuthException ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
        Map<String, Object> body = Map.of("token", customToken, "returnSecureToken", true);
        FirebaseSignInResult exchange;
        try {
            ResponseEntity<Map> resp = postIdentityToolkit("signInWithCustomToken", body);
            exchange = mapSignInResponse(resp.getBody(), false, uid);
        } catch (HttpStatusCodeException ex) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to exchange " + "custom token");
        }
        // signInWithCustomToken does not echo displayName — fetch it from the Admin SDK so callers
        // can return a greet-able name in the access-token response.
        return exchange.toBuilder().displayName(fetchDisplayNameOrNull(uid)).build();
    }

    private String fetchDisplayNameOrNull(String uid) {
        try {
            return firebaseAuth.getUser(uid).getDisplayName();
        } catch (FirebaseAuthException ex) {
            log.warn("Failed to fetch displayName for uid [{}]: {}", uid, ex.getMessage());
            return null;
        }
    }

    private ResponseEntity<Map> postIdentityToolkit(String endpoint, Map<String, Object> body) {
        String apiKey = properties.getFirebase().getApiKey();
        if (apiKey == null || apiKey.isBlank()) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR,
                    "Firebase API key " + "not" + " configured");
        }
        String url = REST_BASE + endpoint + "?key=" + apiKey;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
        return restTemplate.exchange(url, HttpMethod.POST, entity, Map.class);
    }

    private FirebaseSignInResult mapSignInResponse(Map<?, ?> body, boolean readIsNewUser) {
        return mapSignInResponse(body, readIsNewUser, null);
    }

    private FirebaseSignInResult mapSignInResponse(Map<?, ?> body, boolean readIsNewUser, String fallbackUid) {
        if (body == null) {
            throw new AuthException(ErrorCode.INTERNAL_ERROR, HttpStatus.INTERNAL_SERVER_ERROR, "Empty Firebase " +
                    "response");
        }
        String idToken = stringOf(body, "idToken");
        String refreshToken = stringOf(body, "refreshToken");
        String uid = stringOf(body, "localId");
        if (uid == null) {
            uid = fallbackUid;
        }
        boolean newUser = readIsNewUser && Boolean.TRUE.equals(body.get("isNewUser"));
        return FirebaseSignInResult.builder()
                .accessToken(idToken)
                .refreshToken(refreshToken)
                .uid(uid)
                .displayName(stringOf(body, "displayName"))
                .isNewUser(newUser)
                .build();
    }
}
