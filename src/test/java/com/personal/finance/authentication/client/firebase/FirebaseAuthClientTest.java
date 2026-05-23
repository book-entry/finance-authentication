package com.personal.finance.authentication.client.firebase;

import com.google.firebase.ErrorCode;
import com.google.firebase.FirebaseException;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.personal.finance.authentication.config.AuthProperties;
import com.personal.finance.authentication.exception.AuthException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FirebaseAuthClientTest {

    @Mock FirebaseAuth firebaseAuth;
    @Mock RestTemplate restTemplate;

    FirebaseAuthClient client;
    AuthProperties props;

    @BeforeEach
    void setUp() {
        props = new AuthProperties();
        props.getFirebase().setApiKey("test-api-key");
        client = new FirebaseAuthClient(firebaseAuth, props, restTemplate);
    }

    // ── signInWithEmailAndPassword ────────────────────────────────────────

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void signInWithEmailAndPassword_returns_tokens_on_success() {
        Map<String, Object> body = Map.of(
                "idToken", "id-tok",
                "refreshToken", "refresh-tok",
                "localId", "uid-1");
        when(restTemplate.exchange(contains("signInWithPassword"), eq(HttpMethod.POST), any(), eq(Map.class)))
                .thenReturn(new ResponseEntity(body, HttpStatus.OK));

        FirebaseSignInResult result = client.signInWithEmailAndPassword("u@example.com", "Passw0rd!");

        assertThat(result.getAccessToken()).isEqualTo("id-tok");
        assertThat(result.getRefreshToken()).isEqualTo("refresh-tok");
        assertThat(result.getUid()).isEqualTo("uid-1");
    }

    @Test
    @SuppressWarnings("rawtypes")
    void signInWithEmailAndPassword_translates_http_error_to_invalid_credentials() {
        when(restTemplate.exchange(any(String.class), any(HttpMethod.class), any(), eq(Map.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatusCode.valueOf(400), "Bad Request",
                        new org.springframework.http.HttpHeaders(), new byte[0], null));

        assertThatThrownBy(() -> client.signInWithEmailAndPassword("u@example.com", "wrong"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(com.personal.finance.common.exception.ErrorCode.INVALID_CREDENTIALS));
    }

    // ── signInWithIdpCredential ───────────────────────────────────────────

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void signInWithIdpCredential_returns_tokens_and_isNewUser() {
        Map<String, Object> body = Map.of(
                "idToken", "id-tok",
                "refreshToken", "refresh-tok",
                "localId", "uid-G",
                "isNewUser", true);
        when(restTemplate.exchange(contains("signInWithIdp"), eq(HttpMethod.POST), any(), eq(Map.class)))
                .thenReturn(new ResponseEntity(body, HttpStatus.OK));

        FirebaseSignInResult result = client.signInWithIdpCredential("google.com", "provider-id-tok");

        assertThat(result.getUid()).isEqualTo("uid-G");
        assertThat(result.isNewUser()).isTrue();
    }

    @Test
    @SuppressWarnings("rawtypes")
    void signInWithIdpCredential_translates_http_error_to_invalid_id_token() {
        when(restTemplate.exchange(any(String.class), any(HttpMethod.class), any(), eq(Map.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatusCode.valueOf(401), "Unauthorized",
                        new org.springframework.http.HttpHeaders(), new byte[0], null));

        assertThatThrownBy(() -> client.signInWithIdpCredential("google.com", "bad"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(com.personal.finance.common.exception.ErrorCode.INVALID_ID_TOKEN));
    }

    // ── createUser ────────────────────────────────────────────────────────

    @Test
    void createUser_returns_uid_on_success() throws Exception {
        UserRecord record = mock(UserRecord.class);
        when(record.getUid()).thenReturn("uid-N");
        when(firebaseAuth.createUser(any())).thenReturn(record);

        String uid = client.createUser("u@example.com", "Passw0rd!", "Alice");

        assertThat(uid).isEqualTo("uid-N");
    }

    @Test
    void createUser_translates_email_exists_to_email_in_use() throws Exception {
        // FirebaseAuthClient detects EMAIL_EXISTS via message text ("already in use")
        FirebaseAuthException ex = stubFirebaseException(ErrorCode.ALREADY_EXISTS,
                "EMAIL_EXISTS: The email address is already in use by another account.");
        when(firebaseAuth.createUser(any())).thenThrow(ex);

        assertThatThrownBy(() -> client.createUser("u@example.com", "Passw0rd!", "Alice"))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).getErrorCode())
                        .isEqualTo(com.personal.finance.common.exception.ErrorCode.EMAIL_IN_USE));
    }

    // ── verifyIdToken ─────────────────────────────────────────────────────

    @Test
    void verifyIdToken_returns_uid_email_on_success() throws Exception {
        com.google.firebase.auth.FirebaseToken token = mock(com.google.firebase.auth.FirebaseToken.class);
        when(token.getUid()).thenReturn("uid-V");
        when(token.getEmail()).thenReturn("v@example.com");
        when(firebaseAuth.verifyIdToken("good-id-token")).thenReturn(token);

        FirebaseUserRecord result = client.verifyIdToken("good-id-token");

        assertThat(result.getUid()).isEqualTo("uid-V");
        assertThat(result.getEmail()).isEqualTo("v@example.com");
    }

    @Test
    void verifyIdToken_translates_firebase_failure_to_invalid_token() throws Exception {
        FirebaseAuthException ex = stubFirebaseException(ErrorCode.INVALID_ARGUMENT, "Invalid token");
        when(firebaseAuth.verifyIdToken("bad")).thenThrow(ex);

        assertThatThrownBy(() -> client.verifyIdToken("bad"))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).getErrorCode())
                        .isEqualTo(com.personal.finance.common.exception.ErrorCode.INVALID_TOKEN));
    }

    // ── getUserByEmailOrNull ──────────────────────────────────────────────

    @Test
    void getUserByEmailOrNull_returns_record_on_match() throws Exception {
        UserRecord record = mock(UserRecord.class);
        when(record.getUid()).thenReturn("uid-X");
        when(record.getEmail()).thenReturn("x@example.com");
        when(firebaseAuth.getUserByEmail("x@example.com")).thenReturn(record);

        FirebaseUserRecord result = client.getUserByEmailOrNull("x@example.com");

        assertThat(result.getUid()).isEqualTo("uid-X");
    }

    @Test
    void getUserByEmailOrNull_returns_null_when_user_not_found() throws Exception {
        FirebaseAuthException ex = stubFirebaseException(ErrorCode.NOT_FOUND,
                "USER_NOT_FOUND: There is no user record corresponding to the provided identifier.");
        when(firebaseAuth.getUserByEmail("ghost@example.com")).thenThrow(ex);

        assertThat(client.getUserByEmailOrNull("ghost@example.com")).isNull();
    }

    // ── helper ────────────────────────────────────────────────────────────

    /**
     * FirebaseException.getErrorCode() is final, so the {@code code} string is
     * carried via the message — FirebaseAuthClient checks both the ErrorCode
     * enum and message text when classifying failures.
     */
    private static FirebaseAuthException stubFirebaseException(ErrorCode errorCode, String message) {
        return new FirebaseAuthException(
                new FirebaseException(errorCode, message, null));
    }
}
