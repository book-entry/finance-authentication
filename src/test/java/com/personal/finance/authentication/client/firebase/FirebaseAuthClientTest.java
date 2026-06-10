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

    // ── signInWithIdpCredential ───────────────────────────────────────────

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void signInWithIdpCredential_returns_tokens_and_isNewUser() {
        Map<String, Object> body = Map.of(
                "idToken", "id-tok",
                "refreshToken", "refresh-tok",
                "localId", "uid-G",
                "displayName", "Alice",
                "isNewUser", true);
        when(restTemplate.exchange(contains("signInWithIdp"), eq(HttpMethod.POST), any(), eq(Map.class)))
                .thenReturn(new ResponseEntity(body, HttpStatus.OK));

        FirebaseSignInResult result = client.signInWithIdpCredential("google.com", "provider-id-tok");

        assertThat(result.getAccessToken()).isEqualTo("id-tok");
        assertThat(result.getRefreshToken()).isEqualTo("refresh-tok");
        assertThat(result.getUid()).isEqualTo("uid-G");
        assertThat(result.isNewUser()).isTrue();
        assertThat(result.getDisplayName()).isEqualTo("Alice");
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

    // ── getUser (profile) ─────────────────────────────────────────────────

    @Test
    void getUser_returns_profile_on_success() throws Exception {
        UserRecord record = mock(UserRecord.class);
        when(record.getUid()).thenReturn("uid-P");
        when(record.getEmail()).thenReturn("p@example.com");
        when(record.getDisplayName()).thenReturn("Alice");
        when(firebaseAuth.getUser("uid-P")).thenReturn(record);

        FirebaseUserProfile profile = client.getUser("uid-P");

        assertThat(profile.getUid()).isEqualTo("uid-P");
        assertThat(profile.getEmail()).isEqualTo("p@example.com");
        assertThat(profile.getDisplayName()).isEqualTo("Alice");
    }

    @Test
    void getUser_translates_not_found_to_invalid_token() throws Exception {
        FirebaseAuthException ex = stubFirebaseException(ErrorCode.NOT_FOUND,
                "USER_NOT_FOUND: There is no user record corresponding to the provided identifier.");
        when(firebaseAuth.getUser("ghost")).thenThrow(ex);

        assertThatThrownBy(() -> client.getUser("ghost"))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).getErrorCode())
                        .isEqualTo(com.personal.finance.common.exception.ErrorCode.INVALID_TOKEN));
    }

    // ── updateDisplayName (profile) ───────────────────────────────────────

    @Test
    void updateDisplayName_returns_updated_profile() throws Exception {
        UserRecord record = mock(UserRecord.class);
        when(record.getUid()).thenReturn("uid-P");
        when(record.getDisplayName()).thenReturn("New Name");
        when(firebaseAuth.updateUser(any())).thenReturn(record);

        FirebaseUserProfile profile = client.updateDisplayName("uid-P", "New Name");

        assertThat(profile.getDisplayName()).isEqualTo("New Name");
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
