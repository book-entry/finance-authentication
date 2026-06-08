package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseUserProfile;
import com.personal.finance.authentication.client.firebase.FirebaseUserRecord;
import com.personal.finance.authentication.dto.request.UpdateMeRequest;
import com.personal.finance.authentication.dto.response.MeResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MeServiceImplTest {

    @Mock FirebaseAuthClient firebaseClient;

    MeServiceImpl service;

    private static final String BEARER = "Bearer id-token-A";
    private static final String UID = "uid-U";

    @BeforeEach
    void setUp() {
        service = new MeServiceImpl(firebaseClient);
    }

    private FirebaseUserProfile sampleProfile(String displayName) {
        return FirebaseUserProfile.builder()
                .uid(UID)
                .email("u@example.com")
                .emailVerified(true)
                .displayName(displayName)
                .createdAt(OffsetDateTime.of(2025, 8, 12, 3, 14, 21, 0, ZoneOffset.UTC))
                .lastSignInAt(OffsetDateTime.of(2026, 6, 4, 1, 2, 3, 0, ZoneOffset.UTC))
                .build();
    }

    // ── GET /me ───────────────────────────────────────────────────────────

    @Test
    void getMe_verifiesToken_and_returns_hydrated_firebase_fields() {
        when(firebaseClient.verifyIdToken("id-token-A"))
                .thenReturn(new FirebaseUserRecord(UID, "u@example.com"));
        when(firebaseClient.getUser(UID)).thenReturn(sampleProfile("Alice Wong"));

        MeResponse resp = service.getMe(BEARER);

        assertThat(resp.getUid()).isEqualTo(UID);
        assertThat(resp.getEmail()).isEqualTo("u@example.com");
        assertThat(resp.isEmailVerified()).isTrue();
        assertThat(resp.getDisplayName()).isEqualTo("Alice Wong");
        assertThat(resp.getCreatedAt()).isEqualTo(OffsetDateTime.of(2025, 8, 12, 3, 14, 21, 0, ZoneOffset.UTC));
        assertThat(resp.getLastSignInAt()).isEqualTo(OffsetDateTime.of(2026, 6, 4, 1, 2, 3, 0, ZoneOffset.UTC));
    }

    @Test
    void getMe_passes_through_null_displayName_and_lastSignIn() {
        when(firebaseClient.verifyIdToken(anyString()))
                .thenReturn(new FirebaseUserRecord(UID, "u@example.com"));
        when(firebaseClient.getUser(UID)).thenReturn(FirebaseUserProfile.builder()
                .uid(UID).email("u@example.com").emailVerified(false)
                .displayName(null).createdAt(OffsetDateTime.now(ZoneOffset.UTC)).lastSignInAt(null)
                .build());

        MeResponse resp = service.getMe(BEARER);

        assertThat(resp.getDisplayName()).isNull();
        assertThat(resp.getLastSignInAt()).isNull();
        assertThat(resp.isEmailVerified()).isFalse();
    }

    @Test
    void getMe_without_bearer_prefix_throws_invalid_token_and_skips_firebase() {
        assertThatThrownBy(() -> service.getMe("id-token-A"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
        verifyNoInteractions(firebaseClient);
    }

    @Test
    void getMe_with_blank_bearer_throws_invalid_token() {
        assertThatThrownBy(() -> service.getMe("Bearer    "))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_TOKEN));
    }

    // ── PATCH /me ─────────────────────────────────────────────────────────

    @Test
    void updateMe_trims_displayName_updates_firebase_and_returns_hydrated_shape() {
        when(firebaseClient.verifyIdToken("id-token-A"))
                .thenReturn(new FirebaseUserRecord(UID, "u@example.com"));
        when(firebaseClient.updateDisplayName(UID, "Alice W.")).thenReturn(sampleProfile("Alice W."));

        UpdateMeRequest req = new UpdateMeRequest();
        req.setDisplayName("  Alice W.  ");

        MeResponse resp = service.updateMe(BEARER, req);

        ArgumentCaptor<String> name = ArgumentCaptor.forClass(String.class);
        verify(firebaseClient).updateDisplayName(org.mockito.ArgumentMatchers.eq(UID), name.capture());
        assertThat(name.getValue()).isEqualTo("Alice W.");
        assertThat(resp.getDisplayName()).isEqualTo("Alice W.");
    }

    @Test
    void updateMe_with_null_displayName_throws_invalid_input_and_does_not_update() {
        when(firebaseClient.verifyIdToken(anyString()))
                .thenReturn(new FirebaseUserRecord(UID, "u@example.com"));

        UpdateMeRequest req = new UpdateMeRequest(); // displayName null

        assertThatThrownBy(() -> service.updateMe(BEARER, req))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_INPUT));
        verify(firebaseClient, never()).updateDisplayName(anyString(), anyString());
    }

    @Test
    void updateMe_with_blank_displayName_throws_invalid_input() {
        when(firebaseClient.verifyIdToken(anyString()))
                .thenReturn(new FirebaseUserRecord(UID, "u@example.com"));

        UpdateMeRequest req = new UpdateMeRequest();
        req.setDisplayName("   ");

        assertThatThrownBy(() -> service.updateMe(BEARER, req))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_INPUT));
    }

    @Test
    void updateMe_with_too_long_displayName_throws_invalid_input() {
        when(firebaseClient.verifyIdToken(anyString()))
                .thenReturn(new FirebaseUserRecord(UID, "u@example.com"));

        UpdateMeRequest req = new UpdateMeRequest();
        req.setDisplayName("x".repeat(61));

        assertThatThrownBy(() -> service.updateMe(BEARER, req))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_INPUT));
    }

    @Test
    void updateMe_accepts_max_length_displayName() {
        String sixty = "x".repeat(60);
        when(firebaseClient.verifyIdToken(anyString()))
                .thenReturn(new FirebaseUserRecord(UID, "u@example.com"));
        when(firebaseClient.updateDisplayName(UID, sixty)).thenReturn(sampleProfile(sixty));

        UpdateMeRequest req = new UpdateMeRequest();
        req.setDisplayName(sixty);

        MeResponse resp = service.updateMe(BEARER, req);
        assertThat(resp.getDisplayName()).isEqualTo(sixty);
    }
}
