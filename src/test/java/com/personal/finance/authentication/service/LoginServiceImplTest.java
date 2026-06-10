package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseSignInResult;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginServiceImplTest {

    @Mock FirebaseAuthClient firebaseClient;

    LoginServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new LoginServiceImpl(firebaseClient);
    }

    @Test
    void oauthLogin_happy_path_maps_google_to_firebase_provider() {
        when(firebaseClient.signInWithIdpCredential(eq("google.com"), anyString()))
                .thenReturn(FirebaseSignInResult.builder()
                        .accessToken("a").refreshToken("r").uid("u")
                        .displayName("Alice").isNewUser(true).build());

        OAuthLoginResponse resp = service.oauthLogin(oauth("google", "id-token"));

        assertThat(resp.getAccessToken()).isEqualTo("a");
        assertThat(resp.getRefreshToken()).isEqualTo("r");
        assertThat(resp.getUid()).isEqualTo("u");
        assertThat(resp.isNewUser()).isTrue();
        assertThat(resp.getDisplayName()).isEqualTo("Alice");
    }

    @Test
    void oauthLogin_maps_apple_to_firebase_provider() {
        when(firebaseClient.signInWithIdpCredential(eq("apple.com"), anyString()))
                .thenReturn(FirebaseSignInResult.builder().uid("u").isNewUser(false).build());

        OAuthLoginResponse resp = service.oauthLogin(oauth("Apple", "id-token"));

        assertThat(resp.getUid()).isEqualTo("u");
        assertThat(resp.isNewUser()).isFalse();
    }

    @Test
    void oauthLogin_unknown_provider_throws_invalid_provider() {
        assertThatThrownBy(() -> service.oauthLogin(oauth("facebook", "id-token")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_PROVIDER));
    }

    @Test
    void oauthLogin_null_provider_throws_invalid_provider() {
        assertThatThrownBy(() -> service.oauthLogin(oauth(null, "id-token")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_PROVIDER));
    }

    @Test
    void oauthLogin_firebase_rejection_translates_to_invalid_id_token() {
        when(firebaseClient.signInWithIdpCredential(any(), any()))
                .thenThrow(new AuthException(ErrorCode.INVALID_ID_TOKEN, HttpStatus.UNAUTHORIZED));

        assertThatThrownBy(() -> service.oauthLogin(oauth("apple", "bad")))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_ID_TOKEN));
    }

    private OAuthLoginRequest oauth(String provider, String idToken) {
        OAuthLoginRequest r = new OAuthLoginRequest();
        r.setProvider(provider);
        r.setIdToken(idToken);
        return r;
    }
}
