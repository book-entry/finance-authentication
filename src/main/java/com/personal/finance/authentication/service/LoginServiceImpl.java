package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseSignInResult;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginServiceImpl implements LoginService {

    private static final String PROVIDER_GOOGLE = "google";
    private static final String PROVIDER_APPLE = "apple";
    private static final String FIREBASE_GOOGLE = "google.com";
    private static final String FIREBASE_APPLE = "apple.com";

    private final FirebaseAuthClient firebaseClient;

    /**
     * High-Level Logic:
     * <ol>
     *   <li>Validate provider is google|apple (else 400 INVALID_PROVIDER).</li>
     *   <li>Firebase signInWithCredential — 401 INVALID_ID_TOKEN on failure.</li>
     *   <li>Return 200 { accessToken, refreshToken, uid, isNewUser }.</li>
     * </ol>
     */
    @Override
    public OAuthLoginResponse oauthLogin(OAuthLoginRequest request) {
        String providerId = mapProvider(request.getProvider());
        FirebaseSignInResult result = firebaseClient.signInWithIdpCredential(providerId, request.getIdToken());
        log.info("OAuth login successful uid=[{}] newUser=[{}]", result.getUid(), result.isNewUser());
        return OAuthLoginResponse.builder()
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .uid(result.getUid())
                .displayName(result.getDisplayName())
                .isNewUser(result.isNewUser())
                .build();
    }

    private String mapProvider(String provider) {
        if (provider == null) {
            throw new AuthException(ErrorCode.INVALID_PROVIDER, HttpStatus.BAD_REQUEST,
                    "provider is required");
        }
        return switch (provider.trim().toLowerCase()) {
            case PROVIDER_GOOGLE -> FIREBASE_GOOGLE;
            case PROVIDER_APPLE -> FIREBASE_APPLE;
            default -> throw new AuthException(ErrorCode.INVALID_PROVIDER, HttpStatus.BAD_REQUEST,
                    "provider must be 'google' or 'apple'");
        };
    }
}
