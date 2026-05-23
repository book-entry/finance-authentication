package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseSignInResult;
import com.personal.finance.authentication.client.twilio.TwilioVerifyClient;
import com.personal.finance.authentication.dto.request.LoginRequest;
import com.personal.finance.authentication.dto.request.LoginVerifyOtpRequest;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.LoginResponse;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.util.JwtUtil;
import com.personal.finance.authentication.util.TokenContext;
import com.personal.finance.common.exception.ErrorCode;
import io.jsonwebtoken.Claims;
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
    private final TwilioVerifyClient twilioClient;
    private final JwtUtil jwtUtil;

    /**
     * Spec §3.1 — High-Level Logic:
     * <ol>
     *   <li>Normalise email to lowercase.</li>
     *   <li>Firebase signInWithEmailAndPassword — 401 on failure.</li>
     *   <li>Extract uid.</li>
     *   <li>Sign sessionToken (ctx=login, TTL 300s).</li>
     *   <li>Twilio dispatch OTP.</li>
     *   <li>Return 202 { sessionToken, requiresOtp:true, expiresIn:300 }.</li>
     * </ol>
     */
    @Override
    public LoginResponse login(LoginRequest request) {
        String email = normaliseEmail(request.getEmail());
        FirebaseSignInResult signIn = firebaseClient.signInWithEmailAndPassword(email, request.getPassword());
        String sessionToken = jwtUtil.generateToken(
                signIn.getUid(), email, TokenContext.CTX_LOGIN, null, TokenContext.TTL_LOGIN);
        twilioClient.sendVerification(email);
        log.info("Login OTP dispatched for uid [{}]", signIn.getUid());
        return LoginResponse.builder()
                .sessionToken(sessionToken)
                .requiresOtp(true)
                .expiresIn(TokenContext.TTL_LOGIN.toSeconds())
                .build();
    }

    /**
     * Spec §3.2 — High-Level Logic:
     * <ol>
     *   <li>Decode + validate sessionToken; assert ctx=login.</li>
     *   <li>Extract uid + email.</li>
     *   <li>Twilio VerificationCheck; non-approved → 401, max-attempts → 429.</li>
     *   <li>createCustomToken + exchange for idToken/refreshToken.</li>
     *   <li>Return 200 { accessToken, refreshToken, uid }.</li>
     * </ol>
     */
    @Override
    public AccessTokenResponse verifyOtp(LoginVerifyOtpRequest request) {
        Claims claims = jwtUtil.validateAndParse(request.getSessionToken());
        jwtUtil.assertContext(claims, TokenContext.CTX_LOGIN);
        String uid = claims.get(JwtUtil.CLAIM_UID, String.class);
        String email = claims.get(JwtUtil.CLAIM_EMAIL, String.class);
        twilioClient.checkVerification(email, request.getOtp());
        FirebaseSignInResult result = firebaseClient.issueTokensForUid(uid);
        log.info("Login OTP verified for uid [{}]", uid);
        return AccessTokenResponse.builder()
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .uid(uid)
                .build();
    }

    /**
     * Spec §3.3 — High-Level Logic:
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

    private static String normaliseEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
