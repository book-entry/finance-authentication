package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseSignInResult;
import com.personal.finance.authentication.client.twilio.TwilioVerifyClient;
import com.personal.finance.authentication.dto.request.RegisterRequest;
import com.personal.finance.authentication.dto.request.RegisterVerifyOtpRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.RegisterResponse;
import com.personal.finance.authentication.util.JwtUtil;
import com.personal.finance.authentication.util.PasswordValidator;
import com.personal.finance.authentication.util.TokenContext;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterServiceImpl implements RegisterService {

    /**
     * Carries the user's display name across the register → verify-otp boundary
     * via the sessionToken {@code name} claim.
     */
    public static final String CLAIM_NAME = "name";

    private final FirebaseAuthClient firebaseClient;
    private final TwilioVerifyClient twilioClient;
    private final JwtUtil jwtUtil;

    /**
     * Spec §3.4 — High-Level Logic:
     * <ol>
     *   <li>Validate email + password strength + name presence.</li>
     *   <li>Firebase createUserWithEmailAndPassword (EMAIL_EXISTS → 409).</li>
     *   <li>Extract uid (account unverified).</li>
     *   <li>Sign sessionToken (ctx=register, TTL 600s, include name).</li>
     *   <li>Twilio dispatch OTP.</li>
     *   <li>Return 202 { sessionToken, requiresOtp:true, expiresIn:600 }.</li>
     * </ol>
     */
    @Override
    public RegisterResponse register(RegisterRequest request) {
        String email = normaliseEmail(request.getEmail());
        PasswordValidator.validate(request.getPassword());
        String uid = firebaseClient.createUser(email, request.getPassword(), request.getName());
        String sessionToken = signRegisterToken(uid, email, request.getName());
        twilioClient.sendVerification(email);
        log.info("Registration OTP dispatched for uid [{}]", uid);
        return RegisterResponse.builder()
                .sessionToken(sessionToken)
                .requiresOtp(true)
                .expiresIn(TokenContext.TTL_REGISTER.toSeconds())
                .build();
    }

    /**
     * Spec §3.5 — High-Level Logic:
     * <ol>
     *   <li>Decode + validate sessionToken; assert ctx=register.</li>
     *   <li>Twilio VerificationCheck; status must be 'approved'.</li>
     *   <li>Firebase updateUser(emailVerified=true, displayName=name).</li>
     *   <li>createCustomToken + exchange for idToken/refreshToken.</li>
     *   <li>Return 201 { accessToken, refreshToken, uid }.</li>
     * </ol>
     */
    @Override
    public AccessTokenResponse verifyOtp(RegisterVerifyOtpRequest request) {
        Claims claims = jwtUtil.validateAndParse(request.getSessionToken());
        jwtUtil.assertContext(claims, TokenContext.CTX_REGISTER);
        String uid = claims.get(JwtUtil.CLAIM_UID, String.class);
        String email = claims.get(JwtUtil.CLAIM_EMAIL, String.class);
        String name = claims.get(CLAIM_NAME, String.class);
        twilioClient.checkVerification(email, request.getOtp());
        firebaseClient.markEmailVerified(uid, name);
        FirebaseSignInResult result = firebaseClient.issueTokensForUid(uid);
        log.info("Registration OTP verified for uid [{}]", uid);
        return AccessTokenResponse.builder()
                .accessToken(result.getAccessToken())
                .refreshToken(result.getRefreshToken())
                .uid(uid)
                .build();
    }

    /**
     * Adds the {@code name} claim alongside the standard set so verify-otp can
     * propagate it to {@code updateUser(displayName=…)}.
     */
    private String signRegisterToken(String uid, String email, String name) {
        // Reuse JwtUtil.generateToken then re-issue with the name claim baked in.
        // To avoid widening JwtUtil's signature with optional claims, sign in
        // two steps: generate a base token to validate config, then build the
        // final token via the same helper extended with one claim.
        return jwtUtil.generateTokenWithExtraClaim(
                uid, email, TokenContext.CTX_REGISTER, null,
                TokenContext.TTL_REGISTER, CLAIM_NAME, name);
    }

    private static String normaliseEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
