package com.personal.finance.authentication.service;

import com.personal.finance.authentication.client.firebase.FirebaseAuthClient;
import com.personal.finance.authentication.client.firebase.FirebaseUserRecord;
import com.personal.finance.authentication.client.twilio.TwilioVerifyClient;
import com.personal.finance.authentication.dto.request.PasswordResetRequest;
import com.personal.finance.authentication.dto.request.PasswordResetSubmitRequest;
import com.personal.finance.authentication.dto.request.PasswordResetVerifyRequest;
import com.personal.finance.authentication.dto.request.PasswordUpdateRequest;
import com.personal.finance.authentication.dto.response.MessageResponse;
import com.personal.finance.authentication.dto.response.PasswordResetRequestResponse;
import com.personal.finance.authentication.dto.response.PasswordResetVerifyResponse;
import com.personal.finance.authentication.dto.response.PasswordUpdateRequestResponse;
import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.authentication.util.JwtUtil;
import com.personal.finance.authentication.util.PasswordValidator;
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
public class PasswordServiceImpl implements PasswordService {

    private static final String BEARER_PREFIX = "Bearer ";

    private final FirebaseAuthClient firebaseClient;
    private final TwilioVerifyClient twilioClient;
    private final JwtUtil jwtUtil;

    /**
     * Spec §3.6 — High-Level Logic:
     * <ol>
     *   <li>Extract Bearer token from Authorization header.</li>
     *   <li>Firebase verifyIdToken; extract uid + email.</li>
     *   <li>Sign actionToken (ctx=pwd-update, TTL 300s).</li>
     *   <li>Twilio dispatch OTP.</li>
     *   <li>Return 202 { actionToken, requiresOtp:true, expiresIn:300 }.</li>
     * </ol>
     */
    @Override
    public PasswordUpdateRequestResponse requestUpdate(String authorizationHeader) {
        String accessToken = extractBearer(authorizationHeader);
        FirebaseUserRecord user = firebaseClient.verifyIdToken(accessToken);
        String actionToken = jwtUtil.generateToken(
                user.getUid(), user.getEmail(), TokenContext.CTX_PWD_UPDATE, null,
                TokenContext.TTL_PWD_UPDATE);
        twilioClient.sendVerification(user.getEmail());
        log.info("Password-update OTP dispatched for uid [{}]", user.getUid());
        return PasswordUpdateRequestResponse.builder()
                .actionToken(actionToken)
                .requiresOtp(true)
                .expiresIn(TokenContext.TTL_PWD_UPDATE.toSeconds())
                .build();
    }

    /**
     * Spec §3.7 — High-Level Logic:
     * <ol>
     *   <li>Decode + validate actionToken; assert ctx=pwd-update.</li>
     *   <li>Validate newPassword complexity.</li>
     *   <li>Twilio VerificationCheck; status must be 'approved'.</li>
     *   <li>Firebase updateUser(password=newPassword).</li>
     *   <li>Return 200 { message: 'Password updated successfully' }.</li>
     * </ol>
     */
    @Override
    public MessageResponse submitUpdate(PasswordUpdateRequest request) {
        Claims claims = jwtUtil.validateAndParse(request.getActionToken());
        jwtUtil.assertContext(claims, TokenContext.CTX_PWD_UPDATE);
        PasswordValidator.validate(request.getNewPassword());
        String uid = claims.get(JwtUtil.CLAIM_UID, String.class);
        String email = claims.get(JwtUtil.CLAIM_EMAIL, String.class);
        twilioClient.checkVerification(email, request.getOtp());
        firebaseClient.updatePassword(uid, request.getNewPassword());
        log.info("Password updated for uid [{}]", uid);
        return new MessageResponse("Password updated successfully");
    }

    /**
     * Spec §3.8 — High-Level Logic:
     * <ol>
     *   <li>Validate email format.</li>
     *   <li>Firebase getUserByEmail; if NOT_FOUND, return 202 { requiresOtp:false }.</li>
     *   <li>Sign resetToken (ctx=pwd-reset, phase=otp, TTL 600s).</li>
     *   <li>Twilio dispatch OTP.</li>
     *   <li>Return 202 { resetToken, requiresOtp:true, expiresIn:600 }.</li>
     * </ol>
     */
    @Override
    public PasswordResetRequestResponse requestReset(PasswordResetRequest request) {
        String email = normaliseEmail(request.getEmail());
        FirebaseUserRecord user = firebaseClient.getUserByEmailOrNull(email);
        if (user == null) {
            // Anti-enumeration: spec §3.8 — always 202, no token leaked.
            log.info("Password reset requested for unknown email — silently accepted");
            return PasswordResetRequestResponse.builder()
                    .requiresOtp(false)
                    .build();
        }
        String resetToken = jwtUtil.generateToken(
                user.getUid(), email, TokenContext.CTX_PWD_RESET,
                TokenContext.PHASE_OTP, TokenContext.TTL_RESET_OTP);
        twilioClient.sendVerification(email);
        log.info("Password-reset OTP dispatched for uid [{}]", user.getUid());
        return PasswordResetRequestResponse.builder()
                .resetToken(resetToken)
                .requiresOtp(true)
                .expiresIn(TokenContext.TTL_RESET_OTP.toSeconds())
                .build();
    }

    /**
     * Spec §3.9 — High-Level Logic:
     * <ol>
     *   <li>Decode + validate resetToken; assert ctx=pwd-reset AND phase=otp.</li>
     *   <li>Twilio VerificationCheck; status must be 'approved'.</li>
     *   <li>Re-sign confirmedToken (ctx=pwd-reset, phase=confirmed, TTL 300s).</li>
     *   <li>Return 200 { confirmedToken, otpVerified:true }.</li>
     * </ol>
     */
    @Override
    public PasswordResetVerifyResponse verifyReset(PasswordResetVerifyRequest request) {
        Claims claims = jwtUtil.validateAndParse(request.getResetToken());
        jwtUtil.assertContext(claims, TokenContext.CTX_PWD_RESET);
        jwtUtil.assertPhase(claims, TokenContext.PHASE_OTP);
        String uid = claims.get(JwtUtil.CLAIM_UID, String.class);
        String email = claims.get(JwtUtil.CLAIM_EMAIL, String.class);
        twilioClient.checkVerification(email, request.getOtp());
        String confirmedToken = jwtUtil.generateToken(
                uid, email, TokenContext.CTX_PWD_RESET,
                TokenContext.PHASE_CONFIRMED, TokenContext.TTL_RESET_CONFIRMED);
        log.info("Password reset OTP verified for uid [{}]", uid);
        return PasswordResetVerifyResponse.builder()
                .confirmedToken(confirmedToken)
                .otpVerified(true)
                .build();
    }

    /**
     * Spec §3.10 — High-Level Logic:
     * <ol>
     *   <li>Decode + validate confirmedToken; assert ctx=pwd-reset AND phase=confirmed.</li>
     *   <li>Validate newPassword complexity.</li>
     *   <li>Firebase updateUser(password=newPassword).</li>
     *   <li>Return 200 { message: 'Password reset successfully' }.</li>
     * </ol>
     */
    @Override
    public MessageResponse submitReset(PasswordResetSubmitRequest request) {
        Claims claims = jwtUtil.validateAndParse(request.getConfirmedToken());
        jwtUtil.assertContext(claims, TokenContext.CTX_PWD_RESET);
        jwtUtil.assertPhase(claims, TokenContext.PHASE_CONFIRMED);
        PasswordValidator.validate(request.getNewPassword());
        String uid = claims.get(JwtUtil.CLAIM_UID, String.class);
        firebaseClient.updatePassword(uid, request.getNewPassword());
        log.info("Password reset completed for uid [{}]", uid);
        return new MessageResponse("Password reset successfully");
    }

    private static String extractBearer(String header) {
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
                    "Authorization Bearer header is required");
        }
        String value = header.substring(BEARER_PREFIX.length()).trim();
        if (value.isEmpty()) {
            throw new AuthException(ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
                    "Authorization Bearer header is empty");
        }
        return value;
    }

    private static String normaliseEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
