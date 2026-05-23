package com.personal.finance.authentication.service;

import com.personal.finance.authentication.dto.request.PasswordResetRequest;
import com.personal.finance.authentication.dto.request.PasswordResetSubmitRequest;
import com.personal.finance.authentication.dto.request.PasswordResetVerifyRequest;
import com.personal.finance.authentication.dto.request.PasswordUpdateRequest;
import com.personal.finance.authentication.dto.response.MessageResponse;
import com.personal.finance.authentication.dto.response.PasswordResetRequestResponse;
import com.personal.finance.authentication.dto.response.PasswordResetVerifyResponse;
import com.personal.finance.authentication.dto.response.PasswordUpdateRequestResponse;

/** Implements the password-change flows defined in spec §3.6–§3.10. */
public interface PasswordService {

    /** Spec §3.6 — verify accessToken, dispatch OTP for authenticated update. */
    PasswordUpdateRequestResponse requestUpdate(String bearerToken);

    /** Spec §3.7 — verify OTP and apply new password. */
    MessageResponse submitUpdate(PasswordUpdateRequest request);

    /** Spec §3.8 — anti-enumeration-safe reset request. */
    PasswordResetRequestResponse requestReset(PasswordResetRequest request);

    /** Spec §3.9 — verify OTP, return confirmedToken. */
    PasswordResetVerifyResponse verifyReset(PasswordResetVerifyRequest request);

    /** Spec §3.10 — apply new password using confirmedToken. */
    MessageResponse submitReset(PasswordResetSubmitRequest request);
}
