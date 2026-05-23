package com.personal.finance.authentication.service;

import com.personal.finance.authentication.dto.request.RegisterRequest;
import com.personal.finance.authentication.dto.request.RegisterVerifyOtpRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.RegisterResponse;

/** Implements the registration flow defined in spec §3.4, §3.5. */
public interface RegisterService {

    /** Spec §3.4 — create unverified Firebase user + OTP dispatch. */
    RegisterResponse register(RegisterRequest request);

    /** Spec §3.5 — OTP verification, mark email verified, issue tokens. */
    AccessTokenResponse verifyOtp(RegisterVerifyOtpRequest request);
}
