package com.personal.finance.authentication.service;

import com.personal.finance.authentication.dto.request.LoginRequest;
import com.personal.finance.authentication.dto.request.LoginVerifyOtpRequest;
import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.AccessTokenResponse;
import com.personal.finance.authentication.dto.response.LoginResponse;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;

/** Implements the login flows defined in spec §3.1, §3.2, §3.3. */
public interface LoginService {

    /** Spec §3.1 — email/password sign-in + OTP dispatch. */
    LoginResponse login(LoginRequest request);

    /** Spec §3.2 — OTP verification + token issuance. */
    AccessTokenResponse verifyOtp(LoginVerifyOtpRequest request);

    /** Spec §3.3 — Google / Apple OAuth federation. */
    OAuthLoginResponse oauthLogin(OAuthLoginRequest request);
}
