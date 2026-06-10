package com.personal.finance.authentication.service;

import com.personal.finance.authentication.dto.request.OAuthLoginRequest;
import com.personal.finance.authentication.dto.response.OAuthLoginResponse;

/** Implements the OAuth login flow (Google / Apple). */
public interface LoginService {

    /** Google / Apple OAuth federation; provisions the account on first sign-in. */
    OAuthLoginResponse oauthLogin(OAuthLoginRequest request);
}
