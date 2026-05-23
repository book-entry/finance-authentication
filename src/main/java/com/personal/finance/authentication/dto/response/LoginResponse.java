package com.personal.finance.authentication.dto.response;

import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/login} — spec §3.1. */
@Value
@Builder
public class LoginResponse {
    String sessionToken;
    boolean requiresOtp;
    long expiresIn;
}
