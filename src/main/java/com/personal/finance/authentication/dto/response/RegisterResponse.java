package com.personal.finance.authentication.dto.response;

import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/register} — spec §3.4. */
@Value
@Builder
public class RegisterResponse {
    String sessionToken;
    boolean requiresOtp;
    long expiresIn;
}
