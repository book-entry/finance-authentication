package com.personal.finance.authentication.dto.response;

import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/password/update-request} — spec §3.6. */
@Value
@Builder
public class PasswordUpdateRequestResponse {
    String actionToken;
    boolean requiresOtp;
    long expiresIn;
}
