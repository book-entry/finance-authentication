package com.personal.finance.authentication.dto.response;

import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/password/reset-verify} — spec §3.9. */
@Value
@Builder
public class PasswordResetVerifyResponse {
    String confirmedToken;
    boolean otpVerified;
}
