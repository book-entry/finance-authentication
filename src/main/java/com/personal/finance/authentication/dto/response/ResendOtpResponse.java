package com.personal.finance.authentication.dto.response;

import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/otp/resend} — spec §3.11. */
@Value
@Builder
public class ResendOtpResponse {
    String message;
    long retryAfter;
}
