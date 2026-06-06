package com.personal.finance.authentication.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/otp/resend} — spec §3.11. */
@Value
@Builder
@Schema(description = "Confirmation returned after an OTP has been re-sent (spec §3.11).")
public class ResendOtpResponse {

    @Schema(description = "Human-readable confirmation message.", example = "OTP resent successfully.")
    String message;

    @Schema(description = "Seconds the caller must wait before requesting another resend.", example = "60")
    long retryAfter;
}
