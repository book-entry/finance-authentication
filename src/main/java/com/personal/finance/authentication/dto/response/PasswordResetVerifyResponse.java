package com.personal.finance.authentication.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/password/reset-verify} — spec §3.9. */
@Value
@Builder
@Schema(description = "Response returned after successful OTP verification in the password-reset flow (spec §3.9).")
public class PasswordResetVerifyResponse {

    @Schema(description = "Confirmed internal JWT to be supplied to /v1/password/reset.",
            example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature")
    String confirmedToken;

    @Schema(description = "Whether the OTP was successfully verified.", example = "true")
    boolean otpVerified;
}
