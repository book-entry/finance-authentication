package com.personal.finance.authentication.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/password/update-request} — spec §3.6. */
@Value
@Builder
@Schema(description = "Response returned after a successful password-update initiation; OTP step follows (spec §3.6).")
public class PasswordUpdateRequestResponse {

    @Schema(description = "Internal actionToken to be supplied to /v1/password/update and /v1/otp/resend.",
            example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature")
    String actionToken;

    @Schema(description = "Whether an OTP challenge is required before the password is updated.", example = "true")
    boolean requiresOtp;

    @Schema(description = "Seconds until the actionToken expires.", example = "300")
    long expiresIn;
}
