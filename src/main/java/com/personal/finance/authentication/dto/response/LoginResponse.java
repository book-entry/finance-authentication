package com.personal.finance.authentication.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/login} — spec §3.1. */
@Value
@Builder
@Schema(description = "Response returned after a successful password-login initiation; OTP step follows (spec §3.1).")
public class LoginResponse {

    @Schema(description = "Internal session JWT to be supplied to /v1/login/verify-otp and /v1/otp/resend.",
            example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature")
    String sessionToken;

    @Schema(description = "Whether an OTP challenge is required before a Firebase token is issued.",
            example = "true")
    boolean requiresOtp;

    @Schema(description = "Seconds until the sessionToken expires.", example = "300")
    long expiresIn;
}
