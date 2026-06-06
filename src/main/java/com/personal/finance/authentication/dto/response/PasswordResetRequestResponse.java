package com.personal.finance.authentication.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

/**
 * Response for {@code POST /v1/password/reset-request} — spec §3.8.
 *
 * <p>{@code resetToken} is {@code null} when the email does not match an
 * existing account (anti-enumeration): only {@code requiresOtp:false} is
 * returned, the rest of the payload is suppressed via
 * {@link JsonInclude.Include#NON_NULL}.
 */
@Value
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Response for the password reset initiation step (spec §3.8). resetToken is intentionally null for unknown emails to prevent account enumeration.")
public class PasswordResetRequestResponse {

    @Schema(description = "Internal resetToken to be supplied to /v1/password/reset-verify. Null when the email is not registered (anti-enumeration).",
            example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature")
    String resetToken;

    @Schema(description = "Whether an OTP challenge is required to proceed.", example = "true")
    Boolean requiresOtp;

    @Schema(description = "Seconds until the resetToken expires.", example = "300")
    Long expiresIn;
}
