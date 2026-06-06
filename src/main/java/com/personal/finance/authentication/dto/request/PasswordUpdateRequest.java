package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/password/update} — spec §3.7. */
@Data
@NoArgsConstructor
@Schema(description = "Password update payload carrying the action token, OTP, and new password (spec §3.7).")
public class PasswordUpdateRequest {

    @NotBlank
    @Schema(description = "Internal actionToken issued by /v1/password/update-request.",
            example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String actionToken;

    @NotBlank
    @Schema(description = "Six-digit OTP sent to the user's registered contact.", example = "123456",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String otp;

    @NotBlank
    @Schema(description = "New plain-text password to set.", example = "NewSecret123!",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String newPassword;
}
