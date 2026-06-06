package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/password/reset} — spec §3.10. */
@Data
@NoArgsConstructor
@Schema(description = "Password reset submission payload carrying the confirmed token and new password (spec §3.10).")
public class PasswordResetSubmitRequest {

    @NotBlank
    @Schema(description = "Confirmed internal JWT returned by /v1/password/reset-verify.",
            example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String confirmedToken;

    @NotBlank
    @Schema(description = "New plain-text password to set.", example = "NewSecret123!",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String newPassword;
}
