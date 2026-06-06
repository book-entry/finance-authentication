package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/password/reset-request} — spec §3.8. */
@Data
@NoArgsConstructor
@Schema(description = "Password reset initiation request payload (spec §3.8).")
public class PasswordResetRequest {

    @NotBlank
    @Email
    @Schema(description = "Email address associated with the account to reset.", example = "user@example.com",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;
}
