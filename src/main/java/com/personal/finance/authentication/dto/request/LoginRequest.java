package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/login} — spec §3.1. */
@Data
@NoArgsConstructor
@Schema(description = "Password-login request payload (spec §3.1).")
public class LoginRequest {

    @NotBlank
    @Email
    @Schema(description = "Registered email address.", example = "user@example.com",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @NotBlank
    @Schema(description = "Plain-text password.", example = "Secret123!",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;
}
