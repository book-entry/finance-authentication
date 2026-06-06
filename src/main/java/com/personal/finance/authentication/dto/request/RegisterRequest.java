package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/register} — spec §3.4. */
@Data
@NoArgsConstructor
@Schema(description = "New-user registration payload (spec §3.4).")
public class RegisterRequest {

    @NotBlank
    @Email
    @Schema(description = "Email address to register.", example = "user@example.com",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @NotBlank
    @Schema(description = "Plain-text password.", example = "Secret123!",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;

    @NotBlank
    @Schema(description = "Display name.", example = "Anson Wong",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String name;
}
