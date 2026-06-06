package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/login/oauth} — spec §3.3. */
@Data
@NoArgsConstructor
@Schema(description = "OAuth login payload (spec §3.3).")
public class OAuthLoginRequest {

    @NotBlank
    @Schema(description = "Identity provider.", allowableValues = {"google", "apple"},
            example = "google", requiredMode = Schema.RequiredMode.REQUIRED)
    private String provider;

    @NotBlank
    @Schema(description = "Provider-issued ID token.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String idToken;
}
