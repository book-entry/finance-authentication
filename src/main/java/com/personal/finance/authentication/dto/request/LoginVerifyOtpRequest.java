package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/login/verify-otp} — spec §3.2. */
@Data
@NoArgsConstructor
@Schema(description = "Login OTP verification payload (spec §3.2).")
public class LoginVerifyOtpRequest {

    @NotBlank
    @Schema(description = "Internal JWT issued by /v1/login.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String sessionToken;

    @NotBlank
    @Schema(description = "Six-digit OTP delivered via SMS.", example = "123456",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String otp;
}
