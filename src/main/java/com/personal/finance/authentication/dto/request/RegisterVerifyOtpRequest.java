package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/register/verify-otp} — spec §3.5. */
@Data
@NoArgsConstructor
@Schema(description = "Register OTP verification payload (spec §3.5).")
public class RegisterVerifyOtpRequest {

    @NotBlank
    @Schema(description = "Internal JWT issued by /v1/register.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String sessionToken;

    @NotBlank
    @Schema(description = "Six-digit OTP delivered via SMS.", example = "123456",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String otp;
}
