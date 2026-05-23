package com.personal.finance.authentication.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/password/reset-verify} — spec §3.9. */
@Data
@NoArgsConstructor
public class PasswordResetVerifyRequest {

    @NotBlank
    private String resetToken;

    @NotBlank
    private String otp;
}
