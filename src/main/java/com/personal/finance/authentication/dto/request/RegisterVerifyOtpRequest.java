package com.personal.finance.authentication.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/register/verify-otp} — spec §3.5. */
@Data
@NoArgsConstructor
public class RegisterVerifyOtpRequest {

    @NotBlank
    private String sessionToken;

    @NotBlank
    private String otp;
}
