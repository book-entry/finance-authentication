package com.personal.finance.authentication.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/login/verify-otp} — spec §3.2. */
@Data
@NoArgsConstructor
public class LoginVerifyOtpRequest {

    @NotBlank
    private String sessionToken;

    @NotBlank
    private String otp;
}
