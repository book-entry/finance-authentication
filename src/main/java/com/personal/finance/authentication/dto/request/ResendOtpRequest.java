package com.personal.finance.authentication.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/otp/resend} — spec §3.11. */
@Data
@NoArgsConstructor
public class ResendOtpRequest {

    /** sessionToken, actionToken, or resetToken (otp phase). */
    @NotBlank
    private String token;
}
