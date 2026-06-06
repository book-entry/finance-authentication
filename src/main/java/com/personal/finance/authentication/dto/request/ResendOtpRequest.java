package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/otp/resend} — spec §3.11. */
@Data
@NoArgsConstructor
@Schema(description = "OTP resend request payload (spec §3.11).")
public class ResendOtpRequest {

    /** sessionToken, actionToken, or resetToken (otp phase). */
    @NotBlank
    @Schema(description = "Internal JWT issued at the preceding step (sessionToken, actionToken, or resetToken).",
            example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String token;
}
