package com.personal.finance.authentication.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/password/update} — spec §3.7. */
@Data
@NoArgsConstructor
public class PasswordUpdateRequest {

    @NotBlank
    private String actionToken;

    @NotBlank
    private String otp;

    @NotBlank
    private String newPassword;
}
