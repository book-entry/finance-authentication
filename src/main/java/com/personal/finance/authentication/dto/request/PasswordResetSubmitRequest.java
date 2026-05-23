package com.personal.finance.authentication.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/password/reset} — spec §3.10. */
@Data
@NoArgsConstructor
public class PasswordResetSubmitRequest {

    @NotBlank
    private String confirmedToken;

    @NotBlank
    private String newPassword;
}
