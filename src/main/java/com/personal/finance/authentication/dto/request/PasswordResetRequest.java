package com.personal.finance.authentication.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/password/reset-request} — spec §3.8. */
@Data
@NoArgsConstructor
public class PasswordResetRequest {

    @NotBlank
    @Email
    private String email;
}
