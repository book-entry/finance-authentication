package com.personal.finance.authentication.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Body for {@code POST /v1/login/oauth} — spec §3.3. */
@Data
@NoArgsConstructor
public class OAuthLoginRequest {

    /** {@code google} or {@code apple}. */
    @NotBlank
    private String provider;

    @NotBlank
    private String idToken;
}
