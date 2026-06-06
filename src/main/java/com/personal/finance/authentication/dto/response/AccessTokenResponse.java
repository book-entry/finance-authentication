package com.personal.finance.authentication.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

/**
 * Shared response for endpoints that return full Firebase tokens —
 * spec §3.2, §3.5. ({@code POST /v1/login/verify-otp},
 * {@code POST /v1/register/verify-otp}.)
 */
@Value
@Builder
@Schema(description = "Firebase access token response returned after successful OTP verification (spec §3.2, §3.5).")
public class AccessTokenResponse {

    @Schema(description = "Firebase ID token to be sent as Authorization: Bearer on subsequent requests.",
            example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1aWQxMjMifQ.signature")
    String accessToken;

    @Schema(description = "Firebase refresh token for obtaining new ID tokens.",
            example = "AMf-vBw1234refreshtoken")
    String refreshToken;

    @Schema(description = "Firebase UID of the authenticated user.", example = "uid_abc123")
    String uid;

    @Schema(description = "Display name of the authenticated user.", example = "Anson Wong")
    String displayName;
}
