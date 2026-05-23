package com.personal.finance.authentication.dto.response;

import lombok.Builder;
import lombok.Value;

/**
 * Shared response for endpoints that return full Firebase tokens —
 * spec §3.2, §3.5. ({@code POST /v1/login/verify-otp},
 * {@code POST /v1/register/verify-otp}.)
 */
@Value
@Builder
public class AccessTokenResponse {
    String accessToken;
    String refreshToken;
    String uid;
}
