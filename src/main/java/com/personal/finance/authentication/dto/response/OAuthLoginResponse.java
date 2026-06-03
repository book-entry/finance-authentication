package com.personal.finance.authentication.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/login/oauth} — spec §3.3. */
@Value
@Builder
public class OAuthLoginResponse {
    String accessToken;
    String refreshToken;
    String uid;
    String displayName;
    /** Spec field is literally {@code isNewUser} — pin so Jackson does not strip the {@code is} prefix. */
    @JsonProperty("isNewUser")
    boolean isNewUser;
}
