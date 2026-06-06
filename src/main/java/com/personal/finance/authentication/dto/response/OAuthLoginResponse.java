package com.personal.finance.authentication.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

/** Response for {@code POST /v1/login/oauth} — spec §3.3. */
@Value
@Builder
@Schema(description = "Response returned after a successful OAuth login; includes Firebase tokens and new-user flag (spec §3.3).")
public class OAuthLoginResponse {

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

    /** Spec field is literally {@code isNewUser} — pin so Jackson does not strip the {@code is} prefix. */
    @JsonProperty("isNewUser")
    @Schema(description = "True when this OAuth sign-in created a brand-new account.", example = "false")
    boolean isNewUser;
}
