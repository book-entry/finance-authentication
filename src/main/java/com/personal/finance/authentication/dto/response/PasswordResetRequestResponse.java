package com.personal.finance.authentication.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Value;

/**
 * Response for {@code POST /v1/password/reset-request} — spec §3.8.
 *
 * <p>{@code resetToken} is {@code null} when the email does not match an
 * existing account (anti-enumeration): only {@code requiresOtp:false} is
 * returned, the rest of the payload is suppressed via
 * {@link JsonInclude.Include#NON_NULL}.
 */
@Value
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PasswordResetRequestResponse {
    String resetToken;
    Boolean requiresOtp;
    Long expiresIn;
}
