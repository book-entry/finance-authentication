package com.personal.finance.authentication.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Value;

/**
 * Single-field {@code { "message": "..." }} response shape used by spec
 * §3.7 (Password updated successfully) and §3.10 (Password reset successfully).
 */
@Value
@Schema(description = "Generic single-message response used when an operation produces no structured payload (spec §3.7, §3.10).")
public class MessageResponse {

    @Schema(description = "Human-readable result message.", example = "Password updated successfully.")
    String message;
}
