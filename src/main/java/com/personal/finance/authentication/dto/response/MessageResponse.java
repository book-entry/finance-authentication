package com.personal.finance.authentication.dto.response;

import lombok.Value;

/**
 * Single-field {@code { "message": "..." }} response shape used by spec
 * §3.7 (Password updated successfully) and §3.10 (Password reset successfully).
 */
@Value
public class MessageResponse {
    String message;
}
