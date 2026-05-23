package com.personal.finance.authentication.exception;

import com.personal.finance.common.exception.BaseException;
import com.personal.finance.common.exception.ErrorCode;
import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Raised when the resend cooldown Redis key is still alive for the calling uid.
 *
 * <p>Error code {@code RESEND_TOO_SOON}, HTTP {@code 429}. Carries
 * {@code retryAfterSeconds} so the controller layer can surface the remaining
 * TTL to the client.
 */
@Getter
public class ResendCooldownException extends BaseException {

    private final long retryAfterSeconds;

    public ResendCooldownException(long retryAfterSeconds) {
        super(ErrorCode.RESEND_TOO_SOON,
                HttpStatus.TOO_MANY_REQUESTS,
                "Resend cooldown active — retry after " + retryAfterSeconds + " seconds");
        this.retryAfterSeconds = retryAfterSeconds;
    }
}
