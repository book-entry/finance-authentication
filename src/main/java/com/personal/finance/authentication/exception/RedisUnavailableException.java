package com.personal.finance.authentication.exception;

import com.personal.finance.common.exception.BaseException;
import com.personal.finance.common.exception.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * Raised when the resend cooldown store is unreachable. Per spec §2 assumption
 * #7 the resend endpoint MUST fail closed to prevent abuse.
 *
 * <p>Error code {@code REDIS_UNAVAILABLE}, HTTP {@code 503}.
 */
public class RedisUnavailableException extends BaseException {

    public RedisUnavailableException(Throwable cause) {
        super(ErrorCode.REDIS_UNAVAILABLE, HttpStatus.SERVICE_UNAVAILABLE, cause);
    }
}
