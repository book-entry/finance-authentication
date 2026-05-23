package com.personal.finance.authentication.exception;

import com.personal.finance.common.exception.BaseException;
import com.personal.finance.common.exception.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * General-purpose authentication failure. The caller supplies the spec-aligned
 * {@link ErrorCode} (e.g. {@code INVALID_CREDENTIALS}, {@code INVALID_TOKEN},
 * {@code WRONG_CONTEXT}, {@code INVALID_OTP}, {@code WEAK_PASSWORD}, etc.)
 * together with the HTTP status the spec mandates for that scenario.
 */
public class AuthException extends BaseException {

    public AuthException(ErrorCode errorCode, HttpStatus httpStatus) {
        super(errorCode, httpStatus);
    }

    public AuthException(ErrorCode errorCode, HttpStatus httpStatus, String message) {
        super(errorCode, httpStatus, message);
    }

    public AuthException(ErrorCode errorCode, HttpStatus httpStatus, Throwable cause) {
        super(errorCode, httpStatus, cause);
    }
}
