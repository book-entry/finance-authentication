package com.personal.finance.authentication.exception;

import com.personal.finance.common.exception.BaseException;
import com.personal.finance.common.exception.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * Raised when Twilio Verify reports {@code max-attempts-reached}. Per spec §6.2
 * this is a terminal state — the client must restart the flow.
 *
 * <p>Error code {@code MAX_ATTEMPTS}, HTTP {@code 429}.
 */
public class TwilioMaxAttemptsException extends BaseException {

    public TwilioMaxAttemptsException() {
        super(ErrorCode.MAX_ATTEMPTS, HttpStatus.TOO_MANY_REQUESTS);
    }

    public TwilioMaxAttemptsException(String message) {
        super(ErrorCode.MAX_ATTEMPTS, HttpStatus.TOO_MANY_REQUESTS, message);
    }
}
