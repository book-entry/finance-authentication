package com.personal.finance.authentication.util;

import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * Enforces the spec §2 assumption #9 password rules:
 * <ul>
 *   <li>minimum 8 characters</li>
 *   <li>at least one uppercase letter</li>
 *   <li>at least one digit</li>
 *   <li>at least one special (non-alphanumeric) character</li>
 * </ul>
 *
 * <p>On any rule violation throws {@link AuthException} with
 * {@code WEAK_PASSWORD} / HTTP {@code 400}.
 */
public final class PasswordValidator {

    private PasswordValidator() {}

    public static void validate(String password) {
        if (password == null || password.length() < 8) {
            throw new AuthException(ErrorCode.WEAK_PASSWORD, HttpStatus.BAD_REQUEST,
                    "Password must be at least 8 characters long");
        }
        boolean hasUpper = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (!Character.isLetterOrDigit(c)) {
                hasSpecial = true;
            }
        }
        if (!hasUpper) {
            fail("Password must contain at least one uppercase letter");
        }
        if (!hasDigit) {
            fail("Password must contain at least one number");
        }
        if (!hasSpecial) {
            fail("Password must contain at least one special character");
        }
    }

    private static void fail(String reason) {
        throw new AuthException(ErrorCode.WEAK_PASSWORD, HttpStatus.BAD_REQUEST, reason);
    }
}
