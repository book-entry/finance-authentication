package com.personal.finance.authentication.util;

import com.personal.finance.authentication.exception.AuthException;
import com.personal.finance.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordValidatorTest {

    @Test
    void accepts_password_meeting_all_rules() {
        assertThatCode(() -> PasswordValidator.validate("Abcdef1!"))
                .doesNotThrowAnyException();
    }

    @Test
    void rejects_password_shorter_than_eight_chars() {
        assertWeak("A1!a");
    }

    @Test
    void rejects_password_without_uppercase() {
        assertWeak("abcdef1!");
    }

    @Test
    void rejects_password_without_number() {
        assertWeak("Abcdefg!");
    }

    @Test
    void rejects_password_without_special_character() {
        assertWeak("Abcdef12");
    }

    @Test
    void rejects_null_password() {
        assertWeak(null);
    }

    private static void assertWeak(String pw) {
        assertThatThrownBy(() -> PasswordValidator.validate(pw))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> {
                    AuthException ae = (AuthException) ex;
                    org.assertj.core.api.Assertions.assertThat(ae.getErrorCode())
                            .isEqualTo(ErrorCode.WEAK_PASSWORD);
                });
    }
}
