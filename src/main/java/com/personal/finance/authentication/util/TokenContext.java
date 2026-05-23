package com.personal.finance.authentication.util;

import java.time.Duration;

/**
 * JWT context / phase / TTL constants enumerated in spec §4.1.
 */
public final class TokenContext {

    private TokenContext() {}

    // ── ctx values ──────────────────────────────────────────
    public static final String CTX_LOGIN = "login";
    public static final String CTX_REGISTER = "register";
    public static final String CTX_PWD_UPDATE = "pwd-update";
    public static final String CTX_PWD_RESET = "pwd-reset";

    // ── phase values (pwd-reset only) ───────────────────────
    public static final String PHASE_OTP = "otp";
    public static final String PHASE_CONFIRMED = "confirmed";

    // ── spec TTLs ───────────────────────────────────────────
    public static final Duration TTL_LOGIN = Duration.ofMinutes(5);
    public static final Duration TTL_REGISTER = Duration.ofMinutes(10);
    public static final Duration TTL_PWD_UPDATE = Duration.ofMinutes(5);
    public static final Duration TTL_RESET_OTP = Duration.ofMinutes(10);
    public static final Duration TTL_RESET_CONFIRMED = Duration.ofMinutes(5);
}
