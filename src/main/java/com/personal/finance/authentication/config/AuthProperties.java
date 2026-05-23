package com.personal.finance.authentication.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed view over the {@code app.*} configuration keys required by the
 * Authentication Service. Mirrors §7 of the program specification.
 */
@Data
@ConfigurationProperties(prefix = "app")
public class AuthProperties {

    private final Jwt jwt = new Jwt();
    private final Twilio twilio = new Twilio();
    private final Firebase firebase = new Firebase();
    private final Otp otp = new Otp();

    @Data
    public static class Jwt {
        /** HS256 signing secret. Must be at least 32 characters. */
        private String secret;
    }

    @Data
    public static class Twilio {
        private String accountSid;
        private String authToken;
        private String verifySid;
        /** {@code email} (default) or {@code sms}. */
        private String channel = "email";
        /**
         * Local-testing bypass. When {@code true}, {@code TwilioVerifyClient}
         * skips real Twilio calls; OTP dispatch is a no-op and OTP verification
         * accepts only the fixed code {@code 123456}. Never enable in
         * production.
         */
        private boolean bypass = false;
    }

    @Data
    public static class Firebase {
        /** Path to the service-account JSON file. */
        private String credentialsPath;
        /** Base64-encoded service-account JSON. Wins over {@link #credentialsPath} if present. */
        private String credentialsJson;
        private String projectId;
        /**
         * Web API key — required for the Firebase REST endpoints
         * ({@code signInWithPassword}, {@code signInWithIdp},
         * {@code signInWithCustomToken}).
         */
        private String apiKey;
    }

    @Data
    public static class Otp {
        /** Resend cooldown TTL in seconds. Default 60 per spec §3.11. */
        private long resendCooldownSeconds = 60L;
    }
}
