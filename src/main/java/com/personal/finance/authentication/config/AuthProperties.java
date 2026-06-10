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

    private final Firebase firebase = new Firebase();

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
}
