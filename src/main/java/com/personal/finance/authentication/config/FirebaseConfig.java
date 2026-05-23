package com.personal.finance.authentication.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Initialises the Firebase Admin SDK and a {@link RestTemplate} used by the
 * {@code FirebaseAuthClient} wrapper for REST endpoints not exposed by the
 * Admin SDK ({@code signInWithPassword}, {@code signInWithIdp},
 * {@code signInWithCustomToken}).
 */
@Configuration
@Slf4j
public class FirebaseConfig {

    @Bean
    public FirebaseApp firebaseApp(AuthProperties props) throws Exception {
        if (!FirebaseApp.getApps().isEmpty()) {
            return FirebaseApp.getInstance();
        }
        GoogleCredentials credentials = loadCredentials(props.getFirebase());
        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(credentials)
                .setProjectId(props.getFirebase().getProjectId())
                .build();
        FirebaseApp app = FirebaseApp.initializeApp(options);
        log.info("Firebase Admin SDK initialised for project [{}]", props.getFirebase().getProjectId());
        return app;
    }

    @Bean
    public FirebaseAuth firebaseAuth(FirebaseApp app) {
        return FirebaseAuth.getInstance(app);
    }

    @Bean("firebaseRestTemplate")
    public RestTemplate firebaseRestTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }

    private GoogleCredentials loadCredentials(AuthProperties.Firebase fb) throws Exception {
        // Prefer inline base64-encoded JSON; fall back to file path.
        if (fb.getCredentialsJson() != null && !fb.getCredentialsJson().isBlank()) {
            byte[] decoded = Base64.getDecoder().decode(fb.getCredentialsJson());
            try (InputStream is = new ByteArrayInputStream(decoded)) {
                return GoogleCredentials.fromStream(is);
            }
        }
        if (fb.getCredentialsPath() != null && !fb.getCredentialsPath().isBlank()) {
            // The value may itself be raw JSON content rather than a path —
            // detect that and feed it directly, else open as a file.
            String value = fb.getCredentialsPath().trim();
            if (value.startsWith("{")) {
                try (InputStream is = new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8))) {
                    return GoogleCredentials.fromStream(is);
                }
            }
            try (InputStream is = new FileInputStream(value)) {
                return GoogleCredentials.fromStream(is);
            }
        }
        throw new IllegalStateException(
                "Firebase credentials not configured — set app.firebase.credentials-path or credentials-json");
    }
}
