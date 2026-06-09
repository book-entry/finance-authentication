package com.personal.finance.authentication.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Auth-service specific filter chain. Runs at {@link Order @Order(0)} so it
 * wins against finance-common's {@code CommonSecurityConfig} chains
 * ({@code @Order(1..3)}), preventing the catch-all Firebase-bearer chain from
 * gating endpoints whose entire purpose is to ISSUE those bearer tokens.
 *
 * <p>Every endpoint matched here is permitted:
 * <ul>
 *   <li>{@code /v1/login/**}    — spec §3.1 / §3.2 / §3.3 (pre-token).</li>
 *   <li>{@code /v1/register/**} — spec §3.4 / §3.5 (pre-token).</li>
 *   <li>{@code /v1/password/**} — spec §3.6–§3.10. §3.6 carries an
 *       {@code Authorization: Bearer} header that is validated explicitly in
 *       {@code PasswordServiceImpl} via {@code FirebaseAuthClient.verifyIdToken},
 *       so Spring Security need not enforce it.</li>
 *   <li>{@code /v1/otp/**}      — spec §3.11 (token in body).</li>
 * </ul>
 *
 * <p>CSRF is disabled and the session policy is stateless — the auth service
 * never holds server-side session state.
 */
@Configuration
@Slf4j
public class AuthServiceSecurityConfig {

    private static final String[] PERMITTED_PATTERNS = {
            "/v1/login/**",
            "/v1/register/**",
            "/v1/password/**",
            "/v1/otp/**",
            "/actuator/health",
            "/actuator/info"
    };

    @Bean("authServiceSecurityFilterChain")
    @Order(0)
    public SecurityFilterChain authServiceSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(PERMITTED_PATTERNS)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        log.info("Auth-service security chain registered — permitting: {}", String.join(", ", PERMITTED_PATTERNS));
        return http.build();
    }
}
