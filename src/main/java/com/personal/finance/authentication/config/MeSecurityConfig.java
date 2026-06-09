package com.personal.finance.authentication.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Filter chain for the {@code /v1/me/**} endpoints — REQ-settings-backend §3.
 *
 * <p>Unlike the rest of the platform, profile read/update is gated by a plain
 * header check ({@link MeInternalAuthFilter}) rather than finance-common's
 * Spring-Security {@code InternalRequestFilter}. The chain itself is
 * {@code permitAll} — its only job is to stop Spring Boot's default
 * {@code SecurityAutoConfiguration} (HTTP Basic) from gating the path; the
 * actual gateway-envelope verification ({@code X-Internal-Secret} +
 * {@code X-User-Id}) happens inside {@link MeInternalAuthFilter}, which returns
 * 401 on a missing/incorrect secret or absent user id.
 *
 * <p>The internal secret is injected with a blank default
 * ({@code ${finance.security.internal.secret:}}), so — unlike the previous
 * {@code InternalSecurityProperties.validate()} approach — a missing
 * {@code INTERNAL_SERVICE_SECRET} no longer prevents the service from starting.
 * It is validated per request instead.
 *
 * <p>Ordering: registered at {@code @Order(0)} alongside
 * {@link AuthServiceSecurityConfig}; the two chains have disjoint
 * {@code securityMatcher} predicates so this one claims {@code /v1/me/**}
 * cleanly.
 */
@Configuration
@Slf4j
public class MeSecurityConfig {

    private static final String[] ME_PATTERNS = { "/v1/me", "/v1/me/**" };

    private final String internalSecret;

    public MeSecurityConfig(@Value("${finance.security.internal.secret:}") String internalSecret) {
        this.internalSecret = internalSecret;
    }

    @Bean("meSecurityFilterChain")
    @Order(0)
    public SecurityFilterChain meSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(ME_PATTERNS)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(new MeInternalAuthFilter(internalSecret),
                        UsernamePasswordAuthenticationFilter.class);
        log.info("Me security chain registered — header-checked guard on: {}",
                String.join(", ", ME_PATTERNS));
        return http.build();
    }
}
