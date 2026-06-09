package com.personal.finance.authentication.config;

import com.personal.finance.common.security.config.InternalSecurityProperties;
import com.personal.finance.common.security.filter.InternalRequestFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
 * <p>Unlike the rest of {@code finance-authentication}, profile read/update is
 * not a token-issuing flow: it consumes the gateway-injected
 * {@code X-Internal-Secret} + {@code X-User-Id} envelope just like every
 * other downstream service. The gateway has already validated the user's
 * Firebase ID token at the edge, so the service trusts the envelope
 * (constant-time secret check inside {@link InternalRequestFilter}) instead of
 * re-verifying the Bearer here.
 *
 * <p>Ordering: this chain registers at {@code @Order(0)} alongside
 * {@link AuthServiceSecurityConfig}. The two chains have disjoint
 * {@code securityMatcher} predicates — {@code AuthServiceSecurityConfig}
 * deliberately drops {@code /v1/me/**} from its permit list so this chain
 * claims it cleanly.
 *
 * <p>{@code InternalRequestFilter} is instantiated here (not via component
 * scan) because {@code FinanceAuthenticationApplication} intentionally
 * excludes finance-common's auto-configured catch-all chain.
 */
@Configuration
@EnableConfigurationProperties(InternalSecurityProperties.class)
@Slf4j
public class MeSecurityConfig {

    private static final String[] ME_PATTERNS = { "/v1/me", "/v1/me/**" };

    private final InternalSecurityProperties internalSecurityProperties;

    public MeSecurityConfig(InternalSecurityProperties internalSecurityProperties) {
        this.internalSecurityProperties = internalSecurityProperties;
        internalSecurityProperties.validate();
    }

    @Bean("meSecurityFilterChain")
    @Order(0)
    public SecurityFilterChain meSecurityFilterChain(HttpSecurity http) throws Exception {
        InternalRequestFilter internalFilter = new InternalRequestFilter(internalSecurityProperties);
        http
                .securityMatcher(ME_PATTERNS)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .addFilterBefore(internalFilter, UsernamePasswordAuthenticationFilter.class);
        log.info("Me security chain registered — guarding: {}", String.join(", ", ME_PATTERNS));
        return http.build();
    }
}
