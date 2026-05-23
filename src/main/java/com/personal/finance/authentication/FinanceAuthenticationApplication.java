package com.personal.finance.authentication;

import com.personal.finance.authentication.config.AuthProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Authentication Service entry point.
 *
 * <p>{@code com.personal.finance.common.security} is intentionally excluded —
 * the auth service issues tokens; it does not need finance-common's inbound
 * Firebase / internal-secret filters.
 */
@SpringBootApplication
@EnableConfigurationProperties(AuthProperties.class)
public class FinanceAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(FinanceAuthenticationApplication.class, args);
    }
}
