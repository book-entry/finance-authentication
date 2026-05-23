package com.personal.finance.authentication.config;

import com.personal.finance.authentication.client.twilio.TwilioVerifyClient;
import com.twilio.Twilio;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;

/**
 * Initialises the static Twilio SDK with the configured credentials. Required
 * before any {@code Verification} or {@code VerificationCheck} call.
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class TwilioConfig {

    private final AuthProperties properties;

    @PostConstruct
    void initTwilio() {
        AuthProperties.Twilio t = properties.getTwilio();
        if (t.isBypass()) {
            log.warn("Twilio bypass enabled — SDK not initialised. OTP send is a no-op and "
                    + "OTP verification accepts only the fixed code [{}]. "
                    + "Do NOT enable in production.", TwilioVerifyClient.BYPASS_OTP_CODE);
            return;
        }
        if (t.getAccountSid() == null || t.getAccountSid().isBlank()
                || t.getAuthToken() == null || t.getAuthToken().isBlank()) {
            log.warn("Twilio credentials missing — Verify calls will fail at runtime");
            return;
        }
        Twilio.init(t.getAccountSid(), t.getAuthToken());
        log.info("Twilio SDK initialised for verify SID [{}], channel [{}]",
                t.getVerifySid(), t.getChannel());
    }
}
