package com.personal.finance.authentication.controller;

import com.personal.finance.authentication.dto.request.ResendOtpRequest;
import com.personal.finance.authentication.dto.response.ResendOtpResponse;
import com.personal.finance.authentication.service.OtpService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST entry point for the resend OTP flow defined in spec §3.11. Routing only.
 */
@RestController
@RequestMapping("/v1/otp")
@RequiredArgsConstructor
public class OtpController {

    private final OtpService otpService;

    /** Spec §3.11 — {@code POST /v1/otp/resend}. Returns 200. */
    @PostMapping("/resend")
    public ResendOtpResponse resend(@Valid @RequestBody ResendOtpRequest request) {
        return otpService.resend(request);
    }
}
