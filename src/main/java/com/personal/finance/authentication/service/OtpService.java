package com.personal.finance.authentication.service;

import com.personal.finance.authentication.dto.request.ResendOtpRequest;
import com.personal.finance.authentication.dto.response.ResendOtpResponse;

/** Implements the resend OTP flow defined in spec §3.11. */
public interface OtpService {

    ResendOtpResponse resend(ResendOtpRequest request);
}
