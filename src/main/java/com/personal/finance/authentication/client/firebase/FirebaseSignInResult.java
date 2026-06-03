package com.personal.finance.authentication.client.firebase;

import lombok.Builder;
import lombok.Value;

/**
 * Outcome of a Firebase sign-in REST call — accessToken/refreshToken pair plus
 * uid and the {@code isNewUser} flag (OAuth only). Insulates services from
 * Firebase REST response payload shape.
 */
@Value
@Builder(toBuilder = true)
public class FirebaseSignInResult {
    String accessToken;
    String refreshToken;
    String uid;
    String displayName;
    boolean isNewUser;
}
