package com.personal.finance.authentication.client.firebase;

import lombok.Value;

/**
 * Minimal projection of a Firebase {@code UserRecord} — only the fields the
 * service layer needs. Keeps Firebase SDK types out of the service layer.
 */
@Value
public class FirebaseUserRecord {
    String uid;
    String email;
}
