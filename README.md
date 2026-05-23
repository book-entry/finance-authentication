# finance-authentication

Spring Boot 3 implementation of the Authentication Service described in
`Auth_Service_Program_Specification.docx` (v1.0). Provides login (email/password
+ OAuth), registration, password update/reset, and rate-limited OTP resend —
backed by Firebase Authentication, Twilio Verify, and Redis (cooldown only).

## Tech stack

| Layer | Choice |
|---|---|
| Framework | Spring Boot 3.5.x |
| Java | 21 |
| Build | Maven |
| Identity | Firebase Authentication (Admin SDK + Identity Toolkit REST) |
| OTP | Twilio Verify |
| Cooldown store | Redis (Lettuce) |
| Session tokens | JWT HS256 (jjwt 0.12) |
| Shared library | `com.personl.finance:finance-common:0.0.4-SNAPSHOT` |

## Endpoints (spec §3)

All paths under `/v1`; all bodies are JSON. Success responses are wrapped by
`finance-common`'s `ApiResponseBodyAdvice` into the standard `ApiResponse`
envelope; errors are wrapped by `GlobalExceptionHandler`.

| Spec | Method | Path | Status |
|---|---|---|---|
| §3.1  | POST | `/v1/login` | 202 |
| §3.2  | POST | `/v1/login/verify-otp` | 200 |
| §3.3  | POST | `/v1/login/oauth` | 200 |
| §3.4  | POST | `/v1/register` | 202 |
| §3.5  | POST | `/v1/register/verify-otp` | 201 |
| §3.6  | POST | `/v1/password/update-request` | 202 |
| §3.7  | POST | `/v1/password/update` | 200 |
| §3.8  | POST | `/v1/password/reset-request` | 202 |
| §3.9  | POST | `/v1/password/reset-verify` | 200 |
| §3.10 | POST | `/v1/password/reset` | 200 |
| §3.11 | POST | `/v1/otp/resend` | 200 |

## Local setup

### 1. Install the shared library

This module depends on a SNAPSHOT of `finance-common` that introduces the
spec-aligned `ErrorCode` entries (e.g. `INVALID_OTP`, `MAX_ATTEMPTS`,
`RESEND_TOO_SOON`). Install it locally first:

```bash
cd ../finance-common
mvn -DskipTests install
```

### 2. Provision external services

- **Firebase** — create a project with Email/Password, Google, and Apple
  sign-in providers enabled. Download a service-account JSON for
  `FIREBASE_ADMIN_KEY_JSON`, grab the Web API key for `FIREBASE_API_KEY`, and
  note the project id.
- **Twilio Verify** — create a Verify Service (`VA…`) with email channel
  enabled (SMS optional).
- **Redis** — local install (`brew install redis && brew services start redis`)
  or a managed instance. The service only stores 60-second cooldown keys.

### 3. Environment variables

| Var | Required | Notes |
|---|---|---|
| `JWT_SECRET` | yes | HS256 signing secret, min 32 chars. |
| `FIREBASE_PROJECT_ID` | yes | Firebase project id. |
| `FIREBASE_ADMIN_KEY_JSON` | yes | Path to the service-account JSON file (or raw JSON content). |
| `FIREBASE_API_KEY` | yes | Web API key for Identity Toolkit REST sign-in calls. |
| `TWILIO_ACCOUNT_SID` | yes | Twilio account SID. |
| `TWILIO_AUTH_TOKEN` | yes | Twilio API auth token. |
| `TWILIO_VERIFY_SID` | yes | Twilio Verify Service SID (`VA…`). |
| `OTP_CHANNEL` | no  | `email` (default) or `sms`. |
| `TWILIO_BYPASS` | no  | `true` to skip Twilio entirely for local testing (see below). Default `false`. |
| `REDIS_URL` | yes | e.g. `redis://localhost:6379`. |
| `RESEND_COOLDOWN_SECONDS` | no | TTL override; default 60. |
| `FIREBASE_CREDENTIALS_JSON` | no | Alternative to `FIREBASE_ADMIN_KEY_JSON` — base64-encoded service account JSON. |

#### Twilio bypass (local testing only)

Set `TWILIO_BYPASS=true` when your Twilio account is not yet provisioned but
you want to exercise the full OTP flow. With the flag on:

- `sendVerification(...)` is a no-op — no Twilio call is made; no OTP is sent.
- `checkVerification(...)` accepts only the fixed code `123456`; any other
  value is rejected with the normal `401 INVALID_OTP`.

The Twilio SDK is not initialised at all, so `TWILIO_ACCOUNT_SID` /
`TWILIO_AUTH_TOKEN` / `TWILIO_VERIFY_SID` can be left blank in this mode.
**Never enable in production** — every account would accept the same OTP.

### 4. Run

```bash
mvn spring-boot:run
```

Service binds to port `8084` (`server.port` in [application.yaml](src/main/resources/application.yaml)).

### 5. Test

```bash
mvn test
```

95 unit tests cover utilities, both external client wrappers, all four
services, and all four controllers (`@WebMvcTest` with the real
`GlobalExceptionHandler` + `ApiResponseBodyAdvice` imported).

## Package layout

```
com.personal.finance.authentication
├── FinanceAuthenticationApplication
├── client
│   ├── firebase   — FirebaseAuthClient, FirebaseSignInResult, FirebaseUserRecord
│   └── twilio     — TwilioVerifyClient
├── config         — AuthProperties, FirebaseConfig, RedisConfig, TwilioConfig
├── controller     — LoginController, RegisterController, PasswordController, OtpController
├── dto
│   ├── request    — 10 request DTOs, one per endpoint (+ shared resend)
│   └── response   — 8 response DTOs
├── exception      — AuthException, TwilioMaxAttemptsException, ResendCooldownException, RedisUnavailableException
├── service        — LoginService(+Impl), RegisterService(+Impl), PasswordService(+Impl), OtpService(+Impl)
└── util           — JwtUtil, PasswordValidator, TokenContext
```

## Error code mapping

Every spec error code (e.g. `INVALID_OTP`, `MAX_ATTEMPTS`, `RESEND_TOO_SOON`)
is now a value in [`ErrorCode`](../finance-common/src/main/java/com/personal/finance/common/exception/ErrorCode.java)
inside `finance-common`. The shared `GlobalExceptionHandler` was extended with
a generic `@ExceptionHandler(BaseException.class)` so any service-defined
`BaseException` subclass — including this module's `AuthException`,
`TwilioMaxAttemptsException`, `ResendCooldownException`, and
`RedisUnavailableException` — is mapped to the correct HTTP status and code
without per-module advice.

## Notes

- **No Spring Security in this module.** The auth service issues tokens; it
  doesn't validate inbound bearer tokens beyond the single spec §3.6 case,
  which is handled inline via the `Authorization` header. `finance-common`'s
  `CommonSecurityConfig` is intentionally excluded from component scanning in
  [`FinanceAuthenticationApplication`](src/main/java/com/personal/finance/authentication/FinanceAuthenticationApplication.java).
- **Email normalisation** (`toLowerCase().trim()`) is applied in the service
  layer per spec §2 assumption #10.
- **Anti-enumeration** — `POST /v1/password/reset-request` always returns 202.
  Unknown emails yield `{ "requiresOtp": false }` with no `resetToken`
  (suppressed via `@JsonInclude(NON_NULL)`).
- **Fail-closed Redis** — any Redis exception during cooldown enforcement
  surfaces as `RedisUnavailableException` → 503 `REDIS_UNAVAILABLE`, per spec
  §2 assumption #7.
