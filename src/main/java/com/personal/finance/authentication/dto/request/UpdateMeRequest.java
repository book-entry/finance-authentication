package com.personal.finance.authentication.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Body for {@code PATCH /v1/me} (REQ-settings-backend §3.3, P1 scope).
 *
 * <p>Only {@code displayName} is editable in P1. Validation (non-blank,
 * 1–60 chars after trim, body not empty) is enforced in {@code MeServiceImpl}
 * so a single stable {@code INVALID_INPUT} error code is returned, rather than
 * relying on bean-validation's generic VAL_001.
 */
@Data
@NoArgsConstructor
@Schema(description = "Partial profile update. P1 accepts displayName only (REQ-settings-backend §3.3).")
public class UpdateMeRequest {

    @Schema(description = "New display name. 1–60 characters after trimming.", example = "Alice W.")
    private String displayName;
}
