//! Fixed refusal categories for physical reservation diagnostics.
//!
//! Error payloads can contain provider coordinates or credentials. Only exact
//! source-owned messages select these labels; all other errors stay redacted.

/// Classifies a refusal without returning any part of its error payload.
pub(super) fn refusal_reason(error: &anyhow::Error) -> &'static str {
    match error.root_cause().to_string().as_str() {
        "direct physical guard originals changed" => "originals_changed",
        "direct reservation source changed" => "source_changed",
        "direct guard provider effect remains unknown" => "provider_unknown",
        "external physical effect remains unknown" => "external_unknown",
        "external former destination session remains active" => "destination_active",
        "direct baseline already published" => "already_published",
        "lease not yet valid or expired under qualified uncertainty" => "lease_time",
        "unqualified or rolled-back clock" => "clock_regressed",
        "cohort is not independently configured" => "cohort_absent",
        "configured scope mismatch" => "scope_changed",
        "key or effect exceeds cohort scope" => "lease_scope",
        "original renewal is unavailable" => "renewal_unavailable",
        "issuer renewal refused" => "issuer_refused",
        "issuer request is stale" => "issuer_request_expired",
        "direct baseline observation expired" => "observation_expired",
        "external baseline authorization expired" => "authorization_expired",
        "external baseline GET not positively acknowledged" => "provider_refused",
        "direct guard original admission expired" => "admission_expired",
        "original renewal window expired" => "renewal_expired",
        "original renewal window expired or rolled back" => "renewal_clock",
        _ => "other",
    }
}

/// Identifies a preparation boundary without exposing its nested error.
pub(super) fn refusal_phase(error: &anyhow::Error) -> &'static str {
    const PHASES: &[(&str, &str)] = &[
        ("direct baseline: binding", "binding"),
        ("direct baseline: profile", "profile"),
        ("direct baseline: lease", "lease"),
        ("direct baseline: initialize floor", "initialize_floor"),
        ("direct baseline: validate floor", "validate_floor"),
        ("direct baseline: persist floor", "persist_floor"),
        ("direct baseline: provider", "provider"),
    ];

    PHASES
        .iter()
        .find(|(message, _)| error.chain().any(|cause| cause.to_string() == *message))
        .map_or("other", |(_, phase)| phase)
}

#[cfg(test)]
mod tests {
    use super::{refusal_phase, refusal_reason};

    #[test]
    fn nested_refusals_keep_only_the_fixed_category() {
        let error =
            anyhow::anyhow!("configured scope mismatch").context("private request coordinates");

        assert_eq!(refusal_reason(&error), "scope_changed");
        assert_eq!(refusal_phase(&error), "other");
    }

    #[test]
    fn unknown_errors_and_message_suffixes_remain_redacted() {
        for message in [
            "private provider credentials",
            "configured scope mismatch: private provider coordinates",
        ] {
            assert_eq!(refusal_reason(&anyhow::anyhow!(message)), "other");
        }
    }

    #[test]
    fn preparation_boundaries_do_not_expose_nested_payloads() {
        let error =
            anyhow::anyhow!("private provider credentials").context("direct baseline: lease");

        assert_eq!(refusal_phase(&error), "lease");
        assert_eq!(refusal_reason(&error), "other");
        assert_eq!(
            refusal_phase(&anyhow::anyhow!("direct baseline: lease private suffix")),
            "other"
        );
    }
}
