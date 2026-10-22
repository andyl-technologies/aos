//! Fixed stage failure labels that never expose provider or credential values.
//!
//! Context identifies the failed boundary without changing its error or retry
//! semantics. Unknown messages, including lookalikes containing private values,
//! retain the generic reason.

use std::fmt;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(super) enum Phase {
    Lookup,
    Binding,
    Begin,
    Manifest,
    Provider,
    Terminal,
}

impl Phase {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Binding => "binding",
            Self::Begin => "begin",
            Self::Manifest => "manifest",
            Self::Provider => "provider",
            Self::Terminal => "terminal",
        }
    }
}

#[derive(Debug)]
struct Boundary {
    phase: Phase,
    original_message: String,
}

impl fmt::Display for Boundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Callers classify existing error text, including unknown outcomes.
        // Attaching diagnostics must preserve that exact public classification.
        formatter.write_str(&self.original_message)
    }
}

impl std::error::Error for Boundary {}

pub(super) fn at(phase: Phase, error: anyhow::Error) -> anyhow::Error {
    let boundary = Boundary {
        phase,
        original_message: error.to_string(),
    };
    error.context(boundary)
}

pub(super) fn phase(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<Boundary>()
        .map_or("validation", |boundary| boundary.phase.label())
}

pub(super) fn reason(error: &anyhow::Error) -> &'static str {
    match error.root_cause().to_string().as_str() {
        "original logical stage eligibility expired" => "logical_expired",
        "external original invocation expired before Fetch" => "invocation_expired",
        "direct external Native publication permission expired before Fetch" => {
            "permission_expired"
        }
        "lease not yet valid or expired under qualified uncertainty" => "lease_window",
        "unqualified or rolled-back clock" => "clock_unqualified",
        "lease epoch below local floor" => "lease_floor",
        "unknown stage effect blocks other controls" => "pending_effect",
        "unknown mutation permit cannot be reissued" => "pending_mutation",
        "stage journal refused control" => "journal_refused",
        "multipart Create unacknowledged" => "create_unacknowledged",
        "stage terminal acknowledgement differs" => "terminal_changed",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_failure_keeps_its_fixed_boundary_and_reason() {
        for (message, expected) in [
            (
                "external original invocation expired before Fetch",
                "invocation_expired",
            ),
            (
                "unknown mutation permit cannot be reissued",
                "pending_mutation",
            ),
        ] {
            let wrapped = at(Phase::Provider, anyhow::anyhow!(message));
            assert_eq!(wrapped.to_string(), message);

            let error = wrapped.context("private outer context");

            assert_eq!(phase(&error), "provider");
            assert_eq!(reason(&error), expected);
            assert_eq!(error.root_cause().to_string(), message);
        }
    }

    #[test]
    fn private_messages_and_boundary_lookalikes_do_not_become_labels() {
        for message in [
            "unit-only-secret https://unit.invalid/private",
            "multipart Create unacknowledged https://unit.invalid/private",
            "provider",
        ] {
            let error = anyhow::anyhow!(message);

            assert_eq!(phase(&error), "validation");
            assert_eq!(reason(&error), "other");
        }
    }
}
