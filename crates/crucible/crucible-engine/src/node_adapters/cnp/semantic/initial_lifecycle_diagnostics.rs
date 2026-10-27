//! Bounds diagnostics only while the private initial Source operation runs.
//!
//! This scope changes no authority, ownership, effects or error classification.
//! Ordinary operations keep their existing diagnostic constructors. Selected
//! failures retain a bounded cause label without invoking arbitrary Display.

use std::{cell::Cell, fmt::Display};

thread_local! {
    static SELECTED_INITIAL_SOURCE: Cell<bool> = const { Cell::new(false) };
}

const MAXIMUM_CAUSE_BYTES: usize = 192;
const REFUSED_PREFIX: &str = "original initial Source refused: ";
const UNKNOWN_PREFIX: &str = "original initial Source outcome unknown; cause type: ";

/// Restores the exact previous diagnostic mode on normal return or unwind.
///
/// It is private diagnostic state, never a proof or an allocation permission.
pub(crate) struct OriginalInitialLifecycleDiagnostics {
    previous: bool,
}

impl OriginalInitialLifecycleDiagnostics {
    pub(crate) fn begin() -> Self {
        Self {
            previous: SELECTED_INITIAL_SOURCE.with(|selected| selected.replace(true)),
        }
    }

    pub(crate) const fn requested_bytes() -> usize {
        // Exactly one failure String is constructed at a time. An underlying
        // provider/contract error may coexist and remains its own admitted row.
        UNKNOWN_PREFIX.len() + MAXIMUM_CAUSE_BYTES
    }

    /// Quotes one independent borrowed refusal String in either diagnostic mode.
    ///
    /// The ordinary branch copies the actual cause. The selected branch owns
    /// this module's unchanged prefix and at most its true UTF-8 cause limit.
    /// This pure layout DATA neither enters a scope nor constructs a String.
    pub(crate) const fn borrowed_refusal_requested_storage_data(cause_bytes: usize) -> usize {
        let selected_cause = if cause_bytes < MAXIMUM_CAUSE_BYTES {
            cause_bytes
        } else {
            MAXIMUM_CAUSE_BYTES
        };
        let selected = REFUSED_PREFIX.len() + selected_cause;
        if selected > cause_bytes {
            selected
        } else {
            cause_bytes
        }
    }

    pub(crate) const fn counter_scratch_bytes() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Cell<bool>>()
            + std::mem::size_of::<String>()
            + std::mem::size_of::<[usize; 3]>()
            // Actual cause/selected-cause/result views in the pure quote above.
            + std::mem::size_of::<[usize; 3]>()
    }
}

impl Drop for OriginalInitialLifecycleDiagnostics {
    fn drop(&mut self) {
        SELECTED_INITIAL_SOURCE.with(|selected| selected.set(self.previous));
    }
}

// These concrete argument families preserve Into<String>'s ordinary ownership:
// String is moved, while a borrowed refusal is copied exactly once.
pub(super) trait InitialRefusalReason {
    fn reason_data(&self) -> &str;
    fn into_reason(self) -> String;
}

impl InitialRefusalReason for &str {
    fn reason_data(&self) -> &str {
        self
    }

    fn into_reason(self) -> String {
        self.into()
    }
}

impl InitialRefusalReason for String {
    fn reason_data(&self) -> &str {
        self
    }

    fn into_reason(self) -> String {
        self
    }
}

impl InitialRefusalReason for &String {
    fn reason_data(&self) -> &str {
        self
    }

    fn into_reason(self) -> String {
        self.clone()
    }
}

pub(super) fn refusal_reason(reason: impl InitialRefusalReason) -> String {
    if SELECTED_INITIAL_SOURCE.with(Cell::get) {
        bounded(REFUSED_PREFIX, reason.reason_data())
    } else {
        reason.into_reason()
    }
}

pub(crate) fn unknown_reason<E: Display>(error: E) -> String {
    if SELECTED_INITIAL_SOURCE.with(Cell::get) {
        // The closed error family remains visible. Its potentially allocating
        // or user-defined Display implementation is deliberately never called.
        bounded(UNKNOWN_PREFIX, std::any::type_name::<E>())
    } else {
        error.to_string()
    }
}

pub(super) fn refused_display_reason<E: Display>(error: E) -> String {
    if SELECTED_INITIAL_SOURCE.with(Cell::get) {
        bounded(REFUSED_PREFIX, std::any::type_name::<E>())
    } else {
        error.to_string()
    }
}

fn bounded(prefix: &str, cause: &str) -> String {
    let mut end = cause.len().min(MAXIMUM_CAUSE_BYTES);
    while !cause.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = String::with_capacity(prefix.len() + end);
    result.push_str(prefix);
    result.push_str(&cause[..end]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::EffectKnowledge;

    struct NoDisplay;
    impl Display for NoDisplay {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("selected Source diagnostics must not call Display")
        }
    }

    #[test]
    fn original_initial_diagnostics_bound_causes_and_restore_nested_and_unwound_scopes() {
        assert!(!SELECTED_INITIAL_SOURCE.with(Cell::get));
        let scope = OriginalInitialLifecycleDiagnostics::begin();
        let refusal = super::super::refused("actual Source invariant refused");
        let unknown = super::super::unknown(NoDisplay);
        assert!(matches!(refusal.effects, EffectKnowledge::None));
        assert!(matches!(unknown.effects, EffectKnowledge::Unknown));
        assert_eq!(
            refusal.reason,
            format!("{REFUSED_PREFIX}actual Source invariant refused")
        );
        assert!(unknown.reason.contains("NoDisplay"));
        assert!(
            unknown.reason.capacity() <= OriginalInitialLifecycleDiagnostics::requested_bytes()
        );
        assert!(
            refusal.reason.capacity() <= OriginalInitialLifecycleDiagnostics::requested_bytes()
        );
        {
            let nested = OriginalInitialLifecycleDiagnostics::begin();
            drop(nested);
            assert!(SELECTED_INITIAL_SOURCE.with(Cell::get));
        }
        let unwind = std::panic::catch_unwind(|| {
            let _nested = OriginalInitialLifecycleDiagnostics::begin();
            panic!("restore nested state");
        });
        assert!(unwind.is_err());
        assert!(SELECTED_INITIAL_SOURCE.with(Cell::get));
        let unicode = "é".repeat(MAXIMUM_CAUSE_BYTES);
        let bounded = super::super::refused(unicode);
        assert!(bounded.reason.len() <= OriginalInitialLifecycleDiagnostics::requested_bytes());
        drop(scope);
        assert!(!SELECTED_INITIAL_SOURCE.with(Cell::get));
        let ordinary = String::from("ordinary refusal");
        let original_pointer = ordinary.as_ptr();
        let ordinary = super::super::refused(ordinary);
        assert_eq!(ordinary.reason, "ordinary refusal");
        assert_eq!(ordinary.reason.as_ptr(), original_pointer);
        assert_eq!(
            super::super::unknown("ordinary detail").reason,
            "ordinary detail"
        );
    }
}
