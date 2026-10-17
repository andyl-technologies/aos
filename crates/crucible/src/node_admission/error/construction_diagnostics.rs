//! Bounds diagnostic strings inside the selected collecting constructor only.
//!
//! The scope does not issue a resource action or authenticate an installation.
//! Its caller must separately admit all construction and callback phases. The
//! structured AdmissionError classification remains intact; ordinary callers
//! retain their original diagnostics. A non-Send guard restores nested state.

use std::{cell::Cell, marker::PhantomData, rc::Rc};

pub(super) const REQUIRED: &str = "original collecting construction validation";
pub(super) const OBSERVED: &str = "selected original construction refused";

thread_local! {
    static SELECTED: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn is_selected() -> bool {
    SELECTED.get()
}

pub(crate) struct OriginalConstructionDiagnosticScope {
    previous: bool,
    _same_thread: PhantomData<Rc<()>>,
}

impl OriginalConstructionDiagnosticScope {
    pub(crate) fn enter() -> Self {
        Self {
            previous: SELECTED.replace(true),
            _same_thread: PhantomData,
        }
    }
}

impl Drop for OriginalConstructionDiagnosticScope {
    fn drop(&mut self) {
        SELECTED.set(self.previous);
    }
}

pub(in crate::node_admission) fn construction_diagnostic(value: &impl std::fmt::Display) -> String {
    if is_selected() {
        OBSERVED.to_owned()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RefuseDisplay;
    impl std::fmt::Display for RefuseDisplay {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("selected constructor must not evaluate arbitrary Display")
        }
    }

    #[test]
    fn selected_constructor_diagnostic_does_not_evaluate_display() {
        let _scope = OriginalConstructionDiagnosticScope::enter();
        assert_eq!(construction_diagnostic(&RefuseDisplay), OBSERVED);
        let refusal = super::super::refuse(
            super::super::AdmissionStage::Graph,
            super::super::AdmissionSubject::World,
            super::super::AdmissionCode::OwnerConflict,
            "ordinary required text",
            "ordinary observed text",
        );
        assert_eq!(refusal.stage, super::super::AdmissionStage::Graph);
        assert_eq!(refusal.code, super::super::AdmissionCode::OwnerConflict);
        assert_eq!(refusal.effects, super::super::EffectCertainty::Absent);
        assert_eq!(refusal.required, REQUIRED);
        assert_eq!(refusal.observed, OBSERVED);
    }

    #[test]
    fn selected_constructor_diagnostic_restores_nested_and_unwound_state() {
        assert!(!is_selected());
        {
            let _outer = OriginalConstructionDiagnosticScope::enter();
            {
                let _inner = OriginalConstructionDiagnosticScope::enter();
                assert!(is_selected());
            }
            assert!(is_selected());
            let result = std::panic::catch_unwind(|| {
                let _inner = OriginalConstructionDiagnosticScope::enter();
                panic!("original construction failure");
            });
            assert!(result.is_err());
            assert!(is_selected());
        }
        assert!(!is_selected());
        assert_eq!(
            construction_diagnostic(&"ordinary diagnostic"),
            "ordinary diagnostic"
        );
    }
}
