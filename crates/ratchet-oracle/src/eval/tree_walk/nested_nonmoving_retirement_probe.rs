//! Ordinal selection for report-only nested nonmoving retirement admission.
//!
//! This runtime door is intentionally independent from the nested safepoint
//! proof ordinal. At its selected successful final-config completion it builds
//! one non-writeback root set, runs the immutable heap planner while those
//! roots remain live on the stack, and retains only the resulting accounting.

use super::*;

const ORDINAL_ENV: &str = "AOS_NIX_NESTED_NONMOVING_RETIREMENT_REPORT_ORDINAL";

/// Process-local state for one selected report-only retirement admission.
#[derive(Debug)]
pub(super) struct NestedNonmovingRetirementProbe {
    selected_ordinal: u64,
    completions: u64,
    attempts: u64,
    snapshot: Option<NestedNonmovingRetirementSnapshot>,
}

impl NestedNonmovingRetirementProbe {
    /// Creates a probe only for one positive selected completion ordinal.
    pub(super) fn from_env() -> Option<Self> {
        let selected_ordinal = std::env::var(ORDINAL_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|ordinal| *ordinal != 0)?;
        Some(Self::new(selected_ordinal))
    }

    const fn new(selected_ordinal: u64) -> Self {
        Self {
            selected_ordinal,
            completions: 0,
            attempts: 0,
            snapshot: None,
        }
    }
}

/// Result retained after the selected root set has left the stack.
#[derive(Debug)]
struct NestedNonmovingRetirementSnapshot {
    ordinal: u64,
    root_complete: bool,
    proof_blockers: usize,
    root_error: bool,
    weak_scan_error: bool,
    report: Option<crate::eval::heap::NestedNonmovingRetirementReport>,
}

impl TreeWalk {
    /// Runs one immutable retirement admission at the independently selected
    /// final-config completion.
    pub(super) fn note_nested_nonmoving_retirement_completion(&mut self, result: Value) {
        let Some(probe) = self.nested_nonmoving_retirement_probe.as_mut() else {
            return;
        };
        probe.completions = probe.completions.saturating_add(1);
        let ordinal = probe.completions;
        if ordinal != probe.selected_ordinal || probe.snapshot.is_some() {
            return;
        }

        let proof_blockers = self.nested_nonmoving_runtime_blocker_count();
        let proof_root_complete = proof_blockers == 0;
        let roots = self.nested_nonmoving_root_set(result);
        let (root_error, weak_scan_error, report) = match roots {
            Ok((roots, _inventory)) if proof_root_complete => {
                match self.heap.nested_nonmoving_retirement_report(&roots) {
                    Ok(report) => (false, false, Some(report)),
                    Err(_) => (false, true, None),
                }
            }
            Ok(_) => (false, false, None),
            Err(_) => (true, false, None),
        };
        let root_complete = proof_root_complete && !root_error;
        let snapshot = NestedNonmovingRetirementSnapshot {
            ordinal,
            root_complete,
            proof_blockers,
            root_error,
            weak_scan_error,
            report,
        };
        let Some(probe) = self.nested_nonmoving_retirement_probe.as_mut() else {
            return;
        };
        probe.attempts = probe.attempts.saturating_add(1);
        probe.snapshot = Some(snapshot);
    }

    /// Emits the selected admission or its fail-closed refusal reason.
    pub(super) fn emit_nested_nonmoving_retirement_report(&self) {
        let Some(probe) = self.nested_nonmoving_retirement_probe.as_ref() else {
            return;
        };
        if let Some(snapshot) = probe.snapshot.as_ref() {
            if let Some(report) = snapshot.report.as_ref() {
                eprintln!(
                    "aos_nix_nested_nonmoving_retirement_report ordinal={} \
                     root_complete={} proof_blockers={} root_error=false \
                     weak_scan_error=false report={} collection=false mutation=false",
                    snapshot.ordinal, snapshot.root_complete, snapshot.proof_blockers, report,
                );
            } else {
                eprintln!(
                    "aos_nix_nested_nonmoving_retirement_report_refusal ordinal={} \
                     root_complete={} proof_blockers={} root_error={} weak_scan_error={} \
                     report_available=false admitted=false collection=false mutation=false",
                    snapshot.ordinal,
                    snapshot.root_complete,
                    snapshot.proof_blockers,
                    snapshot.root_error,
                    snapshot.weak_scan_error,
                );
            }
        }
        eprintln!(
            "aos_nix_nested_nonmoving_retirement_report_conservation \
             selected_ordinal={} completions={} attempts={} selected_observed={} \
             conserved={} collection=false mutation=false",
            probe.selected_ordinal,
            probe.completions,
            probe.attempts,
            probe.snapshot.is_some(),
            probe.attempts <= 1,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_ordinal_is_positive_and_independent() {
        let probe = NestedNonmovingRetirementProbe::new(192);
        assert_eq!(probe.selected_ordinal, 192);
        assert_eq!(probe.completions, 0);
        assert_eq!(probe.attempts, 0);
        assert!(probe.snapshot.is_none());
        assert_ne!(ORDINAL_ENV, "AOS_NIX_NESTED_NONMOVING_PROOF_ORDINAL");
    }
}
