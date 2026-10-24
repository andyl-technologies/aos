//! Checks real installed four-owner entry points before original native birth.

use super::*;
use crate::node_observed_executor::NodeObservedError;
use crate::node_qualification::{
    AcceptanceLimits, AcceptanceScope, Applicability, CaseEvidence, InstalledAcceptancePolicy,
    InstalledQualificationAuthority, QualificationClass, QualificationError, QualificationUnit,
};
use crucible_node_format::{ContentRef, Id};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct MissingOriginalReport(Arc<AtomicUsize>);

impl InstalledAcceptancePolicy for MissingOriginalReport {
    fn scope_for_node(&self, _: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(QualificationError::Refused(
            "original behavioral report unavailable",
        ))
    }
}

impl InstalledQualificationAuthority for MissingOriginalReport {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &crate::node_qualification::QualificationClaim,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused("no original accepted claim"))
    }

    fn applicability(
        &self,
        _: &QualificationUnit,
        _: &std::collections::BTreeSet<QualificationClass>,
        _: &ContentRef,
    ) -> Result<std::collections::BTreeMap<String, Applicability>, QualificationError> {
        Err(QualificationError::Refused("no original applicability"))
    }

    fn verify_evidence(
        &self,
        _: &ContentRef,
        _: u64,
        _: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        Err(QualificationError::Refused(
            "no original behavioral evidence",
        ))
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused("no original behavioral case"))
    }
}

#[test]
#[ignore = "requires actual compiled source-installed gem5 profile and catalog; starts no native Child"]
fn installed_original_report_is_checked_before_live_or_preserving_owner_allocation()
-> Result<(), NodeObservedError> {
    for preserving in [false, true] {
        let directory =
            tempfile::tempdir().map_err(|error| NodeObservedError::Native(error.to_string()))?;
        let companion =
            std::path::PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_DEVICE").ok_or_else(
                || NodeObservedError::Native("reference device fixture binding absent".into()),
            )?);
        let mut selected_catalog = catalog(directory.path(), &companion);
        let (mut selections, script_ref, base_ref, script_path, base_path) =
            authored(directory.path());
        let original_artifacts = vec![
            InstalledIoArtifact::path(script_path, script_ref),
            InstalledIoArtifact::path(base_path, base_ref),
        ];
        selected_catalog.install_artifacts(original_artifacts.clone())?;
        if !preserving {
            selections[1].kind = InstalledNodeKind::Gem5Closed {
                isa: super::super::super::control::InstalledGem5Isa::X86_64,
            };
        }
        let scenario = if preserving {
            selected_catalog.independent_native_scenario(&selections)?
        } else {
            selected_catalog.scenario(&selections)?
        };
        let original = scenario.canonical_bytes()?;
        let calls = Arc::new(AtomicUsize::new(0));
        selected_catalog.install_behavioral_acceptance(
            Box::new(MissingOriginalReport(Arc::clone(&calls))),
            AcceptanceLimits::default(),
        )?;
        let execution = crucible_campaign::ExecutionId::from_bytes([114; 16])?;

        let refused = if preserving {
            selected_catalog
                .prepare_independent_native_world(&selections, scenario, execution)
                .is_err()
        } else {
            selected_catalog
                .prepare_world(&selections, scenario, execution)
                .is_err()
        };

        assert!(refused);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(selected_catalog.custody().reserved_worlds(), 0);
        let current = if preserving {
            selected_catalog.independent_native_scenario(&selections)
        } else {
            selected_catalog.scenario(&selections)
        };
        // The installed missing policy also closes a new scenario projection.
        // A separate source-built catalog verifies that the refused preparation
        // changed neither the complete immutable world nor its original assets.
        assert!(current.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(selected_catalog.custody().reserved_worlds(), 0);

        let mut unchanged = catalog(directory.path(), &companion);
        unchanged.install_artifacts(original_artifacts)?;
        let unchanged_source = if preserving {
            unchanged.independent_native_scenario(&selections)?
        } else {
            unchanged.scenario(&selections)?
        };
        assert_eq!(unchanged_source.canonical_bytes()?, original);
    }
    Ok(())
}
