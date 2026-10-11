//! Exercises missing and foreign host authorities without granting model acceptance.

// crucible-lint: allow panic-shortcut -- These cfg(test)-only authority controls panic when an exact refusal or no-effects assertion fails.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_observed_executor::factory::{
    InstalledNodeCatalog, NodeObservedError, measure_executable, refused,
};
use crate::{node_qualification::*, node_scenario::NodeRunConfiguration};
use crucible::{
    node_adapters::transcript::{AuthenticatedTranscript, TranscriptArchive, TranscriptLimits},
    node_scheduling::InputPayload,
};
use crucible_campaign::ExecutionId;
use crucible_node_contract::{ContentRef, Id, U64, canonical};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct RefusingSource {
    body: InputPayload,
    calls: Arc<AtomicUsize>,
}

impl InstalledOriginalLineageSourcePolicy for RefusingSource {
    fn immutable_policy(&self) -> &InputPayload {
        &self.body
    }

    fn inspect(
        &self,
        _: &BTreeMap<Id, AuthenticatedTranscript>,
        _: &NodeRunConfiguration,
        _: &ContentRef,
        _: ExecutionId,
    ) -> Result<Box<dyn InstalledOriginalLineagePlan>, NodeObservedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(refused("unknown original source package and journals"))
    }
}

struct MissingAcceptedClass;

impl InstalledAcceptancePolicy for MissingAcceptedClass {
    fn scope_for_node(&self, _: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        Err(QualificationError::Refused(
            "no independently accepted conditional class",
        ))
    }
}

impl InstalledQualificationAuthority for MissingAcceptedClass {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused("foreign authority"))
    }

    fn applicability(
        &self,
        _: &QualificationUnit,
        _: &BTreeSet<QualificationClass>,
        _: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        Err(QualificationError::Refused("foreign authority"))
    }

    fn verify_evidence(
        &self,
        _: &ContentRef,
        _: u64,
        _: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        Err(QualificationError::Refused("foreign authority"))
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused("foreign authority"))
    }
}

fn body(bytes: &[u8]) -> InputPayload {
    InputPayload {
        reference: ContentRef {
            hash: canonical::hash("cnp.blob.v1", bytes).unwrap(),
            length: U64::new(bytes.len() as u64),
            media_type: "application/json".into(),
        },
        bytes: bytes.to_vec(),
    }
}

fn source(bytes: &[u8], calls: &Arc<AtomicUsize>) -> Box<dyn InstalledOriginalLineageSourcePolicy> {
    Box::new(RefusingSource {
        body: body(bytes),
        calls: Arc::clone(calls),
    })
}

fn catalog(directory: &std::path::Path) -> InstalledNodeCatalog {
    // These inert controls measure the retained source-built test ELF; no child exists.
    let path = std::path::PathBuf::from("/proc/self/exe");
    InstalledNodeCatalog::new(
        path.clone(),
        measure_executable(&path).unwrap(),
        directory.to_owned(),
        Duration::from_secs(1),
        1,
    )
    .unwrap()
}

#[test]
fn foreign_policy_full_reference_and_same_extent_bytes_refuse_before_inspection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let expected = body(b"{}").reference;
    assert!(
        InstalledOriginalLineageAuthority::new(expected.clone(), source(b"[]", &calls)).is_err()
    );
    let mut foreign = expected.clone();
    foreign.media_type = "application/octet-stream".into();
    assert!(InstalledOriginalLineageAuthority::new(foreign, source(b"{}", &calls)).is_err());
    assert!(InstalledOriginalLineageAuthority::new(expected, source(b"{}", &calls)).is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn source_authority_cannot_substitute_for_missing_behavioral_acceptance() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let calls = Arc::new(AtomicUsize::new(0));
    catalog
        .install_original_lineage_authority(
            InstalledOriginalLineageAuthority::new(body(b"{}").reference, source(b"{}", &calls))
                .unwrap(),
        )
        .unwrap();

    let refusal = catalog.require_original_lineage_authorities().unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("behavioral acceptance unavailable")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

#[test]
fn behavioral_authority_cannot_substitute_for_missing_source_authority() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    catalog
        .install_behavioral_acceptance(Box::new(MissingAcceptedClass), AcceptanceLimits::default())
        .unwrap();

    let refusal = catalog.require_original_lineage_authorities().unwrap_err();
    assert!(refusal.to_string().contains("source authority unavailable"));
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

#[test]
fn archive_refusal_keeps_original_capsule_and_never_redispatches_inspector() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let calls = Arc::new(AtomicUsize::new(0));
    catalog
        .install_behavioral_acceptance(Box::new(MissingAcceptedClass), AcceptanceLimits::default())
        .unwrap();
    catalog
        .install_original_lineage_authority(
            InstalledOriginalLineageAuthority::new(body(b"{}").reference, source(b"{}", &calls))
                .unwrap(),
        )
        .unwrap();
    let archive_directory = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let archive = TranscriptArchive::open(
        archive_directory.path(),
        TranscriptLimits {
            maximum_records: U64::new(64),
            maximum_record_bytes: U64::new(65_536),
            maximum_total_bytes: U64::new(1024 * 1024),
        },
    )
    .unwrap();
    let refs = ["disk", "link", "source"]
        .into_iter()
        .map(|name| {
            (
                Id::new(name).unwrap(),
                body(b"missing authenticated original").reference,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let config = NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: U64::new(3000),
        maximum_rounds: U64::new(3),
    };
    let execution = ExecutionId::from_bytes([149; 16]).unwrap();

    assert!(
        catalog
            .prepare_original_lineage(&archive, execution, refs.clone(), config.clone())
            .is_err()
    );
    let retained = catalog.original_lineage_preparation(execution).unwrap();
    assert!(!retained.is_prepared());
    assert!(retained.originals().is_empty());
    assert!(
        catalog
            .prepare_original_lineage(&archive, execution, refs, config)
            .unwrap_err()
            .to_string()
            .contains("once-only")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(catalog.custody().reserved_worlds(), 0);

    // Even this pre-native refusal owns its nonce and a complete actor slot.
    // Every create/resume route uses these guards before its native dispatch.
    use crate::node_observed_executor::service::{
        original_lineage_available_worlds, require_grouped_preparation_capacity,
        require_unowned_original_lineage_execution,
    };
    assert!(require_unowned_original_lineage_execution(&catalog, execution).is_err());
    assert!(
        require_unowned_original_lineage_execution(
            &catalog,
            ExecutionId::from_bytes([150; 16]).unwrap(),
        )
        .is_ok()
    );
    assert_eq!(original_lineage_available_worlds(&catalog, 1), 0);
    assert_eq!(original_lineage_available_worlds(&catalog, 0), 0);
    assert_eq!(original_lineage_available_worlds(&catalog, 4), 3);

    // The threaded grouped route must consume the same actual inactive source
    // credit before building its separate catalog or native owner lane.
    let other = ExecutionId::from_bytes([150; 16]).unwrap();
    assert!(require_grouped_preparation_capacity(&catalog, other, 1, 0).is_err());
    assert!(require_grouped_preparation_capacity(&catalog, other, 2, 1).is_err());
    assert!(require_grouped_preparation_capacity(&catalog, other, 2, 0).is_ok());
    assert!(require_grouped_preparation_capacity(&catalog, execution, 8, 0).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(catalog.custody().reserved_worlds(), 0);

    // Genuine empty queue reclamation releases capsule credit, never its nonce.
    catalog.retire_original_lineage_preparations();
    assert_eq!(catalog.original_lineage_preparation_count(), 0);
    assert_eq!(original_lineage_available_worlds(&catalog, 4), 4);
    assert!(require_unowned_original_lineage_execution(&catalog, execution).is_err());
    // Reclamation restores world capacity but never remints the original nonce.
    assert!(require_grouped_preparation_capacity(&catalog, other, 1, 0).is_ok());
    assert!(require_grouped_preparation_capacity(&catalog, execution, 8, 0).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn missing_normal_acceptance_refuses_before_delegated_source_qualification() {
    use crate::node_observed_executor::factory::{
        InstalledNodeKind, InstalledNodeSelection, acceptance::SourceBindingPolicy,
    };
    use crucible::node_admission::{AdmissionEvidence, EvidenceError, QualificationClaim as Claim};
    use crucible_node_contract::{ImplementationIdentity, NodeBinding, SchemaRef};

    struct SourceCalls(Arc<AtomicUsize>);

    impl AdmissionEvidence for SourceCalls {
        fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
            Err(EvidenceError {
                message: "source body not requested by this control".into(),
            })
        }

        fn authenticate_implementation(
            &self,
            _: &ImplementationIdentity,
        ) -> Result<(), EvidenceError> {
            Ok(())
        }

        fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
            Ok(())
        }

        fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
            Ok(())
        }

        fn qualify(&self, _: Claim<'_>) -> Result<(), EvidenceError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let catalog = catalog(directory.path());
    let scenario = catalog
        .scenario(&[InstalledNodeSelection {
            node: Id::new("clock").unwrap(),
            owner: Id::new("clock-owner").unwrap(),
            kind: InstalledNodeKind::HostClock,
        }])
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let underlying = SourceCalls(Arc::clone(&calls));
    let installed = MissingAcceptedClass;
    let scoped = SourceBindingPolicy::new(&installed, &scenario);
    let evidence =
        BehavioralAdmissionEvidence::new(&underlying, &scoped, AcceptanceLimits::default());
    let binding = &scenario.compatibility[0];

    assert!(
        evidence
            .qualify(Claim::Node {
                binding,
                binding_hash: &binding.identity().unwrap(),
                qualification_refs: &binding.qualification_refs
            })
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}
