//! Checks optional roster bracketing and the unchanged single-schema fallback.
//!
//! This uses the existing trusted in-memory admission model, not native code
//! qualification. The separate Daemon controls exercise actual retained files.

use super::*;
use std::cell::Cell;

struct RosterEvidence<'a> {
    inner: &'a Evidence,
    selected: bool,
    batches: Cell<usize>,
    singles: Cell<usize>,
    mutate_during_content: bool,
    content_error: bool,
    changed: Cell<bool>,
    withdraw_at_terminal: bool,
}

impl<'a> RosterEvidence<'a> {
    fn new(inner: &'a Evidence, selected: bool) -> Self {
        Self {
            inner,
            selected,
            batches: Cell::new(0),
            singles: Cell::new(0),
            mutate_during_content: false,
            content_error: false,
            changed: Cell::new(false),
            withdraw_at_terminal: false,
        }
    }
}

impl AdmissionEvidence for RosterEvidence<'_> {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        let bytes = self.inner.content(reference, maximum)?;
        if self.mutate_during_content && self.batches.get() > 0 {
            self.changed.set(true);
            if self.content_error {
                return Err(EvidenceError {
                    message: "modeled content failure".into(),
                });
            }
        }
        Ok(bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.inner.authenticate_implementation(implementation)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.inner.authenticate_authority(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.singles.set(self.singles.get() + 1);
        self.inner.authenticate_schema(schema)
    }

    fn authenticate_schema_roster(
        &self,
        binding: &NodeBinding,
        schemas: &[SchemaRef],
    ) -> Option<Result<(), EvidenceError>> {
        if !self.selected {
            return None;
        }
        self.batches.set(self.batches.get() + 1);
        if self.withdraw_at_terminal && self.batches.get() == 2 {
            return None;
        }
        Some((|| {
            if self.changed.get()
                || schemas != binding.compatibility.implementation.formats.as_slice()
            {
                return Err(EvidenceError {
                    message: "modeled schema owner changed".into(),
                });
            }
            for schema in schemas {
                self.inner.authenticate_schema(schema)?;
            }
            Ok(())
        })())
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.inner.qualify(claim)
    }
}

fn admit_with(
    fixture: &Fixture,
    evidence: &dyn AdmissionEvidence,
) -> Result<AdmittedGraph, AdmissionError> {
    admit_graph(
        AdmissionRequest {
            world: &fixture.world,
            descriptors: &fixture.descriptors,
            bindings: &fixture.bindings,
            owners: &fixture.owners,
            requirements: &fixture.requirements,
        },
        evidence,
        AdmissionLimits::default(),
    )
}

#[test]
fn optional_roster_and_default_fallback_preserve_the_same_graph() {
    let fixture = Fixture::new();
    let fallback = RosterEvidence::new(&fixture.evidence, false);
    let batched = RosterEvidence::new(&fixture.evidence, true);

    let original = admit_with(&fixture, &fallback).unwrap();
    let grouped = admit_with(&fixture, &batched).unwrap();

    assert_eq!(original.world_binding_hash(), grouped.world_binding_hash());
    for binding in &fixture.bindings {
        assert_eq!(
            original.binding(&binding.compatibility.node_id),
            grouped.binding(&binding.compatibility.node_id)
        );
    }
    let formats: usize = fixture
        .bindings
        .iter()
        .map(|binding| binding.compatibility.implementation.formats.len())
        .sum();
    // Payload-lane validators remain separate from implementation batching.
    let lane_schemas: usize = fixture
        .descriptors
        .iter()
        .flat_map(|descriptor| &descriptor.ports)
        .map(|port| port.lanes.len())
        .sum();
    assert_eq!(fallback.singles.get(), formats + lane_schemas);
    assert_eq!(fallback.batches.get(), 0);
    assert_eq!(batched.singles.get(), lane_schemas);
    assert_eq!(batched.batches.get(), 2 * fixture.bindings.len());
}

#[test]
fn terminal_roster_check_observes_content_callback_drift_even_on_content_error() {
    let mut fixture = Fixture::new();
    // The distinct definition ensures a real content callback occurs inside
    // the format loop instead of hitting previously verified fixture content.
    let definition = fixture.evidence.bytes(b"independent schema body".to_vec());
    fixture.bindings[0].compatibility.implementation.formats[0].definition = definition;
    fixture.refresh();

    for content_error in [false, true] {
        let mut evidence = RosterEvidence::new(&fixture.evidence, true);
        evidence.mutate_during_content = true;
        evidence.content_error = content_error;

        assert!(admit_with(&fixture, &evidence).is_err());
        assert!(evidence.changed.get());
        assert_eq!(evidence.batches.get(), 2);
        assert_eq!(evidence.singles.get(), 0);
    }
    let mut evidence = RosterEvidence::new(&fixture.evidence, true);
    evidence.withdraw_at_terminal = true;
    assert!(admit_with(&fixture, &evidence).is_err());
    assert_eq!(evidence.batches.get(), 2);
}

#[test]
fn default_fallback_keeps_the_original_schema_refusal() {
    let mut fixture = Fixture::new();
    fixture.evidence.reject_schema = true;
    let evidence = RosterEvidence::new(&fixture.evidence, false);

    let error = admit_with(&fixture, &evidence).unwrap_err();

    assert_eq!(error.code, AdmissionCode::UnknownInterface);
    assert_eq!(evidence.singles.get(), 1);
    assert_eq!(evidence.batches.get(), 0);
}
