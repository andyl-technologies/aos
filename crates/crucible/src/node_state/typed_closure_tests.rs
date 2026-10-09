//! Data-only typed closure checks without native continuation authority.

#![allow(clippy::unwrap_used)] // Model fixture failures deliberately panic.

use super::closure::{ContentInventoryEdition, verify_closure, verify_closure_with_edition};
use super::*;
use crate::node_admission::AdmittedGraph;
use crucible_node_contract::{CaptureManifest, CapturedOwner, ContentRef, canonical};
use std::cell::Cell;
use std::collections::BTreeMap;

#[derive(Default)]
struct Evidence {
    objects: BTreeMap<ContentRef, (Vec<u8>, Vec<ContentRef>)>,
    reads: Cell<usize>,
}

impl CaptureEvidence for Evidence {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        self.reads.set(self.reads.get() + 1);
        let body = &self
            .objects
            .get(reference)
            .ok_or_else(|| refused("unknown typed role"))?
            .0;
        if body.len() > maximum {
            return Err(refused("oversized typed body"));
        }
        Ok(body.clone())
    }
    fn dependencies(
        &self,
        reference: &ContentRef,
        _: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        let rows = &self
            .objects
            .get(reference)
            .ok_or_else(|| refused("unknown typed role"))?
            .1;
        if rows.len() > maximum {
            return Err(refused("oversized typed adjacency"));
        }
        Ok(rows.clone())
    }
    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(refused("data fixture grants no native source authority"))
    }
    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(refused("data fixture grants no coordinator authority"))
    }
}

fn refused(reason: &str) -> StateError {
    StateError::new(StateErrorCode::Content, "typed closure model", reason)
}

#[test]
fn typed_closure_preserves_independently_enrolled_roles_and_byte_deduplication() {
    let body = b"{\"bytes_processed\":\"0\",\"checksum\":\"0\"}";
    let json = canonical::content_ref(body, "application/json").unwrap();
    let payload = canonical::content_ref(body, "application/octet-stream").unwrap();
    let left = canonical::content_ref(b"left", "text/plain").unwrap();
    let right = canonical::content_ref(b"right", "text/plain").unwrap();
    let evidence = Evidence {
        objects: [
            (json.clone(), (body.to_vec(), vec![left.clone()])),
            (payload.clone(), (body.to_vec(), vec![right.clone()])),
            (left.clone(), (b"left".to_vec(), vec![])),
            (right.clone(), (b"right".to_vec(), vec![])),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let content = verify_closure_with_edition(
        vec![json.clone(), payload.clone()],
        &evidence,
        StateLimits::default(),
        ContentInventoryEdition::Typed,
    )
    .unwrap();
    assert_eq!(content.get(&json), Some(body.as_slice()));
    assert_eq!(content.get(&payload), Some(body.as_slice()));
    assert_eq!(content.get(&left), Some(b"left".as_slice()));
    assert_eq!(content.get(&right), Some(b"right".as_slice()));
    assert_eq!(content.object_count(), 4);
    assert_eq!(content.total_bytes(), body.len() + 9);
    let mut unrecorded_role = json.clone();
    unrecorded_role.media_type = "application/x-unrecorded".into();
    assert_eq!(content.get(&unrecorded_role), None);

    evidence.reads.set(0);
    assert!(verify_closure(vec![json, payload], &evidence, StateLimits::default()).is_err());
    assert_eq!(evidence.reads.get(), 0);
}

#[test]
fn typed_closure_checks_roles_credit_before_reading_and_rejects_changed_alias_bytes() {
    let body = b"original";
    let json = canonical::content_ref(body, "application/json").unwrap();
    let payload = canonical::content_ref(body, "application/octet-stream").unwrap();
    let mut evidence = Evidence {
        objects: [
            (json.clone(), (body.to_vec(), vec![])),
            (payload.clone(), (b"altered!".to_vec(), vec![])),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let limits = StateLimits {
        maximum_content_objects: 1,
        ..StateLimits::default()
    };
    assert!(
        verify_closure_with_edition(
            vec![json.clone(), payload.clone()],
            &evidence,
            limits,
            ContentInventoryEdition::Typed
        )
        .is_err()
    );
    assert_eq!(evidence.reads.get(), 0);
    assert!(
        verify_closure_with_edition(
            vec![json.clone(), payload.clone()],
            &evidence,
            StateLimits::default(),
            ContentInventoryEdition::Typed
        )
        .is_err()
    );
    evidence.objects.get_mut(&payload).unwrap().0 = body.to_vec();
    let limits = StateLimits {
        maximum_total_content_bytes: body.len(),
        ..StateLimits::default()
    };
    let content = verify_closure_with_edition(
        vec![json, payload],
        &evidence,
        limits,
        ContentInventoryEdition::Typed,
    )
    .unwrap();
    assert_eq!(content.total_bytes(), body.len());
    assert_eq!(content.object_count(), 2);
}

#[test]
fn typed_payload_credit_counts_rows_before_a_new_byte_hash() {
    let body = b"same bytes";
    let json = canonical::content_ref(body, "application/json").unwrap();
    let payload = canonical::content_ref(body, "application/octet-stream").unwrap();
    let evidence = Evidence {
        objects: [
            (json.clone(), (body.to_vec(), vec![])),
            (payload.clone(), (body.to_vec(), vec![])),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let limits = StateLimits {
        maximum_content_objects: 2,
        ..StateLimits::default()
    };
    let mut content = verify_closure_with_edition(
        vec![json.clone(), payload.clone()],
        &evidence,
        limits,
        ContentInventoryEdition::Typed,
    )
    .unwrap();
    let third = canonical::content_ref(b"new bytes", "application/octet-stream").unwrap();
    assert!(
        content
            .include_payload(&third, b"new bytes", limits)
            .is_err()
    );
    assert_eq!(content.object_count(), 2);
    assert_eq!(content.total_bytes(), body.len());
    assert_eq!(content.get(&json), Some(body.as_slice()));
    assert_eq!(content.get(&payload), Some(body.as_slice()));
    assert_eq!(content.get(&third), None);
}
