//! Checks positive installed descendants and refusal before capture callbacks.
//!
//! Synthetic full-reference rows exercise only the selected data traversal.

use std::cell::Cell;
use std::collections::BTreeMap;

use crucible_node_contract::{CaptureManifest, CapturedOwner, canonical};

use super::*;
use crate::node_admission::AdmittedGraph;
use crate::node_state::{
    CaptureEvidence, NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateRequirements,
    VerifiedStateContent,
    closure::{ContentInventoryEdition, verify_closure_with_edition},
    schema,
};

type ModelResult = Result<(), StateError>;

#[test]
fn installed_qualification_retains_positive_binding_and_enrollment() -> ModelResult {
    let (evidence, root, binding, receipt) = fixture()?;
    let roots = combine(Vec::new(), vec![root], StateLimits::default())?;
    let closure = verify_closure_with_edition(
        roots,
        &evidence,
        StateLimits::default(),
        ContentInventoryEdition::Typed,
    )?;

    assert_eq!(closure.get(&binding), Some(b"binding".as_slice()));
    assert_eq!(closure.get(&receipt), Some(b"receipt".as_slice()));
    assert_eq!(closure.object_count(), 3);
    assert_eq!(evidence.native_callbacks.get(), 0);
    Ok(())
}

#[test]
fn missing_positive_descendant_refuses_without_capture_or_leaf_fallback() -> ModelResult {
    let (mut evidence, root, _, receipt) = fixture()?;
    evidence.objects.remove(&receipt);
    let roots = combine(Vec::new(), vec![root], StateLimits::default())?;

    assert!(
        verify_closure_with_edition(
            roots,
            &evidence,
            StateLimits::default(),
            ContentInventoryEdition::Typed,
        )
        .is_err()
    );
    assert_eq!(evidence.native_callbacks.get(), 0);
    Ok(())
}

#[test]
fn changed_positive_media_refuses_exact_role_lookup() -> ModelResult {
    let (mut evidence, root, binding, _) = fixture()?;
    let row = evidence
        .objects
        .get_mut(&binding)
        .ok_or_else(|| refused("fixture binding absent"))?;
    row.1[0].media_type = "application/octet-stream".into();

    assert!(
        verify_closure_with_edition(
            vec![root],
            &evidence,
            StateLimits::default(),
            ContentInventoryEdition::Typed,
        )
        .is_err()
    );
    assert_eq!(evidence.native_callbacks.get(), 0);
    Ok(())
}

#[test]
fn aggregate_roots_and_descendants_refuse_under_unchanged_credits() -> ModelResult {
    let (evidence, root, binding, _) = fixture()?;
    let limits = StateLimits {
        maximum_content_objects: 1,
        ..StateLimits::default()
    };
    assert!(combine(vec![root.clone()], vec![binding], limits).is_err());
    assert_eq!(evidence.reads.get(), 0);

    let limits = StateLimits {
        maximum_total_content_bytes: 20,
        ..StateLimits::default()
    };
    assert!(
        verify_closure_with_edition(
            vec![root.clone()],
            &evidence,
            limits,
            ContentInventoryEdition::Typed,
        )
        .is_err()
    );
    let limits = StateLimits {
        maximum_dependency_edges: 1,
        ..StateLimits::default()
    };
    assert!(
        verify_closure_with_edition(
            vec![root],
            &evidence,
            limits,
            ContentInventoryEdition::Typed,
        )
        .is_err()
    );
    assert_eq!(evidence.native_callbacks.get(), 0);
    Ok(())
}

struct Evidence {
    objects: BTreeMap<ContentRef, (Vec<u8>, Vec<ContentRef>)>,
    reads: Cell<usize>,
    native_callbacks: Cell<usize>,
}

fn fixture() -> Result<(Evidence, ContentRef, ContentRef, ContentRef), StateError> {
    let root = canonical::content_ref(b"qualification", "application/json").map_err(schema)?;
    let binding = canonical::content_ref(b"binding", "application/json").map_err(schema)?;
    let receipt = canonical::content_ref(b"receipt", "application/json").map_err(schema)?;
    let evidence = Evidence {
        objects: [
            (
                root.clone(),
                (b"qualification".to_vec(), vec![binding.clone()]),
            ),
            (
                binding.clone(),
                (b"binding".to_vec(), vec![receipt.clone()]),
            ),
            (receipt.clone(), (b"receipt".to_vec(), Vec::new())),
        ]
        .into_iter()
        .collect(),
        reads: Cell::new(0),
        native_callbacks: Cell::new(0),
    };
    Ok((evidence, root, binding, receipt))
}

impl CaptureEvidence for Evidence {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        self.reads.set(self.reads.get() + 1);
        let (body, _) = self
            .objects
            .get(reference)
            .ok_or_else(|| refused("positive body absent"))?;
        if body.len() > maximum {
            return Err(refused("positive body credit exhausted"));
        }
        Ok(body.clone())
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        _: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        let (_, row) = self
            .objects
            .get(reference)
            .ok_or_else(|| refused("positive row absent"))?;
        if row.len() > maximum {
            return Err(refused("positive row credit exhausted"));
        }
        Ok(row.clone())
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        self.native_callbacks.set(self.native_callbacks.get() + 1);
        Err(refused("synthetic closure grants no native authority"))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        self.native_callbacks.set(self.native_callbacks.get() + 1);
        Err(refused("synthetic closure grants no coordinator authority"))
    }
}
