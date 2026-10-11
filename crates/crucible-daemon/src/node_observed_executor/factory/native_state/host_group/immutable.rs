//! Reopens only independently regenerated whole-group immutable source objects.
//!
//! This registry enumerates installed metadata dependencies. It cannot issue
//! owner or coordinator capture proofs, restore native resources or mint Ready.

use std::rc::Rc;

use crucible::{
    node_admission::{AdmissionEvidence, AdmittedGraph},
    node_state::{
        CaptureEvidence, NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateError,
        StateRequirements, VerifiedStateContent,
    },
};
use crucible_node_contract::{CaptureManifest, CapturedOwner, ContentRef};

use super::{evidence::IndependentGroupEvidence, source::error};

pub(in crate::node_observed_executor::factory::native_state) struct GroupImmutableEvidence {
    pub(super) evidence: Rc<IndependentGroupEvidence>,
}

impl CaptureEvidence for GroupImmutableEvidence {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        let metadata = self.evidence.metadata().map_err(error)?;
        if (!metadata.is_root(reference) && metadata.role(reference).is_none())
            || !self.evidence.known_immutable_reference(reference)
        {
            return Err(error("immutable body has no exact installed metadata role"));
        }
        self.evidence.content(reference, maximum).map_err(error)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.evidence
            .metadata()
            .map_err(error)?
            .dependencies(reference, bytes, maximum)
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(error(
            "group immutable registry cannot issue native capture provenance",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(error(
            "group immutable registry cannot issue coordinator capture provenance",
        ))
    }
}
