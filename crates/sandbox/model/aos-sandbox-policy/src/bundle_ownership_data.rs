//! Compares Ownership bundle DATA and quotes its existing decode captures.
//!
//! These helpers neither verify protected custody nor construct a native role.
//! Callers retain their genuine Source, Open, trust and receiving originals.

use std::mem::size_of;

use aos_sandbox_model::{CanonicalAssignmentManifestV1, DecodeLimits,
    ResourceDimension as D, ResourceVector};
use aos_sandbox_model::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_ownership_protocol::{OwnershipClaimAction, response_verification::{
    OwnershipClaimDecodeCaptureV1, OwnershipResponseVerifyCaptureV1}};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    assignment_planned::AssignmentPlannedBodyDataV1,
    controller_intent::ControllerIntentBodyDataV1, ready::ReadyBundleDataV1};

/// Reports overflow in the existing Ownership capture geometry.
#[derive(Debug, thiserror::Error)]
pub enum OwnershipBundleDataErrorV1 {
    /// The complete capture geometry cannot be represented.
    #[error("journal too large")]
    JournalTooLarge,
}

// The old geometry names this same single overflow class at every checked edge.
use OwnershipBundleDataErrorV1 as JournalError;

/// Quotes the complete claim, assignment and response decode capture DATA.
///
/// # Errors
/// Returns an overflow error when a capture supplier or checked sum fails.
pub fn ownership_bundle_typed_demand_v1(
    bundle: ReadyBundleDataV1<'_>, manifest_bytes: usize,
    verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
) -> Result<ResourceVector, OwnershipBundleDataErrorV1> {
    let invalid = || JournalError::JournalTooLarge;
    let quartet = [bundle.ownership_lease, bundle.ownership_signature,
        bundle.ownership_receipt, bundle.ownership_receipt_signature].into_iter()
        .try_fold(0_usize, |sum, field| sum.checked_add(field.len())).ok_or_else(invalid)?;
    let response = ownership_response_receiving_bytes_v2(quartet, verifier).ok_or_else(invalid)?;
    let (assignment_dynamic, _) =
        CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(
            manifest_bytes, DecodeLimits::default(),
        ).ok_or_else(invalid)?;
    let assignment_fixed = CanonicalAssignmentDecodeCaptureV1::receiving_construction_bytes_v1()
        .ok_or_else(invalid)?;
    let memory = OwnershipClaimDecodeCaptureV1::receiving_construction_bytes_v1()
        .and_then(|bytes| bytes.checked_add(response))
        .and_then(|bytes| bytes.checked_add(assignment_fixed))
        .and_then(|bytes| bytes.checked_add(assignment_dynamic))
        .and_then(|bytes| bytes.checked_add(4 * size_of::<usize>())).ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
        .with(D::OutputBytes, u64::try_from(memory).map_err(|_| invalid())?))
}

/// Quotes the existing response verification capture DATA.
///
/// # Errors
/// Returns an overflow error when a capture supplier or conversion fails.
pub fn ownership_response_typed_demand_v2(
    quartet_bytes: usize,
    verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
) -> Result<ResourceVector, OwnershipBundleDataErrorV1> {
    let memory = ownership_response_receiving_bytes_v2(quartet_bytes, verifier)
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::OutputBytes, memory))
}

fn ownership_response_receiving_bytes_v2(
    quartet_bytes: usize,
    verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
) -> Option<usize> {
    OwnershipResponseVerifyCaptureV1::receiving_construction_bytes_v1()?
        .checked_add(verifier.response_receiving_dynamic_bytes_v2(quartet_bytes)?)
}

/// Decodes the exact Controller assignment-planned record in a Ready bundle.
///
/// # Errors
/// Returns the original record framing, key, phase or body decoding error.
pub fn planned_assignment_v1(bundle: ReadyBundleDataV1<'_>)
    -> Result<AssignmentPlannedBodyDataV1<'_>, HistoryErrorV1>
{
    let record = RecordEnvelopeV1::decode(bundle.assignment_planned,
        KeyV1::new(bundle.lane, OwnerV1::Controller, 2)?,
        PhaseV1::new(OwnerV1::Controller, 12)?)?;
    AssignmentPlannedBodyDataV1::decode(record.body())
}

/// Compares the canonical manifest with the claim and accepted specification.
///
/// # Errors
/// Returns a correlation error for any original manifest, project or commitment mismatch.
pub fn require_manifest_data_v1(
    canonical: &CanonicalAssignmentManifestV1,
    claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
    project: [u8; 16],
    planned: &AssignmentPlannedBodyDataV1<'_>,
    specification: &[u8],
) -> Result<(), HistoryErrorV1> {
    let manifest = canonical.manifest();
    if canonical.canonical_bytes() != planned.manifest
        || canonical.digest() != claim.assignment().digest()
        || manifest.project().as_bytes() != &project
        || manifest.sandbox() != claim.assignment().sandbox()
        || manifest.node() != claim.node()
        || manifest.incarnation() != claim.assignment().incarnation()
        || manifest.epoch() != claim.assignment().epoch()
        || manifest.desired_generation() != claim.desired_generation()
        || manifest.epoch().get() != 1 || manifest.desired_generation().get() != 1
        || manifest.namespace_generation().get() != 1 || !manifest.ancestry().ancestors().is_empty()
        || !aos_sandbox_model::format::descriptor_matches_encoded_bytes_data_v1(
            manifest.sandbox_spec(), specification)
    {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
}

/// Compares an Acquire claim with the accepted operation, node and manifest.
///
/// # Errors
/// Returns a correlation error for a different action or association.
pub fn require_claim_data_v1(
    claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
    operation: [u8; 16], sandbox: [u8; 16], node: [u8; 16], manifest: &[u8],
) -> Result<(), HistoryErrorV1> {
    if claim.action() != OwnershipClaimAction::Acquire || claim.request_id() != &operation
        || claim.assignment().sandbox().as_bytes() != &sandbox || claim.node().as_bytes() != &node
        || claim.assignment().digest() != CanonicalAssignmentManifestV1::digest_canonical_bytes_data_v1(manifest)
    {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
}

/// Expands the original association comparison in its caller's retained frame.
///
/// Intent and account-head parsing precede the concrete Source and Open getter
/// expressions. These lexical expressions introduce no callback or native grant.
///
/// # Errors
/// Propagates the original framing errors before completion or association errors.
#[macro_export]
macro_rules! require_root_bundle_ownership_association_data_v1 {
    ($bundle:ident, $planned:ident, $manifest:ident, $claim:ident,
        source = $source:expr, root = $root:expr) => {{
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{
            HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
            controller_intent::ControllerIntentBodyDataV1,
        };

        let intent = RecordEnvelopeV1::decode($bundle.intent_record,
            KeyV1::new($bundle.lane, OwnerV1::Controller, 1)?, PhaseV1::new(OwnerV1::Controller, 1)?)?;
        let accepted = ControllerIntentBodyDataV1::decode(intent.body())?;
        let head = aos_sandbox_protocol::domain_ledger::resource_bank::AccountHead::decode(accepted.j_head)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        let current = ($source).map_err(|_| HistoryErrorV1::Correlation)?;
        let original = ($root).map_err(|_| HistoryErrorV1::Correlation)?;
        $crate::bundle_ownership_data::require_claim_data_v1($claim, accepted.identity.operation, accepted.identity.sandbox,
            head.native_fields().enrollment.native_fields().node, $planned.manifest)?;
        $crate::bundle_ownership_data::require_manifest_data_v1($manifest, $claim, accepted.identity.project,
            &$planned, $bundle.specification)?;
        if $bundle.lane != original.open.lane || accepted.identity.controller_nonce != original.open.controller_nonce
            || accepted.identity.boot != original.boot
            || current.project != accepted.identity.project || current.sandbox != accepted.identity.sandbox
            || current.released_operation != accepted.identity.operation
            || current.tree_head != $planned.tree_head || current.lineage_head != $planned.lineage_head
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())

    }};
}

/// Quotes the two existing fixed prelude-work carriers.
#[must_use]
pub const fn fixed_prelude_work_receiving_bytes_v1() -> Option<usize> {
    size_of::<FixedPreludeWorkV1>().checked_mul(2)
}

/// Quotes the two existing assignment geometry carriers with the caller's error.
#[must_use]
pub const fn assignment_prelude_geometry_receiving_bytes_v1<E>() -> Option<usize> {
    size_of::<AssignmentPreludeGeometryV1<E>>().checked_mul(2)
}

/// Quotes the new pure geometry interfaces and their caller error projection.
///
/// The argument is a type parameter, not a supplied error or financial original.
/// Existing capture backing and canonical framing controls remain separate.
#[must_use]
pub fn fixed_interface_control_bytes_v1<E>() -> Option<usize> {
    // Canonical geometry return, zero-capture map_err argument and caller result.
    let geometry = size_of::<Result<ResourceVector, OwnershipBundleDataErrorV1>>().checked_mul(3)?;
    let projection = size_of::<OwnershipBundleDataErrorV1>().checked_mul(3)?;
    let caller = size_of::<Result<ResourceVector, E>>().checked_mul(3)?;
    let cause = size_of::<E>().checked_mul(3)?;
    // Two passive carrier suppliers and this supplier's actual Option returns.
    let returns = size_of::<Option<usize>>().checked_mul(9)?;
    // Seven local byte values and six checked-add receiver/argument pairs.
    let locals = size_of::<usize>().checked_mul(21)?;
    let additions = size_of::<(usize, usize)>().checked_mul(18)?;
    geometry.checked_add(projection)?
        .checked_add(caller)?
        .checked_add(cause)?
        .checked_add(returns)?
        .checked_add(locals)?
        .checked_add(additions)
}

// Complete fixed prelude/association carriers, including return planes. This
// roster performs no nested heap decoder and reuses no unnamed spare credit.
#[allow(dead_code)]
struct FixedPreludeWorkV1 {
    bundles: [ReadyBundleDataV1<'static>; 4],
    fields: [[&'static [u8]; 25]; 2],
    intents: [ControllerIntentBodyDataV1<'static>; 4],
    intent_fields: [[&'static [u8]; 11]; 2],
    records: [RecordEnvelopeV1<'static>; 6],
    planned: [AssignmentPlannedBodyDataV1<'static>; 4],
    heads: [aos_sandbox_protocol::domain_ledger::resource_bank::AccountHead; 4],
    source: [aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SourceCurrentReplyFieldsV1; 2],
    root: [aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootOpenBodyDataV1; 2],
    readers: [aos_sandbox_model::bounded_codec::BoundedReader<'static, HistoryErrorV1>; 8],
    vectors: [ResourceVector; 8],
    hashers: [sha2::Sha256; 4],
}

// Fixed geometry/return planes reached before typed admission. These fields
// name the actual two shared passive supplier calls and their checked fold.
#[allow(dead_code)]
struct AssignmentPreludeGeometryV1<E> {
    manifest_bytes: usize,
    limits: DecodeLimits,
    dynamic: Option<(usize, usize)>,
    construction: Option<usize>,
    bytes: usize,
    cells: usize,
    raw_depth: usize,
    planes: usize,
    ancestry_slots: usize,
    source_slots: usize,
    feature_slots: usize,
    output: ResourceVector,
    result: Result<ResourceVector, E>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{AssignmentEpoch, DesiredGeneration, IncarnationId,
        LeaseAssignment, NodeId, SandboxId};
    use aos_sandbox_ownership_protocol::{OwnershipClaimV1, ExpectedOwnershipLease};

    #[test]
    fn claim_joins_exact_accepted_operation_node_and_manifest_bytes() {
        // This exercises only fixed comparison DATA, not a genuine Root/J loan,
        // valid canonical manifest or authority derived from these test bytes.
        let manifest = b"proposed manifest bytes";
        let digest = CanonicalAssignmentManifestV1::digest_canonical_bytes_data_v1(manifest);
        let assignment = LeaseAssignment::new(SandboxId::from_bytes([2; 16]),
            IncarnationId::from_bytes([3; 16]), AssignmentEpoch::new(1), digest).unwrap();
        let claim = OwnershipClaimV1::acquire([1; 16], assignment,
            DesiredGeneration::new(1), NodeId::from_bytes([4; 16]), 60).unwrap();

        assert!(require_claim_data_v1(&claim, [1; 16], [2; 16], [4; 16], manifest).is_ok());
        assert!(require_claim_data_v1(&claim, [9; 16], [2; 16], [4; 16], manifest).is_err());
        assert!(require_claim_data_v1(&claim, [1; 16], [2; 16], [9; 16], manifest).is_err());
        assert!(require_claim_data_v1(&claim, [1; 16], [2; 16], [4; 16], b"other manifest").is_err());

        let prior = ExpectedOwnershipLease::new(1, digest).unwrap();
        let renewal = OwnershipClaimV1::renew([1; 16], assignment,
            DesiredGeneration::new(1), NodeId::from_bytes([4; 16]), prior, 60).unwrap();
        assert!(require_claim_data_v1(&renewal, [1; 16], [2; 16], [4; 16], manifest).is_err());
    }

    fn manifest_fixture(ancestor: bool, generation: u64)
        -> (CanonicalAssignmentManifestV1, OwnershipClaimV1, Vec<u8>)
    {
        use aos_sandbox_model::{MediaType, NamespaceGeneration, ObjectDescriptor,
            ObjectDigest, PortableMediaType, ProjectId};
        use aos_sandbox_model::model::{AssignmentManifestV1, SandboxAncestry};

        let specification = b"exact original specification bytes".to_vec();
        let descriptor = |kind: PortableMediaType, byte| ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]), 1,
        );
        let sandbox = SandboxId::from_bytes([1; 16]);
        let spec = aos_sandbox_model::format::descriptor_for_bytes(
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
            &specification,
        );
        let ancestry = SandboxAncestry::new(sandbox,
            if ancestor { vec![SandboxId::from_bytes([9; 16])] } else { Vec::new() }).unwrap();
        let manifest = AssignmentManifestV1::new(
            sandbox, ProjectId::from_bytes([2; 16]), ancestry,
            IncarnationId::from_bytes([4; 16]), NodeId::from_bytes([5; 16]),
            AssignmentEpoch::new(1), DesiredGeneration::new(generation), NamespaceGeneration::new(1),
            spec, descriptor(PortableMediaType::Policy, 7),
            descriptor(PortableMediaType::Environment, 8), descriptor(PortableMediaType::View, 9),
            Vec::new(), ObjectDigest::from_bytes([10; 32]), ResourceVector::ZERO, Vec::new(),
        ).unwrap();
        let canonical = CanonicalAssignmentManifestV1::new(manifest);
        let assignment = LeaseAssignment::new(sandbox, IncarnationId::from_bytes([4; 16]),
            AssignmentEpoch::new(1), canonical.digest()).unwrap();
        let claim = OwnershipClaimV1::acquire([3; 16], assignment,
            DesiredGeneration::new(generation), NodeId::from_bytes([5; 16]), 60).unwrap();
        (canonical, claim, specification)
    }

    #[test]
    fn actual_manifest_model_joins_claim_project_and_exact_spec_commitment() {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::association::AcceptedAssociationDataV1;
        let association = AcceptedAssociationDataV1 {
            operation: [3; 16], project: [2; 16], sandbox: [1; 16],
            accepted_request: [6; 32], coissuance_binding: [7; 32], seed: [8; 32],
            controller_nonce: [9; 16], boot: [10; 16], started: 1, cutoff: 2,
        };
        let (canonical, claim, specification) = manifest_fixture(false, 1);
        let planned = AssignmentPlannedBodyDataV1 { association,
            source_held: [11; 32], cache_held: [12; 32], input_origin: [13; 32],
            tree_head: [14; 32], lineage_head: [15; 32], manifest: canonical.canonical_bytes() };

        assert!(require_manifest_data_v1(&canonical, &claim, [2; 16], &planned, &specification).is_ok());
        assert!(require_manifest_data_v1(&canonical, &claim, [20; 16], &planned, &specification).is_err());
        let mut substituted = specification.clone();
        substituted[0] ^= 1;
        assert!(require_manifest_data_v1(&canonical, &claim, [2; 16], &planned, &substituted).is_err());

        // A valid canonical model and self-consistent claim cannot turn this
        // explicitly first/empty-tree recipe into a different assignment.
        for (ancestor, generation) in [(true, 1), (false, 2)] {
            let (other, other_claim, exact_spec) = manifest_fixture(ancestor, generation);
            let other_planned = AssignmentPlannedBodyDataV1 { manifest: other.canonical_bytes(), ..planned };
            assert!(require_manifest_data_v1(&other, &other_claim, [2; 16], &other_planned, &exact_spec).is_err());
        }
    }

}
