//! Canonical native nonrecursive topology claims, never measurement authority.
//!
//! This profile binds Storage's complete held-root counts to one request,
//! signed receipt, and original descriptor. Depth counts mounts, not portable
//! directories; the native profile admits exactly one mount and no submounts.
//!
//! ```text
//! "aos.sandbox.storage.native-nonrecursive-topology.v1\0" |
//! authority-id[16] | receipt-cut-sequence:u64be |
//! signed-request-digest[32] | signed-receipt-digest[32] |
//! original-descriptor-commitment[32] | read-only-content-digest[32] |
//! actual-nodes:u64be | actual-logical-bytes:u64be |
//! mount-depth:u32be=1 | submounts:u32be=0
//! ```

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{SignedStorageNativeAcquireRequestV2, StorageNativeAcquireErrorV2};
use crate::{
    RecursiveTopologyProofV1, SignedStorageZfsHoldReceiptV1, SourceRootObservationV1,
    source_root_descriptor_commitment_v1,
};

const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.native-nonrecursive-topology.v1\0";

/// Maximum root-inclusive measured node count of the native nonrecursive profile.
pub const MAXIMUM_STORAGE_NATIVE_TOPOLOGY_NODES_V1: u64 = 4096;

/// Maximum measured logical file bytes of the native nonrecursive profile.
pub const MAXIMUM_STORAGE_NATIVE_TOPOLOGY_LOGICAL_BYTES_V1: u64 = 64 * 1024 * 1024;

/// Encodes supplied held-root measurements into the native nonrecursive profile.
///
/// This helper authenticates nothing and does not measure a tree. A production
/// Storage owner must derive both counts from the complete retained held-root
/// readback and establish mount depth one with no submounts before signing V3
/// acceptance. Calling this helper on self-asserted inputs grants no authority.
///
/// # Errors
///
/// Rejects counts outside the native profile, file bytes without a file node,
/// or sentinel authority/cut fields.
pub fn storage_native_nonrecursive_topology_v1(
    request: &SignedStorageNativeAcquireRequestV2,
    receipt: &SignedStorageZfsHoldReceiptV1,
    descriptor: &SourceRootObservationV1,
    actual_nodes: u64,
    actual_logical_bytes: u64,
) -> Result<RecursiveTopologyProofV1, StorageNativeAcquireErrorV2> {
    native_nonrecursive_topology(
        request.digest(),
        receipt,
        descriptor,
        actual_nodes,
        actual_logical_bytes,
    )
}

pub(super) fn native_nonrecursive_topology(
    request_digest: ObjectDigest,
    receipt: &SignedStorageZfsHoldReceiptV1,
    descriptor: &SourceRootObservationV1,
    actual_nodes: u64,
    actual_logical_bytes: u64,
) -> Result<RecursiveTopologyProofV1, StorageNativeAcquireErrorV2> {
    require_counts(actual_nodes, actual_logical_bytes)?;
    let authority_id = receipt.signer().authority().0;
    let cut_sequence = receipt.receipt().head().journal().0;
    let receipt_digest = receipt.digest();
    let descriptor_digest = source_root_descriptor_commitment_v1(descriptor);
    let content_digest = receipt.receipt().snapshot().read_only_content_digest();
    let topology_digest = topology_commitment(
        authority_id,
        cut_sequence,
        request_digest,
        receipt_digest,
        descriptor_digest,
        content_digest,
        actual_nodes,
        actual_logical_bytes,
    );

    RecursiveTopologyProofV1::new(
        authority_id,
        cut_sequence,
        topology_digest,
        actual_nodes,
        actual_logical_bytes,
        1,
        0,
    )
    .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)
}

/// Checks canonical native topology commitments without authenticating Storage.
///
/// This permits a retained original lease to crosslink a Provider's later fence
/// claims. It measures nothing, verifies no Storage signature and grants no
/// descriptor, currentness or retirement authority.
///
/// # Errors
///
/// Rejects sentinel commitments, unsupported counts/mount shape or a digest
/// that does not bind the exact supplied request/receipt/root/content tuple.
pub fn validate_storage_native_topology_commitments_v1(
    topology: &RecursiveTopologyProofV1,
    request_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
    descriptor_digest: ObjectDigest,
    content_digest: ObjectDigest,
) -> Result<(), StorageNativeAcquireErrorV2> {
    require_profile_shape(topology)?;
    if [
        request_digest,
        receipt_digest,
        descriptor_digest,
        content_digest,
    ]
    .iter()
    .any(|digest| digest.as_bytes() == &[0; 32])
        || topology.topology_digest()
            != topology_commitment(
                topology.authority_id(),
                topology.generation(),
                request_digest,
                receipt_digest,
                descriptor_digest,
                content_digest,
                topology.entry_count(),
                topology.byte_count(),
            )
    {
        return Err(StorageNativeAcquireErrorV2::Noncanonical);
    }
    Ok(())
}

fn topology_commitment(
    authority_id: [u8; 16],
    cut_sequence: u64,
    request_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
    descriptor_digest: ObjectDigest,
    content_digest: ObjectDigest,
    actual_nodes: u64,
    actual_logical_bytes: u64,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DIGEST_DOMAIN)
            .chain_update(authority_id)
            .chain_update(cut_sequence.to_be_bytes())
            .chain_update(request_digest.as_bytes())
            .chain_update(receipt_digest.as_bytes())
            .chain_update(descriptor_digest.as_bytes())
            .chain_update(content_digest.as_bytes())
            .chain_update(actual_nodes.to_be_bytes())
            .chain_update(actual_logical_bytes.to_be_bytes())
            .chain_update(1_u32.to_be_bytes())
            .chain_update(0_u32.to_be_bytes())
            .finalize()
            .into(),
    )
}

pub(super) fn require_profile_shape(
    topology: &RecursiveTopologyProofV1,
) -> Result<(), StorageNativeAcquireErrorV2> {
    require_counts(topology.entry_count(), topology.byte_count())?;
    if topology.maximum_depth() != 1 || topology.observed_submounts() != 0 {
        return Err(StorageNativeAcquireErrorV2::Noncanonical);
    }
    Ok(())
}

fn require_counts(nodes: u64, bytes: u64) -> Result<(), StorageNativeAcquireErrorV2> {
    if nodes == 0
        || nodes > MAXIMUM_STORAGE_NATIVE_TOPOLOGY_NODES_V1
        || bytes > MAXIMUM_STORAGE_NATIVE_TOPOLOGY_LOGICAL_BYTES_V1
        || (nodes == 1 && bytes != 0)
    {
        return Err(StorageNativeAcquireErrorV2::Noncanonical);
    }
    Ok(())
}
