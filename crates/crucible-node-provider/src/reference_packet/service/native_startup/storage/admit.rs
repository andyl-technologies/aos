//! Counts the five retained once-Admit normalization trees and fixed MAC owners.
//!
//! Source/registration canonical extents come from the SAME original input and
//! closed Binding14 additions. The producer does not build a future context,
//! key, executable reference, assigned Envelope or native permission object.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};

pub(super) struct AdmitStorage {
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
}

fn object(p: &mut Projection, keys: &[&str]) -> Result<(), ProviderError> {
    p.add_object()?;
    for key in keys {
        p.add_field(key)?;
    }
    Ok(())
}

fn digest(p: &mut Projection) -> Result<(), ProviderError> {
    // Bytes serializes these exact32-octet digests to43 unpadded URL-safe bytes.
    p.add_unescaped_ascii_extent(43)
}

fn context(maximum: usize) -> Result<OriginalSerializationStorageData, ProviderError> {
    use super::super::super::ack_emitter::*;
    let mut p = Projection::new(maximum)?;
    object(
        &mut p,
        &[
            "schema",
            "algorithm",
            "source_birth",
            "kernel_binding",
            "policy_binding",
            "host_registration",
            "native_registration",
            "hello_request",
            "hello_response",
            "assigned_admit",
        ],
    )?;
    p.add_string("source-owned.packet-canonical-ack-admission-context/5")?;
    p.add_string(PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM)?;
    for _ in 0..8 {
        digest(&mut p)?;
    }
    p.finish(maximum)
}

fn proof(maximum: usize) -> Result<OriginalSerializationStorageData, ProviderError> {
    use super::super::super::ack_emitter::*;
    let mut p = Projection::new(maximum)?;
    object(&mut p, &["schema", "algorithm", "context_digest", "mac"])?;
    p.add_string(PACKET_CANONICAL_ACK_ADMISSION_FEATURE)?;
    p.add_string(PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM)?;
    digest(&mut p)?;
    digest(&mut p)?;
    p.finish(maximum)
}

fn normalized_outer_extents(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut association = Projection::new(maximum)?;
    object(
        &mut association,
        &[
            "schema",
            "birth_id",
            "private_launch",
            "host_executable",
            "source_binding",
            "expected_host_registration",
        ],
    )?;
    association.add_string("source-owned.packet-canonical-ack-birth-association/5")?;
    digest(&mut association)?;
    association.add_string(input.private_launch.as_str())?;
    association.add_value(&input.launch.controller_executable)?;
    association.add_value(&())?;
    association.add_value(&())?;

    let mut kernel = Projection::new(maximum)?;
    object(&mut kernel, &["schema", "controller", "native"])?;
    kernel.add_string("source-owned.packet-canonical-ack-kernel-binding/5")?;
    for native in [false, true] {
        object(&mut kernel, &["pid", "uid", "executable"])?;
        if native {
            kernel.add_unescaped_ascii_extent(20)?;
            kernel.add_unescaped_ascii_extent(20)?;
            let mut executables = input
                .launch
                .selection
                .provider
                .implementation
                .artifacts
                .iter()
                .filter(|artifact| artifact.role.as_str() == "executable");
            let executable = executables.next().ok_or_else(refused)?;
            if executables.next().is_some() {
                return Err(refused());
            }
            kernel.add_value(&executable.content)?;
        } else {
            kernel.add_value(&input.launch.controller_pid)?;
            kernel.add_value(&input.launch.controller_uid)?;
            kernel.add_value(&input.launch.controller_executable)?;
        }
    }
    let mut policy = Projection::new(maximum)?;
    object(&mut policy, &["schema", "source_binding", "negotiated"])?;
    policy.add_string("source-owned.packet-canonical-ack-policy-binding/5")?;
    policy.add_value(&())?;
    // A whole actual registration object dominates its negotiated limits,
    // feature/definition/key children without decoding a replacement DTO.
    policy.add_value(&())?;
    Ok([
        association.finish(maximum)?.maximum_encoded_bytes,
        kernel.finish(maximum)?.maximum_encoded_bytes,
        policy.finish(maximum)?.maximum_encoded_bytes,
    ])
}

pub(super) fn project(
    input: &PacketNativeBirthStartupInputs<'_>,
    private: &private_bootstrap::PrivateBootstrapStorage,
    maximum: usize,
) -> Result<AdmitStorage, ProviderError> {
    let source = private.maximum_source_bytes;
    let host = input.host_registration.len();
    let outer = normalized_outer_extents(input, maximum)?;
    let normalized_extents = [
        sum(&[source, host, outer[0]], maximum)?,
        outer[1],
        sum(&[source, host, outer[2]], maximum)?,
        // Only connection_id differs between these exact registration rosters.
        // The genuine native Id has at most128 unescaped ASCII bytes plusquotes.
        sum(&[host, 128 + 2], maximum)?,
        initial::admit_projection(input.launch, maximum)?.maximum_encoded_bytes,
    ];
    let mut retained = 0usize;
    let mut transient = 0usize;
    for extent in normalized_extents {
        let tree = original_json_value_storage_extent_data(extent)?;
        // Each normalized Value survives through the same once-Admit owner.
        // The later canonical bank is independently retained; canonical work
        // finishes before the next normalizer and is conservatively MAXed.
        retained = sum(&[retained, tree.value_dom_requested_bytes], maximum)?;
        transient = transient.max(tree.canonical_pass_requested_bytes()?);
    }
    let context = context(maximum)?;
    let proof = proof(maximum)?;
    let context_children = sum(
        &[
            "source-owned.packet-canonical-ack-admission-context/5".len(),
            super::super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.len(),
            8 * 32,
        ],
        maximum,
    )?;
    let proof_children = sum(
        &[
            super::super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.len(),
            super::super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.len(),
            2 * 32,
        ],
        maximum,
    )?;
    // The source binding and host registration normalized bank payloads are
    // already summed by the parent constructor's exact five-bank roster.
    retained = sum(
        &[
            retained,
            context_children,
            proof_children,
            initial::admit_projection(input.launch, maximum)?.requested_total()?,
        ],
        maximum,
    )?;
    transient = transient.max(sum(
        &[
            context.requested_total()?,
            proof.requested_total()?,
            context_children,
            proof_children,
            32,
        ],
        maximum,
    )?);
    let scratch = sum(
        &[
            size_of::<AdmitStorage>(),
            size_of::<[usize; 5]>(),
            size_of::<[usize; 3]>(),
            size_of::<Projection>(),
            2 * size_of::<OriginalSerializationStorageData>(),
            size_of::<blake3::Hasher>(),
            size_of::<[u8; 32]>(),
        ],
        maximum,
    )?;
    Ok(AdmitStorage {
        retained,
        transient,
        scratch,
    })
}
