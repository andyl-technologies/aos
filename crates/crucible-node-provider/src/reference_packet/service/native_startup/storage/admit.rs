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

fn normalized_outer_storage(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<[OriginalSerializationStorageData; 3], ProviderError> {
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
        association.finish(maximum)?,
        kernel.finish(maximum)?,
        policy.finish(maximum)?,
    ])
}

pub(super) fn project(
    input: &PacketNativeBirthStartupInputs<'_>,
    private: &private_bootstrap::PrivateBootstrapStorage,
    maximum: usize,
) -> Result<AdmitStorage, ProviderError> {
    let source = private.source_requested_bytes;
    let host = decode_value(input.host_registration, maximum)?;
    let host_backing = decoded::quote(
        input.host_registration,
        size_of::<serde_json::Value>(),
        size_of::<serde_json::Value>(),
        maximum,
    )?
    .value_backing;
    let source_backing = private.source_value_backing_bytes;
    let [association, kernel, policy] = normalized_outer_storage(input, maximum)?;
    // Native registration changes only the connection ID. Keep the complete
    // original host tree and add the actual native Id's full128-byte grammar.
    // Its old ID is deliberately not refunded from this conservative bound.
    let mut native_id = Projection::new(maximum)?;
    native_id.add_unescaped_ascii_extent(128)?;
    let native_id = native_id.finish(maximum)?;
    let assigned = initial::admit_projection(input.launch, maximum)?;
    let assigned_admit = assigned.requested_total()?;
    let normalized_requested = [
        sum(&[source, host, association.requested_total()?], maximum)?,
        kernel.requested_total()?,
        sum(&[source, host, policy.requested_total()?], maximum)?,
        sum(&[host, native_id.requested_total()?], maximum)?,
        assigned_admit,
    ];
    // Every normalization keeps its own Value and canonical Vec. Source
    // and host insertions are independent copies, never aliases. Canonical
    // child banks are conservatively summed even within one outer bank.
    let source_bank = private
        .maximum_source_bytes
        .checked_mul(4)
        .and_then(|n| n.checked_add(256))
        .ok_or_else(refused)?;
    let host_bank = input
        .host_registration
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(256))
        .ok_or_else(refused)?;
    let normalized_backing = [
        sum(
            &[
                source_backing,
                host_backing,
                source_bank,
                host_bank,
                association.retained_value_backing_bytes,
                association.canonical_output_requested_bytes,
            ],
            maximum,
        )?,
        sum(
            &[
                kernel.retained_value_backing_bytes,
                kernel.canonical_output_requested_bytes,
            ],
            maximum,
        )?,
        sum(
            &[
                source_backing,
                host_backing,
                source_bank,
                host_bank,
                policy.retained_value_backing_bytes,
                policy.canonical_output_requested_bytes,
            ],
            maximum,
        )?,
        sum(
            &[
                host_backing,
                host_bank,
                native_id.retained_value_backing_bytes,
                native_id.canonical_output_requested_bytes,
            ],
            maximum,
        )?,
        sum(
            &[
                assigned.retained_value_backing_bytes,
                assigned.canonical_output_requested_bytes,
            ],
            maximum,
        )?,
    ];
    let mut retained = sum(&normalized_backing, maximum)?;
    // All five Values/banks above are present; only the temporary complete
    // writer/validation phase is sequential. Earlier expected-body and original
    // owners are added below and remain live throughout this max expression.
    let mut transient = normalized_requested.into_iter().max().ok_or_else(refused)?;
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
            // The lifecycle's original remains separate. owner.original and
            // expected_body/comparison have independent backing beside all five
            // normalizations. A full original Envelope safely overcounts each.
            assigned.retained_value_backing_bytes,
            assigned.retained_value_backing_bytes,
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
    // verify_admit decodes a SECOND launch from owner.launch_body at its
    // entry. That independent typed owner survives through owner.original,
    // expected_body and all five normalizations; it is not the service's moved
    // launch already counted by the parent permanent row. The decode returns
    // before normalization, but its resulting backing stays live throughout.
    let launch_local = decoded::quote(
        input.encoded_launch,
        size_of::<PacketNative5SourceLaunch>(),
        native_element_slot(),
        maximum,
    )?;
    let launch_work = launch_validation_work(input, maximum)?;
    transient = sum(
        &[launch_local.typed_backing, transient.max(launch_work)],
        maximum,
    )?;
    let scratch = sum(
        &[
            size_of::<AdmitStorage>(),
            size_of::<decoded::DecodedStorage>(),
            size_of::<[usize; 3]>(),
            decoded::counter_scratch_data(),
            launch_validation_counter_scratch_data(),
            size_of::<[usize; 5]>(),
            size_of::<[usize; 3]>(),
            // The three outer projections coexist before finishing; their
            // returned data can coexist with the native-ID projection/result.
            3 * size_of::<Projection>(),
            4 * size_of::<OriginalSerializationStorageData>(),
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
