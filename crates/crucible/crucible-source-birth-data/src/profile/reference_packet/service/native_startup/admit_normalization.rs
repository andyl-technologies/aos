//! Shares the actual five-bank once-Admit normalization arithmetic.
//!
//! This owns only numeric reports over borrowed original fields and banks.
//! It cannot issue an admission proof, hash a secret launch, construct a native
//! owner or authenticate caller-supplied source/private operands.

use crate::decoded_occurrences as decoded;
use crate::errors::ProviderError;
use crate::profile::reference_packet::service::PacketNative5LaunchValidationFields;
use crate::profile::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};
use crate::selected_decode::selected_value_decode_storage_data as decode_value;
use std::mem::size_of;

/// Reports the original independently retained and transient normalization owners.
pub struct AdmitStorage {
    /// Counts all five normalized banks and independent context/proof children.
    pub retained: usize,
    /// Counts the full original simultaneous work phase.
    pub transient: usize,
    /// Names the independently supplied defining fixed header row.
    pub scratch: usize,
}

/// Retains the computed phase across the original later launch-decode calls.
///
/// No bank or authority is retained: the caller keeps all actual inputs alive.
pub struct AdmitNormalization {
    retained: usize,
    transient: usize,
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
    use super::super::ack_emitter::*;
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
    use super::super::ack_emitter::*;
    let mut p = Projection::new(maximum)?;
    object(&mut p, &["schema", "algorithm", "context_digest", "mac"])?;
    p.add_string(PACKET_CANONICAL_ACK_ADMISSION_FEATURE)?;
    p.add_string(PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM)?;
    digest(&mut p)?;
    digest(&mut p)?;
    p.finish(maximum)
}

fn normalized_outer_storage(
    launch: &PacketNative5LaunchValidationFields<'_>,
    private_launch: &crucible_node_format::Id,
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
    association.add_string(private_launch.as_str())?;
    association.add_value(launch.controller_executable)?;
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
            let mut executables = launch
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
            kernel.add_value(&launch.controller_pid)?;
            kernel.add_value(&launch.controller_uid)?;
            kernel.add_value(launch.controller_executable)?;
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

impl AdmitNormalization {
    /// Counts the original bank normalizations before independent launch decoding.
    ///
    /// Source quantities must come from the genuine preceding private producer;
    /// none of these numbers authenticates a Source or substitutes for its bank.
    ///
    /// # Errors
    /// Preserves raw registration, selected shape, overflow and maximum refusals.
    pub fn new(
        launch: &PacketNative5LaunchValidationFields<'_>,
        private_launch: &crucible_node_format::Id,
        registration: &[u8],
        source: usize,
        source_backing: usize,
        maximum_source_bytes: usize,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        let host = decode_value(registration, maximum)?;
        let host_backing = decoded::quote(
            registration,
            size_of::<serde_json::Value>(),
            size_of::<serde_json::Value>(),
            maximum,
        )?
        .value_backing;

        let [association, kernel, policy] =
            normalized_outer_storage(launch, private_launch, maximum)?;
        // Native registration changes only the connection ID. Keep the complete
        // original host tree and add the actual native Id's full128-byte grammar.
        // Its old ID is deliberately not refunded from this conservative bound.
        let mut native_id = Projection::new(maximum)?;
        native_id.add_unescaped_ascii_extent(128)?;
        let native_id = native_id.finish(maximum)?;
        let assigned = super::initial_shapes::admit_projection(launch, maximum)?;
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
        let source_bank = maximum_source_bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(256))
            .ok_or_else(refused)?;
        let host_bank = registration
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
                super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.len(),
                8 * 32,
            ],
            maximum,
        )?;
        let proof_children = sum(
            &[
                super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.len(),
                super::super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.len(),
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
        Ok(Self {
            retained,
            transient,
        })
    }

    /// Adds the original independent typed-launch carry after its real quote.
    ///
    /// # Errors
    /// Refuses the same checked simultaneous sum or maximum as the old caller.
    pub fn with_launch(
        mut self,
        typed_backing: usize,
        launch_work: usize,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        self.transient = sum(&[typed_backing, self.transient.max(launch_work)], maximum)?;
        Ok(self)
    }

    /// Attaches the defining fixed header row after the original final queries.
    ///
    /// The row is DATA. Its caller must independently admit every actual owner.
    pub fn finish(self, scratch: usize) -> AdmitStorage {
        AdmitStorage {
            retained: self.retained,
            transient: self.transient,
            scratch,
        }
    }
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(*bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}
