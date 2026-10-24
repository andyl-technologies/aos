//! Seals positive original semantic cleanup independently of kernel reclamation.

use std::io::{self, Write};

use crucible_node_transport::{ProviderError, reference_device::DeviceStatus};

use crate::node_contract::{ActivationRecord, OwnerIdentity};

use super::CnpPeerCustody;

/// Seals the exact owning peer's positively resolved native semantic originals.
///
/// This private-constructor result is issued only after retained runtime audit
/// and complete original-journal export. It does not discharge durable custody
/// or permit another world to reuse operation or owner identities.
pub struct CnpSemanticRetirement<'a> {
    peer: &'a CnpPeerCustody,
}

impl CnpSemanticRetirement<'_> {
    /// Checks whether this seal belongs to the same retained original peer.
    pub fn belongs_to(&self, peer: &CnpPeerCustody) -> bool {
        std::ptr::eq(self.peer, peer)
    }
}

impl CnpPeerCustody {
    /// Exports resolved private originals and returns their opaque semantic seal.
    ///
    /// The output contains private bootstrap authority and complete operational
    /// journals. It belongs in a private durable custody sink, never public CAS
    /// or a conformance report. Native process reaping alone cannot issue this
    /// seal. The original capsule remains owned by the caller on every result.
    ///
    /// # Errors
    /// Refuses unresolved, foreign, unprepared or qualification-probe custody,
    /// incomplete native acknowledgement or cleanup, live process resources,
    /// changed retained metadata, and serialization or output errors.
    pub fn write_resolved_originals(
        &self,
        activation: &ActivationRecord,
        owner: &OwnerIdentity,
        output: &mut impl Write,
    ) -> Result<CnpSemanticRetirement<'_>, ProviderError> {
        let runtime = self.runtime.as_ref().ok_or(ProviderError::Correlation(
            "original runtime custody unavailable for semantic resolution",
        ))?;
        runtime.validate_retained(self.companion)?;
        if self.reaped.is_none() || !super::group_empty(self.child.id())? {
            return Err(ProviderError::Correlation(
                "original peer kernel custody remains live",
            ));
        }
        if self.conflict_probes.is_some() || self.lifecycle_probes.is_some() {
            return Err(ProviderError::Correlation(
                "qualification probe originals require their owning resolver",
            ));
        }
        if !runtime.semantic_release
            || !matches!(
                runtime.status,
                DeviceStatus::Quarantined | DeviceStatus::Reaped
            )
            || runtime.active.as_ref() != Some(activation)
            || runtime.input.is_some()
            || runtime.pending.is_some()
            || runtime.prepared.as_ref().is_none_or(|prepared| {
                !prepared.registry_complete || prepared.record != *activation
            })
            || runtime.binding.authority.incarnation_id != owner.incarnation
            || runtime.binding.authority.owner_generation != owner.generation
            || runtime.owner_binding.owner.id != owner.owner
            || runtime.windows.values().any(|window| {
                !window.closed
                    || !window.consumed
                    || window.receipt.is_none()
                    || window.result.is_none()
                    || window.observations.is_none()
                    || window.original.activation().record() != activation
            })
        {
            return Err(ProviderError::Correlation(
                "original semantic obligations remain unresolved or foreign",
            ));
        }
        let controller = self.controller.as_ref().ok_or(ProviderError::Correlation(
            "original controller unavailable for semantic resolution",
        ))?;
        let (binding, owner_binding) = controller.binding()?;
        if binding != runtime.binding || owner_binding != runtime.owner_binding {
            return Err(ProviderError::Correlation(
                "original controller/runtime scope differs",
            ));
        }
        let windows = runtime
            .windows
            .values()
            .map(|window| {
                (
                    window.original.token().operation(),
                    window.original.token().route(),
                    window.original.request(),
                    window.original.inputs().map(|input| {
                        (
                            input.node(),
                            input.stage_operation(),
                            input.batch(),
                            input.owners(),
                            input.cutoff(),
                            input.inventory(),
                            input.deliveries(),
                            input.payloads(),
                        )
                    }),
                    &window.grant,
                    &window.receipt,
                    &window.result,
                    &window.observations,
                )
            })
            .collect::<Vec<_>>();
        let input_commits = runtime
            .input_commit_history
            .values()
            .map(|attempt| {
                (
                    attempt.original.node(),
                    attempt.original.stage_operation(),
                    attempt.original.batch(),
                    attempt.original.inventory(),
                    attempt.original.cutoff(),
                    &attempt.intent,
                    &attempt.request,
                    &attempt.request_hash,
                    &attempt.inventory_bytes,
                    &attempt.receipt,
                    &attempt.record,
                )
            })
            .collect::<Vec<_>>();
        let boundary = runtime.boundary_evidence.values().collect::<Vec<_>>();
        let dependencies = runtime.boundary_dependencies.iter().collect::<Vec<_>>();
        let prepared = runtime
            .prepared
            .as_ref()
            .map(|prepared| (&prepared.owner, &prepared.ready));
        let mut bounded = BoundedOriginalWriter { output, bytes: 0 };
        bounded.write_all(b"{\"runtime\":")?;
        serde_json::to_writer(
            &mut bounded,
            &(
                (
                    activation.generation,
                    &activation.activation_id,
                    &activation.world_binding_hash,
                    &activation.owners,
                    activation.boundary,
                ),
                owner,
                &runtime.binding,
                &runtime.owner_binding,
                &runtime.gate,
                prepared,
                windows,
                input_commits,
                runtime.next_input_sequence,
                runtime.checksum,
                boundary,
                dependencies,
            ),
        )
        .map_err(crucible_node_format::ContractError::from)?;
        bounded.write_all(b",\"controller\":")?;
        controller.write_owned_terminal_originals(&mut bounded)?;
        bounded.write_all(b"}")?;
        Ok(CnpSemanticRetirement { peer: self })
    }
}

struct BoundedOriginalWriter<'a, W> {
    output: &'a mut W,
    bytes: usize,
}

impl<W: Write> Write for BoundedOriginalWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .checked_add(bytes.len())
            .is_none_or(|total| total > 64 * 1024 * 1024)
        {
            return Err(io::Error::other("private resolved original archive credit"));
        }
        let written = self.output.write(bytes)?;
        self.bytes += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
