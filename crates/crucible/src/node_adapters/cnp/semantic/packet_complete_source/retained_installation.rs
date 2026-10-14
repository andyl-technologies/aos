//! Observes actual retained complete installation, model and coordinator owners.
//!
//! This component deliberately excludes the enclosing Source/node allocation,
//! private birth/association/banks, lineage, executable worker and external
//! native/Host/receiver owners. The whole owning-row composer must add them;
//! this exact component is not a successful Capture geometry or permission.

use super::*;
use crucible_node_provider::retained_metadata::{
    RetainedCompleteSourceDefinition, RetainedCompleteSourceMetadata,
};
use std::mem::size_of;

impl PacketCompleteSemanticSource {
    /// Counts actual installation, model, coordinator and saved-world storage.
    ///
    /// Borrows original typed fields, including spare capacities. No coordinator
    /// JSON is decoded or cloned. The saved activation is a separate retained
    /// copy and is charged independently of the coordinator template. The
    /// coordinator's actual Box payload and Core-only facet Vec are explicit.
    /// Repeated typed shared views are conservatively charged without dedup.
    ///
    /// This component excludes enclosing Source/node headers, private bootstrap,
    /// protocol/semantic capture banks, association DOM/leases, static/lineage,
    /// executable worker and external Host/receiver/native custody. Complete
    /// owning admission must include those actual owners independently.
    ///
    /// # Errors
    /// Refuses foreign creator/thread, ordinary coordinator edition, checked
    /// layout overflow, unsupported alignment or a combined component overrun.
    pub fn original_complete_installation_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.ensure_origin()?;
        let (definition, coordinator, activation) = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                let (definition, coordinator, activation) =
                    source.complete_retained_declaration_parts()?;
                (
                    RetainedCompleteSourceDefinition::Program(definition),
                    coordinator,
                    activation,
                )
            }
            CompletePacketOriginal::Reactive(source) => {
                let (definition, coordinator, activation) =
                    source.complete_retained_declaration_parts()?;
                (
                    RetainedCompleteSourceDefinition::Connected(definition),
                    coordinator,
                    activation,
                )
            }
        };
        let installation = self.installation();
        let view = RetainedCompleteSourceMetadata {
            provider: &installation.provider,
            manifest: &installation.profile,
            descriptor: &installation.descriptor,
            binding: &installation.binding,
            capabilities: &installation.capabilities,
            facet: &installation.exact_facet,
            guarantees: &installation.guarantees,
            owner: &installation.owner,
            realize: &installation.realize,
            admission: &installation.admission,
            transaction: &installation.transaction,
            gate: &installation.gate,
            admission_receipt: &installation.admission_receipt,
            world: &installation.world_binding_hash,
            receipt_schema: &installation.receipt_schema,
            operating_contract: &installation.binding.compatibility.operating_contract,
            coordinator,
            definition,
        };
        let facts = view.observe_retained_metadata().map_err(unknown)?;
        let typed = Self::complete_retained_metadata_storage_data(&facts, maximum)?;
        for facet in &installation.facets {
            match facet {
                FacetKind::ExactExecution
                | FacetKind::QuantizedExecution
                | FacetKind::PhysicalPause
                | FacetKind::Preservation
                | FacetKind::Replay
                | FacetKind::FaultInjection
                | FacetKind::Coverage
                | FacetKind::Introspection
                | FacetKind::Debugging
                | FacetKind::TerminalAssertions => {}
            }
        }
        let facets = installation
            .facets
            .capacity()
            .checked_mul(size_of::<FacetKind>())
            .ok_or_else(|| refused("complete retained facets capacity overflow"))?;
        sum(
            [
                typed,
                facets,
                size_of::<PacketNative5CoordinatorInstallation>(),
                activation_storage(activation, maximum)?,
            ],
            maximum,
        )
    }
}

fn activation_storage(
    value: &SavedRuntimeActivation,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    let owners = value
        .owners
        .capacity()
        .checked_mul(size_of::<OwnerIdentity>())
        .ok_or_else(|| refused("retained activation owner capacity overflow"))?;
    let mut retained = sum(
        [
            owners,
            value.activation_id.allocated_capacity(),
            value.world_binding_hash.algorithm.capacity(),
            value.world_binding_hash.domain.capacity(),
            value.world_binding_hash.digest.capacity(),
        ],
        maximum,
    )?;
    for owner in &value.owners {
        retained = sum(
            [
                retained,
                owner.owner.allocated_capacity(),
                owner.incarnation.allocated_capacity(),
            ],
            maximum,
        )?;
    }
    Ok(retained)
}

fn sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, OperationFailure> {
    terms.into_iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| refused("complete installation requested storage exhausted"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_activation_counts_actual_spare_owner_capacity_before_layout_admission() {
        let mut activation = SavedRuntimeActivation {
            generation: U64::new(1),
            activation_id: Id::new("retained-world").unwrap(),
            world_binding_hash: canonical::hash("source-owned.retained-layout/1", b"world")
                .unwrap(),
            owners: Vec::with_capacity(8),
            boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        };
        activation.owners.push(OwnerIdentity {
            owner: Id::new("retained-owner").unwrap(),
            incarnation: Id::new("retained-incarnation").unwrap(),
            generation: U64::new(1),
        });
        let original_capacity = activation.owners.capacity();
        let original = activation_storage(&activation, usize::MAX).unwrap();

        activation.owners.reserve_exact(32);
        let current = activation_storage(&activation, usize::MAX).unwrap();
        let extra = (activation.owners.capacity() - original_capacity) * size_of::<OwnerIdentity>();
        assert_eq!(current - original, extra);
        assert_eq!(activation_storage(&activation, current).unwrap(), current);
        assert!(activation_storage(&activation, current - 1).is_err());
    }
}
