//! Keeps the native interpreter choice private while preserving legacy receipts.
//!
//! The common projection is used only for shared administrative plumbing.
//! Connected proofs retain their complete distinct input and phased inventory;
//! the projection never authenticates connected custody or future ingress EOF.

use crucible_node_format::*;

use super::super::{
    PacketEvent, PacketGrant, PacketInventory, PacketProgram,
    connected::{PacketConnectedGrant, PacketConnectedNativeRecord, PacketConnectedProgram},
};
use crate::{ProviderError, envelope::Envelope};

pub(super) enum NativeProgram {
    OutputOnly(PacketProgram),
    Connected(PacketConnectedProgram),
    RestorationInProgress,
}

impl NativeProgram {
    /// Reads only the actual stopped gate; no inventory owner is projected.
    pub(super) fn original_native_birth_gate_closed_data(&self) -> Result<bool, ProviderError> {
        match self {
            Self::OutputOnly(program) => Ok(program.gate_closed && !program.failed),
            Self::Connected(program) => program.original_native_birth_gate_closed_data(),
            Self::RestorationInProgress => {
                Err(ProviderError::Conflict("packet restored model incomplete"))
            }
        }
    }

    pub(super) fn inventory_hash(&self) -> Result<HashRef, ProviderError> {
        Ok(match self {
            Self::OutputOnly(program) => {
                canonical::json_hash("source-owned.packet-inventory.v1", &program.inventory())?
            }
            Self::Connected(program) => canonical::json_hash(
                "source-owned.packet-connected-inventory/4",
                &program.inventory()?,
            )?,
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        })
    }

    pub(super) fn attention(&self, grant: &PacketGrant) -> Result<Position, ProviderError> {
        if matches!(self, Self::RestorationInProgress) {
            return Err(ProviderError::Conflict("packet restored model incomplete"));
        }
        if let Self::Connected(program) = self {
            let actual = program.preview(&grant.operation, grant.start, grant.limit)?;
            return Ok(actual
                .inventory
                .reactions
                .iter()
                .map(|reaction| {
                    if actual
                        .inventory
                        .delivered_inputs
                        .iter()
                        .any(|delivery| delivery.reaction == *reaction)
                    {
                        reaction.evaluation
                    } else {
                        reaction.parent
                    }
                })
                .chain(
                    actual
                        .inventory
                        .publications
                        .iter()
                        .map(|publication| publication.publication),
                )
                .min()
                .unwrap_or(program.committed_input()?.0.cut.cutoff));
        }
        Ok(grant
            .inventory
            .pending
            .iter()
            .filter(|event| event.payload.is_some())
            .map(|event| event.completion)
            .min()
            .unwrap_or(grant.inventory.reached))
    }

    pub(super) fn is_connected(&self) -> bool {
        matches!(self, Self::Connected(_))
    }

    pub(super) fn connected_record(
        &self,
        original: &Envelope,
        projected: &PacketInventory,
        grant: Option<&PacketGrant>,
    ) -> Result<Option<PacketConnectedNativeRecord>, ProviderError> {
        if matches!(self, Self::RestorationInProgress) {
            return Err(ProviderError::Conflict("packet restored model incomplete"));
        }
        let Self::Connected(program) = self else {
            return Ok(None);
        };
        let actual_grant = grant
            .map(|grant| program.preview(&grant.operation, grant.start, grant.limit))
            .transpose()?;
        if let (Some(projected_grant), Some(actual)) = (grant, &actual_grant)
            && Self::project_grant(actual, program.definition().output.is_some())?
                != *projected_grant
        {
            return Err(ProviderError::Correlation(
                "packet complete phased grant projection",
            ));
        }
        let mut inventory = actual_grant
            .as_ref()
            .map_or_else(|| program.inventory(), |grant| Ok(grant.inventory.clone()))?;
        // World activation reserves the complete future open-gate proof before
        // opening the actual gate. No other inventory field is reconstructed.
        inventory.gate_closed = projected.gate_closed;
        let mut expected = Self::project_inventory(program)?;
        if let Some(grant) = grant {
            expected = grant.inventory.clone();
        }
        expected.gate_closed = projected.gate_closed;
        if expected != *projected {
            return Err(ProviderError::Correlation(
                "packet complete native inventory projection",
            ));
        }
        Ok(Some(PacketConnectedNativeRecord {
            schema: "source-owned.packet-native/4".into(),
            native_pid: U64::new(u64::from(std::process::id())),
            original: original.clone(),
            inventory,
            grant: actual_grant,
        }))
    }

    pub(super) fn configuration(&self) -> Result<serde_json::Value, ProviderError> {
        Ok(match self {
            Self::OutputOnly(program) => serde_json::to_value(program.definition()),
            Self::Connected(program) => serde_json::to_value(program.definition()),
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
        .map_err(ContractError::from)?)
    }

    pub(super) fn inventory(&self) -> Result<PacketInventory, ProviderError> {
        match self {
            Self::OutputOnly(program) => Ok(program.inventory()),
            Self::Connected(program) => Self::project_inventory(program),
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
    }

    fn project_inventory(
        program: &PacketConnectedProgram,
    ) -> Result<PacketInventory, ProviderError> {
        let inventory = program.inventory()?;
        let mut pending =
            Vec::with_capacity(inventory.reactions.len() + inventory.publications.len());
        for reaction in &inventory.reactions {
            let emits = program.definition().output.is_some();
            pending.push(PacketEvent {
                id: Id::new(format!("packet-reaction-{}", reaction.input_event.as_str()))?,
                evaluation: reaction.evaluation,
                completion: if emits {
                    reaction.evaluation.reaction_publication(U64::new(16))?
                } else {
                    reaction.evaluation
                },
                payload: emits.then(|| reaction.payload.clone()),
            });
        }
        for publication in &inventory.publications {
            pending.push(PacketEvent {
                id: publication.event.clone(),
                evaluation: publication.reaction.evaluation,
                completion: publication.publication,
                payload: Some(publication.reaction.payload.clone()),
            });
        }
        pending.sort_by(|a, b| (a.completion, &a.id).cmp(&(b.completion, &b.id)));
        Ok(PacketInventory {
            reached: inventory.reached,
            gate_closed: inventory.gate_closed,
            pending,
            retained_outputs: inventory
                .retained_outputs
                .into_iter()
                .map(|output| output.output)
                .collect(),
            private_mutations: inventory.reactions_completed,
            packet_effects: inventory.packet_effects,
        })
    }

    fn project_grant(
        grant: &PacketConnectedGrant,
        emits: bool,
    ) -> Result<PacketGrant, ProviderError> {
        let mut pending = Vec::with_capacity(
            grant.inventory.reactions.len() + grant.inventory.publications.len(),
        );
        for reaction in &grant.inventory.reactions {
            pending.push(PacketEvent {
                id: Id::new(format!("packet-reaction-{}", reaction.input_event.as_str()))?,
                evaluation: reaction.evaluation,
                completion: if emits {
                    reaction.evaluation.reaction_publication(U64::new(16))?
                } else {
                    reaction.evaluation
                },
                payload: emits.then(|| reaction.payload.clone()),
            });
        }
        for publication in &grant.inventory.publications {
            pending.push(PacketEvent {
                id: publication.event.clone(),
                evaluation: publication.reaction.evaluation,
                completion: publication.publication,
                payload: Some(publication.reaction.payload.clone()),
            });
        }
        pending.sort_by(|a, b| (a.completion, &a.id).cmp(&(b.completion, &b.id)));
        Ok(PacketGrant {
            operation: grant.operation.clone(),
            start: grant.start,
            limit: grant.limit,
            inventory: PacketInventory {
                reached: grant.inventory.reached,
                gate_closed: grant.inventory.gate_closed,
                pending,
                retained_outputs: grant
                    .inventory
                    .retained_outputs
                    .iter()
                    .map(|output| output.output.clone())
                    .collect(),
                private_mutations: grant.inventory.reactions_completed,
                packet_effects: grant.inventory.packet_effects,
            },
            newborn: grant
                .newborn
                .iter()
                .map(|output| output.output.clone())
                .collect(),
            complete: grant.complete,
        })
    }

    pub(super) fn open_gate(&mut self) -> Result<(), ProviderError> {
        match self {
            Self::OutputOnly(program) => program.open_gate(),
            Self::Connected(program) => program.open_gate(),
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
    }

    pub(super) fn preview(
        &self,
        operation: &Id,
        start: Position,
        limit: Position,
    ) -> Result<PacketGrant, ProviderError> {
        match self {
            Self::OutputOnly(program) => program.preview(operation, start, limit),
            Self::Connected(program) => Self::project_grant(
                &program.preview(operation, start, limit)?,
                program.definition().output.is_some(),
            ),
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
    }

    pub(super) fn execute(
        &mut self,
        operation: Id,
        start: Position,
        limit: Position,
    ) -> Result<PacketGrant, ProviderError> {
        match self {
            Self::OutputOnly(program) => Ok(program.execute(operation, start, limit)?.clone()),
            Self::Connected(program) => {
                let emits = program.definition().output.is_some();
                Self::project_grant(program.run(operation, start, limit)?, emits)
            }
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
    }

    pub(super) fn original(&self, operation: &Id) -> Result<Option<PacketGrant>, ProviderError> {
        match self {
            Self::OutputOnly(program) => Ok(program.original(operation).cloned()),
            Self::Connected(program) => program
                .original(operation)
                .map(|grant| Self::project_grant(grant, program.definition().output.is_some()))
                .transpose(),
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
    }

    pub(super) fn retire(&mut self, operation: &Id, events: &[Id]) -> Result<(), ProviderError> {
        match self {
            Self::OutputOnly(program) => program.retire(operation, events),
            Self::Connected(program) => program.retire(operation, events),
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
    }
}

impl NativeProgram {
    pub(super) fn authenticate_original_capture_cut(
        &self,
        cut: Position,
    ) -> Result<Position, ProviderError> {
        match self {
            Self::OutputOnly(program) => program.authenticate_original_capture_cut(cut),
            Self::Connected(program) => program.authenticate_original_capture_cut(cut),
            Self::RestorationInProgress => {
                Err(ProviderError::Conflict("original Capture model incomplete"))
            }
        }
    }

    pub(super) fn quote_original_capture_inventory(
        &self,
        maximum: usize,
    ) -> Result<
        crate::reference_packet::serialization_storage::NativeSerializationStorageData,
        ProviderError,
    > {
        use crate::reference_packet::serialization_storage::actual_serialization_storage_data;
        use crate::retained_metadata::MetadataObserver;
        let mut observer = MetadataObserver::new();
        match self {
            Self::OutputOnly(program) => {
                let view = program.borrow_original_capture_inventory(&mut observer)?;
                let mut formatter = MetadataObserver::new();
                view.observe_serialized_formatter_fields(&mut formatter)?;
                actual_serialization_storage_data(&view, formatter.finish(), maximum)
            }
            Self::Connected(program) => {
                let view = program.borrow_original_capture_inventory(&mut observer)?;
                let mut formatter = MetadataObserver::new();
                view.observe_serialized_formatter_fields(&mut formatter)?;
                actual_serialization_storage_data(&view, formatter.finish(), maximum)
            }
            Self::RestorationInProgress => {
                Err(ProviderError::Conflict("original Capture model incomplete"))
            }
        }
    }

    pub(super) fn original_capture_inventory_hash(
        &self,
        maximum: usize,
    ) -> Result<HashRef, ProviderError> {
        use crate::retained_metadata::MetadataObserver;
        // Recount the same actual borrowed serializer before the canonical/hash
        // helper allocates. The caller admits this whole independent phase.
        self.quote_original_capture_inventory(maximum)?;
        let mut observer = MetadataObserver::new();
        match self {
            Self::OutputOnly(program) => canonical::json_hash(
                "source-owned.packet-inventory.v1",
                &program.borrow_original_capture_inventory(&mut observer)?,
            )
            .map_err(Into::into),
            Self::Connected(program) => canonical::json_hash(
                "source-owned.packet-connected-inventory/4",
                &program.borrow_original_capture_inventory(&mut observer)?,
            )
            .map_err(Into::into),
            Self::RestorationInProgress => {
                Err(ProviderError::Conflict("original Capture model incomplete"))
            }
        }
    }
}
