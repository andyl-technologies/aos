//! Retains a current checkpoint's typed and canonical construction through failure.
//!
//! The actual Window installs this owner before construction. It materializes
//! the sealed current log under its independent row; no caller-supplied ordinal
//! or ContentRef creates a coordinator boundary or administrative permission.

use super::*;
use crate::node_contract::runtime_owned_counter::OwnedStorage;
use crate::node_scheduling::InputPayload;
use crucible_node_contract::{HashRef, canonical};
use crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::{
    COORDINATOR_CHECKPOINT17_MEDIA, CoordinatorCommitmentActivation17,
    CoordinatorCommitmentSafePoint17,
};

/// Owns every initialized current-checkpoint bank beneath one spent attempt.
pub(crate) struct OriginalRestoredCoordinatorCheckpointOwner17 {
    started: bool,
    verified: bool,
    record: Option<CoordinatorCommitmentCheckpoint17>,
    prefix_value: Option<serde_json::Value>,
    prefix_bytes: Vec<u8>,
    value: Option<serde_json::Value>,
    bytes: Vec<u8>,
    object: Option<InputPayload>,
}

impl OriginalRestoredCoordinatorCheckpointOwner17 {
    pub(crate) fn empty() -> Self {
        Self {
            started: false,
            verified: false,
            record: None,
            prefix_value: None,
            prefix_bytes: Vec::new(),
            value: None,
            bytes: Vec::new(),
            object: None,
        }
    }

    /// Counts initialized backing only; the containing Window pays this root.
    pub(crate) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            verified: _,
            record,
            prefix_value,
            prefix_bytes,
            value,
            bytes,
            object,
        } = self;
        let mut total = prefix_bytes
            .capacity()
            .checked_add(bytes.capacity())
            .ok_or(RuntimeError::ResourceLimit)?;
        if let Some(record) = record {
            total = total
                .checked_add(
                    record
                        .retained_backing_requested_bytes_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        for value in prefix_value.iter().chain(value.iter()) {
            total = total
                .checked_add(value.owned_storage()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(object) = object {
            total = total
                .checked_add(object.bytes.capacity())
                .and_then(|n| {
                    n.checked_add(NodeRuntime::capture_reference_storage(&object.reference).ok()?)
                })
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(total)
    }

    pub(crate) fn object_data(&self) -> Option<&InputPayload> {
        self.verified.then_some(self.object.as_ref()).flatten()
    }

    /// Binds the sealed current checkpoint to the actual ticketed Runtime object.
    ///
    /// The independently preconstructed copy never replaces the ticket's input
    /// identity. The writer's earlier complete-byte join and this full reference
    /// check connect both actual objects to the same retained coordinator record.
    ///
    /// # Errors
    /// Refuses incomplete construction, an absent current record or a different
    /// ticketed Runtime commitment. This DATA loan issues no capture permission.
    pub(crate) fn object_for_runtime_data(
        &self,
        runtime: &crate::node_scheduling::InputPayload,
    ) -> Result<&crate::node_scheduling::InputPayload, RuntimeError> {
        if !self.verified {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let record = self.record.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if record.safe_point.runtime != runtime.reference {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.object_data().ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Borrows the actual verified typed checkpoint for the same Runtime object.
    ///
    /// The encoded-object guard remains the single check for completion and the
    /// full safe-point Runtime reference. No record is parsed, cloned or created
    /// by this DATA loan, and it issues no checkpoint or Capture permission.
    ///
    /// # Errors
    /// Refuses an incomplete owner, absent record/object, or another complete
    /// Runtime reference, exactly as the encoded-object loan does.
    pub(crate) fn record_for_runtime_data(
        &self,
        runtime: &InputPayload,
    ) -> Result<&CoordinatorCommitmentCheckpoint17, RuntimeError> {
        self.object_for_runtime_data(runtime)?;
        self.record.as_ref().ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Constructs from the same sealed current log after whole-row admission.
    /// The later genuine ticket independently binds the actual Runtime7 body.
    pub(crate) fn construct_data(
        &mut self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &crate::node_contract::HostSchedulingSource,
        boundary: &OriginalRestoredCoordinatorBoundary17,
        runtime_reference: &ContentRef,
        scheduling_reference: &ContentRef,
    ) -> Result<(), RuntimeError> {
        if self.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.started = true;
        boundary.authenticate_runtime_data(runtime, world, host)?;
        use crucible_node_contract::Validate;
        runtime_reference
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        scheduling_reference
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if runtime_reference.media_type
            != "application/vnd.crucible.runtime-original-lineage+json;version=7"
            || scheduling_reference.media_type != "application/json"
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let current = world.record();
        runtime
            .scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .with_coordinator17_data(|log| {
                let log = log.ok_or(RuntimeError::UnsupportedFacet)?;
                log.authenticate_boundary_data(boundary)?;
                self.record = Some(CoordinatorCommitmentCheckpoint17 {
                    schema_version: 17,
                    ordering_profile: "coordinator-public-events-v17".into(),
                    activation: CoordinatorCommitmentActivation17 {
                        activation_id: clone_id(&current.activation_id)?,
                        world_generation: current.generation,
                        world_binding: current.world_binding_hash.clone(),
                        boundary: current.boundary,
                    },
                    parent: log.parent.as_ref().map(clone_reference).transpose()?,
                    maximum_records: U64::new(
                        u64::try_from(log.policy.maximum_records)
                            .map_err(|_| RuntimeError::ResourceLimit)?,
                    ),
                    first_sequence: log.first_sequence,
                    next_sequence: log.next_sequence,
                    first_event_ordinal: log.first_event_ordinal,
                    entries: Vec::new(),
                    safe_point: CoordinatorCommitmentSafePoint17 {
                        position: boundary.cut_data(),
                        event_ordinal: boundary.ordinal_data(),
                        // This deliberately incomplete partial cannot leave object_data.
                        // Its actual prefix is retained and hashed below before sealing.
                        prefix: HashRef {
                            algorithm: String::new(),
                            domain: String::new(),
                            digest: String::new(),
                        },
                        runtime: clone_reference(runtime_reference)?,
                        scheduling: clone_reference(scheduling_reference)?,
                    },
                });
                let record = self.record.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
                record
                    .entries
                    .try_reserve_exact(log.entries.len())
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                for entry in &log.entries {
                    record.entries.push(CoordinatorCommitmentEntry17 {
                        sequence: entry.sequence,
                        kind: entry.kind,
                        state: entry.state,
                        operation: None,
                        node: None,
                        position: entry.position,
                        evidence: None,
                        event_ordinal: entry.event_ordinal,
                    });
                    let copy = record
                        .entries
                        .last_mut()
                        .ok_or(RuntimeError::OwnerUnavailable)?;
                    copy.operation = entry.operation.as_ref().map(clone_id).transpose()?;
                    copy.node = entry.node.as_ref().map(clone_id).transpose()?;
                    copy.evidence = entry.evidence.as_ref().map(clone_reference).transpose()?;
                }
                Ok(())
            })?;
        let record = self.record.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        self.prefix_value = Some(
            serde_json::to_value(record.prefix_data()).map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        self.prefix_bytes = canonical::canonical_json(
            self.prefix_value
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        record.safe_point.prefix =
            canonical::hash("crucible.coordinator-prefix.v17", &self.prefix_bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        record
            .authenticate_structure_data(
                runtime_reference,
                boundary.cut_data(),
                boundary.ordinal_data(),
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.value = Some(serde_json::to_value(&record).map_err(|_| RuntimeError::InvalidReceipt)?);
        self.bytes =
            canonical::canonical_json(self.value.as_ref().ok_or(RuntimeError::OwnerUnavailable)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        if self.bytes.len() > boundary.maximum_checkpoint_encoded_bytes_data() {
            return Err(RuntimeError::ResourceLimit);
        }
        let reference = canonical::content_ref(&self.bytes, COORDINATOR_CHECKPOINT17_MEDIA)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.object = Some(InputPayload {
            reference,
            bytes: std::mem::take(&mut self.bytes),
        });
        boundary.authenticate_runtime_data(runtime, world, host)?;
        self.verified = true;
        Ok(())
    }
}

pub(super) fn checkpoint_owner_counter_scratch_data() -> usize {
    size_of::<OriginalRestoredCoordinatorCheckpointOwner17>()
        + size_of::<&mut OriginalRestoredCoordinatorCheckpointOwner17>()
        + size_of::<&CoordinatorCommitmentCheckpoint17>()
        + size_of::<&mut CoordinatorCommitmentCheckpoint17>()
        + size_of::<CoordinatorCommitmentActivation17>()
        + size_of::<CoordinatorCommitmentSafePoint17>()
        + size_of::<Option<&InputPayload>>()
        + size_of::<&InputPayload>()
        + size_of::<Result<&InputPayload, RuntimeError>>()
        + size_of::<Result<&CoordinatorCommitmentCheckpoint17, RuntimeError>>()
        + size_of::<
            std::iter::Chain<
                std::option::Iter<'static, serde_json::Value>,
                std::option::Iter<'static, serde_json::Value>,
            >,
        >()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
        + size_of::<Result<ContentRef, crucible_node_contract::ContractError>>()
        + size_of::<Result<HashRef, crucible_node_contract::ContractError>>()
        + size_of::<Option<&mut CoordinatorCommitmentEntry17>>()
        + size_of::<Result<(), RuntimeError>>()
}

#[cfg(test)]
mod typed_runtime_loan_tests {
    use super::*;
    use crucible_node_contract::{Phase, Position};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn runtime_object() -> Result<InputPayload, Box<dyn std::error::Error>> {
        let bytes = b"inert Runtime7 DATA".to_vec();
        Ok(InputPayload {
            reference: canonical::content_ref(
                &bytes,
                "application/vnd.crucible.runtime-original-lineage+json;version=7",
            )?,
            bytes,
        })
    }

    // Inert partially populated DATA checks that field presence never replaces
    // genuine completion. This fixture never sets the private verified bit.
    fn partial_record(
        runtime: &InputPayload,
    ) -> Result<CoordinatorCommitmentCheckpoint17, Box<dyn std::error::Error>> {
        let cut = Position::new(17.into(), 0.into(), Phase::BoundaryControl);
        Ok(CoordinatorCommitmentCheckpoint17 {
            schema_version: 17,
            ordering_profile: "coordinator-public-events-v17".into(),
            activation: CoordinatorCommitmentActivation17 {
                activation_id: Id::new("typed-checkpoint-data")?,
                world_generation: U64::new(1),
                world_binding: canonical::hash("cnp.world-binding.v1", b"inert DATA")?,
                boundary: cut,
            },
            parent: None,
            maximum_records: U64::new(8),
            first_sequence: U64::new(0),
            next_sequence: U64::new(2),
            first_event_ordinal: U64::new(0),
            entries: Vec::new(),
            safe_point: CoordinatorCommitmentSafePoint17 {
                position: cut,
                event_ordinal: U64::new(0),
                prefix: HashRef {
                    algorithm: String::new(),
                    domain: String::new(),
                    digest: String::new(),
                },
                runtime: runtime.reference.clone(),
                scheduling: canonical::content_ref(b"inert scheduling DATA", "application/json")?,
            },
        })
    }

    #[test]
    fn absent_typed_owner_never_lends_a_record_for_a_well_formed_reference() -> TestResult {
        let owner = OriginalRestoredCoordinatorCheckpointOwner17::empty();
        let runtime = runtime_object()?;

        assert!(matches!(
            owner.record_for_runtime_data(&runtime),
            Err(RuntimeError::OwnerUnavailable)
        ));
        assert!(owner.record.is_none());
        assert!(owner.object.is_none());
        assert_eq!(owner.retained_requested_storage_data()?, 0);
        Ok(())
    }

    #[test]
    fn partial_record_and_object_keep_custody_without_becoming_a_typed_loan() -> TestResult {
        let runtime = runtime_object()?;
        let mut owner = OriginalRestoredCoordinatorCheckpointOwner17::empty();
        owner.started = true;
        owner.record = Some(partial_record(&runtime)?);
        owner.prefix_value = Some(serde_json::json!({"partial":"prefix"}));
        owner.prefix_bytes.extend_from_slice(b"partial-prefix");
        owner.bytes.extend_from_slice(b"partial-object");
        let bytes = b"partial checkpoint DATA".to_vec();
        owner.object = Some(InputPayload {
            reference: canonical::content_ref(&bytes, COORDINATOR_CHECKPOINT17_MEDIA)?,
            bytes,
        });
        let retained = owner.retained_requested_storage_data()?;
        let object_pointer = owner
            .object
            .as_ref()
            .ok_or("missing partial object")?
            .bytes
            .as_ptr();
        let original_runtime = owner
            .record
            .as_ref()
            .ok_or("missing partial record")?
            .safe_point
            .runtime
            .clone();

        assert!(matches!(
            owner.record_for_runtime_data(&runtime),
            Err(RuntimeError::OwnerUnavailable)
        ));
        let mut changed = runtime.clone();
        changed.reference.media_type = "application/json".to_owned();
        assert!(matches!(
            owner.record_for_runtime_data(&changed),
            Err(RuntimeError::OwnerUnavailable)
        ));
        assert_eq!(owner.retained_requested_storage_data()?, retained);
        assert_eq!(
            owner
                .object
                .as_ref()
                .ok_or("lost partial object")?
                .bytes
                .as_ptr(),
            object_pointer
        );
        assert_eq!(
            owner
                .record
                .as_ref()
                .ok_or("lost partial record")?
                .safe_point
                .runtime,
            original_runtime
        );
        assert!(owner.started);
        assert!(!owner.verified);
        Ok(())
    }
}
