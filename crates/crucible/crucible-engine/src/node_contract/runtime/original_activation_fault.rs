//! Retains actual originals at two explicit qualification-only loss boundaries.
//!
//! These cuts never supply native success, readiness or a replacement receipt.
//! They run the ordinary validated implementation first, retain its exact
//! original, then deliberately withhold its acknowledgement and contain the
//! affected real owner. Ordinary Arm and completion paths do not select them.

use super::*;

/// Owns actual readiness withheld from the global activation barrier.
///
/// The preceding preparations and selected preparation are original values
/// returned by the native nodes. They are historical data, never activation
/// authority. The caller retains this owner before examining the refusal.
#[must_use = "retain original ready records with their inactive native world"]
pub struct OriginalReadinessLoss {
    record: ActivationRecord,
    preceding: Vec<ValidatedNodePreparation>,
    withheld: ValidatedNodePreparation,
}

impl OriginalReadinessLoss {
    pub(super) fn retain(
        record: &ActivationRecord,
        preceding: Vec<ValidatedNodePreparation>,
        withheld: ValidatedNodePreparation,
    ) -> Self {
        Self {
            record: record.clone(),
            preceding,
            withheld,
        }
    }

    /// Borrows the exact world whose original readiness delivery was lost.
    pub fn activation_record_data(&self) -> &ActivationRecord {
        &self.record
    }

    /// Borrows earlier nodes' actual validated readiness in execution order.
    pub fn preceding_preparations_data(&self) -> &[ValidatedNodePreparation] {
        &self.preceding
    }

    /// Borrows the selected node's real preparation withheld from the barrier.
    pub fn withheld_preparation_data(&self) -> &ValidatedNodePreparation {
        &self.withheld
    }

    /// Counts this original data owner's inline and independent requested storage.
    ///
    /// The actual moved readiness vector, including spare slots and every
    /// independent native record backing, remains charged. This immutable data
    /// walk invokes no native, source or formatting callback and grants no
    /// origin, activation or allocation authority. Its fixed counter scratch is
    /// an additional simultaneous term; allocator and compiler overhead remain
    /// outside this requested-layout measurement.
    ///
    /// # Errors
    /// Refuses checked-layout overflow, unsupported nested data or the bound.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            record,
            preceding,
            withheld,
        } = self;
        let mut counter =
            crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter::new(maximum);
        counter.add(std::mem::size_of::<Self>())?;
        counter.owned(record)?;
        counter.owned(preceding)?;
        counter.owned(withheld)?;
        Ok(counter.bytes())
    }

    /// Names the actual fixed counter used beside the retained loss data.
    pub fn retained_requested_storage_scratch_data() -> usize {
        std::mem::size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>()
    }
}

/// Retains the real completion replaced by explicit uncertain loss containment.
///
/// The original outcome remains evidence of native effects. The common runtime
/// separately retains an Unknown failure and original token; this value does
/// not acknowledge that operation, roll back effects or release its owner.
#[must_use = "retain original completion with its contained native world"]
pub struct OriginalCompletionLoss {
    outcome: OperationOutcome,
}

impl OriginalCompletionLoss {
    /// Borrows the complete native outcome observed before intentional loss.
    pub fn original_outcome_data(&self) -> &OperationOutcome {
        &self.outcome
    }

    /// Counts this original outcome owner's inline and independent storage.
    ///
    /// This charges the real outcome's capacities, including pending retained
    /// outputs and full scheduling metadata. No native record is synthesized,
    /// authenticated or interpreted as permission by the data observation.
    /// Fixed scratch and physical allocator/compiler costs are separate terms.
    ///
    /// # Errors
    /// Refuses checked-layout overflow, unsupported nested data or the bound.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self { outcome } = self;
        let mut counter =
            crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter::new(maximum);
        counter.add(std::mem::size_of::<Self>())?;
        counter.owned(outcome)?;
        Ok(counter.bytes())
    }

    /// Names the actual fixed counter used beside the retained completion.
    pub fn retained_requested_storage_scratch_data() -> usize {
        std::mem::size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>()
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    use crucible_node_format::{Id, Phase, Position, U64, canonical};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn preparation(
        node: &str,
        owner: OwnerIdentity,
    ) -> Result<ValidatedNodePreparation, Box<dyn std::error::Error>> {
        let body = canonical::content_ref(b"data-only-loss-storage", "application/octet-stream")?;
        Ok(ValidatedNodePreparation {
            node: Id::new(node)?,
            readiness: crate::node_contract::ReadyAttestation {
                owners: vec![owner],
                boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
                state_inventory: body.clone(),
                ready_receipt: body,
            },
            prepared_owners: None,
        })
    }

    #[test]
    fn actual_moved_readiness_vector_counts_spare_slots_and_exact_one_short() -> TestResult {
        let owner = OwnerIdentity {
            owner: Id::new("owner/data-only")?,
            incarnation: Id::new("incarnation/data-only")?,
            generation: U64::new(1),
        };
        let boundary = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
        let record = ActivationRecord {
            generation: U64::new(1),
            activation_id: Id::new("activation/data-only")?,
            world_binding_hash: canonical::hash("crucible.data-only-loss-storage/1", b"world")?,
            owners: vec![owner.clone()],
            boundary,
        };
        let mut actual = OriginalReadinessLoss::retain(
            &record,
            vec![preparation("clock-a", owner.clone())?],
            preparation("clock-b", owner)?,
        );
        let before = actual.retained_requested_storage_data(usize::MAX)?;
        let old_capacity = actual.preceding.capacity();
        actual.preceding.reserve_exact(37);
        let extra = (actual.preceding.capacity() - old_capacity)
            * std::mem::size_of::<ValidatedNodePreparation>();
        let total = actual.retained_requested_storage_data(usize::MAX)?;
        assert_eq!(total - before, extra);
        assert!(extra > 0);
        assert_eq!(actual.retained_requested_storage_data(total)?, total);
        assert_eq!(
            actual.retained_requested_storage_data(total - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(OriginalReadinessLoss::retained_requested_storage_scratch_data() > 0);
        Ok(())
    }

    #[test]
    fn actual_completion_output_bank_counts_spare_without_inventing_effects() -> TestResult {
        let position = Position::new(2.into(), 0.into(), Phase::BoundaryControl);
        let mut actual = OriginalCompletionLoss {
            outcome: OperationOutcome {
                operation: Id::new("operation/data-only")?,
                node: Id::new("clock-b")?,
                owners: Vec::new(),
                progress: crate::node_contract::ProgressEvidence::Exact {
                    reached: position,
                    stop: crate::node_contract::StopReason::HorizonPark,
                },
                retained_outputs: Vec::new(),
                scheduling: None,
            },
        };
        let before = actual.retained_requested_storage_data(usize::MAX)?;
        actual.outcome.retained_outputs.reserve_exact(23);
        let extra = actual.outcome.retained_outputs.capacity() * std::mem::size_of::<Id>();
        let total = actual.retained_requested_storage_data(usize::MAX)?;
        assert_eq!(total - before, extra);
        assert!(actual.outcome.retained_outputs.is_empty());
        assert_eq!(
            actual.outcome.progress,
            crate::node_contract::ProgressEvidence::Exact {
                reached: position,
                stop: crate::node_contract::StopReason::HorizonPark,
            }
        );
        assert_eq!(actual.retained_requested_storage_data(total)?, total);
        assert_eq!(
            actual.retained_requested_storage_data(total - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(OriginalCompletionLoss::retained_requested_storage_scratch_data() > 0);
        Ok(())
    }
}

impl NodeRuntime {
    /// Loses one actual readiness delivery for an original qualification case.
    ///
    /// The selected node must exist and the output must be empty before Arm.
    /// Ordinary preparation order and native validation are preserved. Earlier
    /// readiness and the selected actual preparation enter the output before
    /// containment. The method intentionally returns InvalidReceipt on reaching
    /// its cut; it can never return success or create activation authority.
    ///
    /// # Errors
    /// Refuses a foreign creator, occupied output or absent node before Arm;
    /// retains ordinary native failures; returns InvalidReceipt after losing
    /// the selected real acknowledgement. A failed world cannot be rearmed.
    pub fn arm_all_with_original_readiness_loss(
        &mut self,
        selected: &Id,
        retained: &mut Option<OriginalReadinessLoss>,
    ) -> Result<(), RuntimeError> {
        self.scheduling_origin()?;
        if retained.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        if !self.nodes.contains_key(selected) {
            return Err(RuntimeError::UnknownNode);
        }
        self.arm_all_selected(Some((selected, retained)))
    }

    /// Contains an actual completed operation after qualification loses its ACK.
    ///
    /// A source-owned fault case calls this only after independently retaining
    /// the native body and prior committed effects. The same cached completed
    /// outcome moves into the caller's empty slot; the runtime retains Unknown
    /// effect knowledge and all original operation/native custody. Acknowledged
    /// or pending operations cannot be rewritten through this explicit cut.
    ///
    /// # Errors
    /// Refuses another creator/token, occupied output, missing operation,
    /// outstanding scheduling commit or any non-complete original state.
    pub fn retain_original_completion_loss(
        &mut self,
        token: &OperationToken,
        retained: &mut Option<OriginalCompletionLoss>,
    ) -> Result<(), RuntimeError> {
        self.scheduling_origin()?;
        self.validate_token(token)?;
        if retained.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let entry = self
            .operations
            .get_mut(token.operation())
            .ok_or(RuntimeError::ForeignAuthority)?;
        if entry.scheduling_commit.is_some() || !matches!(entry.result, RetainedResult::Complete(_))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let original = std::mem::replace(
            &mut entry.result,
            RetainedResult::Failed(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "original qualification deliberately lost completion acknowledgement"
                    .to_owned(),
            }),
        );
        let RetainedResult::Complete(outcome) = original else {
            // The exclusive entry loan and checked discriminant above make
            // this unreachable without changing this implementation itself.
            return Err(RuntimeError::InvalidReceipt);
        };
        *retained = Some(OriginalCompletionLoss { outcome });
        self.contain_roster(token.route());
        Ok(())
    }
}
