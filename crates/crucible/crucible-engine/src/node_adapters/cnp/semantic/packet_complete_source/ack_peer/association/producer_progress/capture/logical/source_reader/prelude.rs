//! Joins the genuine first checkpoint before the three-member parent cohort.
//!
//! The retained subset breaks a data dependency cycle: Initial15 ancestry needs
//! all three verified first checkpoints before a full Source17 can be accepted.
//! It contains neither an inherited Source nor a completed Source publication.

use super::*;
use crate::node_contract::NodeRuntime;

/// Retains actual immutable Source selection and strict first-history DATA.
pub(crate) struct OriginalSourceRestoredSettled17Prelude {
    raw: Rc<Value>,
    installation: OriginalSourceRestoredInstallation17,
    first: OriginalSourceRestoredFirstObservationHistory17Read,
    maximum_coordinator_records: usize,
}

impl OriginalSourceRestoredSettled17Prelude {
    /// Reads the first subset under a separately admitted defining constructor.
    ///
    /// The caller retains the archive bytes and independently pays this subset's
    /// raw DOM, typed installation, SDK and native verification work. Failure may
    /// dispose of this pure local cache; no live or native operation occurs here.
    ///
    /// # Errors
    /// Refuses malformed installation/history/policy, another original launch
    /// or World, failed SDK/native proofs, or the independent decode ceiling.
    pub(crate) fn read_data(
        literal: &[u8],
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        world: &SavedRuntimeActivation,
        maximum_bank_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        let raw = Rc::new(
            canonical::parse_json(literal, maximum_bank_bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        let semantic = semantic_data(raw.as_ref())?;
        let root = source_fields::root_data(field(semantic, "source")?)?;
        let installation = source_fields::installation_data(field(root, "installation")?)?;
        native
            .authenticate_original_launch_data(&installation.launch)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let saved_world: SavedRuntimeActivation = read(field(root, "world")?)?;
        if saved_world != *world || installation.world_binding_hash != world.world_binding_hash {
            return Err(RuntimeError::ForeignAuthority);
        }
        let reactive = match &installation.launch.program {
            PacketConnectedSourceProgram::Producer { .. } => None,
            PacketConnectedSourceProgram::Reactive { program } => Some(program),
        };
        let first = OriginalSourceRestoredFirstObservationHistory17Read::validate_data(
            field(root, "first_observation")?,
            controller,
            native,
            world,
            &installation.descriptor,
            reactive,
            maximum_bank_bytes,
        )?;
        // This is the literal archived policy bound. It is not a fresh grant or
        // a default from operation/object counts. The completed Source reader
        // independently verifies the entire outer header using this same bound.
        let maximum_coordinator_records = archived_coordinator_limit_data(field(root, "once")?)?;
        Ok(Self {
            raw,
            installation,
            first,
            maximum_coordinator_records,
        })
    }

    /// Borrows the strict first Source/SDK/native checkpoint.
    pub(crate) fn first_observation_data(
        &self,
    ) -> &OriginalSourceRestoredFirstObservationHistory17Read {
        &self.first
    }

    /// Borrows the inert original installation authenticated by native Boot.
    pub(crate) fn installation_data(&self) -> &OriginalSourceRestoredInstallation17 {
        &self.installation
    }

    /// Returns the exact bound retained in the archived Source policy.
    pub(crate) fn maximum_coordinator_records_data(&self) -> usize {
        self.maximum_coordinator_records
    }

    /// Borrows the exact parsed semantic root without publishing a Source.
    pub(crate) fn semantic_data(&self) -> &Value {
        self.raw.as_ref()
    }

    /// Counts actual raw/typed cache backing without a shared-allocation refund.
    ///
    /// # Errors
    /// Refuses defining metadata overflow or backing above the independent bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::value_storage_with_error;
        let terms = [
            size_of::<Self>(),
            self.installation.retained_heap_storage_data(maximum)?,
            self.first.retained_requested_storage_data(maximum)?,
            value_storage_with_error::<RuntimeError>(self.raw.as_ref(), 0, maximum)?,
            NodeRuntime::capture_shared_allocation_storage::<Value>(),
        ];
        terms.into_iter().try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes)
                .filter(|sum| *sum <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Names the concrete prelude parser, metadata and temporary result controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<SavedRuntimeActivation>()
            + size_of::<Result<SavedRuntimeActivation, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Rc<Value>>()
            + size_of::<[&str; 2]>()
            + OriginalSourceRestoredInstallation17::counter_scratch_data()
            + OriginalSourceRestoredSettled17Read::counter_scratch_data()
    }
}

fn archived_coordinator_limit_data(once: &Value) -> Result<usize, RuntimeError> {
    let policy = once
        .get("outer")
        .and_then(|outer| outer.get("coordinator_policy17"))
        .ok_or(RuntimeError::InvalidReceipt)?;
    let policy = object(policy, &["kind", "maximum_records"])?;
    let maximum: usize = read(field(policy, "maximum_records")?)?;
    if field(policy, "kind")?.as_str() != Some("bound") || maximum < 2 {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn archived_coordinator_bound_has_no_other_budget_fallback() {
        let once = json!({"outer":{"coordinator_policy17":{
            "kind":"bound", "maximum_records":17
        }}});
        assert_eq!(archived_coordinator_limit_data(&once).unwrap(), 17);

        for policy in [
            json!(null),
            json!({"kind":"attempted"}),
            json!({"kind":"bound", "maximum_records":0}),
            json!({"kind":"bound", "maximum_records":1}),
            json!({"kind":"bound", "maximum_records":"17"}),
            json!({"kind":"bound", "maximum_records":17, "maximum_operations":17}),
        ] {
            let once = json!({"outer":{"coordinator_policy17":policy}});
            assert!(archived_coordinator_limit_data(&once).is_err());
        }
        assert!(archived_coordinator_limit_data(&json!({"maximum_operations":17})).is_err());
    }
}
