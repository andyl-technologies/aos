//! Prices the actual launch validator and complete immutable Source comparisons.
//!
//! The defining Provider projection floor is admitted before any serialization
//! counter. The full validate-only row is then joined with every Source-local
//! comparison before the unchanged validator or owning comparison can run.

use super::*;

impl OriginalInitial15ArchivedGroup {
    pub(in super::super) fn launch_terminal_transient_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        contract_row: &serde_json::Value,
    ) -> Result<(usize, usize), OperationFailure> {
        let (validation, scratch) = launch
            .validation_construction_storage_data(self.maximum)
            .map_err(unknown)?;
        let [descriptor] = launch.selection.realization.descriptors.as_slice() else {
            return Err(refused("initial15 launch descriptor roster differs"));
        };
        let [binding] = launch.selection.realization.bindings.as_slice() else {
            return Err(refused("initial15 launch binding roster differs"));
        };
        let typed_contract = NodeRuntime::capture_future_decode_storage(contract_row, self.maximum)
            .map_err(unknown)?
            .checked_mul(3)
            .ok_or_else(|| refused("initial15 launch contract decoder overflow"))?;
        let descriptor = NodeRuntime::capture_serialization_storage(descriptor, self.maximum)
            .map_err(unknown)?;
        let operating = NodeRuntime::capture_serialization_storage(
            &binding.compatibility.operating_contract,
            self.maximum,
        )
        .map_err(unknown)?;
        let compiled = crucible_node_provider::reference_packet::continuation_contracts::complete_packet_contract_history_data();
        let compiled_dom =
            NodeRuntime::capture_serialization_storage(&compiled, self.maximum).map_err(unknown)?;
        let compiled_encoded = NodeRuntime::capture_encoded_output_storage(&compiled, self.maximum)
            .map_err(unknown)?;
        // The enum wrapper contains the complete plain program selected by the
        // comparison. Its additional kind/wrapper fields conservatively dominate
        // both Producer and Reactive branch projections, without allocating them.
        let program = NodeRuntime::capture_serialization_storage(&launch.program, self.maximum)
            .map_err(unknown)?;
        let program_encoded =
            NodeRuntime::capture_encoded_output_storage(&launch.program, self.maximum)
                .map_err(unknown)?;
        let hash = "blake3-256".len() + "cnp.blob.v1".len() + 64;
        let transient = checked_sum(
            [
                validation,
                typed_contract,
                descriptor,
                operating,
                compiled_dom,
                compiled_dom,
                compiled_encoded,
                program,
                program,
                program_encoded,
                hash,
            ],
            self.maximum,
        )?;
        Ok((transient, scratch))
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<&OriginalInitial15ArchivedGroup>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&serde_json::Value>()
        + size_of::<[usize; 11]>()
        + size_of::<std::array::IntoIter<usize, 11>>()
        + size_of::<Result<(usize, usize), OperationFailure>>()
        + PacketNative5SourceLaunch::validation_construction_counter_scratch_data()
        + crucible_node_provider::reference_packet::service::native_snapshot::native_owned14_snapshot_schema_counter_scratch_data()
}
