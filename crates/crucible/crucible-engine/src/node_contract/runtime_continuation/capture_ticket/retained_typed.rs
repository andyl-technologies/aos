//! Counts retained terminal, condition and epoch owners without serialization.
//!
//! Reference-only wire fields still own their actual original payload banks.
//! This data walk never validates, resumes or publishes those records.

use super::*;

impl OwnedStorage for crucible_node_format::Bytes {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        Ok(self.allocation_capacity())
    }
}

owned_fields!(crate::node_contract::FaultMutationRequest; facet_profile, program);
owned_fields!(crate::node_contract::QuantumClosureEvidence;
    input_batch, close_receipt, output_inventory, pending_inventory, clock_evidence);
owned_fields!(crate::node_contract::NativeTerminalInventory; node, owners, receipt);
owned_fields!(crate::node_contract::WorldTerminalRecord;
    operation, node, source, scheduler, native);
owned_fields!(crate::node_contract::SavedWorldTerminal; record, reference, report);
owned_fields!(crate::node_contract::NativeConditionStopInventory;
    node, owners, receipt, proof_objects);
owned_fields!(crate::node_contract::ConditionStopRecord;
    operation, node, source, hit, scheduler, native);
owned_fields!(crate::node_contract::SavedConditionStop;
    record, reference, report, resume_operation, resume_receipt);
owned_fields!(crate::node_adapters::ConditionHitCandidate; condition, input, outcome);
owned_fields!(crate::node_adapters::semantic_model::HostSemanticPublication; parents, bytes);
owned_fields!(crate::node_scheduling::SavedEpochReservation;
    reservation, position, producer);
owned_fields!(crate::node_scheduling::SavedSchedulingEpoch;
    coordinator, scheduler, runtime, policy, reservations);
owned_fields!(crate::node_scheduling::SchedulingEpochEvidence; policy, rows, objects);

impl OwnedStorage for crate::node_contract::ConditionControlRequest {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        match self {
            Self::Stop { barrier, receipt } => {
                storage::add(barrier.owned_storage()?, receipt.owned_storage()?)
            }
            Self::Resume {
                stop_operation,
                barrier,
                report,
            } => {
                let bytes =
                    storage::add(stop_operation.owned_storage()?, barrier.owned_storage()?)?;
                storage::add(bytes, report.owned_storage()?)
            }
        }
    }
}

owned_fields!(crucible_node_format::SemanticVersion; prerelease, build);
owned_fields!(crucible_node_format::ExtensionSelection;
    declaration, identifier, semantic_version, schema_digest);
owned_fields!(crucible_node_format::ExtensionUse; selection, parameters);
owned_fields!(crate::node_admission::CapabilitySelection;
    format, base_scenario_ref, requirements_ref, bindings);
owned_fields!(crate::node_admission::CapabilityBinding; node, compatibility_hash);
owned_fields!(crate::node_admission::CapabilityRequirements; format, nodes);
owned_fields!(crate::node_admission::NodeCapabilityRequirement;
    node, roles, timing, operations, compute, extensions);
owned_fields!(crate::node_admission::TimingRequirement; policy_ref);
owned_fields!(crate::node_admission::OperationRequirement; operation, facet);
owned_fields!(crate::node_admission::ComputeRequirement;
    architecture, machine_ref, devices_ref);

owned_fields!(crate::node_scheduling::NativeExternalInputInventory; endpoint, inputs, proof_ref);
owned_fields!(crate::node_scheduling::NativeExternalInput;
    event_id, payload, payload_bytes, provenance_ref);
