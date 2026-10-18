//! Authenticates this incarnation's complete first restored observation history.
//!
//! The enclosing retained Source17 decoder admits all typed, canonical and
//! native-proof work before calling. This reader joins independent Source banks,
//! the real SDK once owner, the native private history and the common mapping.
//! Its result is historical DATA and cannot reopen an old SDK or Source grant.

use super::producer_fields::{array, field, object, read};
use crate::{
    node_adapters::cnp::semantic::{
        packet_connected_source::PacketConnectedSemanticSource, packet_source::PacketSemanticSource,
    },
    node_contract::{RuntimeError, SavedRuntimeActivation},
    node_scheduling::NativeSchedulingObservation,
};
use crucible_node_contract::{ContentRef, NodeDescriptor, U64, canonical};
use crucible_node_provider::{
    bodies::MethodResult,
    protocol_snapshot::{
        current_controller17::{
            ValidatedControllerSettledHistory17, ValidatedHistoricalFirstRestorationObservation17,
            ValidatedHistoricalRestorationAssociation17,
        },
        restored_settled17::{
            HistoricalRestoredObservation17Data, SealedHistoricalRestoredSettledNative17,
        },
    },
    reference_packet::{
        connected::PacketConnectedDefinition,
        control::PacketNative5UnderlyingRecord,
        service::complete_restore::{
            PacketNativeRestoredRecord, restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE,
        },
    },
};
use serde_json::Value;

/// Retains independently joined first-observation DATA beneath the Source root.
pub(crate) struct OriginalSourceRestoredFirstObservationHistory17Read {
    sdk: ValidatedHistoricalFirstRestorationObservation17,
    binding: [u8; 32],
    record: PacketNativeRestoredRecord,
    underlying: PacketNative5UnderlyingRecord,
    measurement: ContentRef,
    scheduling: NativeSchedulingObservation,
}

impl OriginalSourceRestoredFirstObservationHistory17Read {
    /// Joins the real Source, SDK and native first checkpoint without live rights.
    ///
    /// # Errors
    /// Refuses a partial or malformed owner, unequal Source banks/Values, another
    /// completed SDK pair, unavailable native private proof, changed current
    /// World/owner scope or any mismatch in the full common scheduling mapping.
    pub(crate) fn validate_data(
        history: &Value,
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        world: &SavedRuntimeActivation,
        descriptor: &NodeDescriptor,
        reactive: Option<&PacketConnectedDefinition>,
        maximum_bank_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        let root = object(
            history,
            &[
                "schema",
                "binding",
                "reserved",
                "verified",
                "banks",
                "values",
                "record",
                "underlying",
                "scheduling",
            ],
        )?;
        if field(root, "schema")?.as_str()
            != Some("source-private.source-restored-first-observation-state/17")
            || field(root, "reserved")?.as_bool() != Some(true)
            || field(root, "verified")?.as_bool() != Some(true)
        {
            return Err(invalid());
        }
        let binding: [u8; 32] = read(field(root, "binding")?)?;
        let values = array(field(root, "values")?, 4)?;
        let banks = array(field(root, "banks")?, 4)?;
        for (value, bank) in values.iter().zip(banks) {
            if value.is_null() {
                return Err(invalid());
            }
            let bank: Vec<u8> = read(bank)?;
            if bank.len() > maximum_bank_bytes {
                return Err(RuntimeError::ResourceLimit);
            }
            let canonical = canonical::canonical_json(value).map_err(|_| invalid())?;
            if canonical != bank {
                return Err(invalid());
            }
        }
        let sdk = ValidatedHistoricalFirstRestorationObservation17::validate_data(controller)
            .map_err(|_| invalid())?;
        let (original, terminal, response) = sdk.completed_pair_data();
        if serde_json::to_value(sdk.request_data()).map_err(|_| invalid())? != values[0]
            || serde_json::to_value(original).map_err(|_| invalid())? != values[2]
            || serde_json::to_value(terminal).map_err(|_| invalid())? != values[3]
            || values[1].get("request") != Some(&values[0])
            || original.extensions.len() != 1
            || original.extensions.get(PACKET_RESTORATION_OBSERVE_FEATURE) != Some(&values[1])
        {
            return Err(invalid());
        }
        let target = &sdk.request_data().scope.target;
        let mut owners = world
            .owners
            .iter()
            .filter(|owner| owner.owner == target.owner);
        let owner = owners.next().ok_or_else(invalid)?;
        if owners.next().is_some()
            || target.node != descriptor.id
            || target.world != world.world_binding_hash
            || target.activation != world.activation_id
            || target.generation != world.generation
            || target.owner_generation != owner.generation
            || target.incarnation != owner.incarnation
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let record: PacketNativeRestoredRecord = read(field(root, "record")?)?;
        let underlying = object(field(root, "underlying")?, &["kind", "value"])?;
        let underlying = match field(underlying, "kind")?.as_str() {
            Some("producer") if reactive.is_none() => {
                PacketNative5UnderlyingRecord::Producer(read(field(underlying, "value")?)?)
            }
            Some("reactive") if reactive.is_some() => {
                PacketNative5UnderlyingRecord::Reactive(read(field(underlying, "value")?)?)
            }
            _ => return Err(invalid()),
        };
        let association = ValidatedHistoricalRestorationAssociation17::validate_data(controller)
            .map_err(|_| invalid())?;
        native
            .authenticate_restored_observation_history_data(&HistoricalRestoredObservation17Data {
                association: &association,
                binding: &binding,
                original,
                terminal,
                response,
                record: &record,
                underlying: &underlying,
            })
            .map_err(|_| invalid())?;
        let Some(MethodResult::Observe(observed)) = response.result.as_ref() else {
            return Err(invalid());
        };
        let [batch] = observed.observations.as_slice() else {
            return Err(invalid());
        };
        let measurement = batch.measurement_ref.clone();
        for reference in [&measurement, &record.native_receipt.native_record] {
            controller
                .authenticate_completed_content_reference_data(reference)
                .map_err(|_| invalid())?;
        }
        let scheduling: NativeSchedulingObservation = read(field(root, "scheduling")?)?;
        let expected = match (&underlying, reactive) {
            (PacketNative5UnderlyingRecord::Producer(record), None) => {
                PacketSemanticSource::historical_scheduling17_data(
                    descriptor,
                    || owner.clone(),
                    &measurement,
                    record,
                )
            }
            (PacketNative5UnderlyingRecord::Reactive(record), Some(definition)) => {
                PacketConnectedSemanticSource::historical_scheduling17_data(
                    descriptor,
                    || owner.clone(),
                    definition,
                    &measurement,
                    record,
                )
            }
            _ => return Err(invalid()),
        }
        .map_err(|_| invalid())?;
        if scheduling != expected {
            return Err(invalid());
        }
        Ok(Self {
            sdk,
            binding,
            record,
            underlying,
            measurement,
            scheduling,
        })
    }

    /// Counts every actual typed child retained by this historical result.
    ///
    /// The enclosing Source owner counts its raw and DOM roots separately.
    ///
    /// # Errors
    /// Refuses exhaustive metadata/counter overflow or a total beyond the
    /// independently admitted requested-storage ceiling.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::{node_adapters::cnp::PacketCompleteSemanticSource, node_contract::NodeRuntime};
        use crucible_node_provider::reference_packet::service::complete_restore::activation::restoration_activation_retained_native_evidence_data;
        let sdk = self
            .sdk
            .retained_metadata_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let native = restoration_activation_retained_native_evidence_data(
            &self.record,
            Some(&self.underlying),
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let terms = [
            std::mem::size_of::<Self>(),
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &sdk, maximum,
            )?,
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &native, maximum,
            )?,
            NodeRuntime::capture_reference_storage(&self.measurement)?,
            NodeRuntime::capture_scheduling_observation_storage_data(&self.scheduling, maximum)?,
        ];
        terms.into_iter().try_fold(0usize, |total, next| {
            total
                .checked_add(next)
                .filter(|total| *total <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Borrows the complete historical native/model checkpoint and measurement.
    pub(crate) fn checkpoint_data(
        &self,
    ) -> (
        &PacketNativeRestoredRecord,
        &PacketNative5UnderlyingRecord,
        &ContentRef,
    ) {
        (&self.record, &self.underlying, &self.measurement)
    }

    /// Returns the saved actual post-evidence first-observation SDK frontier.
    pub(crate) fn completed_frontier_data(&self) -> U64 {
        self.sdk.completed_frontier_data()
    }

    /// Borrows the complete independently recomputed common observation.
    pub(crate) fn scheduling_data(&self) -> &NativeSchedulingObservation {
        &self.scheduling
    }
}

fn invalid() -> RuntimeError {
    RuntimeError::InvalidReceipt
}

impl OriginalSourceRestoredFirstObservationHistory17Read {
    pub(crate) fn binding_data(&self) -> &[u8; 32] {
        &self.binding
    }

    pub(crate) fn restoration_scope_data(&self) -> &crucible_node_provider::reference_packet::service::complete_restore::activation::PacketRestorationActivationScope{
        &self.sdk.request_data().scope
    }
}
