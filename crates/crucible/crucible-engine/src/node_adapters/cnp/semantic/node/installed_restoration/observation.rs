//! Consumes the separately signed first observation under the real World gate.
//!
//! The Source retains the new receipt/model and lends its actual scheduling
//! observation inside SourceRead. Both Node copies precede the final opaque
//! evidence fence and Core ledger completion; refusal leaves every partial owned.

use super::*;
use crate::node_adapters::cnp::{
    CnpSemanticSource, OriginalSourceRestorationObservationConstructionData,
    OriginalSourceRestorationObservationVerifiedPhase,
};
use crate::node_contract::NodeRuntime;
use crate::node_scheduling::NativeSchedulingObservation;

impl super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn observe_installed_restoration(
        &mut self,
        world: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.current()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or_else(|| super::super::super::refused("selected native capsule absent"))?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected Source absent"))?;
        let controller = native
            .controller
            .as_mut()
            .ok_or_else(|| super::super::super::refused("selected Controller absent"))?;
        let runtime = native
            .runtime
            .as_mut()
            .ok_or_else(|| super::super::super::refused("selected runtime absent"))?;
        if !runtime
            .active
            .as_ref()
            .is_some_and(|active| active.same_authority(world))
        {
            return Err(super::super::super::refused(
                "selected observation changed actual World",
            ));
        }
        let selected = runtime
            .installed_restoration
            .as_mut()
            .ok_or_else(|| super::super::super::refused("selected association absent"))?;
        if !selected.installed || selected.observation_attempted {
            return Err(super::super::super::refused(
                "selected first observation is spent or uninstalled",
            ));
        }
        let admitted = selected
            .association
            .admitted_source_observation_data()
            .map_err(super::super::super::refused_display)?;
        selected.observation_attempted = true;
        let claim = selected
            .association
            .begin_original_observation_claim_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                world,
            )
            .map_err(super::super::super::refused_display)?;
        let evidence = source
            .call_original_installed_restoration_observation_into(
                controller,
                claim,
                &admitted,
                &mut selected.observation_completed,
            )
            .map_err(super::super::super::unknown)?;

        let InstalledRestorationCustody {
            association,
            observation,
            observation_return,
            ..
        } = selected;
        association
            .with_original_observation_scheduling_data(source.as_ref(), &evidence, |actual| {
                retain_scheduling_copies(
                    actual,
                    observation,
                    observation_return,
                    admitted.node_scheduling_copy_requested_bytes_data(),
                )
            })
            .map_err(super::super::super::unknown)?;
        // The association gate completed the genuine once ledger only after
        // both copies and final Source currency. No callback/allocation follows.
        observation_return
            .take()
            .ok_or_else(|| super::super::super::unknown("selected observation return owner absent"))
    }

    pub(in crate::node_adapters::cnp::semantic) fn validate_installed_restoration_observation(
        &self,
        world: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected native capsule absent"))?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected Source absent"))?;
        let controller = native
            .controller
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected Controller absent"))?;
        let runtime = native
            .runtime
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected runtime absent"))?;
        if !runtime
            .active
            .as_ref()
            .is_some_and(|active| active.same_authority(world))
        {
            return Err(super::super::super::refused(
                "selected observation changed actual World",
            ));
        }
        let selected = runtime
            .installed_restoration
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected association absent"))?;
        let saved = selected
            .observation
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected observation owner absent"))?;
        selected
            .association
            .with_original_current_observation_scheduling_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                world,
                |actual| {
                    if actual != saved || actual != observation {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                    Ok(())
                },
            )
            .map_err(super::super::super::unknown)
    }
}

// This is a private copy operation, never an evidence authenticator. Its sole
// production caller is inside the genuine Core/SourceRead unit gate above.
fn retain_scheduling_copies(
    actual: &NativeSchedulingObservation,
    retained: &mut Option<NativeSchedulingObservation>,
    returned: &mut Option<NativeSchedulingObservation>,
    maximum: usize,
) -> Result<(), RuntimeError> {
    if retained.is_some() || returned.is_some() {
        return Err(RuntimeError::InvalidReceipt);
    }
    let one = NodeRuntime::capture_scheduling_observation_storage_data(actual, maximum)?;
    if one.checked_mul(2).ok_or(RuntimeError::ResourceLimit)? > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    // Source evidence keeps its owned claim through both retained copies and
    // the final Source/member/kernel fence. Refusal never discards these slots.
    *retained = Some(actual.clone());
    *returned = Some(actual.clone());
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    use crucible_node_transport::{client::CnpController, ProviderError};
    use crucible_node_transport::reference_packet::service::complete_restore::restoration_observe::{
        OriginalInstalledRestorationObservationConstructionData,
        original_installed_restoration_observation_construction_counter_scratch_data,
        restoration_observe_protocol_counter_scratch_data,
    };
    use crate::node_admission::OriginalInstalledRestorationObservationClaim;
    use crate::node_adapters::cnp::semantic::{
        process::CnpSemanticProcessCustody,
        state::SemanticRuntimeCustody,
    };
    let fixed = size_of::<OriginalSourceRestorationObservationConstructionData>()
        + size_of::<Result<OriginalSourceRestorationObservationConstructionData, RuntimeError>>()
        + size_of::<OriginalInstalledRestorationObservationClaim>()
        + size_of::<Result<OriginalInstalledRestorationObservationClaim, RuntimeError>>()
        + size_of::<OriginalSourceRestorationObservationVerifiedPhase<'static>>()
        + size_of::<Result<OriginalSourceRestorationObservationVerifiedPhase<'static>, RuntimeError>>(
        )
        + size_of::<&OriginalSourceRestorationObservationVerifiedPhase<'static>>()
        + size_of::<NativeSchedulingObservation>()
        + size_of::<Option<NativeSchedulingObservation>>()
        + size_of::<Option<&NativeSchedulingObservation>>()
        + size_of::<Result<NativeSchedulingObservation, OperationFailure>>()
        + size_of::<Result<&NativeSchedulingObservation, RuntimeError>>()
        + 2 * size_of::<&mut Option<NativeSchedulingObservation>>()
        + size_of::<&NativeSchedulingObservation>()
        + size_of::<&OriginalSourceRestorationObservationConstructionData>()
        + size_of::<OriginalInstalledRestorationObservationConstructionData>()
        + size_of::<Option<OriginalInstalledRestorationObservationConstructionData>>()
        + size_of::<Option<&OriginalInstalledRestorationObservationConstructionData>>()
        + size_of::<Result<OriginalInstalledRestorationObservationConstructionData, ProviderError>>(
        )
        + size_of::<Result<bool, RuntimeError>>()
        + size_of::<Option<crucible_node_transport::bodies::ResponseBody>>()
        + size_of::<Option<&crucible_node_transport::bodies::ResponseBody>>()
        + size_of::<&mut Option<crucible_node_transport::bodies::ResponseBody>>()
        + size_of::<&Rc<dyn CnpSemanticSource>>()
        + size_of::<&dyn CnpSemanticSource>()
        + size_of::<&CnpController>()
        + size_of::<&mut CnpController>()
        + size_of::<Option<&mut CnpController>>()
        + size_of::<Option<&CnpController>>()
        + size_of::<Result<&mut CnpController, OperationFailure>>()
        + size_of::<Result<&CnpController, OperationFailure>>()
        + size_of::<Option<&Rc<dyn CnpSemanticSource>>>()
        + size_of::<Result<&Rc<dyn CnpSemanticSource>, OperationFailure>>()
        + size_of::<Option<&mut Box<CnpSemanticProcessCustody>>>()
        + size_of::<Option<&Box<CnpSemanticProcessCustody>>>()
        + size_of::<Result<&mut Box<CnpSemanticProcessCustody>, OperationFailure>>()
        + size_of::<Result<&Box<CnpSemanticProcessCustody>, OperationFailure>>()
        + size_of::<Option<&mut SemanticRuntimeCustody>>()
        + size_of::<Option<&SemanticRuntimeCustody>>()
        + size_of::<Result<&mut SemanticRuntimeCustody, OperationFailure>>()
        + size_of::<Result<&SemanticRuntimeCustody, OperationFailure>>()
        + size_of::<Option<&mut InstalledRestorationCustody>>()
        + size_of::<Option<&InstalledRestorationCustody>>()
        + size_of::<Result<&mut InstalledRestorationCustody, OperationFailure>>()
        + size_of::<Result<&InstalledRestorationCustody, OperationFailure>>()
        + size_of::<Result<&NativeSchedulingObservation, OperationFailure>>()
        + size_of::<*const ()>()
        + size_of::<bool>()
        + size_of::<&WorldActivation>()
        + size_of::<Option<&WorldActivation>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, RuntimeError>>()
        + 3 * size_of::<usize>()
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>();
    [
        fixed,
        original_installed_restoration_observation_construction_counter_scratch_data(),
        restoration_observe_protocol_counter_scratch_data(),
        super::super::super::PacketCompleteSemanticSource::original_restoration_observation_declaration_counter_scratch_data(),
        super::super::super::PacketCompleteSemanticSource::original_restoration_observation_source_construction_counter_scratch_data(),
    ].into_iter().try_fold(0usize, usize::checked_add).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::OwnerIdentity;
    use crate::node_scheduling::{NativeOutputBound, NativeProducerBound, NativePublication};
    use crucible_node_format::{Endpoint, Id, Phase, Position, U64, canonical};

    fn observation() -> NativeSchedulingObservation {
        let position = Position::new(U64::new(0), U64::new(0), Phase::Publication);
        let mut bytes = Vec::with_capacity(19);
        bytes.extend_from_slice(b"actual retained output");
        let payload = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
        let proof = canonical::content_ref(b"pure copy fixture", "application/json").unwrap();
        NativeSchedulingObservation {
            node: Id::new("actual-node").unwrap(),
            owners: vec![OwnerIdentity {
                owner: Id::new("actual-owner").unwrap(),
                incarnation: Id::new("actual-incarnation").unwrap(),
                generation: U64::new(3),
            }],
            reached: position,
            closed_prefix: position,
            bounds: vec![NativeProducerBound {
                producer: Id::new("actual-node").unwrap(),
                bound: NativeOutputBound::AfterInstant(U64::new(0)),
                proof_ref: proof.clone(),
            }],
            publications: vec![NativePublication {
                publication_id: Id::new("actual-output").unwrap(),
                endpoint: Endpoint {
                    node_id: Id::new("actual-node").unwrap(),
                    port_id: Id::new("actual-port").unwrap(),
                    lane_id: Id::new("actual-lane").unwrap(),
                },
                native_sequence: U64::new(1),
                publication: position,
                evaluation: Some(position),
                causal_parents: vec![position],
                payload,
                payload_bytes: bytes,
            }],
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: proof,
        }
    }

    #[test]
    fn actual_two_scheduling_copies_fit_exact_census_and_one_short_retains_no_copy() {
        let actual = observation();
        let one =
            NodeRuntime::capture_scheduling_observation_storage_data(&actual, usize::MAX).unwrap();
        let exact = one.checked_mul(2).unwrap();
        let mut retained = None;
        let mut returned = None;

        assert!(
            retain_scheduling_copies(&actual, &mut retained, &mut returned, exact - 1).is_err()
        );
        assert!(retained.is_none() && returned.is_none());
        retain_scheduling_copies(&actual, &mut retained, &mut returned, exact).unwrap();

        let saved = retained.as_ref().unwrap();
        let output = returned.as_ref().unwrap();
        assert_eq!(saved, &actual);
        assert_eq!(output, &actual);
        assert_ne!(
            saved.publications[0].payload_bytes.as_ptr(),
            output.publications[0].payload_bytes.as_ptr()
        );
        let copied = NodeRuntime::capture_scheduling_observation_storage_data(saved, exact)
            .unwrap()
            + NodeRuntime::capture_scheduling_observation_storage_data(output, exact).unwrap();
        assert!(copied <= exact);
    }

    #[test]
    fn real_retained_scheduling_slots_cannot_be_replaced_by_another_copy() {
        let actual = observation();
        let mut retained = None;
        let mut returned = None;
        retain_scheduling_copies(&actual, &mut retained, &mut returned, usize::MAX).unwrap();
        let mut changed = actual.clone();
        changed.node = Id::new("foreign-node").unwrap();

        assert!(
            retain_scheduling_copies(&changed, &mut retained, &mut returned, usize::MAX).is_err()
        );
        assert_eq!(retained.as_ref(), Some(&actual));
        assert_eq!(returned.as_ref(), Some(&actual));
    }
}
