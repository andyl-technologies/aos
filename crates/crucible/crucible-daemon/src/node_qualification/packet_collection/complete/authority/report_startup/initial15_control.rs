//! Admits original Journal and Control decoders before native carrier sealing.
//!
//! A real fresh target authority and archive-ticketed capsule already exist.
//! Every prospective constructor row is retained before full policy readmission;
//! no late installed Window or successful parser can pay for earlier birth.

use super::super::super::capture_factory::Initial15ControlStep as Step;
use super::*;
use crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource;
use crucible_engine::node_contract::RuntimeError;
use crucible_engine::node_state::CompleteInitial15PrebirthControlAttempt as Attempt;
use std::mem::size_of;

impl PacketCompleteReportStartupHolder {
    /// Admits each actual original parser seam before native carrier sealing.
    ///
    /// # Errors
    /// Refuses foreign or repeated preparation, another selected family, missing
    /// target/tickets, a failed parser or the unchanged full resource policy.
    pub(in crate::node_qualification::packet_collection::complete) fn prepare_initial15_control_banks_data(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Ok(());
        };
        // The existing whole-holder/Source observer declares the new narrow
        // classifier controls in its policy. It runs before the first capsule
        // origin/family or Source declaration read, including unselected paths.
        // No parser or sequence once flag has been spent at this point.
        Self::current_original_scene_peak_data(original, &held)?;
        if !capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .requires_initial15_control_prebirth_data()?
        {
            return Ok(());
        }
        let maximum = usize::try_from(held.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        // This cached declaration is DATA. Admit its defining fixed observer
        // before walking it; unselected old startup behavior stays unchanged.
        let selected = held
            .authority
            .roster
            .sources
            .iter()
            .try_fold(false, |any, source| {
                Ok::<_, RuntimeError>(
                    any || source.is_original_restored_settled_capture_declaration_data()?,
                )
            })?;
        if !selected {
            return Ok(());
        }
        for source in &held.authority.roster.sources {
            if !source.is_original_restored_settled_capture_declaration_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        if held.attempted.get()
            || held.native_attempted.get()
            || held.host_sdk_attempted.get()
            || held.in_flight.get()
            || held.native_in_flight.get()
            || held.host_sdk_in_flight.get()
            || held.host_sdk_content.get().is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Selected work admits the complete quote/constructor observer controls
        // beside all current retained owners before spending this sequence.
        Self::observe_initial15_control_data(original, &held, maximum)?;
        let capsule_held = capsule.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        capsule_held
            .authenticate_native_startup_target_precredit_data(&held.authority, &held.plan)?;
        let completion = capsule_held.begin_initial15_control_data()?;
        for selected in 0..3 {
            for step in [
                Step::QuoteJournal,
                Step::ConstructJournal,
                Step::QuoteNormalization,
                Step::QuoteGeometry,
                Step::ConstructGeometry,
                Step::QuoteControl,
                Step::ConstructControl,
            ] {
                // No parser/output/Source loan survives either whole observation.
                Self::observe_initial15_control_data(original, &held, maximum)?;
                let result = capsule
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .prepare_initial15_control_step_data(
                        &held.authority,
                        &held.plan,
                        selected,
                        &held.authority.original_launches[selected],
                        step,
                        maximum,
                    );
                let observed = Self::observe_initial15_control_data(original, &held, maximum);
                result?;
                observed?;
            }
        }
        held.authenticate_native_origin_data()?;
        completion.finish();
        Ok(())
    }

    fn observe_initial15_control_data(
        original: &Rc<RefCell<Self>>,
        held: &Self,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        held.authenticate_native_origin_data()?;
        let policy = held
            .policy_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if policy.maximum_requested_bytes != maximum {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (parser_prewalk, _) = Attempt::prewalk_data();
        let (registration_prewalk, _) = PacketCompleteSemanticSource::original_initial15_prebirth_normalization_registration_prewalk_data::<
            crucible_node_transport::protocol_snapshot::Initial15MappingNormalizationConstructionData,
        >();
        let (normalization_prewalk, _) = crucible_node_transport::protocol_snapshot::PreparedArchivedProtocolMapping::initial15_normalization_prewalk_data();
        let prewalk = parser_prewalk
            .checked_add(registration_prewalk)
            .and_then(|bytes| bytes.checked_add(normalization_prewalk))
            .and_then(|bytes| bytes.checked_add(PacketCompleteRestorationPrebirth::initial15_control_normalization_failure_transient_data()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let fixed = policy
            .declared_observer_scratch_bytes
            .checked_add(Self::initial15_control_counter_scratch_data())
            .and_then(|bytes| bytes.checked_add(prewalk))
            .ok_or(RuntimeError::ResourceLimit)?;
        let available = maximum
            .checked_sub(fixed)
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut total = Self::storage_data(original, held, available)
            .map_err(|_| RuntimeError::ResourceLimit)?
            .retained_holder_bytes;
        for source in &held.authority.roster.sources {
            let bytes = source.original_complete_report_startup_retained_storage_precredit_data(
                available
                    .checked_sub(total)
                    .ok_or(RuntimeError::ResourceLimit)?,
            )?;
            total = total
                .checked_add(bytes)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        for axis in capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .initial15_control_construction_data()?
        {
            total = total
                .checked_add(axis)
                .filter(|bytes| *bytes <= available)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if total > available {
            return Err(RuntimeError::ResourceLimit);
        }
        held.graph_owner
            .authenticate_original_report_policy_data(&held.authority.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        held.authenticate_native_origin_data()
    }

    pub(super) fn initial15_control_classification_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        let origin =
            PacketCompleteRestorationPrebirth::original_fresh_construction_counter_scratch_data()?;
        let local = PacketCompleteSemanticSource::original_restored_settled_capture_declaration_counter_scratch_data()
            + size_of::<&Rc<RefCell<Self>>>()
            + size_of::<std::cell::Ref<'static, Self>>()
            + size_of::<std::cell::Ref<'static, PacketCompleteRestorationPrebirth>>()
            + size_of::<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<bool>()
            + size_of::<[usize; 2]>()
            + size_of::<Option<usize>>();
        origin.checked_add(local).ok_or(RuntimeError::ResourceLimit)
    }

    fn initial15_control_counter_scratch_data() -> usize {
        PacketCompleteRestorationPrebirth::initial15_control_counter_scratch_data()
            + PacketCompleteSemanticSource::original_restored_settled_capture_declaration_counter_scratch_data()
            + size_of::<&Rc<RefCell<Self>>>()
            + size_of::<std::cell::Ref<'static, Self>>()
            + size_of::<std::cell::Ref<'static, PacketCompleteRestorationPrebirth>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<std::ops::Range<usize>>()
            + size_of::<[Step; 7]>()
            + size_of::<std::array::IntoIter<Step, 7>>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>()
            + size_of::<OriginalReportStartupPolicy>()
            + size_of::<OriginalReportStartupStorage>()
            + size_of::<Counter>()
    }
}
