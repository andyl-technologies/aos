//! Keeps the actual target publisher behind the same original capsule loan.

use super::super::super::restored_publication::{
    PacketRestoredProducerPublicationInputs, StoredPacketRestoredProducerResultPublisher,
};
use super::*;
use crucible_engine::node_contract::RuntimeError;

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn retain_original_restored_results_into(
        &mut self,
        holder: &Rc<RefCell<super::super::super::PacketCompleteReportStartupHolder>>,
        plan: Rc<InstalledConformancePlan>,
        incoming: &mut Option<PacketRestoredProducerPublicationInputs>,
        maximum: usize,
    ) -> Result<*const (), RuntimeError> {
        self.authenticate_creator()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let original = self
            .report_startup_holder
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !Rc::ptr_eq(holder, &original)
            || self.restored_results.is_some()
            || self.runtime.is_none()
            || self.failed_runtime.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let request = incoming.take().ok_or(RuntimeError::OwnerUnavailable)?;
        self.restored_results = Some(RefCell::new(
            StoredPacketRestoredProducerResultPublisher::retain(
                plan,
                request.blobs,
                request.refs,
                request.references,
                maximum,
            ),
        ));
        Ok(self
            .restored_results
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .as_ptr()
            .cast())
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn original_restored_result_counter_scratch_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        if self.restored_results.is_none() {
            return Ok(0);
        }
        use std::mem::{size_of, size_of_val};
        type Publisher = StoredPacketRestoredProducerResultPublisher;
        let terms = [
            Publisher::counter_scratch_data()?,
            Self::runtime_owner_counter_scratch_data(),
            crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource::original_restored_producer_outcome_counter_scratch_data(),
            crucible_node_transport::reference_packet::service::complete_restore::producer_progress::original_restored_producer_report_counter_scratch_data(),
            size_of::<std::cell::Ref<'static, Publisher>>(),
            size_of::<std::cell::RefMut<'static, Publisher>>(),
            size_of::<Result<std::cell::Ref<'static, Publisher>, std::cell::BorrowError>>(),
            size_of::<Result<std::cell::RefMut<'static, Publisher>, std::cell::BorrowMutError>>(),
            size_of::<Result<std::cell::Ref<'static, Publisher>, RuntimeError>>(),
            size_of::<Result<std::cell::RefMut<'static, Publisher>, RuntimeError>>(),
            size_of::<Option<PacketRestoredProducerPublicationInputs>>(),
            size_of::<&mut Option<PacketRestoredProducerPublicationInputs>>(),
            size_of::<Result<PacketRestoredProducerPublicationInputs, RuntimeError>>(),
            size_of::<Option<Rc<RefCell<super::super::super::PacketCompleteReportStartupHolder>>>>(),
            size_of::<Result<Rc<RefCell<super::super::super::PacketCompleteReportStartupHolder>>, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<*const ()>(), size_of::<Option<*const ()>>(),
            size_of::<Result<*const (), RuntimeError>>(),
            size_of::<&crucible_engine::node_admission::OriginalRestorationConstructionInputs<'static>>(),
            size_of::<&crucible_engine::node_admission::OriginalRestorationConstructionScope<'static>>(),
            size_of::<crucible_engine::node_admission::OriginalRestorationConstructionPhase>(),
            size_of::<crucible_engine::node_adapters::cnp::OriginalRestoredProducerOutcomeConstructionData>(),
            size_of::<Result<crucible_engine::node_adapters::cnp::OriginalRestoredProducerOutcomeConstructionData, RuntimeError>>(),
            size_of::<crucible_engine::node_adapters::cnp::OriginalRestoredProducerOutcomeProjection<'static>>(),
            size_of::<Result<crucible_engine::node_adapters::cnp::OriginalRestoredProducerOutcomeProjection<'static>, RuntimeError>>(),
            size_of::<crucible_node_transport::reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerReportStorageData>(),
            size_of::<Result<crucible_node_transport::reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerReportStorageData, crucible_node_transport::ProviderError>>(),
            size_of::<Result<crucible_node_transport::reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerReportStorageData, RuntimeError>>(),
            size_of::<std::slice::Iter<'static, Rc<crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource>>>(),
            size_of::<std::iter::Enumerate<std::slice::Iter<'static, Rc<crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource>>>>(),
            size_of::<crucible_engine::node_adapters::cnp::PacketCompleteSourceRole>(),
            size_of::<Option<usize>>(), size_of::<Result<usize, RuntimeError>>(),
            size_of::<PublisherInitializationInputs<'static>>(),
            size_of::<&PublisherInitializationInputs<'static>>(),
            size_of::<&crucible_engine::node_admission::OriginalRestoredProducerPublisherConstructionScope<'static>>(),
            size_of::<(*const (), crucible_engine::node_contract::OriginalRestoredProducerPublicationConstructionData)>(),
            size_of::<Option<(*const (), crucible_engine::node_contract::OriginalRestoredProducerPublicationConstructionData)>>(),
            size_of::<Result<Option<(*const (), crucible_engine::node_contract::OriginalRestoredProducerPublicationConstructionData)>, RuntimeError>>(),
            size_of::<(*const (), &crucible_engine::node_contract::OriginalRestoredProducerPublicationConstructionData)>(),
            size_of::<Option<(*const (), &crucible_engine::node_contract::OriginalRestoredProducerPublicationConstructionData)>>(),
            size_of::<(Option<(*const (), &crucible_engine::node_contract::OriginalRestoredProducerPublicationConstructionData)>, Option<(*const (), crucible_engine::node_contract::OriginalRestoredProducerPublicationConstructionData)>)>(),
            size_of::<&crucible_engine::node_state::CompleteOriginalRestorationSource>(),
            size_of::<Result<&crucible_engine::node_state::CompleteOriginalRestorationSource, RuntimeError>>(),
            size_of::<&ConformanceRuntime>(), size_of::<Result<&ConformanceRuntime, RuntimeError>>(),
            size_of::<Option<&ConformanceRuntime>>(),
            size_of::<Option<&RefCell<Publisher>>>(),
            size_of::<Result<&RefCell<Publisher>, RuntimeError>>(),
            size_of::<&crucible_engine::node_contract::ActivationRecord>(),
            size_of::<std::slice::Iter<'static, usize>>(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn original_restored_result_candidate_data(
        &self,
        plan: &InstalledConformancePlan,
        inputs: &crucible_engine::node_admission::OriginalRestorationConstructionInputs<'_>,
        scope: Option<&crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>>,
    ) -> Result<
        Option<(
            *const (),
            crucible_engine::node_contract::OriginalRestoredProducerPublicationConstructionData,
        )>,
        RuntimeError,
    > {
        let Some(owner) = &self.restored_results else {
            return Ok(None);
        };
        self.authenticate_restoration_storage_scope_data(
            inputs.archive,
            inputs.runtime,
            plan,
            inputs.activation,
            scope,
        )?;
        let mut selected = None;
        for (index, source) in inputs.sources.iter().enumerate() {
            if source.role()
                == crucible_engine::node_adapters::cnp::PacketCompleteSourceRole::Producer
                && selected.replace(index).is_some()
            {
                return Err(RuntimeError::UnsupportedFacet);
            }
        }
        let selected = selected.ok_or(RuntimeError::UnsupportedFacet)?;
        let mut publisher = owner
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        publisher.authenticate_plan_data(plan)?;
        let source = &inputs.sources[selected];
        let report = crucible_node_transport::reference_packet::service::complete_restore::producer_progress::original_restored_producer_report_storage_data(
            &inputs.launches[selected], publisher.maximum_requested_data(),
        ).map_err(|_| RuntimeError::ResourceLimit)?;
        let outcome = source.original_restored_producer_outcome_construction_data(
            inputs.activation,
            publisher.maximum_requested_data(),
        )?;
        let projection =
            source.original_restored_producer_outcome_projection_data(inputs.activation)?;
        let slots = publisher.funded_capacity_data();
        let scratch = report
            .counter_scratch_bytes_data()
            .checked_add(outcome.counter_scratch_bytes_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        let row = *publisher.construction_data(
            &projection,
            report.maximum_report_encoded_bytes_data(),
            outcome.maximum_encoded_bytes_data(),
            scratch,
            slots,
        )?;
        Ok(Some((owner.as_ptr().cast(), row)))
    }

    pub(in crate::node_qualification::packet_collection::complete) fn initialize_original_restored_results_data(
        &self,
        window: &Rc<crucible_engine::node_admission::CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        target: &crucible_engine::node_contract::ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let Some(owner) = &self.restored_results else {
            return Ok(());
        };
        let runtime = self.runtime_data()?;
        self.authenticate_restoration_target_storage_data(
            self.source
                .original_restoration_source_data(&runtime, plan, target)?,
            &runtime,
            plan,
            target,
        )?;
        let inputs = PublisherInitializationInputs {
            owner,
            window,
            actions: &self.restored_actions,
        };
        window.with_original_admitted_restored_producer_publication_data(
            plan,
            &runtime,
            target,
            owner.as_ptr().cast(),
            |scope| inputs.initialize(scope),
        )
    }
}

struct PublisherInitializationInputs<'a> {
    owner: &'a RefCell<StoredPacketRestoredProducerResultPublisher>,
    window: &'a Rc<crucible_engine::node_admission::CompleteOriginalRestorationWindow>,
    actions: &'a RefCell<
        Vec<RefCell<super::super::super::restored_publication::RestoredProducerAction>>,
    >,
}

impl PublisherInitializationInputs<'_> {
    fn initialize(
        &self,
        scope: &crucible_engine::node_admission::OriginalRestoredProducerPublisherConstructionScope<
            '_,
        >,
    ) -> Result<(), RuntimeError> {
        let mut actions = self
            .actions
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !actions.is_empty() || actions.capacity() != 0 {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.owner
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .initialize_admitted_data(scope, self.window)?;
        actions
            .try_reserve_exact(scope.funded_capacity_data())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        actions.resize_with(
            scope.funded_capacity_data(),
            super::super::super::restored_publication::RestoredProducerAction::new_owner,
        );
        scope.authenticate_current_data()
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn charge_restored_actions_data(
        actions: &RefCell<
            Vec<RefCell<super::super::super::restored_publication::RestoredProducerAction>>,
        >,
        counter: &mut super::super::super::retained::Counter,
    ) -> Result<(), RuntimeError> {
        let actions = actions.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        counter
            .add(
                actions
                    .capacity()
                    .checked_mul(std::mem::size_of::<
                        RefCell<super::super::super::restored_publication::RestoredProducerAction>,
                    >())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for action in actions.iter() {
            action
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .charge_retained_storage_data(counter)?;
        }
        Ok(())
    }
}
