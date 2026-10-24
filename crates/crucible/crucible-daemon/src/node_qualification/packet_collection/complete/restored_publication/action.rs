//! Retains actual per-action admissions, native results and caller DATA views.
//!
//! The independently admitted action bank is separate from the Directory
//! placement bank so the real prepare census can observe both without a
//! publisher mutation loan. No token, outcome or admission is cloned here.

use super::*;

/// Retains one actual holder-side action without extracting Runtime authority.
#[derive(Default)]
pub(in crate::node_qualification::packet_collection::complete) struct RestoredProducerAction {
    pub(in crate::node_qualification::packet_collection::complete) admission:
        Option<crucible_engine::node_admission::OriginalRestoredProducerExecutionAdmission>,
    pub(in crate::node_qualification::packet_collection::complete) begin:
        Option<crucible_engine::node_contract::BeginResult>,
    pub(in crate::node_qualification::packet_collection::complete) outcome:
        Option<OperationOutcome>,
    pub(in crate::node_qualification::packet_collection::complete) completed: bool,
}

impl RestoredProducerAction {
    pub(in crate::node_qualification::packet_collection::complete) fn new_owner()
    -> std::cell::RefCell<Self> {
        std::cell::RefCell::new(Self::default())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn charge_retained_storage_data(
        &self,
        counter: &mut super::super::retained::Counter,
    ) -> Result<(), RuntimeError> {
        if let Some(admission) = &self.admission {
            counter
                .add(admission.retained_requested_storage_precredit_data(counter.remaining())?)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        if let Some(begin) = &self.begin {
            match begin {
                crucible_engine::node_contract::BeginResult::Accepted(token)
                | crucible_engine::node_contract::BeginResult::Uncertain { token, .. } => {
                    let facts = token.retained_requested_storage_data(counter.remaining())?;
                    counter
                        .core(&facts)
                        .map_err(|_| RuntimeError::ResourceLimit)?;
                }
                crucible_engine::node_contract::BeginResult::Refused(refusal) => {
                    counter
                        .add(refusal.reason.capacity())
                        .map_err(|_| RuntimeError::ResourceLimit)?;
                }
            }
        }
        if let Some(outcome) = &self.outcome {
            counter
                .add(NodeRuntime::original_outcome_requested_storage_data(
                    outcome,
                    counter.remaining(),
                )?)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        Ok(())
    }
}

impl RestoredProducerAction {
    pub(in crate::node_qualification::packet_collection::complete) fn counter_scratch_data()
    -> Result<usize, RuntimeError> {
        use crucible_engine::node_admission::OriginalRestoredProducerExecutionAdmission as Admission;
        use crucible_engine::node_contract::{
            BeginResult, OperationToken, RetainedCoreOwnerStorage, RetainedCoreSharedAllocation,
            RuntimePollFailure,
        };
        use std::cell::{BorrowError, BorrowMutError, Ref, RefCell, RefMut};
        type Actions = Vec<RefCell<RestoredProducerAction>>;
        let terms = [
            Admission::retained_counter_scratch_data(),
            size_of::<
                std::cell::Ref<'static, super::super::authority::PacketCompleteReportStartupHolder>,
            >(),
            size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        super::super::authority::PacketCompleteReportStartupHolder,
                    >,
                    std::cell::BorrowError,
                >,
            >(),
            size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        super::super::authority::PacketCompleteReportStartupHolder,
                    >,
                    RuntimePollFailure,
                >,
            >(),
            size_of::<
                std::cell::Ref<
                    'static,
                    super::super::capture_factory::PacketCompleteRestorationPrebirth,
                >,
            >(),
            size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        super::super::capture_factory::PacketCompleteRestorationPrebirth,
                    >,
                    std::cell::BorrowError,
                >,
            >(),
            size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        super::super::capture_factory::PacketCompleteRestorationPrebirth,
                    >,
                    RuntimePollFailure,
                >,
            >(),
            size_of::<std::cell::RefMut<'static, crucible_engine::node_contract::ConformanceRuntime>>(
            ),
            size_of::<
                Result<
                    std::cell::RefMut<'static, crucible_engine::node_contract::ConformanceRuntime>,
                    RuntimePollFailure,
                >,
            >(),
            size_of::<RefMut<'static, StoredPacketRestoredProducerResultPublisher>>(),
            size_of::<
                Result<
                    RefMut<'static, StoredPacketRestoredProducerResultPublisher>,
                    BorrowMutError,
                >,
            >(),
            size_of::<
                Result<
                    RefMut<'static, StoredPacketRestoredProducerResultPublisher>,
                    RuntimePollFailure,
                >,
            >(),
            size_of::<Option<&RefCell<StoredPacketRestoredProducerResultPublisher>>>(),
            size_of::<
                Result<&RefCell<StoredPacketRestoredProducerResultPublisher>, RuntimePollFailure>,
            >(),
            size_of::<
                Ref<
                    'static,
                    [Option<crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk>; 3],
                >,
            >(),
            size_of::<
                Result<
                    Ref<
                        'static,
                        [Option<crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk>;
                            3],
                    >,
                    BorrowError,
                >,
            >(),
            size_of::<
                Result<
                    Ref<
                        'static,
                        [Option<crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk>;
                            3],
                    >,
                    RuntimePollFailure,
                >,
            >(),
            size_of::<[&crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3]>(),
            size_of::<
                Result<
                    &crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk,
                    RuntimePollFailure,
                >,
            >(),
            size_of::<
                Option<
                    &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
                >,
            >(),
            size_of::<
                Result<
                    &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
                    RuntimePollFailure,
                >,
            >(),
            size_of::<Option<&&[u8]>>(),
            size_of::<Result<&&[u8], RuntimePollFailure>>(),
            size_of::<[&[u8]; 3]>(),
            size_of::<[&Vec<u8>; 3]>(),
            size_of::<std::array::IntoIter<&Vec<u8>, 3>>(),
            size_of::<fn(&Vec<u8>) -> &[u8]>(),
            size_of::<crucible_node_format::Id>(),
            size_of::<&crucible_node_format::Id>(),
            size_of::<crucible_node_format::U64>(),
            size_of::<Option<&RetainedCoreSharedAllocation>>(),
            size_of::<std::option::Iter<'static, RetainedCoreSharedAllocation>>(),
            size_of::<Self>(),
            size_of::<&Self>(),
            size_of::<&mut Self>(),
            size_of::<fn() -> RefCell<Self>>(),
            size_of::<RefCell<Self>>(),
            size_of::<&RefCell<Self>>(),
            size_of::<Actions>(),
            size_of::<&RefCell<Actions>>(),
            size_of::<Ref<'static, Actions>>(),
            size_of::<RefMut<'static, Actions>>(),
            size_of::<Result<Ref<'static, Actions>, BorrowError>>(),
            size_of::<Result<RefMut<'static, Actions>, BorrowMutError>>(),
            size_of::<Result<Ref<'static, Actions>, RuntimeError>>(),
            size_of::<Result<RefMut<'static, Actions>, RuntimeError>>(),
            size_of::<Result<Ref<'static, Actions>, RuntimePollFailure>>(),
            size_of::<Ref<'static, Self>>(),
            size_of::<RefMut<'static, Self>>(),
            size_of::<Result<Ref<'static, Self>, BorrowError>>(),
            size_of::<Result<RefMut<'static, Self>, BorrowMutError>>(),
            size_of::<Result<Ref<'static, Self>, RuntimeError>>(),
            size_of::<Result<RefMut<'static, Self>, RuntimeError>>(),
            size_of::<Result<RefMut<'static, Self>, RuntimePollFailure>>(),
            size_of::<Option<&RefCell<Self>>>(),
            size_of::<Result<&RefCell<Self>, RuntimePollFailure>>(),
            size_of::<std::slice::Iter<'static, RefCell<Self>>>(),
            size_of::<Admission>(),
            size_of::<Option<Admission>>(),
            size_of::<Result<Admission, RuntimeError>>(),
            size_of::<&Admission>(),
            size_of::<&mut Admission>(),
            size_of::<Option<&Admission>>(),
            size_of::<Option<&mut Admission>>(),
            size_of::<Result<&mut Admission, RuntimePollFailure>>(),
            size_of::<BeginResult>(),
            size_of::<Option<BeginResult>>(),
            size_of::<&mut Option<BeginResult>>(),
            size_of::<Option<&BeginResult>>(),
            size_of::<Result<BeginResult, RuntimeError>>(),
            size_of::<Result<&BeginResult, RuntimePollFailure>>(),
            size_of::<&OperationToken>(),
            size_of::<&crucible_engine::node_contract::Refusal>(),
            size_of::<OperationOutcome>(),
            size_of::<Option<OperationOutcome>>(),
            size_of::<&mut Option<OperationOutcome>>(),
            size_of::<Option<&OperationOutcome>>(),
            size_of::<Result<OperationOutcome, RuntimePollFailure>>(),
            size_of::<Result<&OperationOutcome, RuntimePollFailure>>(),
            size_of::<&mut dyn FnMut(&OperationOutcome) -> Result<(), RuntimeError>>(),
            size_of::<(
                &mut Option<Admission>,
                &mut Option<BeginResult>,
                &mut Option<OperationOutcome>,
                &mut bool,
            )>(),
            size_of::<RetainedCoreOwnerStorage<'static>>(),
            size_of::<Result<RetainedCoreOwnerStorage<'static>, RuntimeError>>(),
            size_of::<
                std::iter::Flatten<std::slice::Iter<'static, Option<RetainedCoreSharedAllocation>>>,
            >(),
            size_of::<RetainedCoreSharedAllocation>(),
            size_of::<&RetainedCoreSharedAllocation>(),
            size_of::<RuntimePollFailure>(),
            size_of::<RuntimeError>(),
            size_of::<Result<(), RuntimePollFailure>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<(), std::collections::TryReserveError>>(),
            size_of::<Option<usize>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<usize>(),
            size_of::<bool>(),
            size_of::<&mut bool>(),
        ];
        terms
            .iter()
            .try_fold(size_of_val(&terms), |total, bytes| add(total, *bytes))
    }
}
