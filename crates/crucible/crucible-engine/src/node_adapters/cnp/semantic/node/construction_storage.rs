//! Counts and retains the original collecting-node admission beneath its real graph.
//!
//! Requested data describes new node/route/request/hash/boxed-preparation
//! ownership and the actual provider-receiver reservation. Source, graph, registry
//! and native validation and oracle callbacks are
//! independently admitted by the enclosing same-holder construction action.

use super::*;
use crate::node_adapters::cnp::semantic::{
    packet_complete_source::PacketCompleteSemanticSource,
    packet_connected_source::PacketConnectedSemanticSource, packet_source::PacketSemanticSource,
};
use crate::node_contract::{NodeRuntime, RuntimeError, RuntimeOwnedStorage};
use crucible_node_transport::{ProviderError, client::OriginalObservationReceiveStorageData};
use std::{
    any::Any,
    mem::size_of,
    panic::{AssertUnwindSafe, catch_unwind},
};

/// Names new owning requests for one original inactive collecting CNP node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CnpConformanceNodeConstructionStorageData {
    retained: usize,
    retained_receiver_reservation: usize,
    transient: usize,
    scratch: usize,
}

impl CnpConformanceNodeConstructionStorageData {
    /// Returns the new concrete node/boxed-preparation/route requested bytes.
    pub fn retained_requested_bytes(self) -> usize {
        self.retained
    }

    /// Returns future provider-receiver backing at the actual unchanged SDK ceilings.
    ///
    /// The enclosing Core member retains this charge after node construction.
    /// Existing owners, controller-origin journals, transient work and observation
    /// growth remain independently funded. This DATA grants no quota or allocation
    /// right.
    pub fn retained_receiver_reservation_bytes(self) -> usize {
        self.retained_receiver_reservation
    }

    /// Returns simultaneous local request, identity and diagnostic requests.
    pub fn maximum_simultaneous_transient_bytes(self) -> usize {
        self.transient
    }

    /// Returns explicit fixed counter/view headers, excluding compiler frames.
    pub fn declared_counter_scratch_bytes(self) -> usize {
        self.scratch
    }
}

impl CnpSemanticPreparation {
    /// Quotes the same original node conversion without currentness callbacks.
    ///
    /// This DATA walk compares actual Source allocation and realized full DTOs.
    /// It creates no graph, remote Admit, source permission or runtime authority.
    /// The enclosing action admits this counter before calling it and separately
    /// funds all original Source/graph/native/registry callback construction.
    ///
    /// # Errors
    /// Refuses foreign creator/Source, changed realized DTOs, absent completed
    /// original Admit, an occupied runtime slot, a nonidle receiver or checked
    /// requested overflow.
    pub fn original_conformance_node_construction_storage_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        maximum: usize,
    ) -> Result<CnpConformanceNodeConstructionStorageData, RuntimeError> {
        self.authenticate_original_node_source_data(source)?;
        let native = self
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        // The initial lifecycle must have retained its actual witness before
        // this prospective node census. A later Capture path cannot supply it.
        if native
            .protocol_supervisor
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_none()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if native.runtime.is_some()
            || !native.completed_ack_protocol_started
            || native
                .completed_ack_admission
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let selected = source.installation();
        let identity = [
            &selected.descriptor.id,
            &selected.owner.owner.id,
            &selected.binding.authority.incarnation_id,
            &selected.exact_facet.id,
        ]
        .into_iter()
        .try_fold(0usize, |sum, id| add(sum, id.allocated_capacity(), maximum))?;
        let retained = sum(
            &[
                size_of::<CnpSemanticNode>(),
                size_of::<CnpSemanticPreparation>(),
                size_of::<OwnerIdentity>(),
                identity,
            ],
            maximum,
        )?;
        let request = sum(
            &[
                size_of::<AdmitRequest>(),
                size_of::<crucible_node_format::NodeBinding>(),
                selected.binding.owned_storage()?,
                selected.world_binding_hash.owned_storage()?,
                selected.admission_receipt.owned_storage()?,
            ],
            maximum,
        )?;
        // Both this independent request and the expected identity exist before
        // completed-Admit validation; source callbacks are a separate row.
        let binding_phase = NodeRuntime::capture_serialization_storage(&selected.binding, maximum)?;
        let id_length = sum(
            &[
                "cnp-admit-".len(),
                selected.realize.realization_id.as_str().len(),
            ],
            maximum,
        )?;
        let id_formatting = closed_request_id_growth(id_length, maximum)?;
        let transient = sum(&[request, binding_phase, size_of::<crucible_node_format::HashRef>(),
            "blake3-256".len() + "cnp.node-binding.v1".len() + 64,
            selected.admission.allocated_capacity(), id_formatting,
            size_of::<blake3::Hasher>(), size_of::<blake3::Hash>(),
            returned_layout(|| blake3::Hash::from([0; 32]).to_hex()),
            super::super::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics::requested_bytes()], maximum)?;
        let retained_receiver_reservation = native
            .controller()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_observation_receive_storage_data(maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?
            .retained_requested_bytes_data();
        let scratch = Self::original_conformance_node_construction_counter_scratch_data();
        sum(
            &[retained, retained_receiver_reservation, transient, scratch],
            maximum,
        )?;
        Ok(CnpConformanceNodeConstructionStorageData {
            retained,
            retained_receiver_reservation,
            transient,
            scratch,
        })
    }

    /// Counts fixed original-node projection and diagnostic headers.
    pub fn original_conformance_node_construction_counter_scratch_data() -> usize {
        CnpController::original_observation_receive_counter_scratch_data()
            + size_of::<OriginalObservationReceiveStorageData>()
            + size_of::<Result<OriginalObservationReceiveStorageData, ProviderError>>()
            + size_of::<Option<&CnpController>>()
            + size_of::<usize>()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + super::super::implementation::selected_facet_counter_scratch_data()
            + PacketSemanticSource::reply_credit_selection_counter_scratch_data()
            + PacketConnectedSemanticSource::reply_credit_selection_counter_scratch_data()
            + size_of::<CnpConformanceNodeConstructionStorageData>()
            + size_of::<[&Id; 4]>() + size_of::<[usize; 9]>()
            + size_of::<AdmitRequest>() + size_of::<NodeRoute>()
            + size_of::<std::cell::Ref<'static, Option<super::super::packet_complete_source::OriginalCompletedCanonicalAckWorldAdmission>>>()
            + super::super::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics::counter_scratch_bytes()
            + size_of::<[u8; 20]>()
            + crucible_node_transport::client::CnpController::original_restoration_host_metadata_counter_scratch_data()
            + size_of::<std::cell::Ref<
                'static,
                Option<crucible_node_transport::connection::OriginalProtocolSupervisor>,
            >>()
            + size_of::<Result<
                std::cell::Ref<
                    'static,
                    Option<crucible_node_transport::connection::OriginalProtocolSupervisor>,
                >,
                std::cell::BorrowError,
            >>()
            + size_of::<Option<&crucible_node_transport::connection::OriginalRetainedSupervisor>>()
    }

    fn authenticate_original_node_source_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<(), RuntimeError> {
        self.guard.preparation_storage_origin_precredit_data()?;
        source.storage_origin_with_error::<RuntimeError>()?;
        let native = self
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let original = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if (Rc::as_ptr(original) as *const ()) != (Rc::as_ptr(source) as *const ())
            || self.descriptor() != &source.installation().descriptor
            || self.binding() != &source.installation().binding
            || self.owner_binding() != &source.installation().owner
            || native.conformance.is_none()
            || native.acceptance.is_some()
            || native.collection_plan.is_none()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Admits into fixed original slots while retaining refusal and unwind owners.
    ///
    /// Every existing graph/current-source/completed-Admit validation still runs.
    /// The selected path requires the already completed opaque original Admit;
    /// it cannot dispatch an additional remote Admit. The same non-cloneable
    /// registry and supervisor witnesses move only with the completed node,
    /// after all callbacks; no controller or witness can escape separately.
    ///
    /// # Errors
    /// Refuses occupied outputs, foreign Source or any original graph/node gate.
    /// A failed conversion leaves the same preparation and error/panic payload
    /// in caller slots, including its spent original token and runtime metadata.
    pub fn admit_original_conformance_node_into(
        original: &mut Option<Self>,
        source: &Rc<PacketCompleteSemanticSource>,
        graph: &crate::node_admission::ConformanceGraph,
        registry: &mut Option<crucible_node_transport::handshake::OriginalExtensionRegistryOwner>,
        supervisor: &mut Option<crucible_node_transport::connection::OriginalRetainedSupervisor>,
        operational: &mut Option<
            std::rc::Rc<dyn crucible_node_transport::connection::ConnectionSupervisor>,
        >,
        completed: &mut Option<super::super::CnpSemanticConformanceNode>,
        failure: &mut Option<OperationFailure>,
        unwind: &mut Option<Box<dyn Any + Send>>,
    ) -> Result<(), RuntimeError> {
        if completed.is_some() || failure.is_some() || unwind.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let preparation = original.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        preparation.authenticate_original_node_source_data(source)?;
        let native = preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !native.completed_ack_protocol_started
            || native
                .completed_ack_admission
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_none()
            || native.runtime.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // These exact original metadata owners stay in caller slots through
        // every fallible callback. No clone or erased supervisor fallback is used.
        let registry_loan = registry.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let supervisor_loan = supervisor.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let extension = native
            .extension_handshake
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        registry_loan
            .authenticate_original(extension)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let witness = native
            .protocol_supervisor
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let actual_operational = operational.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        witness
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate_original_operational_handle_data(actual_operational)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_live_host_metadata_facts_with_retained_supervisor(
                supervisor_loan,
                witness.as_ref(),
            )
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        drop(witness);
        let _diagnostics =
            super::super::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics::begin(
            );
        let result = catch_unwind(AssertUnwindSafe(|| {
            preparation.authenticate_original_conformance_graph(graph)?;
            preparation.prepare_original_node_installed(&graph.graph)
        }));
        let (route, exact_profile) = match result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                *failure = Some(error);
                return Err(RuntimeError::OwnerUnavailable);
            }
            Err(error) => {
                *unwind = Some(error);
                return Err(RuntimeError::OwnerUnavailable);
            }
        };
        let preparation = original.take().ok_or(RuntimeError::OwnerUnavailable)?;
        *completed = Some(super::super::CnpSemanticConformanceNode(CnpSemanticNode {
            preparation: Box::new(preparation),
            route,
            exact_profile,
            affinity: ThreadAffinity::OwnerThread(std::thread::current().id()),
            retained_registry: registry.take(),
            retained_supervisor: supervisor.take(),
            retained_operational: operational.take(),
        }));
        Ok(())
    }
}

// The fixed request_id formatter estimates twice its five literal bytes; its two dynamic string arguments append through
// RawVec's min-eight/doubling path. Sum each old/new request, not a byte factor.
fn closed_request_id_growth(length: usize, maximum: usize) -> Result<usize, RuntimeError> {
    let mut capacity = 2 * ("cnp-".len() + "-".len());
    let mut requested = capacity;
    while capacity < length {
        capacity = capacity
            .checked_mul(2)
            .ok_or(RuntimeError::ResourceLimit)?
            .max(length);
        requested = add(requested, capacity, maximum)?;
    }
    Ok(requested)
}

fn returned_layout<T>(_: impl FnOnce() -> T) -> usize {
    size_of::<T>()
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn sum(terms: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    terms
        .iter()
        .try_fold(0, |total, term| add(total, *term, maximum))
}

impl CnpSemanticPreparation {
    /// Names the actual known CNP node observer's nested counter banks.
    ///
    /// The trait leaf first authenticates its retained original witnesses. The
    /// fixed4 caller uses this same layout before any node exists; DATA alone
    /// cannot make an unknown or missing witness supported.
    ///
    /// # Errors
    /// Refuses checked layout overflow.
    pub fn original_conformance_node_retained_counter_scratch_data() -> Result<usize, RuntimeError>
    {
        super::super::CnpPreparationStorageScratch::requested_bytes()
            .checked_add(crucible_node_transport::client::CnpController::original_restoration_host_metadata_counter_scratch_data())
            .and_then(|bytes| bytes.checked_add(PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data()))
            .ok_or(RuntimeError::ResourceLimit)
    }
}
