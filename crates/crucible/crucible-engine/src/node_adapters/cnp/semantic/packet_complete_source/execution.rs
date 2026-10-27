//! Retains the original output metadata and backend before Capture dispatch.
//!
//! Reservations and readonly preparation create data only. The actual Core
//! ticket, original capsule and whole checked preflight remain required before
//! any native request. The completed output moves through the same owning slots.

use super::*;
use crate::node_adapters::cnp::CnpSemanticSnapshotReservation;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crucible_node_transport::protocol_snapshot::OriginalProtocolPayloadOwner;
use std::mem::size_of;

#[path = "execution/allocation_report.rs"]
mod allocation_report;
#[path = "execution/born.rs"]
mod born;
#[path = "execution/dependency_credit.rs"]
pub(super) mod dependency_credit;
#[path = "execution/dispatch.rs"]
mod dispatch;
#[path = "execution/finish.rs"]
mod finish;
#[path = "execution/metadata.rs"]
mod metadata;
#[path = "execution/move_output.rs"]
mod move_output;

const COMPLETE_EVIDENCE_ROLES: usize = 8;
const COMPLETE_BORN_ROLES: usize = 10;
// The pinned CNP decimal_integer serializer owns at most twenty formatter bytes.
const NUMERIC_SERIALIZER_SCRATCH: usize = 20;
const BACKEND_MEDIA: &str = "application/vnd.source-owned.packet-complete-archive-backend.v15+json";
const STARTUP_BACKEND_MEDIA: &str =
    "application/vnd.source-owned.packet-complete-archive-backend.v16+json";
const INVOCATION_BACKEND_MEDIA: &str =
    "application/vnd.source-owned.packet-complete-archive-backend.v17+json";

pub(super) struct OriginalCompleteCaptureExecution {
    backend_bank: Option<CnpSemanticSnapshotReservation>,
    backend: Option<InputPayload>,
    allocation_selected: bool,
    allocation_bank: Vec<u8>,
    allocation: Option<InputPayload>,
    evidence: Vec<InputPayload>,
    born: Vec<born::OriginalBornObject>,
    dependency_plan: Option<dependency_credit::OriginalDependencyPlan>,
    capture_request: Option<Id>,
    confirmation_request: Option<Id>,
    host_protocol: Option<InputPayload>,
    owner: Option<Id>,
    participants: Vec<Id>,
    key: Option<NativeStateKey>,
    retained_protocol_owner: Option<OriginalProtocolPayloadOwner>,
    started: bool,
    wire_attempted: bool,
    failed: bool,
    transferred: bool,
}

impl OriginalCompleteCaptureExecution {
    fn retained_storage(&self, maximum: usize) -> Result<usize, OperationFailure> {
        self.retained_storage_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn retained_storage_with_error<E: StorageError>(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.validate_storage_association_with_error::<E>()?;
        let facts = self.capacity_facts_data(None).map_err(E::runtime)?;
        PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
            &facts, maximum,
        )
    }
}

impl PacketCompleteSemanticSource {
    /// Reserves backend, selected Report and final evidence banks before Child.
    ///
    /// These allocations belong to this Source and survive partial failure.
    /// Their independent finite bound grants no whole-world memory admission,
    /// capture selection, original ticket or native execution right.
    ///
    /// # Errors
    /// Refuses a foreign creator, spent launch reservation, a non-owning profile,
    /// existing native association, repeated reservation or finite excess.
    pub fn reserve_original_complete_capture_execution(
        &mut self,
        maximum_backend_bytes: usize,
        admitted_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.reserve_original_complete_capture_execution_with_error::<OperationFailure>(
            maximum_backend_bytes,
            admitted_bytes,
        )
    }

    // Only an independently issued same-Source startup member supplies the
    // typed finalizer's allowance. This body retains all partial bank owners;
    // its byte arguments and a successful reservation issue no admission.
    pub(in crate::node_adapters::cnp::semantic) fn reserve_original_complete_capture_execution_with_error<
        E: StorageError,
    >(
        &self,
        maximum_backend_bytes: usize,
        admitted_bytes: usize,
    ) -> Result<(), E> {
        self.storage_origin_with_error::<E>()?;
        let mut slot = self
            .capture_execution
            .try_borrow_mut()
            .map_err(|_| E::refused("original output bank custody is borrowed"))?;
        if self.complete_bytes_launch_reserved.get()
            || slot.is_some()
            || !matches!(
                match &self.original {
                    CompletePacketOriginal::Producer(source) =>
                        source.complete_capture_profile.as_ref(),
                    CompletePacketOriginal::Reactive(source) =>
                        source.complete_capture_profile.as_ref(),
                },
                Some(PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            )
        {
            return Err(E::refused(
                "original capture execution banks unavailable before launch",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound_with_error::<E>()
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound_with_error::<E>()
            }
        }?;
        if !unbound {
            return Err(E::refused(
                "original capture execution banks follow native association",
            ));
        }
        let admitted = admitted_bytes.min(
            usize::try_from(
                self.installation()
                    .realize
                    .resource_limits
                    .memory_bytes
                    .get(),
            )
            .map_err(E::unknown)?,
        );
        let allocation_selected = self.capture_allocation_selection.flatten().is_some();
        execution_reservation_requested_bytes_with_error::<E>(
            maximum_backend_bytes,
            allocation_selected,
            admitted,
        )?;
        *slot = Some(OriginalCompleteCaptureExecution {
            backend_bank: None,
            backend: None,
            allocation_selected,
            allocation_bank: Vec::new(),
            allocation: None,
            evidence: Vec::new(),
            born: Vec::new(),
            dependency_plan: None,
            capture_request: None,
            confirmation_request: None,
            host_protocol: None,
            owner: None,
            participants: Vec::new(),
            key: None,
            retained_protocol_owner: None,
            started: false,
            wire_attempted: false,
            failed: false,
            transferred: false,
        });
        let execution = slot
            .as_mut()
            .ok_or_else(|| E::refused("original output bank slot absent"))?;
        let result = (|| {
            CnpSemanticSnapshotReservation::reserve_into_with_error::<E>(
                maximum_backend_bytes,
                admitted,
                &mut execution.backend_bank,
            )?;
            if allocation_selected {
                execution
                    .allocation_bank
                    .try_reserve_exact(allocation_report_capacity())
                    .map_err(E::unknown)?;
            }
            execution
                .evidence
                .try_reserve_exact(execution.evidence_roles())
                .map_err(E::unknown)?;
            execution
                .born
                .try_reserve_exact(execution.born_roles())
                .map_err(E::unknown)?;
            execution.retained_storage_with_error::<E>(admitted)?;
            Ok(())
        })();
        if result.is_err() {
            execution.failed = true;
        }
        result
    }

    pub(super) fn prepare_original_complete_capture_execution(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        runtime_object: &InputPayload,
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        self.authenticate_witness_scope(scope)?;
        let mut execution = self
            .capture_execution
            .try_borrow_mut()
            .map_err(|_| refused("original output bank is borrowed"))?;
        let execution = execution
            .as_mut()
            .ok_or_else(|| refused("original output banks absent"))?;
        if execution.failed || execution.started || execution.transferred {
            return Err(refused("original output preparation is failed or spent"));
        }
        let result: Result<(), OperationFailure> = (|| {
            let installed = self.installation();
            let snapshot_class = self.selected_complete_native_snapshot_class()?;
            if execution.allocation_selected != snapshot_class.has_allocation() {
                return Err(refused(
                    "original Report reservation differs from installed snapshot class",
                ));
            }
            if execution.key.is_none() {
                let mut formats =
                    installed
                        .provider
                        .implementation
                        .formats
                        .iter()
                        .filter(|schema| {
                            schema.id.as_str() == snapshot_class.schema_id()
                                && schema.version == snapshot_class.schema_version()
                        });
                let schema = formats
                    .next()
                    .ok_or_else(|| refused("original native complete schema absent"))?;
                if schema != &snapshot_class.schema()?
                    || formats.next().is_some()
                    || !installed
                        .binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(schema)
                {
                    return Err(refused(
                        "original native complete schema is repeated or different",
                    ));
                }
                #[derive(serde::Serialize)]
                struct Metadata<'a> {
                    owner: &'a Id,
                    participants: &'a IdSet,
                    implementation: &'a Id,
                    profile: &'a str,
                    schema: &'a SchemaRef,
                }
                let borrowed = Metadata {
                owner: &installed.owner.owner.id,
                participants: &installed.owner.owner.participant_ids,
                implementation: &installed.binding.compatibility.implementation.implementation_id,
                profile: crucible_node_transport::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE,
                schema,
            };
                // The existing no-allocation serializer walk conservatively quotes
                // every nested clone before any output metadata allocation.
                retained_values::sum(
                    [
                        execution.retained_storage(maximum)?,
                        NUMERIC_SERIALIZER_SCRATCH,
                    ],
                    maximum,
                )?;
                retained_values::sum(
                    [
                        execution.retained_storage(maximum)?,
                        NodeRuntime::capture_serialization_storage(&borrowed, maximum)
                            .map_err(unknown)?,
                    ],
                    maximum,
                )?;
                execution.owner = Some(borrowed.owner.clone());
                execution.participants = borrowed.participants.clone();
                execution.key = Some(NativeStateKey {
                    implementation: borrowed.implementation.clone(),
                    profile: Id::new(borrowed.profile).map_err(unknown)?,
                    schema: schema.clone(),
                });
                execution.retained_storage(maximum)?;
            }
            {
                let key = execution
                    .key
                    .as_ref()
                    .ok_or_else(|| refused("original output key absent"))?;
                let view =
                    PacketCompleteSettledJournal::backend_registry_identity_view_for_class_data(
                        &installed.binding.compatibility.implementation,
                        key,
                        snapshot_class,
                    );
                retained_values::sum(
                    [
                        execution.retained_storage(maximum)?,
                        NUMERIC_SERIALIZER_SCRATCH,
                    ],
                    maximum,
                )?;
                let canonical_scratch =
                    NodeRuntime::capture_serialization_storage(&view, maximum).map_err(unknown)?;
                retained_values::sum(
                    [
                        execution.retained_storage(maximum)?,
                        canonical_scratch.checked_mul(2).ok_or_else(|| {
                            refused("original canonical backend scratch overflow")
                        })?,
                    ],
                    maximum,
                )?;
                let value = serde_json::to_value(&view).map_err(unknown)?;
                if let Some(body) = &execution.backend {
                    retained_values::sum(
                        [
                            execution.retained_storage(maximum)?,
                            canonical_scratch,
                            NodeRuntime::capture_hash_storage(&body.reference.hash)
                                .map_err(unknown)?,
                        ],
                        maximum,
                    )?;
                    super::super::semantic_snapshot::authenticate_canonical_component(
                        body, &value,
                    )?;
                } else {
                    super::super::semantic_snapshot::record_canonical_component(
                        &mut execution.backend_bank,
                        &value,
                    )?;
                    execution.backend = Some(super::super::semantic_snapshot::take_component(
                        &mut execution.backend_bank,
                        match snapshot_class {
                            super::archive_owner::CompleteNativeSnapshotClass::Legacy11 => BACKEND_MEDIA,
                            super::archive_owner::CompleteNativeSnapshotClass::StartupCapture14 => STARTUP_BACKEND_MEDIA,
                            super::archive_owner::CompleteNativeSnapshotClass::InvocationCapture15 => INVOCATION_BACKEND_MEDIA,
                        },
                    )?);
                }
            }
            self.prepare_original_dependency_plan(scope, runtime_object, execution, maximum)?;
            self.authenticate_witness_scope(scope)
        })();
        if result.is_err() {
            self.ensure_origin()?;
            execution.failed = true;
        }
        result
    }

    pub(super) fn original_complete_execution_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_complete_execution_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_complete_execution_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        let execution = self
            .capture_execution
            .try_borrow()
            .map_err(|_| E::refused("original output banks are borrowed"))?;
        execution
            .as_ref()
            .map(|original| original.retained_storage_with_error::<E>(maximum))
            .transpose()
            .map(|bytes| bytes.unwrap_or(0))
    }
}

#[cfg(test)]
#[path = "execution/prebirth_tests.rs"]
mod prebirth_tests;

fn allocation_report_capacity() -> usize {
    crucible_node_transport::reference_packet::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES
}

#[cfg(test)]
fn execution_reservation_requested_bytes(
    backend: usize,
    allocation_selected: bool,
    admitted: usize,
) -> Result<usize, OperationFailure> {
    execution_reservation_requested_bytes_with_error::<OperationFailure>(
        backend,
        allocation_selected,
        admitted,
    )
}

fn execution_reservation_requested_bytes_with_error<E: StorageError>(
    backend: usize,
    allocation_selected: bool,
    admitted: usize,
) -> Result<usize, E> {
    let extra = usize::from(allocation_selected);
    let requested = backend
        .checked_add(if allocation_selected {
            allocation_report_capacity()
        } else {
            0
        })
        .and_then(|n| {
            n.checked_add((COMPLETE_EVIDENCE_ROLES + extra).checked_mul(size_of::<InputPayload>())?)
        })
        .and_then(|n| {
            n.checked_add(
                (COMPLETE_BORN_ROLES + extra).checked_mul(size_of::<born::OriginalBornObject>())?,
            )
        })
        .filter(|n| backend != 0 && *n <= admitted)
        .ok_or_else(|| E::limit("original output bank admission is insufficient"))?;
    Ok(requested)
}

impl OriginalCompleteCaptureExecution {
    fn evidence_roles(&self) -> usize {
        COMPLETE_EVIDENCE_ROLES + usize::from(self.allocation_selected)
    }

    fn born_roles(&self) -> usize {
        COMPLETE_BORN_ROLES + usize::from(self.allocation_selected)
    }
}

impl PacketCompleteSemanticSource {
    /// Reports pre-Child backend, Report and output-slot requested storage.
    ///
    /// The same immutable selection drives the reservation. Inline Source and
    /// execution headers belong to the enclosing Source owner; this reports
    /// additional dynamic banks only and creates no admission or native right.
    ///
    /// # Errors
    /// Refuses foreign creator custody, a zero backend bound or layout overflow.
    pub fn original_complete_capture_execution_reservation_requested_data(
        &self,
        maximum_backend_bytes: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_complete_capture_execution_reservation_requested_data_with_error::<OperationFailure>(maximum_backend_bytes)
    }
}

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn original_complete_capture_execution_reservation_requested_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum_backend_bytes: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        execution_reservation_requested_bytes_with_error::<E>(
            maximum_backend_bytes,
            self.capture_allocation_selection.flatten().is_some(),
            usize::MAX,
        )
    }

    // Names fixed counter/initializer/borrow/error headers only. The enclosing
    // action separately counts dynamic banks and actual Source inline layout;
    // this is not a compiler-frame or entire-thread-stack bound.
    pub(in crate::node_adapters::cnp::semantic) fn original_complete_capture_execution_counter_scratch_data()
    -> usize {
        size_of::<OriginalCompleteCaptureExecution>()
            + size_of::<std::cell::Ref<'static, Option<OriginalCompleteCaptureExecution>>>()
            + size_of::<std::cell::RefMut<'static, Option<OriginalCompleteCaptureExecution>>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::collections::TryReserveError>()
            + 4 * size_of::<usize>()
            + CnpSemanticSnapshotReservation::reservation_counter_scratch_data()
            + Self::original_complete_capture_execution_capacity_counter_scratch_data()
    }
}
