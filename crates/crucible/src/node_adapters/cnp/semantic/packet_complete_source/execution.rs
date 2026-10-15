//! Retains the original output metadata and backend before Capture dispatch.
//!
//! Reservations and readonly preparation create data only. The actual Core
//! ticket, original capsule and whole checked preflight remain required before
//! any native request. The completed output moves through the same owning slots.

use super::*;
use crate::node_adapters::cnp::CnpSemanticSnapshotReservation;
use crucible_node_provider::protocol_snapshot::OriginalProtocolPayloadOwner;
use std::mem::size_of;

#[path = "execution/born.rs"]
mod born;
#[path = "execution/dependency_credit.rs"]
pub(super) mod dependency_credit;
#[path = "execution/dispatch.rs"]
mod dispatch;
#[path = "execution/finish.rs"]
mod finish;
#[path = "execution/move_output.rs"]
mod move_output;

const COMPLETE_EVIDENCE_ROLES: usize = 8;
const COMPLETE_BORN_ROLES: usize = 10;
// The pinned CNP decimal_integer serializer owns at most twenty formatter bytes.
const NUMERIC_SERIALIZER_SCRATCH: usize = 20;
const BACKEND_MEDIA: &str = "application/vnd.source-owned.packet-complete-archive-backend.v15+json";

pub(super) struct OriginalCompleteCaptureExecution {
    backend_bank: Option<CnpSemanticSnapshotReservation>,
    backend: Option<InputPayload>,
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
        let bank = match (&self.backend_bank, &self.backend) {
            (Some(bank), None) => bank.allocated_bytes(),
            (None, Some(body)) => body.bytes.capacity(),
            (None, None) if self.failed || self.transferred => 0,
            _ => return Err(refused("original backend bank association differs")),
        };
        let references = self
            .backend
            .as_ref()
            .map(|body| NodeRuntime::capture_reference_storage(&body.reference).map_err(unknown))
            .transpose()?
            .unwrap_or(0);
        let mut bytes = retained_values::sum(
            [
                bank,
                references,
                self.evidence
                    .capacity()
                    .checked_mul(size_of::<InputPayload>())
                    .ok_or_else(|| refused("original evidence slots overflow"))?,
                self.born
                    .capacity()
                    .checked_mul(size_of::<born::OriginalBornObject>())
                    .ok_or_else(|| refused("original creation slots overflow"))?,
            ],
            maximum,
        )?;
        if let Some(plan) = &self.dependency_plan {
            bytes = retained_values::sum(
                [
                    bytes,
                    NodeRuntime::capture_reference_storage(&plan.runtime).map_err(unknown)?,
                ],
                maximum,
            )?;
        }
        for original in &self.born {
            bytes = retained_values::sum([bytes, original.retained_storage(maximum)?], maximum)?;
        }
        for request in self
            .capture_request
            .iter()
            .chain(self.confirmation_request.iter())
        {
            bytes = retained_values::sum([bytes, request.allocated_capacity()], maximum)?;
        }
        if let Some(host) = &self.host_protocol {
            bytes = retained_values::sum(
                [
                    bytes,
                    host.bytes.capacity(),
                    NodeRuntime::capture_reference_storage(&host.reference).map_err(unknown)?,
                ],
                maximum,
            )?;
        }
        for object in &self.evidence {
            bytes = retained_values::sum(
                [
                    bytes,
                    object.bytes.capacity(),
                    NodeRuntime::capture_reference_storage(&object.reference).map_err(unknown)?,
                ],
                maximum,
            )?;
        }
        match (&self.owner, &self.key) {
            (Some(owner), Some(key)) => {
                bytes = retained_values::sum(
                    [
                        bytes,
                        NodeRuntime::capture_native_output_metadata_storage_data(
                            owner,
                            &self.participants,
                            key,
                        )
                        .map_err(unknown)?,
                    ],
                    maximum,
                )?;
            }
            (None, None) if self.participants.is_empty() => {}
            _ => return Err(refused("original output metadata association differs")),
        }
        if let Some(owner) = &self.retained_protocol_owner {
            let metadata = owner.original_retained_metadata_facts().map_err(unknown)?;
            let allocation = owner.original_allocation_facts().map_err(unknown)?;
            let records = owner
                .original_metadata_record_allocation_facts()
                .map_err(unknown)?;
            let aliases = owner.original_alias_allocation_facts().map_err(unknown)?;
            bytes = retained_values::sum(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                        &metadata, maximum,
                    )?,
                    allocation.literal.map_or(0, |bank| bank.allocated_bytes),
                    records.map_or(0, |bank| bank.allocated_bytes),
                    aliases
                        .map(|bank| bank.row_bytes.checked_add(bank.lookup_bytes))
                        .unwrap_or(Some(0))
                        .ok_or_else(|| refused("original moved host alias banks overflow"))?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

impl PacketCompleteSemanticSource {
    /// Reserves the backend and final evidence slots before the original Child.
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
        self.ensure_origin()?;
        if self.complete_bytes_launch_reserved.get()
            || self.capture_execution.get_mut().is_some()
            || !matches!(
                self.selected_capture_profile()?,
                PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
        {
            return Err(refused(
                "original capture execution banks unavailable before launch",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
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
            .map_err(unknown)?,
        );
        let requested = maximum_backend_bytes
            .checked_add(
                COMPLETE_EVIDENCE_ROLES
                    .checked_mul(size_of::<InputPayload>())
                    .ok_or_else(|| refused("original output slots overflow"))?,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    COMPLETE_BORN_ROLES.checked_mul(size_of::<born::OriginalBornObject>())?,
                )
            })
            .filter(|requested| maximum_backend_bytes != 0 && *requested <= admitted)
            .ok_or_else(|| refused("original output bank admission is insufficient"))?;
        let _ = requested;
        *self.capture_execution.get_mut() = Some(OriginalCompleteCaptureExecution {
            backend_bank: None,
            backend: None,
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
        let execution = self
            .capture_execution
            .get_mut()
            .as_mut()
            .ok_or_else(|| refused("original output bank slot absent"))?;
        let result = (|| {
            execution.backend_bank = Some(CnpSemanticSnapshotReservation::reserve(
                maximum_backend_bytes,
                admitted,
            )?);
            execution
                .evidence
                .try_reserve_exact(COMPLETE_EVIDENCE_ROLES)
                .map_err(unknown)?;
            execution
                .born
                .try_reserve_exact(COMPLETE_BORN_ROLES)
                .map_err(unknown)?;
            execution.retained_storage(admitted)?;
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
            if execution.key.is_none() {
                let mut formats =
                    installed
                        .provider
                        .implementation
                        .formats
                        .iter()
                        .filter(|schema| {
                            schema.id.as_str() == "source-owned.packet-native-continuation/11"
                                && schema.version == 11
                        });
                let schema = formats
                    .next()
                    .ok_or_else(|| refused("original native complete schema absent"))?;
                if formats.next().is_some()
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
                profile: crucible_node_provider::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE,
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
                let view = PacketCompleteSettledJournal::backend_registry_identity_view_data(
                    &installed.binding.compatibility.implementation,
                    key,
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
                        BACKEND_MEDIA,
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
        self.ensure_origin()?;
        let execution = self
            .capture_execution
            .try_borrow()
            .map_err(|_| refused("original output banks are borrowed"))?;
        execution
            .as_ref()
            .map(|original| original.retained_storage(maximum))
            .transpose()
            .map(|bytes| bytes.unwrap_or(0))
    }
}

#[cfg(test)]
#[path = "execution/prebirth_tests.rs"]
mod prebirth_tests;
