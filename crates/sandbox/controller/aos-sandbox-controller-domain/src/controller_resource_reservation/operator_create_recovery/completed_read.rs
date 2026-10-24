//! Returns an exact completed Recover result under fresh operation-read authority.
//!
//! The earlier complete Root/SDK/Source/native originals stay resident. A new
//! finite read interval pays their actual conservative resident plane and its
//! own request, authorization, floor, renderer and independent posts. It grants
//! no new recovery decision, physical observation, effect, lease or mutation.

use super::*;
use crate::journal::{JournalError, JournalTransaction, RecordNamespace};
use crate::policy_compiler::provisioning_current::{
    RootContinuationClockGateV1 as Clock, RootContinuationHorizonDataV1,
};
use crate::public_api_session::PublicApiPeer;
use crate::{ControllerServiceError, OperationCompilationError, ReconcilerError};
use aos_sandbox_model::{CapabilityId, OperationId};
use buffa::Message as _;

type Native = ControllerOperatorRecoverReceivingV1;
type PublicOperation = aos_sandbox_api::aos::sandbox::v1::Operation;

#[derive(Clone, Copy)]
enum First {
    Native,
    Input,
    Scope,
    Handle,
    AuthorizationNative,
    Authorization,
    Horizon,
    Clock,
    Funding,
    Floor,
    Response,
    Body,
    After,
    FinalClock,
}

pub(super) struct ReadEntryRefusalV1 {
    pub(super) native: Result<Native, ResourceReservationErrorV1>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
}

impl ReadEntryRefusalV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        native_failure(&self.native).or_else(|| error(&self.after))
    }
}

pub(super) struct CompletedReadOriginalV1 {
    previous: Option<Box<Self>>,
    pub(super) native: Result<Native, ResourceReservationErrorV1>,
    operation: OperationId,
    pub(super) reached: ResourceVector,
    input: Option<Result<RequestModelsV1, OperationCompilationError>>,
    scope: Option<Result<crate::PublicOperationAuthorizationV1, ReconcilerError>>,
    get_body: Vec<u8>,
    handle: Option<Result<CapabilityId, ControllerServiceError>>,
    authorization_native: Option<PublicMutationAuthorizationNativeV1>,
    authorization:
        Option<Result<crate::cli_model::AuditAuthorizationV1, CliAuthorizationAdapterError>>,
    horizon: Option<Result<RootContinuationHorizonDataV1, JournalError>>,
    clock: Option<Clock>,
    pub(super) funding: Option<Result<(), ResourceReservationErrorV1>>,
    floor: bool,
    floor_geometry: Option<Result<ResourceVector, JournalError>>,
    response: Option<Result<Option<PublicOperation>, ReconcilerError>>,
    body: Option<Result<(), OperatorCreateRecoveryClosedV1>>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
    final_native: crate::controller::RetainedControllerProtectedClockAttemptV1,
    final_pair: Option<Result<RawPairedClockSample, JournalError>>,
    final_comparison: Option<Result<(), JournalError>>,
    first: Option<First>,
    completed: bool,
}

impl CompletedReadOriginalV1 {
    fn current_failure(&self) -> Option<First> {
        if native_failure(&self.native).is_some() {
            return Some(First::Native);
        }
        if matches!(self.input, Some(Err(_))) {
            return Some(First::Input);
        }
        if matches!(self.scope, Some(Err(_))) {
            return Some(First::Scope);
        }
        if matches!(self.handle, Some(Err(_))) {
            return Some(First::Handle);
        }
        if self
            .authorization_native
            .as_ref()
            .is_some_and(|native| native.failure().is_some())
        {
            return Some(First::AuthorizationNative);
        }
        if matches!(self.authorization, Some(Err(_))) {
            return Some(First::Authorization);
        }
        if matches!(self.horizon, Some(Err(_))) {
            return Some(First::Horizon);
        }
        if self
            .clock
            .as_ref()
            .is_some_and(|clock| clock.failure().is_some())
        {
            return Some(First::Clock);
        }
        if matches!(self.funding, Some(Err(_))) {
            return Some(First::Funding);
        }
        if matches!(self.floor_geometry, Some(Err(_))) {
            return Some(First::Floor);
        }
        if matches!(self.response, Some(Err(_) | Ok(None))) {
            return Some(First::Response);
        }
        if matches!(self.body, Some(Err(_))) {
            return Some(First::Body);
        }
        if matches!(self.after, Some(Err(_))) {
            return Some(First::After);
        }
        if self.final_native.failure().is_some()
            || matches!(self.final_pair, Some(Err(_)))
            || matches!(self.final_comparison, Some(Err(_)))
        {
            return Some(First::FinalClock);
        }
        None
    }

    pub(super) fn latch(&mut self) {
        if self.first.is_none() {
            self.first = self.current_failure();
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first.or_else(|| self.current_failure())? {
            First::Native => native_failure(&self.native),
            First::Input => error(&self.input),
            First::Scope => error(&self.scope),
            First::Handle => error(&self.handle),
            First::AuthorizationNative => self.authorization_native.as_ref()?.failure(),
            First::Authorization => error(&self.authorization),
            First::Horizon => error(&self.horizon),
            First::Clock => self.clock.as_ref()?.failure(),
            First::Funding => error(&self.funding),
            First::Floor => error(&self.floor_geometry),
            First::Response => error(&self.response).or(Some(&CLOSED)),
            First::Body => error(&self.body),
            First::After => error(&self.after),
            First::FinalClock => self
                .final_native
                .failure()
                .or_else(|| error(&self.final_pair))
                .or_else(|| error(&self.final_comparison)),
        }
        .or(Some(&CLOSED))
    }

    pub(super) fn require_current(
        &self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.after.is_some() || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_operator_recover_current_v1(
                self.native
                    .as_ref()
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?,
                controller,
                profile,
            )
    }

    pub(super) fn prepare_floor_v1(
        &mut self,
        controller: &Journal,
        transaction: &JournalTransaction,
        recipe: &crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        if self.floor || self.authorization.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        recipe.require_exact_v1(transaction)?;
        self.floor_geometry = Some((|| {
            let append = controller
                .append_receiving_demand_v1(transaction.records().iter().map(|record| {
                    aos_sandbox_journal::geometry::RecordShape {
                        key_bytes: record.key().len(),
                        value_bytes: record.value().map(<[u8]>::len),
                    }
                }))
                .map_err(|cause| match cause {
                    crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) => cause,
                    crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) => {
                        JournalError::ReceivingAccounting(cause)
                    }
                })?;
            append
                .checked_add(controller.create_storage_semantic_append_demand_v1()?)
                .map_err(JournalError::ReceivingAccounting)
        })());
        let geometry = self
            .floor_geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.reached = self
            .reached
            .checked_add(geometry)
            .map_err(JournalError::ReceivingAccounting)?;
        self.floor = true;
        Ok(())
    }

    pub(super) fn require_floor_transition_v1(
        &self,
        _controller: &Journal,
    ) -> Result<(), JournalError> {
        if !self.floor
            || self.after.is_some()
            || self.authorization.is_some()
            || self.failure().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    pub(super) fn completed_read_resident_demand_v1(
        &self,
        controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let native = self.completed_native_for_resumption_v1()?;
        self.bank
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .completed_operator_recover_resident_demand_v1(native, controller, &self.profile)
    }

    pub(super) fn completed_native_for_resumption_v1(&self)
        -> Result<&aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperatorRecoverReceivingV1,
            ResourceReservationErrorV1>
    {
        let native = match self.completed_read.as_deref() {
            Some(read) if read.completed && read.failure().is_none() => &read.native,
            Some(_) => return Err(ResourceReservationErrorV1::Conflict),
            None => &self.native,
        };
        native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    fn begin_completed_read_v1(
        &mut self,
        controller: &mut Journal,
        peer: &PublicApiPeer,
        encoded: &[u8],
        operation: OperationId,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        self.completed_read_geometry = Some((|| {
            let resident = self.completed_read_resident_demand_v1(controller)?;
            let carrier = std::mem::size_of::<CompletedReadOriginalV1>()
                .checked_mul(3)
                .and_then(|bytes| {
                    bytes.checked_add(3 * std::mem::size_of::<Box<CompletedReadOriginalV1>>())
                })
                .and_then(|bytes| {
                    bytes.checked_add(aos_sandbox_protocol::domain_ledger::public_operation::
                metadata_complete_projection_receiving_bytes_v1()?)
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let reached = resident
                .checked_add(Self::request_receiving_demand_v1(
                    controller, peer, encoded,
                )?)
                .and_then(|complete| {
                    complete.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier))
                })?;
            Ok(reached)
        })());
        self.latch_primary_failure_v1();
        let reached = self
            .completed_read_geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(CLOSED)?;
        let native = match self.bank.lock() {
            Ok(bank) => {
                bank.begin_operator_recover_receiving_v1(controller, &self.profile, reached)
            }
            Err(_) => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
        };
        if !native
            .as_ref()
            .is_ok_and(|native| native.require_prepaid_owed_observation_v1().is_ok())
        {
            let mut entry = ReadEntryRefusalV1 {
                native,
                after: None,
            };
            if let Ok(native) = entry.native.as_mut() {
                entry.after = Some(match self.bank.lock() {
                    Ok(bank) => bank.finish_operator_recover_native_once_v1(
                        native,
                        controller,
                        &self.profile,
                    ),
                    Err(_) => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
                });
            }
            self.completed_read_entry = Some(entry);
            self.latch_primary_failure_v1();
            return Err(CLOSED);
        }
        let previous = self.completed_read.take();
        self.completed_read = Some(Box::new(CompletedReadOriginalV1 {
            previous,
            native,
            operation,
            reached,
            input: None,
            scope: None,
            get_body: Vec::new(),
            handle: None,
            authorization_native: Some(PublicMutationAuthorizationNativeV1::new()),
            authorization: None,
            horizon: None,
            clock: None,
            funding: None,
            floor: false,
            floor_geometry: None,
            response: None,
            body: None,
            after: None,
            final_native: Default::default(),
            final_pair: None,
            final_comparison: None,
            first: None,
            completed: false,
        }));
        Ok(())
    }

    fn finish_completed_read_v1(&mut self, controller: &mut Journal) {
        let Some(read) = self.completed_read.as_deref_mut() else {
            return;
        };
        read.latch();
        read.after = Some(match read.native.as_mut() {
            Ok(native) => match self.bank.lock() {
                Ok(bank) => {
                    bank.finish_operator_recover_native_once_v1(native, controller, &self.profile)
                }
                Err(_) => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
            },
            Err(_) => Err(ResourceReservationErrorV1::Conflict),
        });
        read.latch();
        // A distinct paid native sample is owed even after body/C-after refusal.
        read.final_pair = Some(read.final_native.observe_once_v1());
        if let Some(Ok(pair)) = read.final_pair.as_ref() {
            read.final_comparison = Some(
                read.clock
                    .as_ref()
                    .ok_or(JournalError::ProtectedBoundary)
                    .and_then(|clock| clock.require_final_sample_v1(*pair)),
            );
        }
        read.latch();
        read.completed = read.failure().is_none()
            && matches!(read.body, Some(Ok(())))
            && matches!(read.after, Some(Ok(())))
            && matches!(read.final_comparison, Some(Ok(())));
        self.latch_primary_failure_v1();
    }
}

impl Journal {
    pub(crate) fn read_completed_recover_retry_once_v1(
        &mut self,
        peer: &PublicApiPeer,
        capability: CapabilityId,
        handle: &[u8],
        encoded: &[u8],
        request_scope: crate::controller::ControllerRequestScopeV1,
    ) -> Result<PublicOperation, OperatorCreateRecoveryClosedV1> {
        let mut original = self.take_operator_recover_v1().ok_or(CLOSED)?;
        let operation = match original.completed_metadata_operation_v1(self) {
            Ok(operation) => operation,
            Err(cause) => {
                restore(self, original);
                return Err(cause);
            }
        };
        let entry = original.begin_completed_read_v1(self, peer, encoded, operation);
        restore(self, original);
        entry?;

        let body = self.authorize_completed_recover_read_body_v1(
            peer,
            capability,
            handle,
            encoded,
            request_scope,
            operation,
        );
        let mut original = self.take_operator_recover_v1().ok_or(CLOSED)?;
        if let Some(read) = original.completed_read.as_deref_mut() {
            read.body = Some(body);
            read.latch();
        }
        original.finish_completed_read_v1(self);
        let result = if let Some(read) = original.completed_read.as_deref_mut() {
            if read.completed {
                read.response
                    .take()
                    .and_then(Result::ok)
                    .flatten()
                    .ok_or(CLOSED)
            } else {
                Err(CLOSED)
            }
        } else {
            Err(CLOSED)
        };
        restore(self, original);
        result
    }

    fn authorize_completed_recover_read_body_v1(
        &mut self,
        peer: &PublicApiPeer,
        capability: CapabilityId,
        handle: &[u8],
        encoded: &[u8],
        request_scope: crate::controller::ControllerRequestScopeV1,
        operation: OperationId,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        let mut original = self.take_operator_recover_v1().ok_or(CLOSED)?;
        let preparation = (|| {
            let read = original.completed_read.as_deref_mut().ok_or(CLOSED)?;
            read.require_current(&original.bank, &original.profile, self)
                .map_err(|_| CLOSED)?;
            read.input = Some(RequestModelsV1::decode_completed_retry_v1(
                self,
                peer,
                encoded,
                request_scope,
                operation,
            ));
            if !matches!(read.input, Some(Ok(_))) {
                return Err(CLOSED);
            }
            read.scope = Some(
                self.get(
                    RecordNamespace::PublicOperationAuthorization,
                    operation.as_bytes(),
                )
                .ok_or(ReconcilerError::CorruptLedger(
                    "completed operation scope is absent",
                ))
                .and_then(|bytes| {
                    crate::PublicOperationAuthorizationV1::decode(bytes).map_err(Into::into)
                }),
            );
            if !matches!(read.scope, Some(Ok(_))) {
                return Err(CLOSED);
            }
            read.get_body =
                crate::cli_model::OperationObservationRequestV1::new(operation.into_bytes())
                    .map_err(|_| CLOSED)?
                    .to_proto()
                    .encode_to_vec();
            Ok(())
        })();
        if let Some(read) = original.completed_read.as_deref_mut() {
            read.latch();
        }
        original.latch_primary_failure_v1();
        restore(self, original);
        preparation?;

        let (mut native, scope, get_body) = {
            let read = self
                .operator_recover_original_mut_v1()
                .and_then(|original| original.completed_read.as_deref_mut())
                .ok_or(CLOSED)?;
            (
                read.authorization_native.take().ok_or(CLOSED)?,
                read.scope.take().and_then(Result::ok).ok_or(CLOSED)?,
                std::mem::take(&mut read.get_body),
            )
        };
        let handle_result = crate::controller::resolve_delete_capability_handle_retaining_v1(
            self,
            peer,
            capability,
            handle,
            &mut native.handle_peers,
        );
        let authorization = match handle_result.as_ref() {
            Ok(capability) => native.authorize_completed_operation_read_v1(
                self,
                peer,
                *capability,
                &scope,
                &get_body,
            ),
            Err(_) => Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected),
        };
        {
            let read = self
                .operator_recover_original_mut_v1()
                .and_then(|original| original.completed_read.as_deref_mut())
                .ok_or(CLOSED)?;
            read.handle = Some(handle_result);
            read.scope = Some(Ok(scope));
            read.get_body = get_body;
            read.authorization = Some(match authorization {
                Ok((authorization, decision)) => {
                    let pair = decision.clock();
                    let expiry = decision
                        .capability()
                        .claims()
                        .expires_at
                        .min(decision.policy().expires_at());
                    read.horizon = Some((|| {
                        let horizon = RecoverHorizonV1::from_current_authorization_v1(pair, expiry)
                            .map_err(|_| JournalError::ProtectedBoundary)?;
                        Ok(RootContinuationHorizonDataV1::from_original_data_v1(
                            pair,
                            horizon.cutoff,
                        )?
                        .with_wall_expiry_data_v1(expiry))
                    })());
                    if let Some(Ok(horizon)) = read.horizon.as_ref() {
                        read.clock = Some(Clock::new_controller_authorization_v1(*horizon));
                    }
                    native.decision = Some(decision);
                    Ok(authorization)
                }
                Err(cause) => Err(cause),
            });
            read.authorization_native = Some(native);
            read.latch();
            if read.failure().is_some() {
                return Err(CLOSED);
            }
        }
        let mut original = self.take_operator_recover_v1().ok_or(CLOSED)?;
        let rendered = (|| {
            let read = original.completed_read.as_deref_mut().ok_or(CLOSED)?;
            read.require_current(&original.bank, &original.profile, self)
                .map_err(|_| CLOSED)?;
            read.clock
                .as_mut()
                .ok_or(CLOSED)?
                .check_next_once_v1()
                .map_err(|_| CLOSED)?;
            read.response = Some(crate::reconciler::recovered_public_operation_resource_v1(
                self, operation,
            ));
            read.latch();
            if read.failure().is_some() {
                Err(CLOSED)
            } else {
                Ok(())
            }
        })();
        if let Some(read) = original.completed_read.as_deref_mut() {
            read.latch();
        }
        original.latch_primary_failure_v1();
        restore(self, original);
        rendered
    }
}

fn restore(controller: &mut Journal, original: Box<OperatorCreateRecoveryOriginalV1>) {
    if let Err(original) = controller.install_operator_recover_v1(original) {
        let _retained_original = original;
        std::process::abort();
    }
}

fn native_failure(
    native: &Result<Native, ResourceReservationErrorV1>,
) -> Option<&(dyn Error + 'static)> {
    match native {
        Ok(native) => native.failure(),
        Err(cause) => Some(cause),
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

const CLOSED: OperatorCreateRecoveryClosedV1 = OperatorCreateRecoveryClosedV1;
