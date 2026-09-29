//! Owned original native flight, reborrowing the same table/writer/Session.
//!
//! Every attempted byte and actual move-only owner stays in this runtime child
//! across errors. There are no references into its own runtime, cloning of live
//! admission, row-derived custody, or restart/re-sign factories.

use std::collections::BTreeMap;

use aos_sandbox::{
    JournalTransaction, MountOriginalNativeJournalAuthorityV5, OriginalRootProtectedReadbackV5,
    PreparedOriginalRootAppendV5, ProtectedJournalAuthority,
};
use aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest;
use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::RootNativeHeldSidecarV2;
use aos_sandbox_source_provider_protocol::native_held_completion::frame::{
    PreparedNativeHeldControlV1, SignedNativeHeldControlV1,
};
use aos_sandbox_source_provider_security::{
    CurrentRootMountSourceProviderSessionV1, MountProviderRequestSendRecoveryV2,
    PendingNativeMountAcquireV3, PreparedMountProviderRequestV2, ReservedMountProviderRequestV2,
    SentMountProviderRequestV2,
};

use super::{PendingNativeProviderAcquireV3, reservation_coordinates};
use crate::Result;
use crate::source_acquisition::{
    SourceAcquisitionTableV2,
    format::state_error,
    model::{SourceProviderHeadV2, SourceProviderQueryAttemptV2},
    transition::prepare_mutation,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    BeginQuery,
    Query,
    PrepareAdmission,
    CommitAdmission,
    Confirm,
    Sign,
    PrepareRoot1Store,
    CommitRoot1Store,
    SendRoot1,
    SendAcquire,
    RetryAcquire,
    Finished,
}

/// Holds the real original Live admission and each exact subsequent owner.
pub(in crate::source_acquisition) struct OriginalNativeAcquireFlightV5 {
    live: LiveValidatedAcquireMountSourceRequest,
    mount_request: Vec<u8>,
    mount_plan: [u8; 32],
    ownership_lease: [u8; 32],
    publication: Vec<u8>,
    catalog: Vec<u8>,
    selection: Option<Vec<u8>>,
    deadline: i64,
    stage: Stage,
    stopped: bool,
    query: Option<PendingNativeMountAcquireV3>,
    prepared: Option<PreparedMountProviderRequestV2>,
    owners: Option<JournalTransaction>,
    tentative: Option<SourceAcquisitionTableV2>,
    attempt: Option<SourceProviderQueryAttemptV2>,
    head: Option<SourceProviderHeadV2>,
    unsigned_root1: Option<PreparedNativeHeldControlV1>,
    admission_append: Option<PreparedOriginalRootAppendV5>,
    admission: Option<OriginalRootProtectedReadbackV5>,
    reservation: Option<ReservedMountProviderRequestV2>,
    signed_root1: Option<SignedNativeHeldControlV1>,
    root1_append: Option<PreparedOriginalRootAppendV5>,
    persisted_root1: Option<OriginalRootProtectedReadbackV5>,
    root1_possible_send: bool,
    root1_sent: bool,
    acquire_send_attempted: bool,
    send_recovery: Option<MountProviderRequestSendRecoveryV2>,
    sent: Option<SentMountProviderRequestV2>,
}

impl OriginalNativeAcquireFlightV5 {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::source_acquisition) fn new(
        live: LiveValidatedAcquireMountSourceRequest,
        mount_request: Vec<u8>,
        mount_plan: [u8; 32],
        ownership_lease: [u8; 32],
        publication: Vec<u8>,
        catalog: Vec<u8>,
        selection: Option<Vec<u8>>,
        deadline: i64,
    ) -> Self {
        Self {
            live,
            mount_request,
            mount_plan,
            ownership_lease,
            publication,
            catalog,
            selection,
            deadline,
            stage: Stage::BeginQuery,
            stopped: false,
            query: None,
            prepared: None,
            owners: None,
            tentative: None,
            attempt: None,
            head: None,
            unsigned_root1: None,
            admission_append: None,
            admission: None,
            reservation: None,
            signed_root1: None,
            root1_append: None,
            persisted_root1: None,
            root1_possible_send: false,
            root1_sent: false,
            acquire_send_attempted: false,
            send_recovery: None,
            sent: None,
        }
    }

    pub(in crate::source_acquisition) fn needs_catalog(&self) -> bool {
        matches!(self.stage, Stage::BeginQuery | Stage::Query)
    }

    /// Moves only actual sent outcome authority to the existing response slot.
    pub(in crate::source_acquisition) fn take_sent(
        &mut self,
    ) -> Option<crate::source_acquisition::reservation::SentProviderQueryV2> {
        let attempt = self.attempt.as_ref()?;
        self.sent.take().map(|sent| {
            crate::source_acquisition::reservation::SentProviderQueryV2::from_original_native_sent(
                attempt.attempt_id,
                sent,
            )
        })
    }

    /// Advances original catalog custody without taking the live admission away.
    pub(in crate::source_acquisition) fn advance_catalog(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        journal: &mut ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<()> {
        if self.stopped {
            return Err(state_error(
                "original native flight is retained after failure",
            ));
        }
        let result = (|| {
            if self.stage == Stage::BeginQuery {
                table.begin_original_native_provider_acquire_retaining_v5(
                    journal,
                    session,
                    &self.live,
                    &self.mount_request,
                    self.mount_plan,
                    self.ownership_lease,
                    &self.publication,
                    &self.catalog,
                    self.selection.clone(),
                    self.deadline,
                    &mut self.query,
                )?;
                self.stage = Stage::Query;
            }
            let query = self
                .query
                .as_mut()
                .ok_or_else(|| state_error("original native query custody absent"))?;
            if let Some(prepared) = session
                .prepare_native_acquire_v3(journal, query)
                .map_err(|_| state_error("original native catalog preparation failed"))?
            {
                self.prepared = Some(prepared);
                self.stage = Stage::PrepareAdmission;
            }
            Ok(())
        })();
        if result.is_err() {
            self.stopped = true;
        }
        result
    }

    /// Performs one bounded physical/sign/send stage while retaining all errors.
    pub(in crate::source_acquisition) fn advance(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        native_index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<bool> {
        if self.stopped {
            return Err(state_error(
                "original native flight is retained after failure",
            ));
        }
        let result = self.advance_stage(table, native_index, writer, session);
        if result.is_err() {
            self.stopped = true;
        }
        result
    }

    fn install(
        table: &mut SourceAcquisitionTableV2,
        native_index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
    ) -> Result<()> {
        writer.validate_readback(readback)?;
        *table = SourceAcquisitionTableV2::from_state(readback.graph().legacy().clone());
        *native_index = readback.graph().sidecars().clone();
        if !table.matches_state(readback.graph().legacy())
            || native_index != readback.graph().sidecars()
        {
            return Err(state_error(
                "original native private installation differs from physical readback",
            ));
        }
        writer.validate_readback(readback)?;
        Ok(())
    }

    fn advance_stage(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        native_index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<bool> {
        match self.stage {
            Stage::PrepareAdmission => {
                let prepared = self
                    .prepared
                    .as_ref()
                    .ok_or_else(|| state_error("original Acquire preparation absent"))?;
                let derived = table.derive_acquire_reservation(
                    &self.live,
                    self.mount_request.clone(),
                    self.mount_plan,
                    self.ownership_lease,
                    prepared,
                    true,
                )?;
                let (owners, tentative) =
                    prepare_mutation(table, derived.mutation, derived.records)?;
                self.owners = Some(owners);
                self.tentative = Some(tentative);
                self.attempt = Some(derived.attempt);
                self.head = Some(derived.head);
                let owners = self
                    .owners
                    .as_ref()
                    .ok_or_else(|| state_error("original owner bytes absent"))?;
                self.unsigned_root1 = Some(
                    session
                        .prepare_original_root_assertion_v5(writer, prepared, owners)
                        .map_err(|_| state_error("original unsigned Root1 currentness failed"))?,
                );
                self.admission_append = Some(
                    writer.prepare_admission(
                        owners,
                        self.unsigned_root1
                            .as_ref()
                            .ok_or_else(|| state_error("original unsigned Root1 absent"))?
                            .clone(),
                    )?,
                );
                self.stage = Stage::CommitAdmission;
            }
            Stage::CommitAdmission => {
                session
                    .revalidate_original_native_preparation_v5(
                        writer,
                        self.prepared
                            .as_ref()
                            .ok_or_else(|| state_error("original prepared Acquire absent"))?,
                    )
                    .map_err(|_| state_error("original admission currentness failed"))?;
                let append = self
                    .admission_append
                    .as_ref()
                    .ok_or_else(|| state_error("original admission append absent"))?;
                self.admission = Some(writer.commit_prepared(append).map_err(|error| {
                    session.invalidate_native_acquire_commit_v3();
                    error
                })?);
                let readback = self
                    .admission
                    .as_ref()
                    .ok_or_else(|| state_error("original admission readback absent"))?;
                if self
                    .tentative
                    .as_ref()
                    .is_none_or(|expected| !expected.matches_state(readback.graph().legacy()))
                {
                    session.invalidate_native_acquire_commit_v3();
                    return Err(state_error(
                        "original owner proposal differs from physical successor",
                    ));
                }
                Self::install(table, native_index, writer, readback)?;
                self.stage = Stage::Confirm;
            }
            Stage::Confirm => {
                let coordinates = reservation_coordinates(
                    self.attempt
                        .as_ref()
                        .ok_or_else(|| state_error("original Attempt absent"))?,
                    self.head
                        .as_ref()
                        .ok_or_else(|| state_error("original Head absent"))?,
                )?;
                let prepared = self
                    .prepared
                    .take()
                    .ok_or_else(|| state_error("original preparation absent"))?;
                match session.confirm_original_native_reservation_v5(
                    writer,
                    prepared,
                    coordinates.attempt_key,
                    coordinates.attempt_record,
                    coordinates.head_key,
                    coordinates.head_record,
                ) {
                    Ok(reservation) => self.reservation = Some(reservation),
                    Err((prepared, _)) => {
                        self.prepared = Some(prepared);
                        return Err(state_error("original reservation unconfirmed"));
                    }
                }
                self.stage = Stage::Sign;
            }
            Stage::Sign => {
                let admission = self
                    .admission
                    .as_ref()
                    .ok_or_else(|| state_error("original admission readback absent"))?;
                Self::install(table, native_index, writer, admission)?;
                match session.sign_original_root1_v5(
                    writer,
                    admission,
                    self.reservation
                        .as_ref()
                        .ok_or_else(|| state_error("original reservation absent"))?,
                ) {
                    Ok(signed) => self.signed_root1 = Some(signed),
                    Err((signed, _)) => {
                        self.signed_root1 = signed;
                        return Err(state_error("original Root1 signing/currentness failed"));
                    }
                }
                self.stage = Stage::PrepareRoot1Store;
            }
            Stage::PrepareRoot1Store => {
                self.root1_append = Some(
                    writer.prepare_root1_store(
                        self.admission
                            .as_ref()
                            .ok_or_else(|| state_error("original admission absent"))?,
                        self.signed_root1
                            .as_ref()
                            .ok_or_else(|| state_error("original signed Root1 absent"))?,
                    )?,
                );
                self.stage = Stage::CommitRoot1Store;
            }
            Stage::CommitRoot1Store => {
                self.persisted_root1 = Some(
                    writer
                        .commit_prepared(
                            self.root1_append
                                .as_ref()
                                .ok_or_else(|| state_error("original Root1 append absent"))?,
                        )
                        .map_err(|error| {
                            session.invalidate_native_acquire_commit_v3();
                            error
                        })?,
                );
                let persisted = self
                    .persisted_root1
                    .as_ref()
                    .ok_or_else(|| state_error("stored Root1 readback absent"))?;
                Self::install(table, native_index, writer, persisted)?;
                session
                    .advance_original_root1_reservation_v5(
                        writer,
                        persisted,
                        self.reservation
                            .as_mut()
                            .ok_or_else(|| state_error("original reservation absent"))?,
                        self.signed_root1
                            .as_ref()
                            .ok_or_else(|| state_error("original Root1 bytes absent"))?,
                    )
                    .map_err(|_| state_error("stored Root1 currentness/snapshot advance failed"))?;
                self.stage = Stage::SendRoot1;
            }
            Stage::SendRoot1 => {
                let send = session.send_original_root1_v5(
                    writer,
                    self.persisted_root1
                        .as_ref()
                        .ok_or_else(|| state_error("stored Root1 readback absent"))?,
                    self.reservation
                        .as_ref()
                        .ok_or_else(|| state_error("original reservation absent"))?,
                    self.signed_root1
                        .as_ref()
                        .ok_or_else(|| state_error("original Root1 bytes absent"))?,
                );
                match send {
                    Ok(false) => return Ok(false),
                    Ok(true) => {
                        self.root1_possible_send = true;
                        self.root1_sent = true;
                        self.stage = Stage::SendAcquire;
                    }
                    Err((possible, _)) => {
                        self.root1_possible_send |= possible;
                        return Err(state_error("original Root1 send/currentness failed"));
                    }
                }
            }
            Stage::SendAcquire | Stage::RetryAcquire => {
                if !self.root1_sent {
                    return Err(state_error(
                        "original Acquire cannot precede stored Root1 send",
                    ));
                }
                let persisted = self
                    .persisted_root1
                    .as_ref()
                    .ok_or_else(|| state_error("stored Root1 readback absent"))?;
                let signed = self
                    .signed_root1
                    .as_ref()
                    .ok_or_else(|| state_error("original Root1 bytes absent"))?;
                self.acquire_send_attempted = true;
                let send = if self.stage == Stage::SendAcquire {
                    session.send_original_native_acquire_v5(
                        writer,
                        persisted,
                        signed,
                        self.reservation
                            .take()
                            .ok_or_else(|| state_error("original reservation absent"))?,
                    )
                } else {
                    session.retry_original_native_acquire_v5(
                        writer,
                        persisted,
                        signed,
                        self.send_recovery
                            .take()
                            .ok_or_else(|| state_error("original send recovery absent"))?,
                    )
                };
                match send {
                    Ok(sent) => {
                        self.sent = Some(sent);
                        self.stage = Stage::Finished;
                    }
                    Err(recovery) => {
                        self.send_recovery = Some(recovery);
                        self.stage = Stage::RetryAcquire;
                        if session.current_authority_scope_v2().is_err() {
                            return Err(state_error("original Acquire send is occupied/poisoned"));
                        }
                        return Ok(false);
                    }
                }
            }
            Stage::Finished => return Ok(true),
            Stage::BeginQuery | Stage::Query => {
                return Err(state_error(
                    "original native query requires its retained catalog owner",
                ));
            }
        }
        Ok(self.stage == Stage::Finished)
    }
}
