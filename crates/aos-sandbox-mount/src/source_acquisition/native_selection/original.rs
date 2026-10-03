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
    CurrentRootMountSourceProviderSessionV1, CurrentMountProviderSessionPlanV2,
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

mod pending;
use pending::OriginalNativePendingFlightV5;

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
    catalog_plan: Option<CurrentMountProviderSessionPlanV2>,
    catalog_draft: Option<aos_sandbox_source_provider_protocol::AcquireSourceRequestV1>,
    query: Option<PendingNativeMountAcquireV3>,
    prepared: Option<PreparedMountProviderRequestV2>,
    owners: Option<JournalTransaction>,
    tentative: Option<SourceAcquisitionTableV2>,
    attempt: Option<SourceProviderQueryAttemptV2>,
    head: Option<SourceProviderHeadV2>,
    unsigned_root1: Option<PreparedNativeHeldControlV1>,
    admission_append: Option<PreparedOriginalRootAppendV5>,
    reservation: Option<ReservedMountProviderRequestV2>,
    signed_root1: Option<SignedNativeHeldControlV1>,
    root1_append: Option<PreparedOriginalRootAppendV5>,
    root1_possible_send: bool,
    root1_sent: bool,
    acquire_send_attempted: bool,
    sent: Option<SentMountProviderRequestV2>,
    pending: OriginalNativePendingFlightV5,
}

/// Fails the genuine original flight and actual Session on returned error or unwind.
struct OriginalFlightBoundaryV5<'flight, 'session> {
    flight: &'flight mut OriginalNativeAcquireFlightV5,
    session: &'session mut CurrentRootMountSourceProviderSessionV1,
    succeeded: bool,
}

impl<'flight, 'session> OriginalFlightBoundaryV5<'flight, 'session> {
    fn new(
        flight: &'flight mut OriginalNativeAcquireFlightV5,
        session: &'session mut CurrentRootMountSourceProviderSessionV1,
    ) -> Self {
        Self {
            flight,
            session,
            succeeded: false,
        }
    }

    fn run<R>(
        &mut self,
        operation: impl FnOnce(
            &mut OriginalNativeAcquireFlightV5,
            &mut CurrentRootMountSourceProviderSessionV1,
        ) -> Result<R>,
    ) -> Result<R> {
        let result = operation(self.flight, self.session);
        self.succeeded = result.is_ok();
        result
    }
}

impl Drop for OriginalFlightBoundaryV5<'_, '_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.flight.stop_original_inventory_v6(self.session);
        }
    }
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
            catalog_plan: None,
            catalog_draft: None,
            query: None,
            prepared: None,
            owners: None,
            tentative: None,
            attempt: None,
            head: None,
            unsigned_root1: None,
            admission_append: None,
            reservation: None,
            signed_root1: None,
            root1_append: None,
            root1_possible_send: false,
            root1_sent: false,
            acquire_send_attempted: false,
            sent: None,
            pending: OriginalNativePendingFlightV5::new(),
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
        OriginalFlightBoundaryV5::new(self, session).run(|flight, session| {
            if flight.stopped {
                return Err(state_error(
                    "original native flight is retained after failure",
                ));
            }
            let result = (|| {
                if flight.stage == Stage::BeginQuery {
                    table.begin_original_native_provider_acquire_retaining_v5(
                        journal,
                        session,
                        &flight.live,
                        &flight.mount_request,
                        flight.mount_plan,
                        flight.ownership_lease,
                        &flight.publication,
                        &flight.catalog,
                        flight.selection.clone(),
                        flight.deadline,
                        &mut flight.catalog_plan,
                        &mut flight.catalog_draft,
                        &mut flight.query,
                    )?;
                    flight.stage = Stage::Query;
                }
                let query = flight
                    .query
                    .as_mut()
                    .ok_or_else(|| state_error("original native query custody absent"))?;
                if session
                    .prepare_original_native_acquire_retaining_v5(journal, query, &mut flight.prepared)
                    .map_err(|_| state_error("original native catalog preparation failed"))?
                {
                    flight.stage = Stage::PrepareAdmission;
                }
                Ok(())
            })();
            if result.is_err() {
                flight.stopped = true;
            }
            result
        })
    }

    /// Performs one bounded physical/sign/send stage while retaining all errors.
    pub(in crate::source_acquisition) fn advance(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        native_index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<bool> {
        OriginalFlightBoundaryV5::new(self, session).run(|flight, session| {
            if flight.stopped {
                return Err(state_error(
                    "original native flight is retained after failure",
                ));
            }
            let result = flight.advance_stage(table, native_index, writer, session);
            if result.is_err() {
                flight.stopped = true;
            }
            result
        })
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
                session.prepare_original_root_assertion_retaining_v5(
                    writer,
                    prepared,
                    owners,
                    &mut self.unsigned_root1,
                ).map_err(|_| state_error("original unsigned Root1 currentness failed"))?;
                writer.prepare_admission_retaining_v5(
                    owners,
                    self.unsigned_root1.as_ref()
                        .ok_or_else(|| state_error("original unsigned Root1 absent"))?,
                    &mut self.admission_append,
                )?;
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
                let append = self.admission_append.as_mut()
                    .ok_or_else(|| state_error("original admission append absent"))?;
                writer.commit_prepared_retaining_v5(append)?;
                let readback = append.readback()?;
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
                session.confirm_original_native_reservation_retaining_v5(
                    writer,
                    &mut self.prepared,
                    coordinates.attempt_key,
                    coordinates.attempt_record,
                    coordinates.head_key,
                    coordinates.head_record,
                    &mut self.reservation,
                ).map_err(|_| state_error("original reservation unconfirmed"))?;
                self.stage = Stage::Sign;
            }
            Stage::Sign => {
                let admission = self.admission_append.as_ref()
                    .ok_or_else(|| state_error("original admission append absent"))?.readback()?;
                Self::install(table, native_index, writer, admission)?;
                session.sign_original_root1_retaining_v5(
                    writer,
                    admission,
                    self.reservation.as_ref()
                        .ok_or_else(|| state_error("original reservation absent"))?,
                    &mut self.signed_root1,
                ).map_err(|_| state_error("original Root1 signing/currentness failed"))?;
                self.stage = Stage::PrepareRoot1Store;
            }
            Stage::PrepareRoot1Store => {
                writer.prepare_root1_store_retaining_v5(
                    self.admission_append.as_ref()
                        .ok_or_else(|| state_error("original admission append absent"))?.readback()?,
                    self.signed_root1.as_ref()
                        .ok_or_else(|| state_error("original signed Root1 absent"))?,
                    &mut self.root1_append,
                )?;
                self.stage = Stage::CommitRoot1Store;
            }
            Stage::CommitRoot1Store => {
                let append = self.root1_append.as_mut()
                    .ok_or_else(|| state_error("original Root1 append absent"))?;
                writer.commit_prepared_retaining_v5(append)?;
                let persisted = append.readback()?;
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
                    self.root1_append
                        .as_ref()
                        .ok_or_else(|| state_error("stored Root1 append absent"))?.readback()?,
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
                let persisted = self.root1_append.as_ref()
                    .ok_or_else(|| state_error("stored Root1 append absent"))?.readback()?;
                let signed = self.signed_root1.as_ref()
                    .ok_or_else(|| state_error("original Root1 bytes absent"))?;
                self.acquire_send_attempted = true;
                if session.send_original_native_acquire_retaining_v5(
                    writer,
                    persisted,
                    signed,
                    &mut self.reservation,
                    &mut self.sent,
                ).map_err(|_| state_error("original Acquire send/currentness failed"))? {
                    self.stage = Stage::Finished;
                } else {
                    self.stage = Stage::RetryAcquire;
                    return Ok(false);
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
