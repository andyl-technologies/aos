//! Retained resource-bearing global genesis on the original Root flight.
//!
//! This owner parks Controller, Source, signer, transport and native outcomes
//! until the whole invocation succeeds or terminates. It enters only the Global
//! Empty/recovery purpose and borrows the common initial-Project bank grant
//! engine while the genuine Completed Root and Source ACK loans remain held.
//! A completion digest is provenance, not a paid operation permit.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;

use crate::Journal;
use crate::hierarchy::controller_genesis::require_controller;
use crate::hierarchy::controller_genesis_input::{
    ControllerSourceGenesisInputErrorV1, ProvisionedControllerSourceGenesisInputV1,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::protected_journal::retained_tree_inventory_data_v1;
use crate::hierarchy::source_genesis::{
    observe_retained_source_genesis_v1, observe_source_genesis_attempt_v1,
};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;

use super::flight::{OriginalRootGenesisFlightV1, OriginalRootGenesisOpeningClockV2};
use super::wire::RootSourceGenesisFrameKindV1 as Phase;

/// Parks the real configured pair and writers before the existing signer callback.
///
/// The signing key is a short callback argument and never a field of this owner.
/// An unfinished invocation aborts before any original resource field drops.
#[must_use = "retain the failed configured resource-Global genesis invocation until termination"]
pub struct OriginalConfiguredGlobalGenesisInvocationV2<'writers, 'profile> {
    journal: Option<&'writers mut Journal>,
    source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
    input: &'writers ProvisionedControllerSourceGenesisInputV1,
    profile: &'profile ProductionControllerNormalRootProfileV1,

    controller: Option<Result<
        crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1<'writers>,
        ControllerSourceGenesisInputErrorV1,
    >>,
    raw: Option<std::os::fd::OwnedFd>,
    adopted: Option<aos_sandbox_linux::unix_stream::RetainedUnixStream>,
    flight: Option<OriginalRootGenesisFlightV1<'profile>>,
    opening_clock: OriginalRootGenesisOpeningClockV2,
    negative_clock: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    negative_clock_check: Option<Result<(), SourceGenesisErrorV1>>,

    hello: Vec<u8>,
    hello_received: Option<Result<
        aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk,
        aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1,
    >>,
    connection: Option<Result<(), SourceGenesisErrorV1>>,
    signatures: [Option<Result<
        super::controller_readback::ControllerGenesisReadbackPacketV2,
        SourceGenesisErrorV1,
    >>; 3],
    signature_posts: [Vec<Result<(), SourceGenesisErrorV1>>; 3],
    io: [super::flight::ProjectGenesisFlightIoV3; 8],
    append: crate::hierarchy::source_genesis::SourceProjectGenesisMutationV3,
    acknowledge: crate::hierarchy::source_genesis::SourceProjectGenesisMutationV3,
    floor_ack: crate::hierarchy::controller_genesis::ControllerProjectGenesisMutationV3,
    complete: crate::hierarchy::controller_genesis::ControllerProjectGenesisMutationV3,

    resource_bank: Option<std::sync::Arc<std::sync::Mutex<
        crate::controller_resource_reservation::ControllerResourceBankOpeningV1,
    >>>,
    resource_grant: crate::controller_resource_reservation::ProjectResourceGrantAttemptV1,
    prefix: Option<crate::controller_resource_reservation::service_interval::FirstGlobalPrefixLoan<'writers>>,
    prefix_admission: Option<Result<(), crate::ResourceReservationErrorV1>>,
    prefix_duplicate: Option<crate::ResourceReservationErrorV1>,

    action: Option<Result<ObjectDigest, ControllerSourceGenesisInputErrorV1>>,
    signer_admission: Option<Result<(), std::io::Error>>,
    owner_posts: Vec<Result<(), SourceGenesisErrorV1>>,
    profile_post: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    clock_posts: Vec<Result<(), SourceGenesisErrorV1>>,
    first_failure: Option<ConfiguredGlobalGenesisSiteV2>,
    armed: bool,
}

#[derive(Clone, Copy)]
enum ConfiguredGlobalGenesisSiteV2 {
    Action,
    Signer,
    Connection,
    Controller,
    Signature(usize),
    SignaturePost(usize, usize),
    Io(usize),
    Append,
    FloorAck,
    Acknowledge,
    Complete,
    ResourceGrant,
    Prefix,
    PrefixDuplicate,
    OwnerPost(usize),
    ProfilePost,
    ClockPost(usize),
    NegativeClock,
    NegativeClockCheck,
}

/// Keeps the failed whole configured invocation resident through worker termination.
#[must_use = "the failed original configured resource-Global genesis loan must terminate"]
pub struct FailedConfiguredGlobalGenesisInvocationV2<'writers, 'profile> {
    original: OriginalConfiguredGlobalGenesisInvocationV2<'writers, 'profile>,
}

impl<'writers, 'profile> OriginalConfiguredGlobalGenesisInvocationV2<'writers, 'profile> {
    // These are DATA extents of the entered fixed family, not an admission
    // constructor. The bank joins them before this owner or its buffers exist.
    pub(crate) fn first_global_allocation_shape(
    ) -> Result<crate::controller_resource_reservation::service_interval::GlobalShape, SourceGenesisErrorV1> {
        let phases = [
            Phase::Prepare,
            Phase::Prepared,
            Phase::Anchor,
            Phase::Anchored,
            Phase::Complete,
            Phase::Completed,
            Phase::Finish,
            Phase::Finish,
        ];
        let header = super::wire::ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1;
        let mut wire_bytes = 32_usize.checked_add(56)
            .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let mut largest_payload = 0;
        for phase in phases {
            let payload = phase.payload_bytes_for_resource(true);
            largest_payload = largest_payload.max(payload);
            wire_bytes = wire_bytes.checked_add(header)
                .and_then(|bytes| bytes.checked_add(payload))
                .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        }
        // Three canonical signed packets and the independent native receive
        // originals coexist with their header/payload decode buffers.
        let packet_bytes = Phase::Prepare.payload_bytes_for_resource(true)
            .checked_mul(3).ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let retained_bytes = std::mem::size_of::<Self>()
            .checked_add(wire_bytes.checked_mul(3).ok_or(SourceGenesisErrorV1::NonCanonical)?)
            .and_then(|bytes| bytes.checked_add(packet_bytes.checked_mul(2)?))
            .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        Ok(crate::controller_resource_reservation::service_interval::GlobalShape {
            retained_bytes,
            wire_bytes,
            largest_payload,
        })
    }

    /// Parks the genuine executor Source field and Controller writer without effects.
    pub fn park(
        journal: &'writers mut Journal,
        source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Self {
        Self::park_inner(journal, Some(source), input, profile)
    }

    /// Parks the same startup bank owner for initial global Project reservation.
    ///
    /// The Arc is shared custody, not a grant. The actual completed original
    /// Controller/Source/Root chain must still authorize its durable CAS.
    pub fn park_with_resource_bank(
        journal: &'writers mut Journal,
        source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        bank: Option<std::sync::Arc<std::sync::Mutex<
            crate::controller_resource_reservation::ControllerResourceBankOpeningV1,
        >>>,
    ) -> Self {
        let mut original = Self::park(journal, source, input, profile);
        original.resource_bank = bank;
        original
    }

    fn park_inner(
        journal: &'writers mut Journal,
        source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Self {
        Self {
            journal: Some(journal),
            source,
            input,
            profile,
            controller: None,
            raw: None,
            adopted: None,
            flight: None,
            hello: Vec::new(),
            hello_received: None,
            connection: None,
            opening_clock: OriginalRootGenesisOpeningClockV2::new(),
            negative_clock: None,
            negative_clock_check: None,
            signatures: std::array::from_fn(|_| None),
            signature_posts: std::array::from_fn(|_| Vec::new()),
            io: std::array::from_fn(|_| super::flight::ProjectGenesisFlightIoV3::default()),
            append: crate::hierarchy::source_genesis::SourceProjectGenesisMutationV3::new(),
            acknowledge: crate::hierarchy::source_genesis::SourceProjectGenesisMutationV3::new(),
            floor_ack: crate::hierarchy::controller_genesis::ControllerProjectGenesisMutationV3::new(),
            complete: crate::hierarchy::controller_genesis::ControllerProjectGenesisMutationV3::new(),
            resource_bank: None,
            resource_grant: crate::controller_resource_reservation::ProjectResourceGrantAttemptV1::new(),
            prefix: None,
            prefix_admission: None,
            prefix_duplicate: None,
            action: None,
            signer_admission: None,
            owner_posts: Vec::new(),
            profile_post: None,
            clock_posts: Vec::new(),
            first_failure: None,
            armed: true,
        }
    }

    /// Attaches the same once-only entered prefix before signer or input work.
    ///
    /// Failure remains with this original invocation and cannot manufacture a
    /// replacement borrower or renew its later Root opening deadline.
    ///
    /// # Errors
    /// Refuses absent, different, spent or closed original receiving owners.
    /// The whole failure and available posts remain parked before this coarse
    /// status; the caller must refuse before loading the temporary signing key.
    pub fn attach_first_global_prefix(
        &mut self,
        original: &'writers crate::ControllerFirstGlobalPrefixAttemptV1,
    ) -> Result<(), crate::ResourceReservationErrorV1> {
        if self.prefix_admission.is_some() {
            if self.prefix_duplicate.is_none() {
                self.prefix_duplicate = Some(crate::ResourceReservationErrorV1::Conflict);
                if self.first_failure.is_none() {
                    self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::PrefixDuplicate);
                }
                if self.action.is_none() {
                    self.action = Some(Err(SourceGenesisErrorV1::AdmissionClosed.into()));
                    self.posts();
                }
            }
            return Err(crate::ResourceReservationErrorV1::Conflict);
        }
        let borrowed = match (
            self.resource_bank.as_ref(),
            self.journal.as_deref(),
            self.source.as_deref_mut(),
        ) {
            (Some(bank), Some(controller), Some(source)) =>
                original.borrow_for(bank, controller, source, self.profile),
            _ => Err(crate::ResourceReservationErrorV1::EnrollmentUnavailable),
        };
        self.prefix_admission = Some(match borrowed {
            Ok(loan) => {
                self.prefix = Some(loan);
                Ok(())
            }
            Err(error) => Err(error),
        });
        if self.prefix_admission.as_ref().is_some_and(Result::is_err) {
            if self.first_failure.is_none() {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Prefix);
            }
            if self.action.is_none() {
                self.action = Some(Err(SourceGenesisErrorV1::AdmissionClosed.into()));
                self.posts();
            }
            return Err(crate::ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Runs once with the existing temporary Controller signer callback loan.
    pub fn run_with_signer(&mut self, generation: u64, signer: &SigningKey) {
        if self.action.is_some() || self.signer_admission.is_some() {
            return;
        }
        self.action = Some(self.run_steps(generation, signer));
        if self.action.as_ref().is_some_and(Result::is_err) && self.first_failure.is_none() {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Action);
        }
        self.posts();
    }

    /// Parks actual fixed-signer admission failure without borrowing a dropped key.
    pub fn fail_signer_admission(&mut self, error: std::io::Error) {
        if self.signer_admission.is_some() {
            return;
        }
        self.signer_admission = Some(Err(error));
        if self.first_failure.is_none() {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Signer);
        }
        self.posts();
    }

    fn posts(&mut self) {
        let controller = match &self.controller {
            Some(Ok(controller)) => controller.recheck(),
            _ => self.journal.as_deref().map_or(Ok(()), |journal| {
                journal.ensure_healthy().map_err(SourceGenesisErrorV1::from)
            }),
        };
        let index = self.owner_posts.len();
        self.owner_posts.push(controller);
        if self.first_failure.is_none() && self.owner_posts[index].is_err() {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::OwnerPost(index));
        }

        if let Some(source) = self.source.as_deref() {
            let index = self.owner_posts.len();
            self.owner_posts.push(
                source
                    .require_fixed_named_writer_v1()
                    .map_err(SourceGenesisErrorV1::from),
            );
            if self.first_failure.is_none() && self.owner_posts[index].is_err() {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::OwnerPost(index));
            }
        }

        let index = self.owner_posts.len();
        self.owner_posts.push(
            self.input
                .recheck()
                .map_err(|_| SourceGenesisErrorV1::Stale),
        );
        if self.first_failure.is_none() && self.owner_posts[index].is_err() {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::OwnerPost(index));
        }

        self.profile_post = Some(if self.prefix_admission.is_some() {
            match self.prefix.as_ref() {
                Some(_) => self.profile.recheck_first_global_profile(),
                // A rejected receiving conjunction has no spending borrower
                // for the target profile. It must not enter a legacy observer
                // or spend a different original's still-open rows to diagnose
                // that refusal. Other owner/input posts and raw LAST still run.
                None => Err(crate::normal_root::NormalRootStartupErrorV1::Service),
            }
        } else {
            self.profile.recheck()
        });
        if self.first_failure.is_none() && self.profile_post.as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::ProfilePost);
        }

        if let Some(flight) = &self.flight {
            let index = self.owner_posts.len();
            self.owner_posts.push(if self.action.as_ref().is_some_and(Result::is_ok) {
                flight.original_terminal_clock().map(|_| ())
            } else {
                flight.first_successor_clock().map(|_| ())
            });
            if self.first_failure.is_none() && self.owner_posts[index].is_err() {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::OwnerPost(index));
            }

            let index = self.clock_posts.len();
            self.clock_posts
                .push(flight.observe_first_successor_clock().map(|_| ()));
            if self.first_failure.is_none() && self.clock_posts[index].is_err() {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::ClockPost(index));
            }
        } else if self.negative_clock.is_none() {
            // The final native pair remains available without an assembled
            // flight, including an initial pair failure. It cannot admit I/O
            // or replace the failed original; only original-cut checks follow.
            self.negative_clock = Some(super::flight::kernel_pair());
            if self.first_failure.is_none()
                && self.negative_clock.as_ref().is_some_and(Result::is_err)
            {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::NegativeClock);
            }
            self.negative_clock_check = Some(match &self.negative_clock {
                Some(Ok(current)) => self.opening_clock.check_later(*current),
                _ => Err(SourceGenesisErrorV1::Stale),
            });
            if self.first_failure.is_none()
                && self.negative_clock_check.as_ref().is_some_and(Result::is_err)
            {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::NegativeClockCheck);
            }
        }
    }

    fn run_steps(
        &mut self,
        generation: u64,
        signer: &SigningKey,
    ) -> Result<ObjectDigest, ControllerSourceGenesisInputErrorV1> {
        if self.prefix_duplicate.is_some()
            || self.prefix_admission.as_ref().is_some_and(Result::is_err)
        {
            return Err(SourceGenesisErrorV1::AdmissionClosed.into());
        }
        self.input.recheck()?;
        let journal = self.journal.as_deref().ok_or(SourceGenesisErrorV1::Stale)?;
        let uid = journal
            .protected_owner_uid()
            .map_err(SourceGenesisErrorV1::from)?;
        require_controller(journal, uid)?;
        self.source
            .as_deref()
            .ok_or(SourceGenesisErrorV1::Stale)?
            .require_fixed_named_writer_v1()
            .map_err(SourceGenesisErrorV1::from)?;

        // Seed/current-policy acceptance is independently authorized and fully
        // suffix-preflighted by the existing genuine input supplier. Retain
        // its whole Result before Root opens last; it makes no Root clock claim.
        let original_journal = self
            .journal
            .take()
            .ok_or(SourceGenesisErrorV1::Stale)?;
        self.controller = Some(self.input.hold(original_journal));
        if self.controller.as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Controller);
            return Err(SourceGenesisErrorV1::Stale.into());
        }

        self.connection = Some(OriginalRootGenesisFlightV1::connect_global_genesis_parked_v2(
            self.profile,
            &mut self.opening_clock,
            &mut self.raw,
            &mut self.adopted,
            &mut self.flight,
            &mut self.hello,
            &mut self.hello_received,
            uid,
            self.prefix.as_ref(),
        ));
        if self.connection.as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Connection);
            return Err(SourceGenesisErrorV1::Stale.into());
        }

        let flight = self.flight.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let source = self
            .source
            .as_deref_mut()
            .ok_or(SourceGenesisErrorV1::Stale)?;
        let controller = self
            .controller
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or(SourceGenesisErrorV1::Stale)?;

        {
            let observed = observe_source_genesis_attempt_v1(
                source,
                flight.first_successor_source_uid()?,
                self.input.project(),
            )?;
            if let Err(site) = super::controller_readback::capture_global_genesis_readback_v2(
                controller,
                &observed,
                generation,
                signer,
                flight,
                false,
                &mut self.signatures[0],
                &mut self.signature_posts[0],
            ) {
                self.first_failure = Some(signature_failure_site_v2(0, site));
                return Err(SourceGenesisErrorV1::Stale.into());
            }
        }
        let packet = self.signatures[0]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(SourceGenesisErrorV1::Stale)?;
        if flight
            .send_global_genesis_phase_v2(
                Phase::Prepare,
                packet.as_ref(),
                &mut self.io[0],
            )
            .is_err()
        {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Io(0));
            return Err(SourceGenesisErrorV1::Stale.into());
        }
        let phase = match flight.receive_global_genesis_phase_v2(
            &[Phase::Prepared, Phase::Anchored],
            &mut self.io[1],
        ) {
            Ok(phase) => phase,
            Err(()) => {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Io(1));
                return Err(SourceGenesisErrorV1::Stale.into());
            }
        };
        let reply = flight.global_genesis_reply_from_received_v2(
            controller,
            phase,
            &self.io[1].payload,
        )?;

        let floor = match reply {
            super::flight::OriginalRootGenesisReplyV1::Prepared(intent) => {
                if crate::hierarchy::source_genesis::append_source_global_genesis_v2(
                    source,
                    controller,
                    &intent,
                    &mut self.append,
                )
                .is_err()
                {
                    self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Append);
                    return Err(SourceGenesisErrorV1::Stale.into());
                }
                {
                    let inventory = retained_tree_inventory_data_v1(source)
                    .map_err(SourceGenesisErrorV1::from)?;
                    let observed = observe_retained_source_genesis_v1(
                        &inventory,
                        flight.first_successor_source_uid()?,
                        self.input.project(),
                    )?;
                    if let Err(site) = super::controller_readback::capture_global_genesis_readback_v2(
                        controller,
                        &observed,
                        generation,
                        signer,
                        flight,
                        false,
                        &mut self.signatures[1],
                        &mut self.signature_posts[1],
                    ) {
                        self.first_failure = Some(signature_failure_site_v2(1, site));
                        return Err(SourceGenesisErrorV1::Stale.into());
                    }
                }
                let packet = self.signatures[1]
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(SourceGenesisErrorV1::Stale)?;
                if flight
                    .send_global_genesis_phase_v2(
                        Phase::Anchor,
                        packet.as_ref(),
                        &mut self.io[2],
                    )
                    .is_err()
                {
                    self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Io(2));
                    return Err(SourceGenesisErrorV1::Stale.into());
                }
                if flight
                    .receive_global_genesis_phase_v2(&[Phase::Anchored], &mut self.io[3])
                    .is_err()
                {
                    self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Io(3));
                    return Err(SourceGenesisErrorV1::Stale.into());
                }
                flight.global_genesis_floor_from_received_v2(controller, &self.io[3].payload)?
            }
            super::flight::OriginalRootGenesisReplyV1::Anchored(floor) => floor,
        };

        {
            let inventory = retained_tree_inventory_data_v1(source)
                .map_err(SourceGenesisErrorV1::from)?;
            let observed = observe_retained_source_genesis_v1(
                &inventory,
                floor.source_uid(),
                self.input.project(),
            )?;
            if controller
                .settle_global_genesis_v2(&observed, &floor, false, &mut self.floor_ack)
                .is_err()
            {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::FloorAck);
                return Err(SourceGenesisErrorV1::Stale.into());
            }
        }

        if crate::hierarchy::source_genesis::acknowledge_source_global_genesis_v2(
            source,
            controller,
            &floor,
            &mut self.acknowledge,
        )
        .is_err()
        {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Acknowledge);
            return Err(SourceGenesisErrorV1::Stale.into());
        }

        {
            let inventory = retained_tree_inventory_data_v1(source)
                .map_err(SourceGenesisErrorV1::from)?;
            let observed = observe_retained_source_genesis_v1(
                &inventory,
                floor.source_uid(),
                self.input.project(),
            )?;
            if controller
                .settle_global_genesis_v2(&observed, &floor, true, &mut self.complete)
                .is_err()
            {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Complete);
                return Err(SourceGenesisErrorV1::Stale.into());
            }
            if let Err(site) = super::controller_readback::capture_global_genesis_readback_v2(
                controller,
                &observed,
                generation,
                signer,
                flight,
                true,
                &mut self.signatures[2],
                &mut self.signature_posts[2],
            ) {
                self.first_failure = Some(signature_failure_site_v2(2, site));
                return Err(SourceGenesisErrorV1::Stale.into());
            }
        }

        let packet = self.signatures[2]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(SourceGenesisErrorV1::Stale)?;
        if flight
            .send_global_genesis_phase_v2(
                Phase::Complete,
                packet.as_ref(),
                &mut self.io[4],
            )
            .is_err()
        {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Io(4));
            return Err(SourceGenesisErrorV1::Stale.into());
        }
        if flight
            .receive_global_genesis_phase_v2(&[Phase::Completed], &mut self.io[5])
            .is_err()
        {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Io(5));
            return Err(SourceGenesisErrorV1::Stale.into());
        }
        let completed = flight.completed_global_genesis_from_received_v2(
            &floor,
            &self.io[5].payload,
        )?;

        {
            let inventory = retained_tree_inventory_data_v1(source)
                .map_err(SourceGenesisErrorV1::from)?;
            let observed = observe_retained_source_genesis_v1(
                &inventory,
                completed.source_uid(),
                self.input.project(),
            )?;
            super::super::public_create_source::consume_completed_gen1_ancestry_v1(
                controller,
                &observed,
                &inventory,
                &completed,
            )?;
            if (self.resource_bank.is_some() || controller.acceptance().resource_envelope().is_some())
                && controller.reserve_completed_global_resources_v2(
                    self.resource_bank.as_ref(),
                    &observed,
                    &inventory,
                    &completed,
                    self.profile,
                    &mut self.resource_grant,
                )
                .is_err()
            {
                self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::ResourceGrant);
                return Err(SourceGenesisErrorV1::AdmissionClosed.into());
            }
        }

        if flight
            .send_global_genesis_phase_v2(
                Phase::Finish,
                completed.floor().digest().as_bytes(),
                &mut self.io[6],
            )
            .is_err()
        {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Io(6));
            return Err(SourceGenesisErrorV1::Stale.into());
        }
        if flight
            .receive_global_genesis_phase_v2(&[Phase::Finish], &mut self.io[7])
            .is_err()
        {
            self.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Io(7));
            return Err(SourceGenesisErrorV1::Stale.into());
        }
        if self.io[7].payload != completed.floor().digest().as_bytes() {
            return Err(SourceGenesisErrorV1::Conflict.into());
        }

        self.input.recheck()?;
        Ok(floor.floor().digest())
    }

    /// Returns success or the whole resident failed original without a local drop.
    ///
    /// # Errors
    /// Returns the original invocation when an action or independent check failed.
    pub fn into_outcome(
        mut self,
    ) -> Result<
        ObjectDigest,
        FailedConfiguredGlobalGenesisInvocationV2<'writers, 'profile>,
    > {
        if self.first_failure.is_none() {
            if let Some(Ok(digest)) = &self.action {
                let digest = *digest;
                self.armed = false;
                return Ok(digest);
            }
        }
        Err(FailedConfiguredGlobalGenesisInvocationV2 { original: self })
    }
}

fn signature_failure_site_v2(
    index: usize,
    site: super::controller_readback::ProjectGenesisSignatureFailureV3,
) -> ConfiguredGlobalGenesisSiteV2 {
    match site {
        super::controller_readback::ProjectGenesisSignatureFailureV3::Signature =>
            ConfiguredGlobalGenesisSiteV2::Signature(index),
        super::controller_readback::ProjectGenesisSignatureFailureV3::Post(post) =>
            ConfiguredGlobalGenesisSiteV2::SignaturePost(index, post),
        super::controller_readback::ProjectGenesisSignatureFailureV3::Refused =>
            ConfiguredGlobalGenesisSiteV2::Action,
    }
}

impl FailedConfiguredGlobalGenesisInvocationV2<'_, '_> {
    /// Borrows the exact first resident cause without observations or clones.
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let original = &self.original;
        match original.first_failure? {
            ConfiguredGlobalGenesisSiteV2::Action =>
                original.action
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::Signer =>
                original.signer_admission
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::Connection =>
                original.opening_clock
                    .initial_error()
                    .map(|e| e as _)
                    .or_else(|| {
                        original.hello_received
                            .as_ref()
                            .and_then(|r| r.as_ref().err())
                            .map(|e| e as _)
                    })
                    .or_else(|| {
                        original.connection
                            .as_ref()?
                            .as_ref()
                            .err()
                            .map(|e| e as _)
                    }),
            ConfiguredGlobalGenesisSiteV2::Controller =>
                original.controller
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::Signature(index) =>
                original.signatures
                    .get(index)?
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::SignaturePost(index, post) =>
                original.signature_posts
                    .get(index)?
                    .get(post)?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::Io(index) =>
                original.io.get(index)?.error(),
            ConfiguredGlobalGenesisSiteV2::Append =>
                original.append.error(),
            ConfiguredGlobalGenesisSiteV2::FloorAck =>
                original.floor_ack.error(),
            ConfiguredGlobalGenesisSiteV2::Acknowledge =>
                original.acknowledge.error(),
            ConfiguredGlobalGenesisSiteV2::Complete =>
                original.complete.error(),
            ConfiguredGlobalGenesisSiteV2::ResourceGrant =>
                original.resource_grant.error(),
            ConfiguredGlobalGenesisSiteV2::Prefix =>
                original.prefix_admission.as_ref()?.as_ref().err().map(|error| error as _),
            ConfiguredGlobalGenesisSiteV2::PrefixDuplicate =>
                original.prefix_duplicate.as_ref().map(|error| error as _),
            ConfiguredGlobalGenesisSiteV2::OwnerPost(index) =>
                original.owner_posts
                    .get(index)?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::ProfilePost =>
                original.profile_post
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::ClockPost(index) =>
                original.clock_posts
                    .get(index)?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::NegativeClock =>
                original.negative_clock
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
            ConfiguredGlobalGenesisSiteV2::NegativeClockCheck =>
                original.negative_clock_check
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _),
        }
    }
}

impl Drop for OriginalConfiguredGlobalGenesisInvocationV2<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

pub(crate) fn unavailable_global_genesis_v2<'writers, 'profile>(
    journal: &'writers mut Journal,
    input: &'writers ProvisionedControllerSourceGenesisInputV1,
    profile: &'profile ProductionControllerNormalRootProfileV1,
) -> FailedConfiguredGlobalGenesisInvocationV2<'writers, 'profile> {
    let mut original = OriginalConfiguredGlobalGenesisInvocationV2::park_inner(
        journal,
        None,
        input,
        profile,
    );
    original.action = Some(Err(SourceGenesisErrorV1::AdmissionClosed.into()));
    original.first_failure = Some(ConfiguredGlobalGenesisSiteV2::Action);
    FailedConfiguredGlobalGenesisInvocationV2 { original }
}
