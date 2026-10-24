//! Retains the actual accepted producer and stream without a self-reference.
//!
//! The accepted flight moves both existing originals into one custody bundle.
//! A native Current programme owns that bundle beside its writer state. Each
//! real Initial/predecessor or physical loan is transient; no field borrows
//! another field, and failed prefixes remain owned for terminal disposition.

mod bundle;
mod cache;
mod controller;
mod exchange;
mod query;
mod refreshed_cache;
mod refreshed_query;
mod refreshed_source;
mod signed;
mod trust;
mod use_admitted;
mod use_authorized;
mod use_reserved;

use std::error::Error;
use std::mem::size_of;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1, RootSelectedStartupBorrowV1,
    RootUpperMutationGuardV1,
};
use aos_sandbox_model::ResourceVector;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

use crate::native::startup::RootStartupControllerPeerOriginalV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{RootInitialOpenErrorV1, RootInitialOpenProgrammeOriginalV1};
use super::initial_provision::RootInitialOpenProvisionOriginalV1;
use super::writers::RootCurrentWritersOriginalV1;

/// Owns the same actual Initial peer producer and retained accepted stream.
///
/// This is a custody container. Moving these genuine originals supplies no
/// successful Current, Open, Ready, issuer or append completion. Fields remain
/// private, and a native programme must still run all original receiving stages.
pub struct RootCurrentAcceptedOriginalsV1<'startup> {
    pub(super) peer: RootStartupControllerPeerOriginalV1<'startup>,
    pub(super) stream: RetainedUnixStream,
}

impl<'startup> RootCurrentAcceptedOriginalsV1<'startup> {
    /// Moves the actual pair taken atomically from its accepted flight slots.
    ///
    /// This performs no observation, allocation, completion or role admission.
    #[doc(hidden)]
    #[must_use]
    pub fn from_taken_originals_v1(
        peer: RootStartupControllerPeerOriginalV1<'startup>,
        stream: RetainedUnixStream,
    ) -> Self {
        Self { peer, stream }
    }

    /// Moves the same original pair to its existing final disposition owner.
    ///
    /// The completed programme controls when its private bundle may leave.
    /// This method constructs no replacement peer, stream or positive receipt.
    #[doc(hidden)]
    #[must_use]
    pub fn into_taken_originals_v1(
        self,
    ) -> (
        RootStartupControllerPeerOriginalV1<'startup>,
        RetainedUnixStream,
    ) {
        (self.peer, self.stream)
    }

    /// Quotes the custody-only pair argument, constructor and transfer planes.
    ///
    /// The actual earlier incoming constructor pays this Memory-only amount.
    #[must_use]
    pub fn transfer_control_bytes_v1() -> Option<usize> {
        size_of::<(
            RootStartupControllerPeerOriginalV1<'startup>,
            RetainedUnixStream,
        )>()
        .checked_mul(6)?
        .checked_add(size_of::<Self>().checked_mul(4)?)?
        .checked_add(size_of::<Option<Self>>().checked_mul(3)?)
    }
}

/// Retains the genuine Current programme's owned accepted originals and stages.
///
/// Construction is inert. The only writer-state factory derives a transient
/// predecessor from this owner's actual producer and the same mutable Initial.
/// It never accepts supplied writer state, geometry as completion or a phase
/// result. Failure retains both original peer and stream beside reached writers.
pub struct RootOwnedCurrentOriginalV1<'startup> {
    original: UnixStream,
    originals: RootCurrentAcceptedOriginalsV1<'startup>,
    writers: Option<Result<RootCurrentWritersOriginalV1, RootObservationErrorV1>>,
    entered: bool,
    open_provision: RootInitialOpenProvisionOriginalV1,
    open_entry: Option<Result<(), RootObservationErrorV1>>,
    open: Option<RootInitialOpenProgrammeOriginalV1>,
    ready: super::initial_ready::RootInitialReadyOriginalV1,
    negative_shutdown: Option<Result<(), rustix::io::Errno>>,
    pins: super::initial_pins::RootInitialPinsOriginalV1,
    inputs: super::initial_inputs::RootInitialPolicyInputsOriginalV1,
    trust_fixed: super::initial_receiving::RootInitialStageOriginalV1,
    trust: Option<Box<super::initial_trust::RootInitialTrustOriginalV1>>,
    source_query: super::initial_source_query::RootInitialSourceQueryOriginalV1,
    source_exchange: super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    bundle_ownership: super::initial_bundle::RootInitialBundleOwnershipOriginalV1,
    cache_proof: super::initial_cache::RootInitialCacheProofOriginalV1,
    controller: super::initial_controller::RootInitialControllerReadonlyOriginalV1,
    use_authorized: super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
    use_reserved: super::use_tail::reserved::RootUseReservedOriginalV1,
    refreshed_source_query: super::initial_source_query::RootInitialSourceQueryOriginalV1,
    refreshed_source_exchange: super::initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    refreshed_cache_proof: super::initial_cache::RootInitialCacheProofOriginalV1,
    use_admitted: super::use_tail::admitted::RootUseAdmittedOriginalV1,
    signed_fixed: Option<super::initial_receiving::RootInitialStageOriginalV1>,
    signed_quote: Option<Result<ResourceVector, crate::native::PolicyNativeJournalErrorV1>>,
    signed_predecessor: Option<RootObservationErrorV1>,
    signed: Option<Box<super::use_tail::signed::RootSignedBoundOriginalV1>>,
}

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Retains the actual moved pair and the same owned handler socket.
    ///
    /// The original attempt already owns this handler after Prelude. Moving it
    /// together with the other originals avoids a self-reference and duplicates
    /// no descriptor. The existing append endpoint comparison binds it before
    /// Hello borrows it for the unchanged standard-library write path.
    #[must_use]
    pub fn from_originals_v1(
        originals: RootCurrentAcceptedOriginalsV1<'startup>,
        original: UnixStream,
    ) -> Self {
        Self {
            original,
            originals,
            writers: None,
            entered: false,
            open_provision: RootInitialOpenProvisionOriginalV1::new(),
            open_entry: None,
            open: None,
            ready: super::initial_ready::RootInitialReadyOriginalV1::new(),
            negative_shutdown: None,
            pins: super::initial_pins::RootInitialPinsOriginalV1::new(),
            inputs: super::initial_inputs::RootInitialPolicyInputsOriginalV1::new(),
            trust_fixed: super::initial_receiving::RootInitialStageOriginalV1::new(),
            trust: None,
            source_query: super::initial_source_query::RootInitialSourceQueryOriginalV1::new(),
            source_exchange:
                super::initial_source_exchange::RootInitialSourceExchangeOriginalV1::new(),
            bundle_ownership: super::initial_bundle::RootInitialBundleOwnershipOriginalV1::new(),
            cache_proof: super::initial_cache::RootInitialCacheProofOriginalV1::new(),
            controller: super::initial_controller::RootInitialControllerReadonlyOriginalV1::new(),
            use_authorized: super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1::new(
            ),
            use_reserved: super::use_tail::reserved::RootUseReservedOriginalV1::new(),
            refreshed_source_query:
                super::initial_source_query::RootInitialSourceQueryOriginalV1::new(),
            refreshed_source_exchange:
                super::initial_source_exchange::RootInitialSourceExchangeOriginalV1::new(),
            refreshed_cache_proof: super::initial_cache::RootInitialCacheProofOriginalV1::new(),
            use_admitted: super::use_tail::admitted::RootUseAdmittedOriginalV1::new(),
            signed_fixed: Some(super::initial_receiving::RootInitialStageOriginalV1::new()),
            signed_quote: None,
            signed_predecessor: None,
            signed: None,
        }
    }

    /// Enters the original once-only two-writer stages using the same Initial.
    ///
    /// The actual upper caller holds the original exclusion only for these
    /// existing receiving/native writer stages. No Initial borrow survives this
    /// call into later identity, clock, accepted-stream or issuer operations.
    ///
    /// # Errors
    /// Retains reentry, foreign Initial, earlier producer or writer refusal.
    pub fn receive_writers_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
        semantic_supplements: [Option<ResourceVector>; 2],
    ) -> Result<(), RootObservationErrorV1> {
        if self.entered || self.writers.is_some() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.entered = true;

        self.writers = Some(
            match self
                .originals
                .peer
                .borrow_current_writers_predecessor_v1(initial)
            {
                Ok(predecessor) => Ok(RootCurrentWritersOriginalV1::receive_once_v1(
                    predecessor,
                    startup,
                    exclusion,
                    semantic_supplements,
                )),
                Err(error) => Err(error),
            },
        );
        self.require_writers_complete_v1()
    }

    fn require_writers_complete_v1(&self) -> Result<(), RootObservationErrorV1> {
        if self.negative_shutdown.is_some() {
            return Err(RootObservationErrorV1::Service);
        }
        match &self.writers {
            Some(Ok(writers)) => writers.require_complete_v1(),
            _ => Err(RootObservationErrorV1::Service),
        }
    }

    /// Pays the actual initial Open Stage and its first service observation.
    ///
    /// # Errors
    /// Retains a foreign Initial, repeated entry, full-geometry, real debit or
    /// service refusal before constructing any initial native name/clock state.
    pub fn begin_initial_open_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.require_writers_complete_v1()?;
        if self.open_entry.is_some() || self.open.is_some() {
            if let Some(open) = &mut self.open {
                open.closed.get_or_insert(RootInitialOpenErrorV1::Boundary);
            }
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let entry = match &self.writers {
            Some(Ok(writers)) => match self
                .originals
                .peer
                .borrow_current_writers_predecessor_v1(initial)
            {
                Ok(predecessor) => {
                    self.open_provision
                        .begin_once_v1(writers, predecessor, startup, exclusion)
                }
                Err(error) => Err(error),
            },
            _ => Err(RootObservationErrorV1::Service),
        };
        self.open_entry = Some(entry);
        if !matches!(self.open_entry, Some(Ok(()))) {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.open = Some(RootInitialOpenProgrammeOriginalV1::new());
        Ok(())
    }

    /// Arms the distinct outer history obligation before identity and first time.
    ///
    /// # Errors
    /// Retains any original Stage/arm/traffic refusal on the same whole owner.
    pub fn arm_initial_open_outer_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.open_provision.require_complete_v1()?;
        let open = self.open.as_mut().ok_or(RootObservationErrorV1::Service)?;
        if open.outer_arm_returned.is_some() || open.closed.is_some() {
            open.closed.get_or_insert(RootInitialOpenErrorV1::Boundary);
            return Err(RootObservationErrorV1::Service);
        }
        open.outer_arm_returned = Some(
            match self
                .originals
                .peer
                .borrow_current_writers_predecessor_v1(initial)
            {
                Ok(predecessor) => open.outer.arm_once_v1(predecessor, startup, exclusion),
                Err(error) => Err(error),
            },
        );
        match &open.outer_arm_returned {
            Some(Ok(())) => Ok(()),
            _ => Err(RootObservationErrorV1::Service),
        }
    }

    /// Prepares the initial record from the actual pair, peer and first clock.
    ///
    /// # Errors
    /// Retains the second service observation, native names, first clock,
    /// nonce, encoding or transaction refusal without renewing the interval.
    pub fn prepare_initial_open_once_v1(
        &mut self,
        query: aos_sandbox_protocol::domain_ledger::create_storage_history::transport::OpenQueryV1,
    ) -> Result<(), RootInitialOpenErrorV1> {
        self.open_provision.require_complete_v1()?;
        let open = self.open.as_mut().ok_or(RootInitialOpenErrorV1::Boundary)?;
        if open.preparation_returned.is_some() || open.closed.is_some() {
            open.closed.get_or_insert(RootInitialOpenErrorV1::Boundary);
            return Err(RootInitialOpenErrorV1::Boundary);
        }
        let writers = match &mut self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(RootInitialOpenErrorV1::Boundary),
        };
        open.preparation_returned = Some(
            match open
                .outer
                .borrow_for_preparation_v1(&self.originals.peer, &self.originals.stream)
            {
                Ok(accepted) => open.prepared.prepare_once_v1(writers, &accepted, query),
                Err(error) => Err(RootInitialOpenErrorV1::Root(error)),
            },
        );
        match &open.preparation_returned {
            Some(Ok(())) => Ok(()),
            _ => Err(RootInitialOpenErrorV1::Boundary),
        }
    }

    /// Arms the separate final append crossing after actual preparation.
    ///
    /// # Errors
    /// Retains changed Initial, duplicate arm or real Stage/arm/traffic refusal.
    pub fn arm_initial_open_crossing_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.open_provision.require_complete_v1()?;
        let open = self.open.as_mut().ok_or(RootObservationErrorV1::Service)?;
        if !matches!(open.preparation_returned, Some(Ok(())))
            || open.crossing_history.is_some()
            || open.crossing_arm_returned.is_some()
            || open.closed.is_some()
        {
            open.closed.get_or_insert(RootInitialOpenErrorV1::Boundary);
            return Err(RootObservationErrorV1::Service);
        }
        open.crossing_arm_returned = Some(
            match self
                .originals
                .peer
                .borrow_current_writers_predecessor_v1(initial)
            {
                Ok(predecessor) => {
                    open.crossing_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(
                        predecessor,
                        startup,
                        exclusion,
                    ));
                    open.crossing_history
                        .as_ref()
                        .ok_or(RootObservationErrorV1::Service)?
                        .require_armed_v1()
                }
                Err(error) => Err(error),
            },
        );
        match &open.crossing_arm_returned {
            Some(Ok(())) => Ok(()),
            _ => Err(RootObservationErrorV1::Service),
        }
    }

    /// Appends through the sole native gate and retains the durable result first.
    ///
    /// # Errors
    /// Retains changed original custody, crossing, append or readback refusal.
    pub fn append_initial_open_once_v1(&mut self) -> Result<(), RootInitialOpenErrorV1> {
        self.open_provision.require_complete_v1()?;
        let open = self.open.as_mut().ok_or(RootInitialOpenErrorV1::Boundary)?;
        if open.append_returned.is_some() || open.closed.is_some() {
            open.closed.get_or_insert(RootInitialOpenErrorV1::Boundary);
            return Err(RootInitialOpenErrorV1::Boundary);
        }
        let writers = match &mut self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(RootInitialOpenErrorV1::Boundary),
        };
        let history = open
            .crossing_history
            .as_mut()
            .ok_or(RootInitialOpenErrorV1::Boundary)?;
        open.append_returned = Some(open.prepared.append_once_v1(
            writers,
            &mut open.crossing,
            history,
            &self.originals.peer,
            &self.originals.stream,
            self.original.as_fd(),
        ));
        match &open.append_returned {
            Some(Ok(())) => Ok(()),
            _ => Err(RootInitialOpenErrorV1::Boundary),
        }
    }

    /// Observes the independently owed outer names, peer and late clock once.
    ///
    /// This path requires neither healthy Current nor successful body/append.
    /// It uses the same owned originals and retains every reached actual cause.
    pub fn finish_initial_open_posts_once_v1(&mut self) {
        let Some(open) = &mut self.open else {
            return;
        };
        if open.finished {
            open.closed.get_or_insert(RootInitialOpenErrorV1::Boundary);
            return;
        }
        open.finished = true;
        if let Some(Ok(writers)) = &mut self.writers {
            open.outer.observe_once_v1(
                writers,
                &open.prepared,
                &self.originals.peer,
                &self.originals.stream,
            );
        }
        open.completion = Some(open.complete_after_posts_v1());
    }

    /// Requires the genuine initial Open including all independently owed posts.
    ///
    /// # Errors
    /// Refuses incomplete, failed, unappended or unobserved original custody.
    pub fn require_initial_open_complete_v1(&self) -> Result<(), RootInitialOpenErrorV1> {
        if self.negative_shutdown.is_some() {
            return Err(RootInitialOpenErrorV1::Boundary);
        }
        self.open_provision.require_complete_v1()?;
        self.open
            .as_ref()
            .ok_or(RootInitialOpenErrorV1::Boundary)?
            .require_complete_v1()
    }

    /// Pays the actual fixed Ready stage after this programme's complete Open.
    ///
    /// # Errors
    /// Retains same-Initial, receiver, quote, real debit and service refusal.
    pub fn begin_initial_ready_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.ready.claim_entry_once_v1()?;
        self.require_initial_open_complete_v1()
            .map_err(|_| RootObservationErrorV1::Service)?;
        let open = self.open.as_ref().ok_or(RootObservationErrorV1::Service)?;
        self.ready
            .require_entry_inputs_v1(&open.prepared)
            .map_err(|_| RootObservationErrorV1::Service)?;
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.ready.refuse_fixed_entry_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        self.ready.begin_fixed_once_v1(
            &open.prepared,
            &self.open_provision,
            predecessor,
            startup,
            exclusion,
        )
    }

    /// Closes a Ready entry after its earlier upper lock or borrower refusal.
    ///
    /// Full Open must already hold. The caller retains its actual owning error;
    /// this negative marker only preserves the old independently owed names,
    /// peer and ordinary-clock posts, and cannot authorize Hello or receipt.
    pub fn refuse_initial_ready_entry_once_v1(&mut self) {
        if self.require_initial_open_complete_v1().is_ok() {
            self.ready.refuse_unentered_once_v1();
        }
    }

    /// Enables strict receipt and sends Hello through the saved handler socket.
    ///
    /// # Errors
    /// Retains enable, unchanged clock, encoding and actual standard-write failure.
    pub fn send_initial_ready_hello_once_v1(&mut self) -> Result<(), RootInitialOpenErrorV1> {
        self.require_initial_open_complete_v1()?;
        let open = self.open.as_ref().ok_or(RootInitialOpenErrorV1::Boundary)?;
        self.ready
            .send_hello_once_v1(&mut self.originals, &self.original, &open.prepared)
    }

    /// Lends the actual prepared index frame and its same-owner subject stages.
    ///
    /// # Errors
    /// Refuses an unsent Hello, missing frame, repeated or negative entry.
    pub fn borrow_initial_ready_index_v1(
        &mut self,
    ) -> Result<
        super::initial_subject::RootInitialSubjectFrameBorrowV1<'_, 'startup>,
        RootInitialOpenErrorV1,
    > {
        let open = self.open.as_ref().ok_or(RootInitialOpenErrorV1::Boundary)?;
        self.ready
            .borrow_index_v1(&mut self.originals, &open.prepared)
    }

    /// Decodes only this genuinely received sequence-two Ready index.
    ///
    /// # Errors
    /// Retains frame, correlation, digest, extent or incomplete native custody.
    pub fn decode_initial_ready_index_once_v1(&mut self) -> Result<(), RootInitialOpenErrorV1> {
        let open = self.open.as_ref().ok_or(RootInitialOpenErrorV1::Boundary)?;
        self.ready.decode_index_once_v1(&open.prepared)
    }

    /// Pays actual declared Ready bytes before reserving the cumulative buffer.
    ///
    /// # Errors
    /// Retains repeated entry, changed original, quote, real debit or service refusal.
    pub fn fund_initial_ready_bytes_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.ready.refuse_variable_entry_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        self.ready
            .begin_variable_once_v1(predecessor, startup, exclusion)
    }

    /// Reserves only the actual funded cumulative encoded Ready extent.
    ///
    /// # Errors
    /// Retains allocation refusal or missing/repeated genuine variable stage.
    pub fn allocate_initial_ready_once_v1(&mut self) -> Result<(), RootInitialOpenErrorV1> {
        self.ready.allocate_once_v1()
    }

    /// Reports the actual next-chunk condition from this owner's decoded index.
    ///
    /// # Errors
    /// Refuses missing or failed actual variable allocation.
    pub fn initial_ready_has_next_v1(&self) -> Result<bool, RootInitialOpenErrorV1> {
        self.ready.has_next_v1()
    }

    /// Returns this index's checked extent for the shared lexical programme.
    ///
    /// # Errors
    /// Refuses a missing actual index or an unrepresentable extent.
    pub fn initial_ready_extent_v1(&self) -> Result<usize, RootInitialOpenErrorV1> {
        self.ready.extent_v1()
    }

    /// Prepares the next bounded frame from the actual private index and counter.
    ///
    /// # Errors
    /// Retains native preparation refusal and refuses any retained prior frame.
    pub fn prepare_initial_ready_frame_once_v1(&mut self) -> Result<(), RootInitialOpenErrorV1> {
        self.ready.prepare_frame_once_v1()
    }

    /// Lends this actual next Ready frame without exposing its mutable reader.
    ///
    /// # Errors
    /// Refuses an absent, unfunded or already closed same-owner frame.
    pub fn borrow_initial_ready_frame_v1(
        &mut self,
    ) -> Result<
        super::initial_subject::RootInitialSubjectFrameBorrowV1<'_, 'startup>,
        RootInitialOpenErrorV1,
    > {
        let open = self.open.as_ref().ok_or(RootInitialOpenErrorV1::Boundary)?;
        self.ready
            .borrow_chunk_v1(&mut self.originals, &open.prepared)
    }

    /// Validates and copies the genuinely received next frame using the sole recipe.
    ///
    /// # Errors
    /// Retains exact framing, sequence, correlation, capacity or extent refusal.
    pub fn copy_initial_ready_frame_once_v1(&mut self) -> Result<(), RootInitialOpenErrorV1> {
        let open = self.open.as_ref().ok_or(RootInitialOpenErrorV1::Boundary)?;
        self.ready.bind_copy_frame_once_v1(&open.prepared)
    }

    /// Disposes this fully copied frame before advancing the actual chunk counter.
    ///
    /// # Errors
    /// Refuses failed native custody or any missing exact copy conjunction.
    pub fn dispose_initial_ready_frame_once_v1(&mut self) -> Result<(), RootInitialOpenErrorV1> {
        self.ready.dispose_frame_once_v1()
    }

    /// Checks the complete Ready digest with the same canonical transfer recipe.
    ///
    /// # Errors
    /// Retains missing chunks, final length, commitment or repeated-entry refusal.
    pub fn digest_initial_ready_once_v1(&mut self) -> Result<(), RootInitialOpenErrorV1> {
        self.ready.digest_once_v1()
    }

    /// Runs owed writer names and committed readback after any transfer refusal.
    pub fn observe_initial_ready_names_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            self.ready
                .observe_names_and_readback_once_v1(writers, &open.prepared);
        }
    }

    /// Arms the independently owed Ready peer post under the same real Initial.
    ///
    /// Native transfer failure does not suppress this reached obligation.
    pub fn arm_initial_ready_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let returned = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => self
                .ready
                .arm_peer_post_once_v1(predecessor, startup, exclusion),
            Err(error) => {
                self.ready.park_peer_arm_refusal_v1(error);
                Err(())
            }
        };
        // The actual failed arm is already retained before denying this same
        // Initial under its real upper exclusion. No owning cause is replaced.
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Records failed upper exclusion acquisition before the owed Ready post.
    ///
    /// The actual upper lock error stays with its caller. This method cannot
    /// arm, observe or complete anything; it only preserves the negative arm
    /// slot so the independent late clock remains owed and reachable.
    pub fn refuse_initial_ready_post_arm_once_v1(&mut self) {
        self.ready.refuse_external_peer_arm_once_v1();
    }

    /// Observes the owed peer and separate late clock without a healthy gate.
    pub fn observe_initial_ready_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        self.ready
            .observe_peer_and_clock_once_v1(&self.originals, &open.prepared);
    }

    /// Borrows inert bytes only after every genuine Ready stage and owed post.
    ///
    /// This DATA query cannot construct pins, a native role or append completion.
    ///
    /// # Errors
    /// Refuses incomplete, failed, repeated or still-resident native custody.
    pub fn initial_ready_bytes_v1(&self) -> Result<&[u8], RootInitialOpenErrorV1> {
        self.require_initial_open_complete_v1()?;
        self.ready.raw_ready_bytes_v1()
    }

    /// Pays actual issuer capture only after this same original's full Ready.
    ///
    /// # Errors
    /// Retains incomplete Ready, foreign Initial, receiver, debit or service refusal.
    pub fn begin_initial_pins_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.pins.claim_entry_once_v1()?;
        self.initial_ready_bytes_v1()
            .map_err(|_| RootObservationErrorV1::Service)?;
        let open = self.open.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.pins.refuse_entry_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        self.pins
            .begin_once_v1(&open.prepared, &self.ready, predecessor, startup, exclusion)
    }

    /// Closes an entered issuer attempt after an earlier upper lock refusal.
    ///
    /// The upper driver retains its actual owning error before this negative
    /// marker. Full Ready must already hold; the marker only preserves the old
    /// independently owed writer, peer and ordinary-clock posts.
    pub fn refuse_initial_pins_entry_once_v1(&mut self) {
        if self.initial_ready_bytes_v1().is_ok() {
            self.pins.refuse_unentered_once_v1();
        }
    }

    /// Captures fixed issuers between the same real writer and record bookends.
    ///
    /// # Errors
    /// Retains actual native names/readback, credential, role-row or cache refusal.
    pub fn capture_initial_pins_once_v1(
        &mut self,
    ) -> Result<(), super::initial_pins::RootInitialPinsErrorV1> {
        self.initial_ready_bytes_v1()?;
        let open = self
            .open
            .as_ref()
            .ok_or(super::initial_pins::RootInitialPinsErrorV1::Stale)?;
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(super::initial_pins::RootInitialPinsErrorV1::Stale),
        };
        self.pins.capture_once_v1(writers, &open.prepared)
    }

    /// Posts entered credential custody and both writers after capture refusal.
    pub fn observe_initial_pins_native_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            self.pins
                .observe_native_posts_once_v1(writers, &open.prepared);
        }
    }

    /// Arms the independently owed issuer peer post under the same real Initial.
    pub fn arm_initial_pins_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let returned = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => self.pins.arm_peer_once_v1(predecessor, startup, exclusion),
            Err(error) => {
                self.pins.park_peer_refusal_v1(error);
                Err(())
            }
        };
        // The actual failed arm is already retained before denying this same
        // Initial under its real upper exclusion. No owning cause is replaced.
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Negatively records upper arm-lock refusal while preserving the owed clock.
    ///
    /// The upper caller retains its original owning lock cause before this marker.
    pub fn refuse_initial_pins_post_arm_once_v1(&mut self) {
        self.pins.refuse_peer_arm_once_v1();
    }

    /// Observes the independently owed issuer peer and ordinary original clock.
    pub fn observe_initial_pins_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        self.pins
            .observe_peer_and_clock_once_v1(&self.originals, &open.prepared);
    }

    /// Requires actual issuer capture and every same-original independent post.
    ///
    /// # Errors
    /// Refuses incomplete Ready/Open, negative disposition or any actual pins debt.
    pub fn require_initial_pins_complete_v1(
        &self,
    ) -> Result<(), super::initial_pins::RootInitialPinsErrorV1> {
        self.initial_ready_bytes_v1()?;
        self.pins.require_complete_v1()
    }

    /// Borrows genuine completed Initial pins without transferring the pair.
    ///
    /// This loan is not terminal Root6 or permanent serving authority. Its
    /// native consumers must retain their purpose-specific live final gates.
    ///
    /// # Errors
    /// Refuses any incomplete same-original Ready, issuer or owed-post result.
    pub fn borrow_initial_pins_v1(
        &self,
    ) -> Result<RootInitialPinsBorrowV1<'_, 'startup>, super::initial_pins::RootInitialPinsErrorV1>
    {
        self.require_initial_pins_complete_v1()?;
        Ok(RootInitialPinsBorrowV1 { owner: self })
    }

    /// Quotes native names owed even when the issuer fixed debit refuses.
    ///
    /// # Errors
    /// Retains a genuine native name forecast or checked arithmetic refusal.
    pub fn initial_pins_owed_names_demand_v1()
    -> Result<ResourceVector, crate::native::PolicyNativeJournalErrorV1> {
        super::initial_pins::RootInitialPinsOriginalV1::owed_names_demand_v1()
    }

    /// Pays the actual signed-input verifier from the same completed pins prefix.
    ///
    /// # Errors
    /// Retains prior custody, Initial association, cumulative debit or service refusal.
    pub fn begin_initial_policy_inputs_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        self.inputs.claim_entry_once_v1()?;
        self.require_initial_pins_complete_v1()
            .map_err(|_| RootObservationErrorV1::Service)?;
        let open = self.open.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.inputs.refuse_entry_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        self.inputs
            .begin_once_v1(&open.prepared, &self.pins, predecessor, startup, exclusion)
    }

    /// Preserves owed input-verification posts after an earlier upper lock refusal.
    ///
    /// The actual owning upper error precedes this negative marker. This cannot
    /// authorize the decoder, a signed-source result or any later purpose.
    pub fn refuse_initial_policy_inputs_entry_once_v1(&mut self) {
        if self.require_initial_pins_complete_v1().is_ok() {
            self.inputs.refuse_unentered_once_v1();
        }
    }

    /// Verifies untrusted retained inputs against this same opened policy pair.
    ///
    /// # Errors
    /// Retains writer/readback, raw shape/head, original clock or verifier refusal.
    pub fn verify_initial_policy_inputs_once_v1(
        &mut self,
        data: &crate::root_policy_inputs_data::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), super::initial_inputs::RootInitialPolicyInputsErrorV1> {
        self.require_initial_pins_complete_v1()
            .map_err(|_| super::initial_inputs::RootInitialPolicyInputsErrorV1::Incomplete)?;
        let open = self
            .open
            .as_ref()
            .ok_or(super::initial_inputs::RootInitialPolicyInputsErrorV1::Incomplete)?;
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(super::initial_inputs::RootInitialPolicyInputsErrorV1::Incomplete),
        };
        self.inputs.verify_once_v1(writers, &open.prepared, data)
    }

    /// Observes the independently owed writer bookend after input verification.
    pub fn observe_initial_policy_inputs_native_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            self.inputs
                .observe_native_posts_once_v1(writers, &open.prepared);
        }
    }

    /// Arms the independently owed policy-input peer using the same actual Initial.
    pub fn arm_initial_policy_inputs_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let returned = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => self
                .inputs
                .arm_peer_once_v1(predecessor, startup, exclusion),
            Err(error) => {
                self.inputs.park_peer_refusal_v1(error);
                Err(())
            }
        };
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Negatively records upper arm refusal while preserving the owed final clock.
    pub fn refuse_initial_policy_inputs_post_arm_once_v1(&mut self) {
        self.inputs.refuse_peer_arm_once_v1();
    }

    /// Observes the independent policy-input peer and final ordinary paired clock.
    pub fn observe_initial_policy_inputs_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        self.inputs
            .observe_peer_and_clock_once_v1(&self.originals, &open.prepared);
    }

    /// Requires actual signed-input verification and all same-original posts.
    ///
    /// # Errors
    /// Refuses incomplete prior issuer custody, decoding or independent posts.
    pub fn require_initial_policy_inputs_complete_v1(
        &self,
    ) -> Result<(), super::initial_inputs::RootInitialPolicyInputsErrorV1> {
        self.require_initial_pins_complete_v1()
            .map_err(|_| super::initial_inputs::RootInitialPolicyInputsErrorV1::Incomplete)?;
        self.inputs.require_complete_v1()
    }

    /// Borrows authenticated comparison DATA without exporting its native custody.
    ///
    /// # Errors
    /// Refuses any missing actual verification or owed post. Returned DATA cannot
    /// construct a native completion owner, later purpose or append permission.
    pub fn verified_initial_sources_data_v1(
        &self,
    ) -> Result<
        &crate::root_policy_inputs_data::RootSignedProjectSourcesDataV1,
        super::initial_inputs::RootInitialPolicyInputsErrorV1,
    > {
        self.require_initial_policy_inputs_complete_v1()?;
        self.inputs.verified_v1()
    }

    /// Quotes the four input-verification native names owed after fixed refusal.
    ///
    /// # Errors
    /// Refuses a native-name supplier failure or checked representation overflow.
    pub fn initial_policy_inputs_owed_names_demand_v1()
    -> Result<ResourceVector, crate::native::PolicyNativeJournalErrorV1> {
        super::initial_inputs::RootInitialPolicyInputsOriginalV1::owed_names_demand_v1()
    }

    /// Ends the same retained socket at the original negative disposition slot.
    ///
    /// This performs the existing shutdown once and retains its actual result.
    /// It returns no original, drops no failed state, and permanently prevents
    /// positive writer/Open/Ready continuation even when shutdown succeeds.
    pub fn observe_negative_shutdown_once_v1(&mut self) {
        if self.negative_shutdown.is_none() {
            self.negative_shutdown = Some(rustix::net::shutdown(
                self.originals.stream.as_fd(),
                rustix::net::Shutdown::Both,
            ));
        }
    }

    /// Borrows this same reached shutdown result without performing more IO.
    #[must_use]
    pub fn negative_shutdown_result_v1(&self) -> Option<&Result<(), rustix::io::Errno>> {
        self.negative_shutdown.as_ref()
    }

    /// Borrows the actual failed shutdown at its original disposition frontier.
    #[must_use]
    pub fn negative_shutdown_failure_v1(&self) -> Option<&rustix::io::Errno> {
        self.negative_shutdown
            .as_ref()
            .and_then(|result| result.as_ref().err())
    }

    /// Borrows the first reached writer or original predecessor failure.
    ///
    /// This performs no observation and cannot turn an error into completion.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if self.open_entry.is_some() {
            if let Some(error) = self.open_provision.failure_v1() {
                return Some(error);
            }
            if let Some(open) = &self.open {
                if let Some(error) = open.failure_v1() {
                    return Some(error);
                }
            }
            if let Some(Err(error)) = &self.open_entry {
                return Some(error);
            }
        }
        if self.ready.entered_v1() {
            if let Some(error) = self.ready.failure_v1() {
                return Some(error);
            }
        }
        if self.pins.entered_v1() {
            if let Some(error) = self.pins.failure_v1() {
                return Some(error);
            }
        }
        if self.inputs.entered_v1() {
            if let Some(error) = self.inputs.failure_v1() {
                return Some(error);
            }
        }
        if self.trust_fixed.entered {
            if let Some(error) = self.trust_fixed.failure_v1() {
                return Some(error);
            }
            if let Some(trust) = &self.trust {
                if let Some(error) = trust.failure_v1() {
                    return Some(error);
                }
            }
        }
        if self.source_query.entered_v1() {
            if let Some(error) = self.source_query.failure_v1() {
                return Some(error);
            }
        }
        if self.source_exchange.entered_v1() {
            if let Some(error) = self.source_exchange.failure_v1() {
                return Some(error);
            }
        }
        if self.bundle_ownership.entered_v1() {
            if let Some(error) = self.bundle_ownership.failure_v1() {
                return Some(error);
            }
        }
        if self.cache_proof.entered_v1() {
            if let Some(error) = self.cache_proof.failure_v1() {
                return Some(error);
            }
        }
        if self.controller.entered_v1() {
            if let Some(error) = self.controller.failure_v1() {
                return Some(error);
            }
        }
        if self.use_authorized.fixed.entered {
            if let Some(error) = self.use_authorized.failure_v1() {
                return Some(error);
            }
        }
        if self.use_reserved.entered_v1() {
            if let Some(error) = self.use_reserved.failure_v1() {
                return Some(error);
            }
        }
        if self.refreshed_source_query.entered_v1() {
            if let Some(error) = self.refreshed_source_query.failure_v1() {
                return Some(error);
            }
        }
        if self.refreshed_source_exchange.entered_v1() {
            if let Some(error) = self.refreshed_source_exchange.failure_v1() {
                return Some(error);
            }
        }
        if self.refreshed_cache_proof.entered_v1() {
            if let Some(error) = self.refreshed_cache_proof.failure_v1() {
                return Some(error);
            }
        }
        if self.use_admitted.fixed.entered {
            if let Some(error) = self.use_admitted.failure_v1() {
                return Some(error);
            }
        }
        if let Some(error) = self.signed_predecessor.as_ref() {
            return Some(error);
        }
        if let Some(Err(error)) = &self.signed_quote {
            return Some(error);
        }
        if let Some(error) = self
            .signed_fixed
            .as_ref()
            .and_then(super::initial_receiving::RootInitialStageOriginalV1::failure_v1)
        {
            return Some(error);
        }
        if let Some(error) = self
            .signed
            .as_deref()
            .and_then(super::use_tail::signed::RootSignedBoundOriginalV1::failure_v1)
        {
            return Some(error);
        }
        let earlier = match &self.writers {
            Some(Ok(writers)) => writers.failure_v1(),
            Some(Err(error)) => self.originals.peer.failure_v1().or(Some(error)),
            None => None,
        };
        earlier.or_else(|| self.negative_shutdown_failure_v1().map(|error| error as _))
    }

    /// Identifies only the actual selected deferred upper semantic diagnostic.
    ///
    /// The caller retains its original owning quote errors. This passive query
    /// returns a role only when the programme's genuine first failure is the
    /// identical negative marker stored at that role's native variable frontier.
    /// It selects no earlier error and supplies no geometry or successful debit.
    #[must_use]
    pub fn deferred_semantic_quote_role_v1(&self) -> Option<usize> {
        let selected = self
            .failure_v1()?
            .downcast_ref::<super::writers::RootCurrentWriterDemandErrorV1>()?;
        match &self.writers {
            Some(Ok(writers)) => writers.deferred_semantic_quote_role_v1(selected),
            _ => None,
        }
    }

    /// Quotes incremental native names owed even after Ready fixed refusal.
    ///
    /// The genuine incoming INITIAL constructor pays this before native programme
    /// construction. It is separate from later Ready fixed/byte stages and from
    /// Memory-only helper controls. It cannot replace financial provenance.
    ///
    /// # Errors
    /// Refuses checked overflow or an actual native name supplier failure.
    pub fn initial_ready_owed_names_demand_v1()
    -> Result<ResourceVector, crate::native::PolicyNativeJournalErrorV1> {
        super::initial_ready::RootInitialReadyOriginalV1::owed_names_demand_v1()
    }

    /// Quotes actual owned construction and transient predecessor interfaces.
    ///
    /// The real earlier Create branch consumes this before taking the accepted
    /// originals or constructing this owner. It grants no receiving permission.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        let writer_controls = RootCurrentWritersOriginalV1::receiving_construction_bytes_v1()?
            .checked_sub(size_of::<RootCurrentWritersOriginalV1>())?;
        size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<(&mut Self, std::os::fd::BorrowedFd<'_>,
                rustix::net::Shutdown)>().checked_mul(3)?)?
            .checked_add(size_of::<Option<Result<(), rustix::io::Errno>>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), rustix::io::Errno>>().checked_mul(3)?)?
            .checked_add(size_of::<(&Self, Option<&Result<(), rustix::io::Errno>>)>().checked_mul(3)?)?
            .checked_add(size_of::<(&Self, Option<&rustix::io::Errno>)>().checked_mul(3)?)?
            .checked_add(RootCurrentAcceptedOriginalsV1::transfer_control_bytes_v1()?)?
            .checked_add(size_of::<(RootCurrentAcceptedOriginalsV1<'startup>,
                UnixStream)>().checked_mul(3)?)?
            .checked_add(size_of::<(&UnixStream, std::os::fd::BorrowedFd<'_>)>()
                .checked_mul(3)?)?
            .checked_add(writer_controls)?
            .checked_add(super::initial_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_ready_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_pins_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_inputs_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_trust_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_source_query_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_source_exchange_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_bundle_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_cache_controls::construction_control_bytes_v1()?)?
            .checked_add(super::initial_controller::RootInitialControllerReadonlyOriginalV1::receiving_construction_bytes_v1()?)?
            .checked_add(super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1::receiving_construction_bytes_v1()?)?
            .checked_add(Self::use_reserved_construction_control_bytes_v1()?)?
            .checked_add(super::refreshed_controls::construction_control_bytes_v1()?)?
            .checked_add(super::preopen_geometry::EXTENT_QUERY_CONTROL_BYTES_V1)?
            .checked_add(Self::use_admitted_construction_control_bytes_v1()?)?
            .checked_add(Self::signed_construction_control_bytes_v1()?)?
            .checked_add(RootCurrentWritersOriginalV1::deferred_semantic_role_control_bytes_v1()?)?
            .checked_add(size_of::<(&Self, Option<usize>)>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?)?
            .checked_add(size_of::<(&mut Self, &mut RootInitialReceivingOriginalV1,
                &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>,
                [Option<ResourceVector>; 2])>().checked_mul(3)?)?
            .checked_add(size_of::<Result<crate::native::startup::RootCurrentWritersPredecessorV1<'_, '_, '_>,
                RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootCurrentWritersOriginalV1, RootObservationErrorV1>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<(&Self, Option<&(dyn Error + 'static)>)>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)
    }
}

/// Borrows actual Initial issuer custody and its original held pair.
///
/// Private construction requires the owning programme's genuine completed pins.
/// Public getters return diagnostic public-key DATA. Neither this loan nor any
/// returned bytes constructs terminal Root6, a completed pair or a new role.
pub struct RootInitialPinsBorrowV1<'held, 'startup> {
    owner: &'held RootOwnedCurrentOriginalV1<'startup>,
}

impl RootInitialPinsBorrowV1<'_, '_> {
    /// Borrows the independently captured Cache public verifier DATA.
    ///
    /// # Errors
    /// Refuses missing or no-longer-complete actual native issuer custody.
    pub fn cache_signer_v1(
        &self,
    ) -> Result<
        &aos_sandbox_protocol::cache_owner_readback::PinnedCacheOwnerReadbackSignerV1,
        super::initial_pins::RootInitialPinsErrorV1,
    > {
        self.owner.require_initial_pins_complete_v1()?;
        self.owner.pins.cache_signer_v1()
    }

    /// Borrows the independently captured Source public verifier DATA.
    ///
    /// # Errors
    /// Refuses missing or no-longer-complete actual native issuer custody.
    pub fn source_signer_v1(
        &self,
    ) -> Result<
        &aos_sandbox_ledger_replay::source_signer_data::PinnedSourceHoldReadbackSignerV1,
        super::initial_pins::RootInitialPinsErrorV1,
    > {
        self.owner.require_initial_pins_complete_v1()?;
        self.owner.pins.source_signer_v1()
    }

    /// Borrows the same whole original role tuple without recapturing any file.
    ///
    /// # Errors
    /// Refuses any incomplete actual issuer, writer, peer or original-clock post.
    pub fn saved_genesis_role_tuple_v1(
        &self,
    ) -> Result<&[u8; 488], super::initial_pins::RootInitialPinsErrorV1> {
        self.owner.require_initial_pins_complete_v1()?;
        self.owner.pins.saved_role_tuple_v1()
    }

    /// Compares saved pins to the SAME actual held policy at the transfer slot.
    ///
    /// This performs no credential IO, recapture, append, interval renewal or
    /// permission minting. Actual terminal/purpose provenance stays separate.
    ///
    /// # Errors
    /// Refuses incomplete custody or any changed whole role/cache row.
    pub fn require_serving_policy_v1(
        &self,
    ) -> Result<(), super::initial_pins::RootInitialPinsErrorV1> {
        self.owner.require_initial_pins_complete_v1()?;
        let (_, policy) = self.pair_v1()?;
        self.owner.pins.require_serving_policy_v1(policy)
    }

    pub(in crate::native) fn pair_v1(
        &self,
    ) -> Result<
        (
            &crate::native::journal::RootPolicyJournalV1,
            &crate::native::target::RootPolicyTargetOriginalV1,
        ),
        super::initial_pins::RootInitialPinsErrorV1,
    > {
        self.owner.require_initial_pins_complete_v1()?;
        let writers = match &self.owner.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(super::initial_pins::RootInitialPinsErrorV1::Stale),
        };
        Ok(writers
            .opened_pair_view_v1()
            .map_err(RootInitialOpenErrorV1::from)?)
    }

    pub(in crate::native) fn completed_prefix_data_v1(
        &self,
    ) -> Result<ResourceVector, super::initial_pins::RootInitialPinsErrorV1> {
        self.owner.pins.completed_prefix_v1()
    }
}
