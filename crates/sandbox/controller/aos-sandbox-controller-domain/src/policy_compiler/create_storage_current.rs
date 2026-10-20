//! Owns the actual selected Root connection before current-cut Open work.
//!
//! Open correlation remains untrusted DATA. This owner retains the accepted
//! endpoint, bounded Controller comparison and the same staged authority/state
//! writers. No decoded Open constructs Root authority or a signing permission.

use std::error::Error as StdError;
use std::os::unix::net::UnixStream;

use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, transport::{OPEN_BYTES, OpenQueryV1},
};

use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};

use super::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::root_policy_prelude::{RootPolicyPreludeOriginalV1, RootPolicyPurposeV1,
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1};
use super::bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1};

mod geometry;
mod history_pair;
pub(crate) mod use_admitted;
pub(crate) mod signed_bound;
pub(crate) mod outcome;
pub(crate) mod closed;
mod failure_view;
pub use failure_view::RootCurrentFailureViewV1;
pub(crate) mod ownership_trust;
pub(crate) mod bundle_ownership;
pub(crate) mod cache_current;
pub(crate) mod controller_readonly;
pub(crate) mod use_authorized;
pub(crate) mod use_reserved;
pub(crate) mod ready;
pub(crate) mod pins;
pub(crate) mod policy_inputs;
mod writer_sample;
pub(crate) mod root_open;
pub(crate) mod source_current;
use root_open::RootCurrentOpenStateV1;
use ready::RootCurrentReadyStateV1;
use pins::RootCurrentPinsStateV1;
use policy_inputs::{RootCurrentPolicyInputDataV1, RootCurrentPolicyInputsStateV1};

/// Reports a closed current-cut entrance without discarding its native cause.
#[derive(Debug, thiserror::Error)]
pub enum RootCreateStorageCurrentErrorV1 {
    /// The original endpoint, selected recipient or Controller comparison failed.
    #[error("original Root Create current connection is unavailable")]
    Original,
    /// Open correlation or fixed receipt failed before any variable phase.
    #[error("Root Create current Open is unavailable")]
    Open,
    /// The same-file authority/state replay or independent post failed.
    #[error("Root Create current writers are unavailable")]
    Writers,
    /// The history append or subsequent live current-cut continuation failed.
    #[error("Root Create current history supplier is unavailable")]
    History,
    /// The strictly received Ready transfer or its same-original posts failed.
    #[error("Root Create current Ready transfer is unavailable")]
    Ready,
}

/// Retains one actual accepted Root Create connection and every reached cause.
///
/// Only the whole selected prelude supplies this receiver. It already owns
/// the endpoint comparison and fixed prefix; this owner retains the same
/// absolute opening cutoff through the remainder and independent clock post.
/// Its Hello and inert Ready bytes grant no current-cut proof, U, signing,
/// dispatch or Prepare authority. Failed custody must remain
/// resident through intentional process termination.
pub struct OriginalRootCreateStorageCurrentAttemptV1<'flight, 'listener, 'startup> {
    disposition_guard: RootPolicyDispositionGuardV1,
    original: UnixStream,
    flight: &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    open_bytes: [u8; OPEN_BYTES],
    remainder_io: FixedDeadlineStreamIoV1<{ OPEN_BYTES - 32 }>,
    remainder_bytes: [u8; OPEN_BYTES - 32],
    remainder_read: Option<Result<(), RootCreateStorageCurrentErrorV1>>,
    decoded: Option<Result<OpenQueryV1, HistoryErrorV1>>,
    writers: RootCreateStorageCurrentWritersV1,
    opening: Option<Result<(), NormalRootStartupErrorV1>>,
    root_open: RootCurrentOpenStateV1,
    ready: RootCurrentReadyStateV1,
    pins: RootCurrentPinsStateV1,
    policy_inputs: RootCurrentPolicyInputsStateV1,
    ownership_trust_admission: Option<Result<(), NormalRootStartupErrorV1>>,
    ownership_trust: Option<Box<ownership_trust::RootCurrentOwnershipTrustStateV1>>,
    source_query: source_current::RootCurrentSourceQueryStateV1,
    source_exchange: source_current::RootCurrentSourceExchangeStateV1,
    bundle_ownership_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    bundle_ownership: Option<Box<bundle_ownership::RootCurrentBundleOwnershipStateV1>>,
    cache_current_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    cache_current: Option<Box<cache_current::RootCurrentCacheProofStateV1>>,
    controller_readonly_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    controller_readonly: Option<Box<controller_readonly::RootCurrentControllerReadonlyStateV1>>,
    use_authorized_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    use_authorized: Option<Box<use_authorized::RootCurrentUseAuthorizedStateV1>>,
    use_reserved_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    use_reserved: Option<Box<use_reserved::RootCurrentUseReservedStateV1>>,
    second_source_query: source_current::RootCurrentSourceQueryStateV1,
    second_source_exchange: source_current::RootCurrentSourceExchangeStateV1,
    second_cache_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    second_cache: Option<Box<cache_current::RootCurrentCacheProofStateV1>>,
    closed_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    terminal_closed: Option<Box<closed::RootCurrentClosedStateV1>>,
    outcome_entry: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    outcome: Option<Box<outcome::RootCurrentOutcomeStateV1>>,
    signed_bound_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    signed_bound: Option<Box<signed_bound::RootCurrentSignedBoundStateV1>>,
    use_admitted_entry: Option<Result<(), NormalRootStartupErrorV1>>,
    use_admitted: Option<Box<use_admitted::RootCurrentUseAdmittedStateV1>>,
    completion: Option<Result<(), RootCreateStorageCurrentErrorV1>>,
    negative_post: Option<Result<(), NormalRootStartupErrorV1>>,
    reentry: bool,
}

impl<'flight, 'listener, 'startup> OriginalRootCreateStorageCurrentAttemptV1<'flight, 'listener, 'startup> {
    /// Consumes the whole successfully classified original Create opening.
    pub(super) fn from_prelude_v1(
        prelude: RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup>,
    ) -> Self {
        if prelude.purpose_v1() != Some(RootPolicyPurposeV1::CreateStorage) {
            std::process::abort();
        }
        let RootPolicyPreludeOriginalV1 { disposition, original, flight, native, .. } = prelude;
        Self {
            disposition_guard: disposition, original, flight, prelude: native,
            peer: None, open_bytes: [0; OPEN_BYTES],
            remainder_io: Default::default(), remainder_bytes: [0; OPEN_BYTES - 32],
            remainder_read: None, decoded: None,
            writers: RootCreateStorageCurrentWritersV1::new(), opening: None,
            root_open: RootCurrentOpenStateV1::new(),
            ready: RootCurrentReadyStateV1::new(),
            pins: RootCurrentPinsStateV1::new(),
            policy_inputs: RootCurrentPolicyInputsStateV1::new(),
            ownership_trust_admission: None, ownership_trust: None,
            source_query: source_current::RootCurrentSourceQueryStateV1::new(),
            source_exchange: source_current::RootCurrentSourceExchangeStateV1::default(),
            bundle_ownership_entry: None, bundle_ownership: None,
            cache_current_entry: None, cache_current: None,
            controller_readonly_entry: None, controller_readonly: None,
            use_authorized_entry: None, use_authorized: None,
            use_reserved_entry: None, use_reserved: None,
            second_source_query: source_current::RootCurrentSourceQueryStateV1::new(),
            second_source_exchange: source_current::RootCurrentSourceExchangeStateV1::default(),
            second_cache_entry: None, second_cache: None,
            use_admitted_entry: None, use_admitted: None,
            signed_bound_entry: None,
            outcome_entry: None, outcome: None, signed_bound: None,
            closed_entry: None, terminal_closed: None,
            completion: None, negative_post: None, reentry: false,
        }
    }

    /// Transfers the actually completed Root6 writer pair to permanent serving custody.
    ///
    /// All completed input/read/phase owners are physically disposed before
    /// the original listener completes socket, independent Root and financial
    /// disposition. This consumes the one actual attempt; no native writer is
    /// reopened, copied or replaced by a newly constructed placeholder.
    ///
    /// # Errors
    /// Retains a rejected same-pair/financial handoff on the actual listener,
    /// or retains failed final socket/Root/common-operation disposition there.
    /// The installed caller terminates with that original still resident.
    ///
    /// Invalid or incomplete invocation aborts the process while this whole
    /// attempt remains resident, rather than unwinding failed native custody.
    pub fn finish_positive_once(mut self) -> Result<(), NormalRootStartupErrorV1> {
        if !matches!(self.completion, Some(Ok(()))) || self.reentry || self.failure().is_some()
            || self.terminal_closed.as_deref().is_none_or(|closed| closed.require_complete_v1().is_err()) {
            std::process::abort();
        }
        let terminal = match self.terminal_closed.as_mut().and_then(|closed| closed.take_terminal_once_v1().ok()) {
            Some(terminal) => terminal,
            None => std::process::abort(),
        };
        let Self {
            mut disposition_guard,
            original,
            flight,
            prelude,
            peer,
            open_bytes,
            remainder_io,
            remainder_bytes,
            remainder_read,
            decoded,
            writers,
            opening,
            root_open,
            ready,
            pins,
            policy_inputs,
            ownership_trust_admission,
            ownership_trust,
            source_query,
            source_exchange,
            bundle_ownership_entry,
            bundle_ownership,
            cache_current_entry,
            cache_current,
            controller_readonly_entry,
            controller_readonly,
            use_authorized_entry,
            use_authorized,
            use_reserved_entry,
            use_reserved,
            second_source_query,
            second_source_exchange,
            second_cache_entry,
            second_cache,
            closed_entry,
            terminal_closed,
            outcome_entry,
            outcome,
            signed_bound_entry,
            signed_bound,
            use_admitted_entry,
            use_admitted,
            completion,
            negative_post,
            reentry,
        } = self;
        if let Err(cause) = flight.park_completed_root_writers_once_v1(writers, terminal, pins) {
            // The whole failed offer is already parked on the listener. Run
            // its independent owed final disposition before terminating while
            // all remaining upper originals are still held on this stack.
            let _owed = flight.finish_dispatch_once(Err(Box::new(cause)));
            std::process::abort();
        }
        disposition_guard.handed_off = true;
        // Each carrier passed its real final borrower before this disposal.
        // The same terminal pair and actual pinned issuer owner remain in
        // permanent serving custody; no initial pin capture is rearmed.
        drop((
            disposition_guard,
            original,
            prelude,
            peer,
            open_bytes,
            remainder_io,
            remainder_bytes,
            remainder_read,
            decoded,
            opening,
            root_open,
            ready,
            policy_inputs,
            ownership_trust_admission,
            ownership_trust,
            source_query,
            source_exchange,
            bundle_ownership_entry,
            bundle_ownership,
            cache_current_entry,
            cache_current,
            controller_readonly_entry,
            controller_readonly,
            use_authorized_entry,
            use_authorized,
            use_reserved_entry,
            use_reserved,
            second_source_query,
            second_source_exchange,
            second_cache_entry,
            second_cache,
            closed_entry,
            terminal_closed,
            outcome_entry,
            outcome,
            signed_bound_entry,
            signed_bound,
            use_admitted_entry,
            use_admitted,
            completion,
            negative_post,
            reentry,
        ));
        flight.finish_dispatch_once(Ok(()))
    }

    pub(super) fn positive_disposition_demand_v1() -> Result<aos_sandbox_model::ResourceVector, crate::journal::JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(crate::journal::JournalError::JournalTooLarge)?;
        Ok(aos_sandbox_model::ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes, bytes))
    }

    /// Receives Ready, verifies local policy inputs and requests a fresh Source cut.
    ///
    /// # Errors
    /// Retains endpoint, native timeout/read, purpose, PID1/peer, decoder and
    /// replay, strict Ready, local signed-input and Source17 failures. The
    /// fixed Source UID/GID come from the actual service configuration; neither
    /// those scalars nor reply bytes choose a verification key or grant Use.
    /// Complete typed B and the cross-owner terminal remain closed.
    pub fn serve_once(
        &mut self,
        policy_inputs: &RootCurrentPolicyInputDataV1<'_>,
        source_signer_uid: u32,
        source_socket_gid: u32,
        private: crate::journal::broker_session_receiving::StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), RootCreateStorageCurrentErrorV1> {
        if self.completion.is_some() {
            self.reentry = true;
            return Err(RootCreateStorageCurrentErrorV1::Original);
        }
        self.disposition_guard.entered = true;
        self.completion = Some(self.receive_open_inner(policy_inputs, source_signer_uid, source_socket_gid, private));
        if matches!(self.completion, Some(Ok(()))) { Ok(()) }
        else { Err(RootCreateStorageCurrentErrorV1::Open) }
    }

    fn receive_open_inner(
        &mut self,
        policy_inputs: &RootCurrentPolicyInputDataV1<'_>,
        source_signer_uid: u32,
        source_socket_gid: u32,
        private: crate::journal::broker_session_receiving::StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), RootCreateStorageCurrentErrorV1> {
        use RootCreateStorageCurrentErrorV1 as Error;

        self.receive_open_frame_once_v1()?;
        let startup = self.flight.current_cut_startup().map_err(|_| Error::Original)?;
        self.opening = Some(startup.receive_create_storage_current_writers_once(&mut self.writers));
        if !matches!(self.opening, Some(Ok(()))) { return Err(Error::Writers); }
        let open = self.decoded.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(Error::Open)?;
        self.root_open.produce_once(self.flight, &mut self.writers, &self.original, open)?;
        self.ready.receive_once(self.flight, &mut self.writers, &self.original, &self.root_open)?;
        let _encoded_ready = self.ready.raw_ready_bytes()?;
        self.pins.capture_once(self.flight, &mut self.writers, &self.root_open, &self.ready)?;
        self.policy_inputs.verify_once(
            self.flight, &mut self.writers, &self.root_open, &self.pins, policy_inputs,
        )?;
        self.capture_ownership_trust_once()?;
        let trust = self.ownership_trust.as_deref().ok_or(Error::History)?;
        self.source_query.prepare_once(self.flight, &self.root_open, &self.ready,
            &self.pins, &self.policy_inputs, trust)?;
        self.source_exchange.exchange_once(self.flight, &mut self.writers, &self.root_open,
            &self.ready, &self.pins, &self.source_query, source_signer_uid, source_socket_gid)?;
        let trust = self.ownership_trust.as_deref().ok_or(Error::History)?;
        self.bundle_ownership_entry = Some(self.flight.current_cut_startup()
            .map_err(|_| Error::Original)?
            .prepay_create_storage_bundle_ownership_fixed_once(
                &self.root_open, &self.source_exchange, trust,
            ));
        if !matches!(self.bundle_ownership_entry, Some(Ok(()))) {
            return Err(Error::History);
        }
        self.bundle_ownership = Some(Box::new(bundle_ownership::RootCurrentBundleOwnershipStateV1::new()));
        self.bundle_ownership.as_mut().ok_or(Error::History)?.verify_once(
            self.flight, &mut self.writers, &self.root_open, &self.ready,
            &self.source_exchange, trust,
        )?;
        let ownership = self.bundle_ownership.as_deref().ok_or(Error::History)?;
        self.cache_current_entry = Some(self.flight.current_cut_startup()
            .map_err(|_| Error::Original)?
            .prepay_create_storage_cache_current_once(&self.root_open, ownership, &self.pins));
        if !matches!(self.cache_current_entry, Some(Ok(()))) { return Err(Error::History); }
        self.cache_current = Some(Box::new(cache_current::RootCurrentCacheProofStateV1::new()));
        self.cache_current.as_mut().ok_or(Error::History)?.exchange_once(
            self.flight, &mut self.writers, &self.original, &self.root_open,
            &self.ready, &self.source_exchange, &self.pins, ownership,
        )?;
        let cache = self.cache_current.as_deref().ok_or(Error::History)?;
        self.controller_readonly_entry = Some(self.flight.current_cut_startup()
            .map_err(|_| Error::Original)?
            .prepay_create_storage_controller_readonly_fixed_once(&self.root_open, cache));
        if !matches!(self.controller_readonly_entry, Some(Ok(()))) {
            return Err(Error::History);
        }
        self.controller_readonly = Some(Box::new(controller_readonly::RootCurrentControllerReadonlyStateV1::new()));
        self.controller_readonly.as_mut().ok_or(Error::History)?.capture_once(
            self.flight, &mut self.writers, &self.root_open, &self.ready,
            cache, &self.source_exchange, ownership, policy_inputs,
        )?;
        let readonly = self.controller_readonly.as_deref().ok_or(Error::History)?;
        self.use_authorized_entry = Some(self.flight.current_cut_startup()
            .map_err(|_| Error::Original)?
            .prepay_create_storage_use_authorized_once(&self.root_open, readonly));
        if !matches!(self.use_authorized_entry, Some(Ok(()))) { return Err(Error::History); }
        self.use_authorized = Some(Box::new(use_authorized::RootCurrentUseAuthorizedStateV1::new()));
        self.use_authorized.as_mut().ok_or(Error::History)?.produce_once(
            self.flight, &mut self.writers, &self.original, &self.root_open,
            &self.ready, &self.source_exchange, cache, ownership, readonly, private,
        )?;
        let authorization = self.use_authorized.as_deref().ok_or(Error::History)?;
        self.use_reserved_entry = Some(self.flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_use_reserved_frame_once(&self.root_open, authorization));
        if !matches!(self.use_reserved_entry, Some(Ok(()))) { return Err(Error::History); }
        self.use_reserved = Some(Box::new(use_reserved::RootCurrentUseReservedStateV1::new()));
        self.use_reserved.as_mut().ok_or(Error::History)?.capture_once(self.flight, &mut self.writers,
            &self.original, &self.root_open, authorization, &self.ready, &self.source_exchange,
            cache, readonly, ownership, policy_inputs)?;
        let reserved = self.use_reserved.as_deref().ok_or(Error::History)?;
        self.second_source_query.prepare_use_once(self.flight, &self.root_open, &self.ready,
            &self.pins, &self.policy_inputs, trust, authorization, reserved)?;
        self.second_source_exchange.exchange_use_once(self.flight, &mut self.writers,
            &self.root_open, &self.ready, &self.pins, &self.second_source_query,
            source_signer_uid, source_socket_gid, authorization, reserved)?;
        self.second_cache_entry = Some(self.flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_use_cache_current_once(&self.root_open, authorization,
                reserved, &self.second_source_exchange, &self.pins, ownership));
        if !matches!(self.second_cache_entry, Some(Ok(()))) { return Err(Error::History); }
        self.second_cache = Some(Box::new(cache_current::RootCurrentCacheProofStateV1::new()));
        self.second_cache.as_mut().ok_or(Error::History)?.exchange_use_once(self.flight,
            &mut self.writers, &self.original, &self.root_open, &self.ready,
            &self.second_source_exchange, &self.pins, ownership, authorization, reserved)?;
        let second_cache = self.second_cache.as_deref().ok_or(Error::History)?;
        self.use_admitted_entry = Some(self.flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_use_admitted_once(&self.root_open, authorization,
                reserved, &self.second_source_exchange, second_cache));
        if !matches!(self.use_admitted_entry, Some(Ok(()))) { return Err(Error::History); }
        self.use_admitted = Some(Box::new(use_admitted::RootCurrentUseAdmittedStateV1::new()));
        self.use_admitted.as_mut().ok_or(Error::History)?.produce_once(self.flight, &mut self.writers,
            &self.original, &self.root_open, &self.ready, authorization, reserved,
            &self.second_source_exchange, second_cache)?;
        let admitted = self.use_admitted.as_deref().ok_or(Error::History)?;
        self.signed_bound_entry = Some(self.flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_signed_fixed_once(&self.root_open, admitted));
        if !matches!(self.signed_bound_entry, Some(Ok(()))) { return Err(Error::History); }
        self.signed_bound = Some(Box::new(signed_bound::RootCurrentSignedBoundStateV1::new()));
        self.signed_bound.as_mut().ok_or(Error::History)?.produce_once(self.flight, &mut self.writers,
            &self.original, &self.root_open, &self.ready, admitted, reserved,
            &self.second_source_exchange, ownership, second_cache, policy_inputs, authorization)?;
        let signed = self.signed_bound.as_deref().ok_or(Error::History)?;
        self.outcome_entry = Some(self.flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_outcome_fixed_once(&self.root_open, signed, admitted));
        if !matches!(self.outcome_entry, Some(Ok(()))) { return Err(Error::History); }
        self.outcome = Some(Box::new(outcome::RootCurrentOutcomeStateV1::new()));
        self.outcome.as_mut().ok_or(Error::History)?.produce_once(self.flight, &mut self.writers,
            &self.original, &self.root_open, &self.ready, second_cache, &self.second_source_exchange,
            ownership, policy_inputs, authorization, reserved, admitted, signed)?;
        let outcome = self.outcome.as_deref().ok_or(Error::History)?;
        self.closed_entry = Some(self.flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_closed_fixed_once(&self.root_open, signed, outcome));
        if !matches!(self.closed_entry, Some(Ok(()))) { return Err(Error::History); }
        self.terminal_closed = Some(Box::new(closed::RootCurrentClosedStateV1::new()));
        self.terminal_closed.as_mut().ok_or(Error::History)?.produce_once(self.flight, &mut self.writers,
            &self.original, &self.root_open, &self.ready, second_cache, &self.second_source_exchange,
            ownership, policy_inputs, authorization, reserved, signed, outcome)
    }

    pub(crate) fn completed_second_source_v1(&self)
        -> Result<&source_current::RootCurrentSourceExchangeStateV1, RootCreateStorageCurrentErrorV1>
    {
        let authorization = self.use_authorized.as_deref().ok_or(RootCreateStorageCurrentErrorV1::History)?;
        let reserved = self.use_reserved.as_deref().ok_or(RootCreateStorageCurrentErrorV1::History)?;
        self.second_source_exchange.require_use_complete_for_v1(&self.root_open, authorization, reserved)?;
        Ok(&self.second_source_exchange)
    }

    pub(crate) fn completed_second_cache_v1(&self)
        -> Result<&cache_current::RootCurrentCacheProofStateV1, RootCreateStorageCurrentErrorV1>
    {
        self.completed_second_source_v1()?;
        let authorization = self.use_authorized.as_deref().ok_or(RootCreateStorageCurrentErrorV1::History)?;
        let reserved = self.use_reserved.as_deref().ok_or(RootCreateStorageCurrentErrorV1::History)?;
        let cache = self.second_cache.as_deref().ok_or(RootCreateStorageCurrentErrorV1::History)?;
        cache.require_use_complete_for_v1(&self.root_open, authorization, reserved)?;
        Ok(cache)
    }

    fn receive_open_frame_once_v1(&mut self) -> Result<(), RootCreateStorageCurrentErrorV1> {
        use RootCreateStorageCurrentErrorV1 as Error;
        let received = (|| {
            let cutoff = self.prelude.cutoff_v1().map_err(|_| Error::Open)?;
            self.open_bytes[..32].copy_from_slice(self.prelude.prefix_bytes_v1());
            self.peer = Some(self.flight.admit_current_controller_peer_once());
            if !matches!(self.peer, Some(Ok(()))) { return Err(Error::Original); }
            // These bytes remain correlation DATA. The later strict subject
            // receipt is unchanged and never retroactively authenticates Open.
            self.remainder_read = Some(self.remainder_io.run_once(
                &mut self.original, &mut self.remainder_bytes, cutoff,
                DeadlineStreamDirectionV1::Read).map_err(|_| Error::Open));
            if !matches!(self.remainder_read, Some(Ok(()))) { return Err(Error::Open); }
            self.open_bytes[32..].copy_from_slice(&self.remainder_bytes);
            self.decoded = Some(OpenQueryV1::decode(&self.open_bytes));
            if !matches!(self.decoded, Some(Ok(_))) { return Err(Error::Open); }
            Ok(())
        })();
        // The original opening pair is always posted before any writer growth,
        // including a rejected peer or partial fixed remainder.
        let posted = self.prelude.finish_opening_once_v1();
        received?;
        posted.map_err(|_| Error::Open)
    }

    fn capture_ownership_trust_once(&mut self) -> Result<(), RootCreateStorageCurrentErrorV1> {
        use RootCreateStorageCurrentErrorV1 as Error;
        if self.ownership_trust_admission.is_some() || self.ownership_trust.is_some() {
            return Err(Error::Original);
        }
        self.ownership_trust_admission = Some(self.flight.current_cut_startup()
            .map_err(|_| Error::Original)?
            .prepay_create_storage_ownership_trust_fixed_once(&self.root_open, &self.policy_inputs));
        if !matches!(self.ownership_trust_admission, Some(Ok(()))) { return Err(Error::Original); }
        // Both the construction temporary and this exact Box destination were
        // paid before allocation. Negative work remains parked on this attempt.
        self.ownership_trust = Some(Box::new(ownership_trust::RootCurrentOwnershipTrustStateV1::new()));
        self.ownership_trust.as_mut().ok_or(Error::History)?
            .capture_once(self.flight, &mut self.writers, &self.root_open, &self.policy_inputs)
    }

    /// Parks the actual negative classification and independently posts Root.
    ///
    /// The same accepted endpoint is ended while every partial owner remains
    /// in this attempt. This is negative disposition, never positive settlement
    /// or authority release. The caller terminates intentionally while holding
    /// the attempt after this method, including when an independent post fails.
    ///
    /// # Errors
    /// Retains missing/repeated disposition, same-socket shutdown and original
    /// Root-currentness failure without replacing an earlier receive cause.
    pub fn finish_negative_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.negative_post.is_some() || !matches!(self.completion, Some(Err(_))) {
            self.reentry = true;
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.negative_post = Some(self.flight.finish_dispatch_once(
            Err(Box::new(RootCreateStorageCurrentErrorV1::Open)),
        ));
        // A negative dispatch deliberately cannot become a successful reusable
        // flight. The whole independent shutdown/Root Results stay on flight.
        self.negative_post.as_ref().and_then(|result| result.as_ref().ok())
            .map(|_| ()).ok_or(NormalRootStartupErrorV1::Service)
    }

    /// Borrows the precise retained failure while holding any required original guard.
    ///
    /// A failed signed-stage permit resides in the SAME Root financial owner.
    /// Its guard remains alive through diagnostic formatting; unrelated later
    /// owed-post errors cannot replace that source. No operation is performed.
    #[must_use]
    pub fn failure_view(&self) -> Option<RootCurrentFailureViewV1<'_>> {
        let signed_fixed = matches!(self.signed_bound_entry, Some(Err(_)));
        let signed_bytes = self.signed_bound.as_deref().is_some_and(|stage| stage.failed_variable_entry_v1());
        if signed_fixed || signed_bytes {
            if let Some(view) = self.flight.current_signed_failure_view_v1(signed_bytes) { return Some(view); }
        }
        if let Some(stage) = self.signed_bound.as_deref().and_then(|signed| signed.failed_controller_financial_entry_v1()) {
            if let Some(view) = self.flight.current_signed_controller_failure_view_v1(stage) { return Some(view); }
        }
        let outcome = if matches!(self.outcome_entry, Some(Err(_))) {
            Some(outcome::OutcomeFinancialStageV1::Fixed)
        } else { self.outcome.as_deref().and_then(|stage| stage.failed_financial_entry_v1()) };
        if let Some(stage) = outcome {
            if let Some(view) = self.flight.current_outcome_failure_view_v1(stage) { return Some(view); }
        }
        let closed = if matches!(self.closed_entry, Some(Err(_))) {
            Some(closed::ClosedFinancialStageV1::Fixed)
        } else { self.terminal_closed.as_deref().and_then(|stage| stage.failed_financial_entry_v1()) };
        if let Some(stage) = closed {
            if let Some(view) = self.flight.current_closed_failure_view_v1(stage) { return Some(view); }
        }
        self.failure().map(RootCurrentFailureViewV1::borrowed)
    }

    /// Borrows the first retained cause without another read or comparison.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn StdError + 'static)) };
        }
        self.prelude.failure_before_v1()
            .or_else(|| {
                if matches!(self.peer, Some(Err(_))) { self.flight.failure() } else { None }
            })
            .or_else(|| cause!(self.peer))
            .or_else(|| self.remainder_io.failure())
            .or_else(|| cause!(self.remainder_read))
            .or_else(|| cause!(self.decoded))
            .or_else(|| self.prelude.failure_after_v1())
            .or_else(|| self.writers.concrete_failure_v1())
            .or_else(|| cause!(self.opening))
            .or_else(|| self.root_open.failure())
            .or_else(|| self.ready.failure())
            .or_else(|| self.pins.failure())
            .or_else(|| self.policy_inputs.failure())
            .or_else(|| cause!(self.ownership_trust_admission))
            .or_else(|| self.ownership_trust.as_ref().and_then(|trust| trust.failure()))
            .or_else(|| self.source_query.failure())
            .or_else(|| self.source_exchange.failure())
            .or_else(|| {
                if matches!(self.bundle_ownership_entry, Some(Err(_))) {
                    self.flight.failure()
                } else { None }
            })
            .or_else(|| cause!(self.bundle_ownership_entry))
            .or_else(|| self.bundle_ownership.as_ref()
                .and_then(|state| state.failure_with_original(self.flight)))
            .or_else(|| if matches!(self.cache_current_entry, Some(Err(_))) { self.flight.failure() } else { None })
            .or_else(|| cause!(self.cache_current_entry))
            .or_else(|| self.cache_current.as_ref().and_then(|state| state.failure_with_original(self.flight)))
            .or_else(|| if matches!(self.controller_readonly_entry, Some(Err(_))) { self.flight.failure() } else { None })
            .or_else(|| cause!(self.controller_readonly_entry))
            .or_else(|| self.controller_readonly.as_ref().and_then(|state| state.failure_with_original(self.flight)))
            .or_else(|| if matches!(self.use_authorized_entry, Some(Err(_))) { self.flight.failure() } else { None })
            .or_else(|| cause!(self.use_authorized_entry))
            .or_else(|| self.use_authorized.as_ref().and_then(|state| state.failure()))
            .or_else(|| if matches!(self.use_reserved_entry, Some(Err(_))) { self.flight.failure() } else { None })
            .or_else(|| cause!(self.use_reserved_entry))
            .or_else(|| self.use_reserved.as_ref().and_then(|state| state.failure_with_original(self.flight)))
            .or_else(|| self.second_source_query.failure_with_original(self.flight))
            .or_else(|| self.second_source_exchange.failure_with_original(self.flight))
            .or_else(|| if matches!(self.second_cache_entry, Some(Err(_))) { self.flight.failure() } else { None })
            .or_else(|| cause!(self.second_cache_entry))
            .or_else(|| self.second_cache.as_ref().and_then(|state| state.failure_with_original(self.flight)))
            .or_else(|| if matches!(self.use_admitted_entry, Some(Err(_))) { self.flight.failure() } else { None })
            .or_else(|| cause!(self.use_admitted_entry))
            .or_else(|| self.use_admitted.as_ref().and_then(|state| state.failure()))
            .or_else(|| cause!(self.signed_bound_entry))
            .or_else(|| self.signed_bound.as_ref().and_then(|state| state.failure_with_original(self.flight)))
            .or_else(|| if matches!(self.outcome_entry, Some(Err(_))) { self.flight.failure() } else { None })
            .or_else(|| self.outcome_entry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.outcome.as_deref().and_then(|state| state.failure_with_original(self.flight)))
            .or_else(|| self.closed_entry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.terminal_closed.as_deref().and_then(|state| state.failure_with_original(self.flight)))
            .or_else(|| cause!(self.completion))
            .or_else(|| cause!(self.negative_post))
    }
}
