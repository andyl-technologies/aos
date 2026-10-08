//! Non-detachable Root proofs backed by the same actual authenticated stream.
//!
//! The conditional producer invariant is normal Root's exact immutable code
//! and enforcing policy: no accepted-FD fork/transfer, out-of-role endpoint
//! fd-use/write, task-file theft/ptrace, role escape or SYS_ADMIN nomination.
//! Every received fragment must additionally nominate the exact still-live
//! original daemon TGID. SCM_SECURITY is the socket SID, not the task SID.
//! Endpoint credentials, a Boolean, cached bytes, or a raw floor cannot mint
//! these proofs. The normal Root role and canonical loaded-policy comparison
//! must be genuinely installed; the old init_t endpoint necessarily refuses.

use std::cell::{Cell, RefCell};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};

use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, take};

use super::records::{RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1};
use super::transport;
use super::wire::{
    ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1, ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1,
    ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1, RootSourceGenesisFrameKindV1 as Phase,
    decode_root_source_genesis_frame_v1, encode_root_source_genesis_frame_v1,
};

use crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1;
use crate::normal_root::{OriginalNormalRootPeerV1, ProductionControllerNormalRootProfileV1};
use crate::policy_compiler::controller_readback_session::fresh_root_nonce;
const MAXIMUM_FLIGHT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
enum Q04ReceivePositionV1 {
    Open,
    FinalSourceObservation,
}

#[derive(Clone, Copy)]
enum FirstSuccessorReceivePositionV2 { Open, Finished }

#[derive(Clone, Copy)]
enum OriginalWriteModeV2 { Ordinary, FirstSuccessor }

#[derive(Default)]
pub(super) struct ProjectGenesisFlightIoV3 {
    pub(super) outgoing: Vec<u8>,
    pub(super) header: Vec<u8>,
    pub(super) payload: Vec<u8>,
    pub(super) received: Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    action: Option<Result<Phase, SourceGenesisErrorV1>>,
    posts: [Option<Result<(), SourceGenesisErrorV1>>; 2],
    first_failure: Option<ProjectGenesisIoSiteV3>,
}

#[derive(Clone, Copy)]
enum ProjectGenesisIoSiteV3 { Action, NativeReceive, Post(usize) }

impl ProjectGenesisFlightIoV3 {
    pub(super) fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            ProjectGenesisIoSiteV3::Action => self.action.as_ref()?.as_ref().err().map(|e| e as _),
            ProjectGenesisIoSiteV3::NativeReceive => self.received.as_ref()?.as_ref().err().map(|e| e as _),
            ProjectGenesisIoSiteV3::Post(index) => self.posts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }

    fn posts(&mut self, original: &OriginalRootGenesisFlightV1<'_>) {
        if self.action.as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(if self.received.as_ref().is_some_and(Result::is_err) {
                ProjectGenesisIoSiteV3::NativeReceive
            } else { ProjectGenesisIoSiteV3::Action });
        }
        self.posts[0] = Some(if self.action.as_ref().is_some_and(|result| matches!(result, Ok(Phase::Finish))) {
            original.original_terminal_clock().map(|_| ())
        } else { original.first_successor_clock().map(|_| ()) });
        if self.first_failure.is_none() && self.posts[0].as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ProjectGenesisIoSiteV3::Post(0));
        }
        self.posts[1] = Some(original.observe_first_successor_clock().map(|_| ()));
        if self.first_failure.is_none() && self.posts[1].as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ProjectGenesisIoSiteV3::Post(1));
        }
    }
}

// Both closed genesis purposes share the original I/O custody and post order.
// Only their existing wire codecs differ. Global replaces the outgoing Vec;
// Project retains the existing mutable-buffer encoder and its reserve order.
#[derive(Clone, Copy)]
enum GenesisFrameFamily {
    GlobalResource,
    Project,
}

impl GenesisFrameFamily {
    fn encode(
        self,
        outgoing: &mut Vec<u8>,
        phase: Phase,
        nonce: [u8; 16],
        payload: &[u8],
    ) -> Result<(), SourceGenesisErrorV1> {
        match self {
            Self::GlobalResource => {
                *outgoing = super::wire::encode_root_source_genesis_frame_v2(
                    phase, nonce, payload,
                )?;
                Ok(())
            }
            Self::Project => super::wire::encode_root_source_project_genesis_frame_v3(
                outgoing, phase, nonce, payload,
            ),
        }
    }

    fn payload_bytes(
        self,
        header: &[u8],
        phase: Phase,
        nonce: [u8; 16],
    ) -> Result<usize, SourceGenesisErrorV1> {
        match self {
            Self::GlobalResource => super::wire::root_source_resource_genesis_payload_bytes_v2(
                header, phase, nonce,
            ),
            Self::Project => super::wire::root_source_project_genesis_payload_bytes_v3(
                header, phase, nonce,
            ),
        }
    }
}

/// Borrows one actual Root prepare flight; decoding an intent cannot create it.
pub struct HeldRootSourceGenesisIntentV1<'flight> {
    origin: &'flight OriginalRootGenesisFlightV1<'flight>,
    record: RootSourceGenesisIntentRecordV1,
    deadline: u64,
    expires: i64,
}

impl HeldRootSourceGenesisIntentV1<'_> {
    pub(crate) fn native_crossing_clock_v2(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck_current_admission()
    }

    pub(crate) fn independent_clock_v2(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.observe_first_successor_clock().map(|_| ())
    }

    /// Borrows the exact Root-owned prepare record from this original flight.
    #[must_use]
    pub const fn record(&self) -> &RootSourceGenesisIntentRecordV1 {
        &self.record
    }

    /// Rechecks the actual Root role, original endpoint, process and held flight.
    ///
    /// # Errors
    /// Rejects lost or changed original peer/cgroup/policy, poisoned transport,
    /// or a different privileged Source UID. This is historical custody only.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()?;
        if self.record.source_uid() != self.origin.source_uid {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    /// Separately checks the unchanged initial paired-clock admission deadline.
    ///
    /// # Errors
    /// Rejects expiry or clock/boot discontinuity before genuinely new Source
    /// mutation. Historical prepared readback/ACK does not grant this condition.
    pub fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let later = kernel_pair()?;
        self.origin
            .clock
            .validate_later_sample(later)
            .map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
        if later.wall_seconds() >= self.expires || later.boottime_nanoseconds() >= self.deadline {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        Ok(())
    }
}

/// Borrows the actual original Root flight through Controller and Source ACK.
pub struct RootSourceGenesisFloorProofV1<'flight> {
    origin: &'flight OriginalRootGenesisFlightV1<'flight>,
    floor: SourceHierarchyFloorRecordV1,
}

/// Borrows a genuine fresh selected-project intent on its version-three flight.
///
/// The common storage is private. No decoded record, historical observation or
/// public strict V1 loan can be converted into this selected append boundary.
pub struct HeldRootSourceProjectGenesisIntentV3<'flight> {
    original: HeldRootSourceGenesisIntentV1<'flight>,
}

impl HeldRootSourceProjectGenesisIntentV3<'_> {
    /// Borrows the unchanged canonical original Intent792 as DATA.
    pub const fn record(&self) -> &RootSourceGenesisIntentRecordV1 { &self.original.record }

    /// Rechecks the genuine original profile, stream and nonrenewable admission.
    ///
    /// # Errors
    /// Rejects changed original custody, expiry, boot/clock discontinuity or poison.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.original.origin.first_successor_clock().map(|_| ())
    }

    pub(crate) fn independent_clock_v3(&self) -> Result<(), SourceGenesisErrorV1> {
        self.original.origin.observe_first_successor_clock().map(|_| ())
    }

    pub(crate) fn native_crossing_clock_v3(&self) -> Result<(), SourceGenesisErrorV1> {
        let current = self.original.origin.first_successor_clock()?;
        if current.wall_seconds() >= self.original.expires
            || current.boottime_nanoseconds() >= self.original.deadline
        {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        Ok(())
    }
}

/// Borrows an actual selected semantic floor from the same authenticated flight.
pub struct RootSourceProjectGenesisFloorProofV3<'flight> {
    original: RootSourceGenesisFloorProofV1<'flight>,
}

impl RootSourceProjectGenesisFloorProofV3<'_> {
    /// Borrows only the logical original floor DATA.
    pub const fn floor(&self) -> &SourceHierarchyFloorRecordV1 { &self.original.floor }

    /// Returns Source UID from the actual independently authenticated Root hello.
    pub const fn source_uid(&self) -> u32 { self.original.origin.source_uid }

    /// Rechecks the same original stream, peer, profile and finite custody cut.
    ///
    /// # Errors
    /// Rejects changed real custody, poison or the original deadline.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.original.origin.first_successor_clock().map(|_| ())
    }

    pub(crate) fn native_crossing_clock_v3(&self) -> Result<(), SourceGenesisErrorV1> {
        self.original.origin.first_successor_clock().map(|_| ())
    }

    pub(crate) fn independent_clock_v3(&self) -> Result<(), SourceGenesisErrorV1> {
        self.original.origin.observe_first_successor_clock().map(|_| ())
    }
}

pub(crate) struct CompletedRootSourceProjectGenesisFloorV3<'completed, 'flight> {
    proof: &'completed RootSourceProjectGenesisFloorProofV3<'flight>,
}

impl CompletedRootSourceProjectGenesisFloorV3<'_, '_> {
    pub(crate) fn floor(&self) -> &SourceHierarchyFloorRecordV1 { self.proof.floor() }
    pub(crate) fn source_uid(&self) -> u32 { self.proof.source_uid() }
    pub(crate) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.proof.recheck() }
    pub(crate) fn signing_boundary_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.proof.original.origin.first_successor_clock()
    }

    // The bank admission borrows the initial cut, never a refreshed sample.
    pub(crate) fn resource_admission_cut(&self) -> Result<(RawPairedClockSample, u64), SourceGenesisErrorV1> {
        let original = self.proof.original.origin.clock;
        let deadline = original.boottime_nanoseconds().checked_add(60_000_000_000)
            .ok_or(SourceGenesisErrorV1::Stale)?;
        Ok((original, deadline))
    }

    pub(crate) fn independent_resource_clock(&self) -> Result<(), SourceGenesisErrorV1> {
        self.proof.original.origin.observe_first_successor_clock().map(|_| ())
    }
}

impl RootSourceGenesisFloorProofV1<'_> {
    pub(crate) fn native_crossing_clock_v2(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.first_successor_clock().map(|_| ())
    }

    pub(crate) fn independent_clock_v2(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.observe_first_successor_clock().map(|_| ())
    }

    /// Borrows the exact Root-owned floor, whose raw bytes remain data only.
    #[must_use]
    pub const fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        &self.floor
    }

    /// Returns the privileged Source UID bound by the actual Root flight hello.
    ///
    /// This comes from normal Root's protected service configuration, never
    /// decoded floor data, Source journal ownership, or a caller assertion.
    #[must_use]
    pub const fn source_uid(&self) -> u32 {
        self.origin.source_uid
    }

    /// Rechecks actual original live Root custody without granting fresh genesis.
    ///
    /// # Errors
    /// Rejects changed endpoint/process/cgroup, unenforcing or changed exact
    /// deployed policy, failed subject receive, or a completed/lost flight.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()
    }
}

// Only receipt of Completed on the original held stream constructs this loan.
// Its floor remains borrowed; a decoded floor or earlier Anchored reply cannot
// select the current-ancestry consumer.
pub(crate) struct CompletedRootSourceGenesisFloorV1<'completed, 'flight> {
    proof: &'completed RootSourceGenesisFloorProofV1<'flight>,
}

impl CompletedRootSourceGenesisFloorV1<'_, '_> {
    pub(crate) fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        self.proof.floor()
    }

    pub(crate) fn source_uid(&self) -> u32 {
        self.proof.source_uid()
    }

    pub(crate) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.proof.recheck()
    }

    pub(in crate::policy_compiler) fn signing_boundary_clock(
        &self,
    ) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.proof.origin.signing_boundary_clock()
    }

    // Payment uses this flight's initial cut, not a completion-time sample.
    pub(crate) fn resource_admission_cut(&self) -> Result<(RawPairedClockSample, u64), SourceGenesisErrorV1> {
        let original = self.proof.origin.clock;
        let deadline = original.boottime_nanoseconds().checked_add(60_000_000_000)
            .ok_or(SourceGenesisErrorV1::Stale)?;
        Ok((original, deadline))
    }

    pub(crate) fn independent_resource_clock(&self) -> Result<(), SourceGenesisErrorV1> {
        self.proof.origin.observe_first_successor_clock().map(|_| ())
    }
}

// Private to the same-flight coordinator. There is no adoption constructor
// accepting caller-supplied peers, subjects, floor bytes, or ready flags.
pub(in crate::policy_compiler) struct OriginalRootGenesisFlightV1<'profile> {
    stream: RefCell<RetainedUnixStream>,
    peer: OriginalNormalRootPeerV1<'profile>,
    clock: RawPairedClockSample,
    started: Instant,
    poisoned: Cell<bool>,
    nonce: [u8; 16],
    source_uid: u32,
    first_successor_wait_owners: RefCell<Vec<Result<(), SourceGenesisErrorV1>>>,
    first_successor_wait_clocks: RefCell<Vec<Result<RawPairedClockSample, SourceGenesisErrorV1>>>,
    first_global_wait_capacity: Cell<Option<usize>>,
    first_global_wait_preparation: RefCell<[Option<Result<(), std::collections::TryReserveError>>; 2]>,
}

// Prearmed by the resource-Global parent before connection can fail. The whole
// first native Result stays here even when no flight can be assembled.
pub(super) struct OriginalRootGenesisOpeningClockV2 {
    started: Option<Instant>,
    initial: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
}

impl OriginalRootGenesisOpeningClockV2 {
    pub(super) fn new() -> Self {
        Self { started: None,
        initial: None }
    }

    fn capture(&mut self) -> Result<(Instant, RawPairedClockSample), SourceGenesisErrorV1> {
        if self.started.is_some() || self.initial.is_some() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        self.started = Some(Instant::now());
        self.initial = Some(kernel_pair());
        self.initial_values()
    }

    fn initial_values(&self) -> Result<(Instant, RawPairedClockSample), SourceGenesisErrorV1> {
        let started = self.started.ok_or(SourceGenesisErrorV1::Stale)?;
        let clock = self.initial.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(SourceGenesisErrorV1::Stale)?;
        Ok((started, clock))
    }

    pub(super) fn initial_error(&self) -> Option<&SourceGenesisErrorV1> {
        self.initial.as_ref()?.as_ref().err()
    }

    // Checks parked paired DATA and the same monotonic deadline without a new
    // paired sample or admission cut. Missing original custody stays negative.
    pub(super) fn check_later(&self, current: RawPairedClockSample) -> Result<(), SourceGenesisErrorV1> {
        let (started, original) = self.initial_values()?;
        original.validate_later_sample(current).map_err(|_| SourceGenesisErrorV1::Stale)?;
        require_original_root_age(original, current)?;
        transport::require_remaining(started + MAXIMUM_FLIGHT).map(|_| ())
    }
}

pub(super) enum OriginalRootGenesisReplyV1<'flight> {
    Prepared(HeldRootSourceGenesisIntentV1<'flight>),
    Anchored(RootSourceGenesisFloorProofV1<'flight>),
}

pub(super) enum OriginalRootProjectGenesisReplyV3<'flight> {
    Prepared(HeldRootSourceProjectGenesisIntentV3<'flight>),
    Anchored(RootSourceProjectGenesisFloorProofV3<'flight>),
}

impl<'profile> OriginalRootGenesisFlightV1<'profile> {
    // Only the actual coordinator calls this after retaining both named
    // Controller and Source writers. No supplied policy path/peer/proof enters.
    pub(super) fn connect(
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, SourceGenesisErrorV1> {
        let started = Instant::now();
        let clock = kernel_pair()?;
        let deadline = started + MAXIMUM_FLIGHT;
        profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
        let mut stream = transport::connect_fixed(deadline)?;
        stream.enable_subject_reporting()?;
        let peer = profile
            .observe_original_peer(&stream)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let source_uid = peer.source_uid();
        let client_nonce = fresh_root_nonce()?;
        let mut origin = Self {
            stream: RefCell::new(stream),
            peer,
            clock,
            started,
            poisoned: Cell::new(false),
            nonce: [0; 16],
            source_uid,
            first_successor_wait_owners: RefCell::new(Vec::new()),
            first_successor_wait_clocks: RefCell::new(Vec::new()),
            first_global_wait_capacity: Cell::new(None),
            first_global_wait_preparation: RefCell::new([None, None]),
        };
        origin.establish_hello(client_nonce)?;
        Ok(origin)
    }

    // The issuer owns both slots before this method starts. In particular,
    // peer/adoption errors cannot release the retained original raw socket.
    pub(super) fn connect_parked(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>,
        adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>,
    ) -> Result<(), SourceGenesisErrorV1> {
        let client_nonce = Self::park_connection(profile, raw, adopted, parked)?;
        let origin = parked.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
        origin.establish_hello(client_nonce)
    }

    // This is the same connection/adoption/peer engine for the old issuer and
    // Q04. The latter selects only a distinct fixed query and retaining receive
    // below; it does not accept an endpoint or invoke a caller trust callback.
    fn park_connection(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>,
        adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>,
    ) -> Result<[u8; 16], SourceGenesisErrorV1> {
        if parked.is_some() || adopted.is_some() || raw.is_some() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let started = Instant::now();
        let clock = kernel_pair()?;
        Self::park_connection_at_original(profile, raw, adopted, parked, started, clock)
    }

    // Sole connection/adoption engine. Only the ordinary sampler above or the
    // prearmed Global sampler supplies these original values.
    fn park_connection_at_original(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>,
        adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>,
        started: Instant,
        clock: RawPairedClockSample,
    ) -> Result<[u8; 16], SourceGenesisErrorV1> {
        profile.recheck().map_err(|_| SourceGenesisErrorV1::Stale)?;
        *adopted = Some(transport::connect_parked(raw, started + MAXIMUM_FLIGHT)?);
        let stream = adopted.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
        stream.enable_subject_reporting()?;
        let peer = profile.observe_original_peer(&stream)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let source_uid = peer.source_uid();
        let client_nonce = fresh_root_nonce()?;
        let stream = adopted.take().ok_or(SourceGenesisErrorV1::Stale)?;
        *parked = Some(Self {
            stream: RefCell::new(stream),
            peer,
            clock,
            started,
            poisoned: Cell::new(false),
            nonce: [0; 16],
            source_uid,
            first_successor_wait_owners: RefCell::new(Vec::new()),
            first_successor_wait_clocks: RefCell::new(Vec::new()),
            first_global_wait_capacity: Cell::new(None),
            first_global_wait_preparation: RefCell::new([None, None]),
        });

        Ok(client_nonce)
    }

    fn establish_hello(&mut self, client_nonce: [u8; 16]) -> Result<(), SourceGenesisErrorV1> {
        let mut request = [0; 32];
        request[..8].copy_from_slice(ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1);
        request[8..24].copy_from_slice(&client_nonce);
        self.write(&request)?;
        let hello = self.receive_exact(56)?;
        self.accept_hello(&hello, client_nonce)
    }

    // Only the private first-successor invocation selects this purpose. The
    // partial socket, adopted description and complete native receive Result
    // are caller-resident before any later observation can fail.
    pub(super) fn connect_first_successor_parked(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>,
        adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>,
        hello: &mut Vec<u8>,
        received: &mut Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
        controller_uid: u32,
    ) -> Result<(), SourceGenesisErrorV1> {
        Self::connect_successor_with_recipe_v3(profile, raw, adopted, parked, hello, received,
            controller_uid, super::wire::FirstSuccessorWireRecipeV3::StrictV2)
    }

    pub(super) fn connect_project_successor_parked_v3(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>, adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>, hello: &mut Vec<u8>,
        received: &mut Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
        controller_uid: u32,
    ) -> Result<(), SourceGenesisErrorV1> {
        Self::connect_successor_with_recipe_v3(profile, raw, adopted, parked, hello, received,
            controller_uid, super::wire::FirstSuccessorWireRecipeV3::MixedV3)
    }

    fn connect_successor_with_recipe_v3(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>, adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>, hello: &mut Vec<u8>,
        received: &mut Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
        controller_uid: u32, recipe: super::wire::FirstSuccessorWireRecipeV3,
    ) -> Result<(), SourceGenesisErrorV1> {
        let client_nonce = Self::park_connection(profile, raw, adopted, parked)?;
        let origin = parked.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
        let mut request = [0; 32];
        request[..8].copy_from_slice(match recipe {
            super::wire::FirstSuccessorWireRecipeV3::StrictV2 => super::wire::ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2,
            super::wire::FirstSuccessorWireRecipeV3::MixedV3 => super::wire::ROOT_PROJECT_SOURCE_SUCCESSOR_QUERY_MAGIC_V3,
        });
        request[8..24].copy_from_slice(&client_nonce);
        origin.write_first_successor(&request)?;
        origin.receive_first_successor_exact(56, hello, received)?;
        let magic = match recipe {
            super::wire::FirstSuccessorWireRecipeV3::StrictV2 => super::wire::ROOT_FIRST_SOURCE_SUCCESSOR_HELLO_MAGIC_V2,
            super::wire::FirstSuccessorWireRecipeV3::MixedV3 => super::wire::ROOT_PROJECT_SOURCE_SUCCESSOR_HELLO_MAGIC_V3,
        };
        if hello.get(..8) != Some(magic.as_slice())
            || hello[8..16] != [0, recipe.version() as u8, 0, 0, 0, 0, 0, 0]
            || take::<16>(hello, 16)? != client_nonce || take::<16>(hello, 32)? == [0; 16]
            || u32::from_be_bytes(take(hello, 48)?) != origin.source_uid
            || u32::from_be_bytes(take(hello, 52)?) != controller_uid
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        origin.nonce = take(hello, 32)?;
        origin.recheck()
    }

    // The selected resource Global route keeps the ordinary Global query and
    // hello purpose, but parks every available original before later failure.
    pub(super) fn connect_global_genesis_parked_v2(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        opening_clock: &mut OriginalRootGenesisOpeningClockV2,
        raw: &mut Option<OwnedFd>,
        adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>,
        hello: &mut Vec<u8>,
        received: &mut Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
        controller_uid: u32,
        prefix: Option<&crate::controller_resource_reservation::service_interval::FirstGlobalPrefixLoan<'_>>,
    ) -> Result<(), SourceGenesisErrorV1> {
        if parked.is_some() || adopted.is_some() || raw.is_some() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let (started, clock) = opening_clock.capture()?;
        let client_nonce = Self::park_connection_at_original(profile, raw, adopted, parked, started, clock)?;
        let origin = parked.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
        if let Some(prefix) = prefix {
            origin.attach_first_global_wait_capacity(prefix.wait_capacity())?;
        }
        let mut request = [0; 32];
        request[..8].copy_from_slice(super::wire::ROOT_SOURCE_RESOURCE_GENESIS_QUERY_MAGIC_V2);
        request[8..24].copy_from_slice(&client_nonce);
        origin.write_first_successor(&request)?;
        origin.receive_first_successor_exact(56, hello, received)?;
        origin.accept_hello(hello, client_nonce)?;
        if u32::from_be_bytes(take(hello, 52)?) != controller_uid {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        origin.first_successor_clock().map(|_| ())
    }

    pub(super) fn send_global_genesis_phase_v2(
        &self,
        phase: Phase,
        payload: &[u8],
        io: &mut ProjectGenesisFlightIoV3,
    ) -> Result<(), ()> {
        self.send_genesis_phase(GenesisFrameFamily::GlobalResource, phase, payload, io)
    }

    pub(super) fn receive_global_genesis_phase_v2(
        &self,
        allowed: &[Phase],
        io: &mut ProjectGenesisFlightIoV3,
    ) -> Result<Phase, ()> {
        self.receive_genesis_phase(GenesisFrameFamily::GlobalResource, allowed, io)
    }

    fn send_genesis_phase(
        &self,
        family: GenesisFrameFamily,
        phase: Phase,
        payload: &[u8],
        io: &mut ProjectGenesisFlightIoV3,
    ) -> Result<(), ()> {
        if io.action.is_some() {
            return Err(());
        }

        io.action = Some((|| {
            family.encode(&mut io.outgoing, phase, self.nonce, payload)?;
            self.write_first_successor(&io.outgoing)?;
            Ok(phase)
        })());

        io.posts(self);
        if io.error().is_some() {
            Err(())
        } else {
            Ok(())
        }
    }

    fn receive_genesis_phase(
        &self,
        family: GenesisFrameFamily,
        allowed: &[Phase],
        io: &mut ProjectGenesisFlightIoV3,
    ) -> Result<Phase, ()> {
        if io.action.is_some() {
            return Err(());
        }

        io.action = Some((|| {
            let position = if allowed == [Phase::Finish] {
                FirstSuccessorReceivePositionV2::Finished
            } else {
                FirstSuccessorReceivePositionV2::Open
            };
            self.receive_first_successor_at_position(
                32, &mut io.header, &mut io.received, position,
            )?;

            let phase = allowed.iter().copied().find(|phase| {
                family.payload_bytes(&io.header, *phase, self.nonce).is_ok()
            }).ok_or(SourceGenesisErrorV1::NonCanonical)?;
            let payload_bytes = family.payload_bytes(&io.header, phase, self.nonce)?;
            self.receive_first_successor_at_position(
                payload_bytes, &mut io.payload, &mut io.received, position,
            )?;
            Ok(phase)
        })());

        io.posts(self);
        if io.error().is_some() {
            Err(())
        } else {
            io.action.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(())
        }
    }

    pub(super) fn global_genesis_reply_from_received_v2<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
        phase: Phase,
        payload: &[u8],
    ) -> Result<OriginalRootGenesisReplyV1<'flight>, SourceGenesisErrorV1> {
        if phase == Phase::Anchored {
            return self.floor_from_original_payload(controller, payload)
                .map(OriginalRootGenesisReplyV1::Anchored);
        }
        if phase != Phase::Prepared
            || payload.len() != phase.payload_bytes_for_resource(true)
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let expires = i64::from_be_bytes(take(payload, 0)?);
        let record = RootSourceGenesisIntentRecordV1::from_record_bytes(&payload[8..])?;
        if record.accepted_input() != controller.acceptance()
            || record.source_uid() != self.source_uid
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let deadline = self.clock.boottime_nanoseconds().checked_add(60_000_000_000)
            .ok_or(SourceGenesisErrorV1::Stale)?;
        self.first_successor_clock()?;
        Ok(OriginalRootGenesisReplyV1::Prepared(HeldRootSourceGenesisIntentV1 {
            origin: self, record, deadline, expires,
        }))
    }

    pub(super) fn global_genesis_floor_from_received_v2<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
        payload: &[u8],
    ) -> Result<RootSourceGenesisFloorProofV1<'flight>, SourceGenesisErrorV1> {
        self.floor_from_original_payload(controller, payload)
    }

    pub(super) fn completed_global_genesis_from_received_v2<'completed, 'flight>(
        &self,
        proof: &'completed RootSourceGenesisFloorProofV1<'flight>,
        payload: &[u8],
    ) -> Result<CompletedRootSourceGenesisFloorV1<'completed, 'flight>, SourceGenesisErrorV1> {
        if !std::ptr::eq(self, proof.origin) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        proof.recheck()?;
        require_completed_digest(payload, proof.floor().digest().as_bytes())?;
        proof.recheck()?;
        Ok(CompletedRootSourceGenesisFloorV1 { proof })
    }

    pub(super) fn connect_project_genesis_parked_v3(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>, adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>, hello: &mut Vec<u8>,
        received: &mut Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
        controller_uid: u32,
    ) -> Result<(), SourceGenesisErrorV1> {
        let client_nonce = Self::park_connection(profile, raw, adopted, parked)?;
        let origin = parked.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
        let mut request = [0; 32];
        request[..8].copy_from_slice(super::wire::ROOT_SOURCE_PROJECT_GENESIS_QUERY_MAGIC_V3);
        request[8..24].copy_from_slice(&client_nonce);
        origin.write_first_successor(&request)?;
        origin.receive_first_successor_exact(56, hello, received)?;
        if hello.get(..8) != Some(super::wire::ROOT_SOURCE_PROJECT_GENESIS_HELLO_MAGIC_V3.as_slice())
            || hello[8..16] != [0, 3, 0, 0, 0, 0, 0, 0]
            || take::<16>(hello, 16)? != client_nonce || take::<16>(hello, 32)? == [0; 16]
            || u32::from_be_bytes(take(hello, 48)?) != origin.source_uid
            || u32::from_be_bytes(take(hello, 52)?) != controller_uid
        { return Err(SourceGenesisErrorV1::NonCanonical); }
        origin.nonce = take(hello, 32)?;
        origin.first_successor_clock().map(|_| ())
    }

    pub(super) fn send_project_genesis_phase_v3(
        &self, phase: Phase, payload: &[u8], io: &mut ProjectGenesisFlightIoV3,
    ) -> Result<(), ()> {
        self.send_genesis_phase(GenesisFrameFamily::Project, phase, payload, io)
    }

    pub(super) fn receive_project_genesis_phase_v3(
        &self, allowed: &[Phase], io: &mut ProjectGenesisFlightIoV3,
    ) -> Result<Phase, ()> {
        self.receive_genesis_phase(GenesisFrameFamily::Project, allowed, io)
    }

    pub(super) fn project_genesis_reply_from_received_v3<'flight>(
        &'flight self, controller: &HeldControllerSourceGenesisV1<'_>,
        phase: Phase, payload: &[u8],
    ) -> Result<OriginalRootProjectGenesisReplyV3<'flight>, SourceGenesisErrorV1> {
        if phase == Phase::Anchored {
            return self.project_genesis_floor_from_received_v3(controller, payload)
                .map(OriginalRootProjectGenesisReplyV3::Anchored);
        }
        if phase != Phase::Prepared
            || (payload.len() != phase.payload_bytes() && payload.len() != phase.payload_bytes() + 176) {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let expires = i64::from_be_bytes(take(payload, 0)?);
        let record = RootSourceGenesisIntentRecordV1::from_record_bytes(&payload[8..])?;
        if record.accepted_input() != controller.acceptance() || record.source_uid() != self.source_uid {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let deadline = self.clock.boottime_nanoseconds().checked_add(
            MAXIMUM_FLIGHT.as_nanos().try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
        ).ok_or(SourceGenesisErrorV1::NonCanonical)?;
        self.first_successor_clock()?;
        controller.recheck()?;
        Ok(OriginalRootProjectGenesisReplyV3::Prepared(HeldRootSourceProjectGenesisIntentV3 {
            original: HeldRootSourceGenesisIntentV1 { origin: self, record, deadline, expires },
        }))
    }

    pub(super) fn project_genesis_floor_from_received_v3<'flight>(
        &'flight self, controller: &HeldControllerSourceGenesisV1<'_>, payload: &[u8],
    ) -> Result<RootSourceProjectGenesisFloorProofV3<'flight>, SourceGenesisErrorV1> {
        let floor = SourceHierarchyFloorRecordV1::from_record_bytes(payload)?;
        let receipt = floor.receipt();
        let accepted = controller.acceptance();
        if floor.project() != accepted.project() || receipt.acceptance_digest() != accepted.digest()
            || &receipt.seed_packet() != accepted.seed_packet()
            || receipt.auth_packet() != accepted.auth_packet()
        { return Err(SourceGenesisErrorV1::Conflict); }
        self.first_successor_clock()?;
        controller.recheck()?;
        Ok(RootSourceProjectGenesisFloorProofV3 { original: RootSourceGenesisFloorProofV1 { origin: self, floor } })
    }

    pub(super) fn completed_project_genesis_from_received_v3<'completed, 'flight>(
        &self, floor: &'completed RootSourceProjectGenesisFloorProofV3<'flight>, payload: &[u8],
    ) -> Result<CompletedRootSourceProjectGenesisFloorV3<'completed, 'flight>, SourceGenesisErrorV1> {
        if !std::ptr::eq(self, floor.original.origin) || payload != floor.floor().digest().as_bytes() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        floor.recheck()?;
        Ok(CompletedRootSourceProjectGenesisFloorV3 { proof: floor })
    }

    pub(super) fn first_successor_source_uid(&self) -> Result<u32, SourceGenesisErrorV1> {
        self.recheck()?;
        Ok(self.source_uid)
    }

    pub(super) fn first_successor_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.recheck()?;
        self.observe_first_successor_clock()
    }

    // This independent observation remains available after transport poison.
    // It compares the SAME original cut but never admits a send or a mutation.
    pub(super) fn observe_first_successor_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        let current = kernel_pair()?;
        self.clock.validate_later_sample(current).map_err(|_| SourceGenesisErrorV1::Stale)?;
        require_original_root_age(self.clock, current)?;
        transport::require_remaining(self.started + MAXIMUM_FLIGHT)?;
        Ok(current)
    }

    // Reserve BOTH sides before poll. A native failure cannot be followed by
    // a fallible post-reservation that would suppress its independent clocks.
    pub(super) fn first_successor_wait_crossing(&self) -> Result<(), SourceGenesisErrorV1> {
        {
            let mut owners = self.first_successor_wait_owners.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?;
            let mut clocks = self.first_successor_wait_clocks.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?;
            if let Some(capacity) = self.first_global_wait_capacity.get() {
                let owner_end = owners.len().checked_add(2).ok_or(SourceGenesisErrorV1::NonCanonical)?;
                let clock_end = clocks.len().checked_add(2).ok_or(SourceGenesisErrorV1::NonCanonical)?;
                if owner_end > capacity || clock_end > capacity
                    || owner_end > owners.capacity() || clock_end > clocks.capacity()
                {
                    return Err(SourceGenesisErrorV1::AdmissionClosed);
                }
            } else {
                owners.try_reserve(2).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
                clocks.try_reserve(2).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
            }
        }
        self.first_successor_wait_bookend()
    }

    // The genuine entered prefix funds both existing archives before their
    // first crossing. No timing-derived retry count or replacement poll loop
    // exists; exhaustion refuses before native poll and never renews the cut.
    fn attach_first_global_wait_capacity(&self, polls: usize) -> Result<(), SourceGenesisErrorV1> {
        let capacity = polls.checked_mul(2).filter(|capacity| *capacity != 0)
            .ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
        let mut prepared = self.first_global_wait_preparation.try_borrow_mut()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let mut owners = self.first_successor_wait_owners.try_borrow_mut()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let mut clocks = self.first_successor_wait_clocks.try_borrow_mut()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if prepared.iter().any(Option::is_some) || !owners.is_empty() || !clocks.is_empty() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        self.first_global_wait_capacity.set(Some(capacity));
        prepared[0] = Some(owners.try_reserve_exact(capacity));
        prepared[1] = Some(clocks.try_reserve_exact(capacity));
        if prepared.iter().any(|result| !matches!(result, Some(Ok(()))))
            || owners.capacity() > capacity || clocks.capacity() > capacity
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(())
    }

    // Called only by the closed selected mode. The final sample follows slow
    // owner work, with pre-reserved residency and no subsequent allocation.
    pub(super) fn first_successor_wait_bookend(&self) -> Result<(), SourceGenesisErrorV1> {
        let mut owners = self.first_successor_wait_owners.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?;
        let mut clocks = self.first_successor_wait_clocks.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?;
        owners.push(self.recheck());
        clocks.push(self.observe_first_successor_clock());
        if owners.last().is_some_and(Result::is_err) || clocks.last().is_some_and(Result::is_err) {
            self.poisoned.set(true);
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    pub(super) fn first_successor_wait_owner_results(&self) -> Result<std::cell::Ref<'_, Vec<Result<(), SourceGenesisErrorV1>>>, SourceGenesisErrorV1> {
        self.first_successor_wait_owners.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)
    }

    pub(super) fn first_successor_wait_clock_results(&self) -> Result<std::cell::Ref<'_, Vec<Result<RawPairedClockSample, SourceGenesisErrorV1>>>, SourceGenesisErrorV1> {
        self.first_successor_wait_clocks.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)
    }

    pub(super) fn first_successor_terminal_recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        let current = self.original_terminal_clock()?;
        require_original_root_age(self.clock, current)
    }

    pub(super) fn receive_first_successor_exact(
        &self,
        length: usize,
        output: &mut Vec<u8>,
        received: &mut Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.receive_first_successor_at_position(length, output, received, FirstSuccessorReceivePositionV2::Open)
    }

    pub(super) fn receive_first_successor_finish(
        &self, length: usize, output: &mut Vec<u8>,
        received: &mut Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.receive_first_successor_at_position(length, output, received, FirstSuccessorReceivePositionV2::Finished)
    }

    fn require_first_successor_position(&self, position: FirstSuccessorReceivePositionV2) -> Result<(), SourceGenesisErrorV1> {
        let current = match position {
            FirstSuccessorReceivePositionV2::Open => self.first_successor_clock()?,
            FirstSuccessorReceivePositionV2::Finished => self.original_terminal_clock()?,
        };
        require_original_root_age(self.clock, current)
    }

    fn receive_first_successor_at_position(
        &self, length: usize, output: &mut Vec<u8>,
        received: &mut Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
        position: FirstSuccessorReceivePositionV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        if length == 0 || length > 4096 || !output.is_empty() || received.is_some() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        output.try_reserve_exact(length).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        while output.len() < length {
            self.require_first_successor_position(position)?;
            *received = Some(self.stream.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?
                .try_receive_subject_chunk_retaining(length - output.len()));
            if received.as_ref().is_some_and(|result| result.as_ref().err().is_some_and(|error| {
                error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted()
            })) {
                *received = None;
                let stream = self.stream.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
                transport::wait_first_successor(
                    stream.as_fd(), rustix::event::PollFlags::IN, self.started + MAXIMUM_FLIGHT, self,
                )?;
                continue;
            }
            if matches!(received, Some(Err(_))) {
                self.poisoned.set(true);
                return Err(SourceGenesisErrorV1::Stale);
            }
            let chunk = received.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(SourceGenesisErrorV1::Stale)?;
            self.require_first_successor_position(position)?;
            let stream = self.stream.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
            self.peer.require_chunk(&stream, chunk).map_err(|_| SourceGenesisErrorV1::Stale)?;
            drop(stream);
            output.extend_from_slice(chunk.payload());
            self.require_first_successor_position(position)?;
            *received = None;
        }
        self.require_first_successor_position(position)
    }

    fn accept_hello(&mut self, hello: &[u8], client_nonce: [u8; 16]) -> Result<(), SourceGenesisErrorV1> {
        if hello.get(..8) != Some(ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1.as_slice())
            || hello[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
            || take::<16>(&hello, 16)? != client_nonce
            || take::<16>(&hello, 32)? == [0; 16]
            || u32::from_be_bytes(take(&hello, 48)?) != self.source_uid
            || u32::from_be_bytes(take(&hello, 52)?) != self.source_uid
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        self.nonce = take(&hello, 32)?;
        self.recheck()
    }

    pub(in crate::policy_compiler) fn connect_q04_parked(
        profile: &'profile ProductionControllerNormalRootProfileV1,
        raw: &mut Option<OwnedFd>,
        adopted: &mut Option<RetainedUnixStream>,
        parked: &mut Option<Self>,
        hello: &mut Vec<u8>,
        received: &mut Option<Result<
            UnixStreamSubjectChunk,
            aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1,
        >>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        if !hello.is_empty() || received.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let client_nonce = Self::park_connection(profile, raw, adopted, parked)?;
        let origin = parked.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let mut request = [0; 32];
        request[..8].copy_from_slice(b"AOSSGQ04");
        request[8..24].copy_from_slice(&client_nonce);
        origin.write(&request)?;
        origin.receive_q04_exact(56, hello, received)?;
        origin.accept_hello(hello, client_nonce)?;
        Ok(())
    }

    // The enclosing invocation already owns both slots. No partial or owning
    // fatal result can disappear through a caller's post-receive boundary.
    pub(in crate::policy_compiler) fn receive_q04_exact(
        &self,
        length: usize,
        output: &mut Vec<u8>,
        received: &mut Option<Result<
            UnixStreamSubjectChunk,
            aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1,
        >>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.receive_q04_at_position(length, output, received, Q04ReceivePositionV1::Open)
    }

    // Only the actual C8 continuation selects this fixed last DATA response.
    // Root may close immediately after sending it, so original role/subject
    // and clock checks remain, but an open queue is not a terminal invariant.
    pub(in crate::policy_compiler) fn receive_q04_final_source_observation(
        &self,
        resource_version: bool,
        output: &mut Vec<u8>,
        received: &mut Option<Result<
            UnixStreamSubjectChunk,
            aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1,
        >>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.receive_q04_at_position(
            ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
                + if resource_version {
                    super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V2
                } else {
                    super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V1
                },
            output, received, Q04ReceivePositionV1::FinalSourceObservation,
        )
    }

    fn require_q04_receive_position(
        &self,
        position: Q04ReceivePositionV1,
    ) -> Result<(), SourceGenesisErrorV1> {
        match position {
            Q04ReceivePositionV1::Open => self.recheck(),
            Q04ReceivePositionV1::FinalSourceObservation => self.q04_terminal_clock().map(|_| ()),
        }
    }

    fn receive_q04_at_position(
        &self,
        length: usize,
        output: &mut Vec<u8>,
        received: &mut Option<Result<
            UnixStreamSubjectChunk,
            aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1,
        >>,
        position: Q04ReceivePositionV1,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        if length == 0 || length > 4096 || !output.is_empty() || received.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        output.try_reserve_exact(length)?;
        while output.len() < length {
            self.require_q04_receive_position(position)?;
            *received = Some(self.stream.try_borrow_mut()
                .map_err(|_| CreateQ04ErrorV1::ChangedCut)?
                .try_receive_subject_chunk_retaining(length - output.len()));

            let nonconsuming = match received.as_ref() {
                Some(Err(error)) => {
                    error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted()
                }
                Some(Ok(_)) => false,
                None => return Err(CreateQ04ErrorV1::ChangedCut),
            };
            if nonconsuming {
                *received = None;
                let stream = self.stream.try_borrow()
                    .map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
                transport::wait(stream.as_fd(), rustix::event::PollFlags::IN,
                    self.started + MAXIMUM_FLIGHT)?;
                continue;
            }
            if matches!(received, Some(Err(_))) {
                self.poisoned.set(true);
                return match received.take() {
                    Some(Err(first)) => Err(first.into()),
                    Some(Ok(chunk)) => {
                        *received = Some(Ok(chunk));
                        Err(CreateQ04ErrorV1::ChangedCut)
                    }
                    None => Err(CreateQ04ErrorV1::ChangedCut),
                };
            }

            let chunk = received.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            match position {
                Q04ReceivePositionV1::Open => self.require_root_chunk(chunk)?,
                Q04ReceivePositionV1::FinalSourceObservation => {
                    self.q04_terminal_clock()?;
                    let stream = self.stream.try_borrow()
                        .map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
                    self.peer.require_chunk(&stream, chunk)
                        .map_err(|_| SourceGenesisErrorV1::Stale)?;
                }
            }
            output.extend_from_slice(chunk.payload());
            self.require_q04_receive_position(position)?;
            *received = None;
        }
        self.require_q04_receive_position(position)?;
        Ok(())
    }

    // Preparation precedes this final same-flight sample. Continuity alone
    // is not an age bound, and neither original start is ever renewed.
    pub(in crate::policy_compiler) fn require_q04_signing_boundary(
        &self,
    ) -> Result<(), SourceGenesisErrorV1> {
        let now = self.signing_boundary_clock()?;
        require_q04_original_age(self.clock, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_compiler) fn capture_q04_prepare_readback(
        &self,
        controller: &HeldControllerSourceGenesisV1<'_>,
        source: &crate::hierarchy::source_genesis::HeldSourceTreeGenesisObservationV1<'_>,
        generation: u64,
        key: &ed25519_dalek::SigningKey,
        resident: &mut Option<Result<
            super::controller_readback::ControllerGenesisReadbackPacketV2,
            SourceGenesisErrorV1,
        >>,
        first: &mut Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
        debt: &mut Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    ) -> Result<(), ()> {
        super::controller_readback::capture_q04_prepare_readback_v1(
            controller, source, generation, key, self, resident, first, debt,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_compiler) fn capture_q04_complete_readback(
        &self,
        controller: &HeldControllerSourceGenesisV1<'_>,
        source: &crate::hierarchy::source_genesis::HeldSourceTreeGenesisObservationV1<'_>,
        generation: u64,
        key: &ed25519_dalek::SigningKey,
        resident: &mut Option<Result<
            super::controller_readback::ControllerGenesisReadbackPacketV2,
            SourceGenesisErrorV1,
        >>,
        first: &mut Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
        debt: &mut Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    ) -> Result<(), ()> {
        super::controller_readback::capture_q04_complete_readback_v1(
            controller, source, generation, key, self, resident, first, debt,
        )
    }

    pub(in crate::policy_compiler) fn q04_original_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.signing_boundary_clock()?;
        Ok(self.clock)
    }

    pub(in crate::policy_compiler) fn q04_current_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.signing_boundary_clock()
    }

    pub(in crate::policy_compiler) fn q04_nonce(&self) -> Result<[u8; 16], SourceGenesisErrorV1> {
        self.recheck()?;
        if self.nonce == [0; 16] {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(self.nonce)
    }

    pub(in crate::policy_compiler) fn q04_send_original(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        self.write(bytes)
    }

    // Only the Q04 final receipt calls this position after actual Root7/C8
    // and its last same-flight gen1 observation. The original process/profile
    // and socket identity remain mandatory; an open receive queue does not.
    pub(in crate::policy_compiler) fn q04_terminal_clock(
        &self,
    ) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.original_terminal_clock()
    }

    pub(super) fn original_terminal_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        if self.poisoned.get() || self.started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let stream = self.stream.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
        stream.revalidate_original()?;
        self.peer.recheck_stream(&stream).map_err(|_| SourceGenesisErrorV1::Stale)?;
        if self.source_uid != self.peer.source_uid() {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let now = kernel_pair()?;
        self.clock.validate_later_sample(now).map_err(|_| SourceGenesisErrorV1::Stale)?;
        transport::require_remaining(self.started + MAXIMUM_FLIGHT)?;
        Ok(now)
    }

    pub(in crate::policy_compiler) fn q04_terminal_nonce(&self) -> Result<[u8; 16], SourceGenesisErrorV1> {
        self.q04_terminal_clock()?;
        if self.nonce == [0; 16] {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(self.nonce)
    }

    pub(in crate::policy_compiler) fn q04_terminal_original_clock(
        &self,
    ) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.q04_terminal_clock()?;
        Ok(self.clock)
    }

    pub(in crate::policy_compiler) fn q04_expect_original_shutdown(
        &self,
        observation: &mut Option<Result<usize, rustix::io::Errno>>,
        byte: &mut [u8; 1],
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        if observation.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        loop {
            self.q04_terminal_clock()?;
            let stream = self.stream.try_borrow().map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
            *observation = Some(rustix::net::recv(
                stream.as_fd(), &mut *byte, rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
            ).map(|(_, received)| received));
            drop(stream);
            // The raw result and peek byte are owned by the invocation before
            // either classification or these potentially slow final checks.
            self.q04_terminal_clock()?;
            match observation.as_ref() {
                Some(Ok(0)) => return Ok(()),
                Some(Ok(_)) => return Err(CreateQ04ErrorV1::ChangedCut),
                Some(Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR)) => {
                    *observation = None;
                    let stream = self.stream.try_borrow().map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
                    transport::wait(stream.as_fd(), rustix::event::PollFlags::IN, self.started + MAXIMUM_FLIGHT)?;
                }
                Some(Err(first)) => return Err(std::io::Error::from(*first).into()),
                None => return Err(CreateQ04ErrorV1::ChangedCut),
            }
        }
    }

    // The same old receipt/parser and original owner construct this short
    // proof. Q04 only supplies a retaining receive at its preceding boundary.
    pub(in crate::policy_compiler) fn q04_floor_from_frame<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
        original_frame: &[u8],
    ) -> Result<RootSourceGenesisFloorProofV1<'flight>, SourceGenesisErrorV1> {
        let payload = super::wire::decode_root_source_genesis_frame_v2(original_frame, Phase::Anchored, self.nonce)?;
        self.floor_from_original_payload(controller, payload)
    }

    pub(in crate::policy_compiler) fn q04_completed_from_frame<'completed, 'flight>(
        &self,
        proof: &'completed RootSourceGenesisFloorProofV1<'flight>,
        original_frame: &[u8],
    ) -> Result<CompletedRootSourceGenesisFloorV1<'completed, 'flight>, SourceGenesisErrorV1> {
        if !std::ptr::eq(self, proof.origin) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        proof.recheck()?;
        let payload = decode_root_source_genesis_frame_v1(original_frame, Phase::Completed, self.nonce)?;
        require_completed_digest(payload, proof.floor().digest().as_bytes())?;
        proof.recheck()?;
        Ok(CompletedRootSourceGenesisFloorV1 { proof })
    }

    pub(super) fn issuance_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.recheck()?;
        let now = kernel_pair()?;
        self.clock.validate_later_sample(now).map_err(|_| SourceGenesisErrorV1::Stale)?;
        self.recheck()?;
        Ok(now)
    }

    // Unlike the general observation above, signing needs its genuine pair
    // after the potentially slow original-flight observations. Only continuity
    // and the unchanged original deadline are checked after this sample.
    fn signing_boundary_clock(&self) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
        self.recheck()?;

        let now = kernel_pair()?;
        self.clock.validate_later_sample(now)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if self.poisoned.get() || self.started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(SourceGenesisErrorV1::Stale);
        }

        Ok(now)
    }

    pub(super) fn end_failed(&self) -> Result<(), SourceGenesisErrorV1> {
        self.poisoned.set(true);
        let stream = self.stream.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
        rustix::net::shutdown(stream.as_fd(), rustix::net::Shutdown::Both)
            .map_err(std::io::Error::from)?;
        Ok(())
    }

    pub(super) const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }

    pub(super) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        if self.poisoned.get() || self.started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let stream = self
            .stream
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        stream.revalidate_original()?;
        require_open_receive_queue(stream.as_fd())?;
        self.peer
            .recheck_stream(&stream)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if self.source_uid != self.peer.source_uid() {
            return Err(SourceGenesisErrorV1::Stale);
        }
        // Genuine PID1/property and immutable-image reads are bounded too,
        // but their completion may cross the original flight's deadline.
        transport::require_remaining(self.started + MAXIMUM_FLIGHT).map(|_| ())
    }

    pub(super) fn write(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        let result = self.write_remaining(bytes);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    pub(super) fn write_first_successor(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        let result = self.write_with_mode(bytes, OriginalWriteModeV2::FirstSuccessor);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    fn write_remaining(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        self.write_with_mode(bytes, OriginalWriteModeV2::Ordinary)
    }

    // Ordinary mode preserves the original check/send/wait/drop ordering.
    // The selected mode only adds final genuine original samples to this loop.
    fn write_with_mode(&self, bytes: &[u8], mode: OriginalWriteModeV2) -> Result<(), SourceGenesisErrorV1> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let mut sent = 0;
        while sent < bytes.len() {
            self.recheck()?;
            let stream = self
                .stream
                .try_borrow()
                .map_err(|_| SourceGenesisErrorV1::Stale)?;
            if matches!(mode, OriginalWriteModeV2::FirstSuccessor) {
                self.observe_first_successor_clock()?;
            }
            match rustix::net::send(
                stream.as_fd(),
                &bytes[sent..],
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            ) {
                Ok(0) => return Err(SourceGenesisErrorV1::Stale),
                Ok(count) => sent += count,
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    match mode {
                        OriginalWriteModeV2::Ordinary => transport::wait(
                            stream.as_fd(),
                            rustix::event::PollFlags::OUT,
                            self.started + MAXIMUM_FLIGHT,
                        )?,
                        OriginalWriteModeV2::FirstSuccessor => transport::wait_first_successor(
                            stream.as_fd(),
                            rustix::event::PollFlags::OUT,
                            self.started + MAXIMUM_FLIGHT,
                            self,
                        )?,
                    }
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
        transport::require_remaining(self.started + MAXIMUM_FLIGHT).map(|_| ())
    }

    pub(super) fn send_phase(
        &self,
        phase: Phase,
        payload: &[u8],
    ) -> Result<(), SourceGenesisErrorV1> {
        self.write(&encode_root_source_genesis_frame_v1(
            phase, self.nonce, payload,
        )?)
    }

    pub(super) fn receive_reply<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
    ) -> Result<OriginalRootGenesisReplyV1<'flight>, SourceGenesisErrorV1> {
        let (phase, payload) = self.receive_phase(&[Phase::Prepared, Phase::Anchored])?;
        if phase == Phase::Anchored {
            return self
                .floor_from_original_payload(controller, &payload)
                .map(OriginalRootGenesisReplyV1::Anchored);
        }
        let expires = i64::from_be_bytes(take(&payload, 0)?);
        let record = RootSourceGenesisIntentRecordV1::from_record_bytes(&payload[8..])?;
        if record.accepted_input() != controller.acceptance()
            || record.source_uid() != self.source_uid
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let deadline = self
            .clock
            .boottime_nanoseconds()
            .checked_add(
                MAXIMUM_FLIGHT
                    .as_nanos()
                    .try_into()
                    .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
            )
            .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        self.recheck()?;
        Ok(OriginalRootGenesisReplyV1::Prepared(
            HeldRootSourceGenesisIntentV1 {
                origin: self,
                record,
                deadline,
                expires,
            },
        ))
    }

    pub(super) fn receive_floor<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
    ) -> Result<RootSourceGenesisFloorProofV1<'flight>, SourceGenesisErrorV1> {
        let (_, payload) = self.receive_phase(&[Phase::Anchored])?;
        self.floor_from_original_payload(controller, &payload)
    }

    fn floor_from_original_payload<'flight>(
        &'flight self,
        controller: &HeldControllerSourceGenesisV1<'_>,
        payload: &[u8],
    ) -> Result<RootSourceGenesisFloorProofV1<'flight>, SourceGenesisErrorV1> {
        let floor = SourceHierarchyFloorRecordV1::from_record_bytes(payload)?;
        let receipt = floor.receipt();
        let accepted = controller.acceptance();
        if floor.project() != accepted.project()
            || receipt.acceptance_digest() != accepted.digest()
            || &receipt.seed_packet() != accepted.seed_packet()
            || receipt.auth_packet() != accepted.auth_packet()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        self.recheck()?;
        controller.recheck()?;
        Ok(RootSourceGenesisFloorProofV1 {
            origin: self,
            floor,
        })
    }

    pub(super) fn receive_completed<'completed, 'flight>(
        &self,
        proof: &'completed RootSourceGenesisFloorProofV1<'flight>,
    ) -> Result<CompletedRootSourceGenesisFloorV1<'completed, 'flight>, SourceGenesisErrorV1> {
        if !std::ptr::eq(self, proof.origin) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        proof.recheck()?;
        let (_, completed) = self.receive_phase(&[Phase::Completed])?;
        require_completed_digest(&completed, proof.floor().digest().as_bytes())?;
        proof.recheck()?;
        Ok(CompletedRootSourceGenesisFloorV1 { proof })
    }

    pub(super) fn finish(
        &self,
        completed: CompletedRootSourceGenesisFloorV1<'_, '_>,
    ) -> Result<(), SourceGenesisErrorV1> {
        if !std::ptr::eq(self, completed.proof.origin) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        completed.recheck()?;
        // Completed was received on the original held stream. Finish may make
        // Root close immediately, so no later open-queue predicate is asserted.
        self.send_phase(Phase::Finish, completed.floor().digest().as_bytes())
    }

    fn receive_phase(&self, allowed: &[Phase]) -> Result<(Phase, Vec<u8>), SourceGenesisErrorV1> {
        let result = (|| {
            let mut frame = self.receive_exact(ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1)?;
            let phase = select_reply_phase(&frame, allowed, self.nonce)?;
            frame.extend_from_slice(&self.receive_exact(phase.payload_bytes())?);
            let payload = decode_root_source_genesis_frame_v1(&frame, phase, self.nonce)?.to_vec();
            Ok((phase, payload))
        })();
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    pub(super) fn receive_exact(&self, length: usize) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        if length == 0 || length > 4096 {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let result = self.receive_fragments(length);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    fn receive_fragments(&self, length: usize) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            self.recheck()?;
            let chunk = self
                .stream
                .try_borrow_mut()
                .map_err(|_| SourceGenesisErrorV1::Stale)?
                .try_receive_subject_chunk(length - bytes.len());
            match chunk {
                Ok(chunk) => {
                    self.require_root_chunk(&chunk)?;
                    bytes.extend_from_slice(chunk.payload());
                }
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    let stream = self
                        .stream
                        .try_borrow()
                        .map_err(|_| SourceGenesisErrorV1::Stale)?;
                    transport::wait(
                        stream.as_fd(),
                        rustix::event::PollFlags::IN,
                        self.started + MAXIMUM_FLIGHT,
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.recheck()?;
        Ok(bytes)
    }

    fn require_root_chunk(
        &self,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let stream = self
            .stream
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        self.peer
            .require_chunk(&stream, chunk)
            .map_err(|_| SourceGenesisErrorV1::Stale)
    }
}

// Pure framing checks never adopt a stream or return authorizing owner types.
fn select_reply_phase(
    header: &[u8],
    allowed: &[Phase],
    nonce: [u8; 16],
) -> Result<Phase, SourceGenesisErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
        || header[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
        || nonce == [0; 16]
        || header[16..32] != nonce
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    allowed
        .iter()
        .copied()
        .find(|phase| header.get(..8) == Some(phase.magic().as_slice()))
        .ok_or(SourceGenesisErrorV1::NonCanonical)
}

fn require_completed_digest(
    completed: &[u8],
    expected: &[u8; 32],
) -> Result<(), SourceGenesisErrorV1> {
    if completed != expected.as_slice() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

impl Drop for OriginalRootGenesisFlightV1<'_> {
    fn drop(&mut self) {
        // Shutdown precedes releasing either enclosing writer. It also tells
        // Root to close its accepted queue before releasing its own writer.
        let _ = rustix::net::shutdown(self.stream.get_mut().as_fd(), rustix::net::Shutdown::Both);
    }
}

// Creator pidfd liveness does not imply the daemon still retains this writer:
// the server shuts down its original endpoint before releasing the journal.
pub(in crate::policy_compiler) fn require_open_receive_queue(
    descriptor: BorrowedFd<'_>,
) -> Result<(), SourceGenesisErrorV1> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let mut descriptors = [PollFd::new(&descriptor, PollFlags::RDHUP)];
    poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(std::io::Error::from)?;
    if descriptors[0]
        .revents()
        .intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    Ok(())
}

pub(in crate::policy_compiler) fn kernel_pair() -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
    let before = KernelBootId::current()?.into_bytes();
    let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    let after = KernelBootId::current()?.into_bytes();
    if before != after {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let boot = u64::try_from(boot.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(boot.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or(SourceGenesisErrorV1::Stale)?;
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
            .map_err(|_| SourceGenesisErrorV1::Stale)?,
        before,
        wall,
        boot,
    )
    .map_err(|_| SourceGenesisErrorV1::Stale)
}

/// Samples the genuine kernel clock for one retained Root successor flight.
///
/// This is nonauthorizing clock DATA. A later sample must remain within the
/// same boot and original 65-second server custody bound; it never changes a
/// persisted successor intent's admission deadline.
///
/// # Errors
/// Rejects kernel observation failure, reversed clocks, reboot or expiry.
pub fn observe_root_first_source_successor_clock_v2(
    original: Option<RawPairedClockSample>,
) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
    let current = kernel_pair()?;
    if let Some(original) = original {
        original.validate_later_sample(current)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let deadline = original.boottime_nanoseconds().checked_add(65_000_000_000)
            .ok_or(SourceGenesisErrorV1::Stale)?;
        if current.boottime_nanoseconds() >= deadline {
            return Err(SourceGenesisErrorV1::Stale);
        }
    }
    Ok(current)
}

// Pure nonauthorizing clock DATA comparison. The sole production caller
// supplies its retained original pair and the just-observed genuine pair.
fn require_q04_original_age(
    original: RawPairedClockSample,
    current: RawPairedClockSample,
) -> Result<(), SourceGenesisErrorV1> {
    require_original_root_age(original, current)
}

// Sole pure finite-age comparison shared by the two closed original purposes.
// Neither a clock sample nor this comparison grants admission or adopts a peer.
fn require_original_root_age(
    original: RawPairedClockSample,
    current: RawPairedClockSample,
) -> Result<(), SourceGenesisErrorV1> {
    let deadline = original.boottime_nanoseconds()
        .checked_add(60_000_000_000)
        .ok_or(SourceGenesisErrorV1::Stale)?;
    if current.boottime_nanoseconds() >= deadline {
        return Err(SourceGenesisErrorV1::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn completed_window_accepts_only_original_completed_phase_and_nonce_data() {
        let nonce = [31; 16];
        let floor = [32; 32];
        let frame = encode_root_source_genesis_frame_v1(Phase::Completed, nonce, &floor).unwrap();

        assert_eq!(
            select_reply_phase(&frame[..32], &[Phase::Completed], nonce).unwrap(),
            Phase::Completed,
        );
        assert!(select_reply_phase(&frame[..32], &[Phase::Completed], [33; 16]).is_err());
        for phase in [Phase::Anchored, Phase::Complete, Phase::Finish] {
            let substituted =
                encode_root_source_genesis_frame_v1(phase, nonce, &vec![0; phase.payload_bytes()])
                    .unwrap();
            assert!(
                select_reply_phase(&substituted[..32], &[Phase::Completed], nonce).is_err(),
            );
        }
    }

    #[test]
    fn live_creator_does_not_hide_original_queue_shutdown() {
        let (client, server) = UnixStream::pair().unwrap();
        require_open_receive_queue(client.as_fd()).unwrap();

        server.shutdown(Shutdown::Both).unwrap();

        assert!(matches!(
            require_open_receive_queue(client.as_fd()),
            Err(SourceGenesisErrorV1::Stale)
        ));
    }

    #[test]
    fn initial_reply_allows_only_prepared_or_exact_anchored_recovery() {
        // These are DATA-only frames, not fake Root peers or live proofs.
        let nonce = [11; 16];
        for phase in [Phase::Prepared, Phase::Anchored] {
            let frame =
                encode_root_source_genesis_frame_v1(phase, nonce, &vec![0; phase.payload_bytes()])
                    .unwrap();
            assert_eq!(
                select_reply_phase(&frame[..32], &[Phase::Prepared, Phase::Anchored], nonce)
                    .unwrap(),
                phase
            );
        }
        for phase in [
            Phase::Prepare,
            Phase::Anchor,
            Phase::Complete,
            Phase::Completed,
            Phase::Finish,
        ] {
            let frame =
                encode_root_source_genesis_frame_v1(phase, nonce, &vec![0; phase.payload_bytes()])
                    .unwrap();
            assert!(
                select_reply_phase(&frame[..32], &[Phase::Prepared, Phase::Anchored], nonce)
                    .is_err()
            );
        }
    }

    #[test]
    fn every_reply_rejects_wrong_nonce_version_reserved_or_width() {
        let nonce = [12; 16];
        let frame =
            encode_root_source_genesis_frame_v1(Phase::Completed, nonce, &[13; 32]).unwrap();
        let header = &frame[..32];
        assert!(select_reply_phase(header, &[Phase::Completed], [14; 16]).is_err());
        assert!(select_reply_phase(header, &[Phase::Completed], [0; 16]).is_err());
        assert!(select_reply_phase(&header[..31], &[Phase::Completed], nonce).is_err());
        for offset in [8, 9, 10, 15, 16, 31] {
            let mut changed = header.to_vec();
            changed[offset] ^= 1;
            assert!(select_reply_phase(&changed, &[Phase::Completed], nonce).is_err());
        }
    }

    #[test]
    fn finish_never_acknowledges_another_or_incomplete_floor() {
        let floor = [15; 32];
        require_completed_digest(&floor, &floor).unwrap();
        assert!(require_completed_digest(&[16; 32], &floor).is_err());
        assert!(require_completed_digest(&floor[..31], &floor).is_err());
        assert!(require_completed_digest(&[], &floor).is_err());
    }

    #[test]
    fn q04_original_age_refuses_deadline_equality_and_overflow_data() {
        let sample = |boottime| RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([91; 16]).unwrap(), [92; 16], 0, boottime,
        ).unwrap();
        let original = sample(1_000_000_000);
        let deadline = 61_000_000_000;

        assert!(require_q04_original_age(original, sample(deadline - 1)).is_ok());
        assert!(require_q04_original_age(original, sample(deadline)).is_err());
        assert!(require_q04_original_age(original, sample(deadline + 1)).is_err());
        assert!(require_q04_original_age(sample(u64::MAX), sample(u64::MAX)).is_err());
    }

    #[test]
    fn paired_continuity_does_not_replace_q04_original_age_data() {
        let provenance = RawClockProvenance::new_untrusted([93; 16]).unwrap();
        let original = RawPairedClockSample::new_untrusted(
            provenance, [94; 16], 100, 1_000_000_000,
        ).unwrap();
        let later = RawPairedClockSample::new_untrusted(
            provenance, [94; 16], 161, 62_000_000_000,
        ).unwrap();

        original.validate_later_sample(later).unwrap();
        assert!(require_q04_original_age(original, later).is_err());
        // These raw DATA samples never construct a flight or authorize signing.
    }
}
