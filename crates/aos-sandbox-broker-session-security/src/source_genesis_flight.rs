//! Actual normal-Root writer and Source-signer joins on one original stream.
//!
//! The Controller already retains its real Controller and Source writers.
//! This producer opens Root last, verifies actual role-pinned observations,
//! and retains Root through floor, Controller/Source ACKs and a final stream
//! acknowledgement. It never reads Controller's private DAC-owned journal.
//! Replies are data: the shared Controller coordinator must independently join
//! its selected immutable profile and original per-fragment Root peer before
//! constructing a non-detachable proof. Installed qualification stays separate.

use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox::policy_compiler::{
    ROOT_FIRST_SOURCE_SUCCESSOR_HELLO_MAGIC_V2,
    ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2, RootFirstSourceSuccessorFrameKindV2,
    RootFirstSourceSuccessorOpeningV2, RootFirstSuccessorMutationResultsV2,
    RootFirstSourceSuccessorIntentV2, RootFirstSourceSuccessorFloorV2,
    SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2,
    decode_root_first_source_successor_frame_v2, encode_root_first_source_successor_frame_v2,
    observe_root_first_source_successor_clock_v2,
    ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1, ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1,
    RootSourceGenesisAuthorityV1, RootSourceGenesisFrameKindV1,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SourceHierarchyFloorRecordV1,
    decode_root_source_genesis_frame_v1, encode_root_source_genesis_frame_v1,
};

use crate::source_signer_exchange::request_root_source_tree_genesis_readback_v2;
use crate::source_signer_exchange::request_root_source_first_successor_readback_v2;

/// Selects the daemon's already installed current or historical entry route.
///
/// This routing DATA supplies no authority. Historical routing requires an
/// existing original intent/archive, and current routing still authenticates
/// the actual independent role pins and nonrenewable admission bounds.
#[derive(Clone, Copy)]
pub enum RootFirstSourceSuccessorRouteV2 {
    /// Uses the genuine normal Root startup and fresh admission suppliers.
    Current,
    /// Settles only actual retained intent/receipt/archive custody.
    Historical,
}

#[derive(Default)]
struct RootFirstSourceSuccessorIoV2 {
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    native: Option<Result<usize, io::Error>>,
    timeouts: Vec<Result<(), io::Error>>,
    posts: Vec<Result<(), SourceGenesisErrorV1>>,
    clock_posts: Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    decoded: Option<Result<(), SourceGenesisErrorV1>>,
}

#[derive(Clone, Copy)]
struct RootFirstSourceSuccessorBookendV2<'owner, 'startup> {
    owner: Option<&'owner RootSourceGenesisAuthorityV1>,
    startup: Option<&'startup crate::production_normal_root::ProductionNormalRootStartupV1>,
    controller_uid: u32,
    controller_gid: u32,
    deadline: Instant,
    clock: aos_sandbox_core::RawPairedClockSample,
}

impl RootFirstSourceSuccessorBookendV2<'_, '_> {
    fn post(
        &self, stream: &UnixStream, posts: &mut Vec<Result<(), SourceGenesisErrorV1>>,
        clock_posts: &mut Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    ) -> Result<(), ()> {
        // Obtain residency before slow checks and the final genuine sample.
        // None is an empty slot, never a successful clock/currentness Result.
        clock_posts.push(None);
        let clock_slot = clock_posts.last_mut().ok_or(())?;
        // Attempt every independent supplier after the original action Result
        // is resident; none replaces the action's first cause.
        posts.push(crate::production_normal_root::recheck_optional(self.startup)
            .map_err(|_| SourceGenesisErrorV1::Stale));
        posts.push(self.owner.map_or(Ok(()), RootSourceGenesisAuthorityV1::recheck));
        posts.push((|| {
            let peer = rustix::net::sockopt::socket_peercred(stream).map_err(io::Error::from)?;
            if peer.uid.as_raw() != self.controller_uid || peer.gid.as_raw() != self.controller_gid
                || Instant::now() >= self.deadline
            { return Err(SourceGenesisErrorV1::Stale); }
            Ok(())
        })());
        // Peer/owner failure cannot suppress this independent actual sample.
        *clock_slot = Some(observe_root_first_source_successor_clock_v2(Some(self.clock)).and_then(|current| {
            if Instant::now() >= self.deadline { return Err(SourceGenesisErrorV1::Stale); }
            Ok(current)
        }));
        if posts.iter().any(Result::is_err) || clock_posts.iter().flatten().any(Result::is_err) { Err(()) } else { Ok(()) }
    }

    fn remaining(&self) -> Result<Duration, ()> {
        self.deadline.checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero()).ok_or(())
    }
}

impl RootFirstSourceSuccessorIoV2 {
    fn read(
        &mut self, stream: &UnixStream, bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>,
        phase: RootFirstSourceSuccessorFrameKindV2, nonce: [u8; 16],
    ) -> Result<(), ()> {
        if !self.incoming.is_empty() || self.decoded.is_some() { return Err(()); }
        self.incoming.resize(32 + phase.payload_bytes(), 0);
        let mut received = 0;
        let mut original = stream;
        while received < self.incoming.len() {
            bookend.post(stream, &mut self.posts, &mut self.clock_posts)?;
            self.timeouts.push(stream.set_read_timeout(Some(bookend.remaining()?)));
            bookend.post(stream, &mut self.posts, &mut self.clock_posts)?;
            if self.timeouts.last().is_some_and(Result::is_err) { return Err(()); }
            self.native = Some(original.read(&mut self.incoming[received..]));
            let post = bookend.post(stream, &mut self.posts, &mut self.clock_posts);
            match &self.native {
                Some(Ok(count)) if *count > 0 => { received += *count; post?; }
                Some(Err(error)) if error.kind() == io::ErrorKind::Interrupted => { post?; }
                _ => return Err(()),
            }
            // Only a checked successful fragment or recognized nonconsuming
            // interrupt may release its count. A fatal actual Result remains.
            self.native = None;
        }
        self.decoded = Some(decode_root_first_source_successor_frame_v2(&self.incoming, phase, nonce).map(|_| ()));
        bookend.post(stream, &mut self.posts, &mut self.clock_posts)?;
        if matches!(self.decoded, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    fn send(
        &mut self, stream: &UnixStream, bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>,
        phase: RootFirstSourceSuccessorFrameKindV2, nonce: [u8; 16], payload: &[u8],
    ) -> Result<(), ()> {
        let encoding = encode_root_first_source_successor_frame_v2(&mut self.outgoing, phase, nonce, payload);
        self.posts.push(encoding);
        bookend.post(stream, &mut self.posts, &mut self.clock_posts)?;
        self.write(stream, bookend)
    }

    fn write(&mut self, stream: &UnixStream, bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>) -> Result<(), ()> {
        let mut written = 0;
        let mut original = stream;
        while written < self.outgoing.len() {
            bookend.post(stream, &mut self.posts, &mut self.clock_posts)?;
            self.timeouts.push(stream.set_write_timeout(Some(bookend.remaining()?)));
            bookend.post(stream, &mut self.posts, &mut self.clock_posts)?;
            if self.timeouts.last().is_some_and(Result::is_err) { return Err(()); }
            self.native = Some(original.write(&self.outgoing[written..]));
            let post = bookend.post(stream, &mut self.posts, &mut self.clock_posts);
            match &self.native {
                Some(Ok(count)) if *count > 0 => { written += *count; post?; }
                Some(Err(error)) if error.kind() == io::ErrorKind::Interrupted => { post?; }
                _ => return Err(()),
            }
            self.native = None;
        }
        Ok(())
    }
}

/// Retains the accepted original stream and actual Root writer through Finish.
///
/// The daemon parks this owner before selected-purpose gates or protected
/// opening. Every returned native or Source RPC Result is resident before
/// independent posts. An armed failure must terminate without local disposal.
#[must_use = "retain the failed original Root attempt through terminal exit"]
pub struct RootFirstSourceSuccessorAttemptV2<'stream, 'startup> {
    stream: &'stream mut UnixStream,
    startup: Option<&'startup crate::production_normal_root::ProductionNormalRootStartupV1>,
    request: [u8; 32],
    route: RootFirstSourceSuccessorRouteV2,
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    source_signer_uid: u32,
    deadline: Instant,
    clock: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    opening: RootFirstSourceSuccessorOpeningV2,
    owner: Option<RootSourceGenesisAuthorityV1>,
    context: Option<Result<RootFirstSourceSuccessorIntentV2, SourceGenesisErrorV1>>,
    prepared: Option<Result<RootFirstSourceSuccessorIntentV2, ()>>,
    floor: Option<Result<RootFirstSourceSuccessorFloorV2, ()>>,
    prepare: RootFirstSuccessorMutationResultsV2,
    anchor: RootFirstSuccessorMutationResultsV2,
    source: [Option<Result<[u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2], io::Error>>; 3],
    hello_io: RootFirstSourceSuccessorIoV2,
    prepare_io: RootFirstSourceSuccessorIoV2,
    anchor_io: RootFirstSourceSuccessorIoV2,
    complete_io: RootFirstSourceSuccessorIoV2,
    finish_io: RootFirstSourceSuccessorIoV2,
    posts: Vec<Result<(), SourceGenesisErrorV1>>,
    clock_posts: Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    cause: Option<SourceGenesisErrorV1>,
    cleanup: Option<Result<(), io::Error>>,
    started: bool,
    armed: bool,
}

impl<'stream, 'startup> RootFirstSourceSuccessorAttemptV2<'stream, 'startup> {
    /// Parks only original arguments before inspecting the selected purpose.
    pub fn new(
        stream: &'stream mut UnixStream,
        startup: Option<&'startup crate::production_normal_root::ProductionNormalRootStartupV1>,
        request: [u8; 32], route: RootFirstSourceSuccessorRouteV2,
        controller_uid: u32, controller_gid: u32, source_uid: u32, source_signer_uid: u32,
    ) -> Self {
        Self {
            stream, startup, request, route, controller_uid, controller_gid, source_uid, source_signer_uid,
            deadline: Instant::now() + ROOT_HOLD_LIMIT, clock: None,
            opening: RootFirstSourceSuccessorOpeningV2::new(), owner: None, context: None,
            prepared: None, floor: None, prepare: RootFirstSuccessorMutationResultsV2::new(),
            anchor: RootFirstSuccessorMutationResultsV2::new(), source: [None, None, None],
            hello_io: Default::default(), prepare_io: Default::default(), anchor_io: Default::default(),
            complete_io: Default::default(), finish_io: Default::default(), posts: Vec::new(),
            clock_posts: Vec::new(),
            cause: None, cleanup: None, started: false, armed: true,
        }
    }

    /// Runs the exact selected original flight once, without retrying a mutation.
    ///
    /// # Errors
    /// Returns a marker while actual causes, writers and shutdown remain held.
    pub fn serve_once(&mut self) -> Result<(), ()> {
        if self.started { return Err(()); }
        self.started = true;
        let returned = serve_first_successor(self);
        if let Err(error) = returned { self.cause.get_or_insert(error); }
        if self.cause.is_some() {
            self.cleanup = Some(self.stream.shutdown(Shutdown::Both));
            return Err(());
        }
        Ok(())
    }

    /// Borrows the first retained action failure and later debt without disposal.
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.clock { return Some(error); }
        if let Some(error) = self.opening.error() { return Some(error); }
        if let Some(Err(error)) = &self.context { return Some(error); }
        for index in 0..3 {
            if let Some(Err(error)) = &self.source[index] { return Some(error); }
            if index == 0 { if let Some(error) = self.prepare.error() { return Some(error); } }
            if index == 1 { if let Some(error) = self.anchor.error() { return Some(error); } }
        }
        for boundary in [&self.hello_io, &self.prepare_io, &self.anchor_io, &self.complete_io, &self.finish_io] {
            if let Some(Err(error)) = &boundary.native { return Some(error); }
            for timeout in &boundary.timeouts { if let Err(error) = timeout { return Some(error); } }
            if let Some(Err(error)) = &boundary.decoded { return Some(error); }
            for post in &boundary.posts { if let Err(error) = post { return Some(error); } }
            for post in boundary.clock_posts.iter().flatten() { if let Err(error) = post { return Some(error); } }
        }
        for post in &self.posts { if let Err(error) = post { return Some(error); } }
        if let Some(error) = self.clock_post_failures().next() { return Some(error); }
        self.cause.as_ref().map(|error| error as &dyn std::error::Error)
    }

    /// Borrows independent original-clock debt while actual native cause stays first.
    pub fn clock_post_failures(&self) -> impl Iterator<Item = &SourceGenesisErrorV1> {
        self.clock_posts.iter().flatten()
            .chain(self.hello_io.clock_posts.iter().flatten())
            .chain(self.prepare_io.clock_posts.iter().flatten())
            .chain(self.anchor_io.clock_posts.iter().flatten())
            .chain(self.complete_io.clock_posts.iter().flatten())
            .chain(self.finish_io.clock_posts.iter().flatten())
            .chain(self.prepare.clock_post_result())
            .chain(self.anchor.clock_post_result())
            .filter_map(|result| result.as_ref().err())
    }
}

impl Drop for RootFirstSourceSuccessorAttemptV2<'_, '_> {
    fn drop(&mut self) {
        if self.armed {
            if self.cleanup.is_none() { self.cleanup = Some(self.stream.shutdown(Shutdown::Both)); }
            // No failed original Root writer is released during ordinary
            // unwinding or an accidental caller return.
            std::process::abort();
        }
    }
}

fn serve_first_successor(attempt: &mut RootFirstSourceSuccessorAttemptV2<'_, '_>) -> Result<(), SourceGenesisErrorV1> {
    use RootFirstSourceSuccessorFrameKindV2 as Phase;
    let RootFirstSourceSuccessorAttemptV2 {
        stream, startup, request, route, controller_uid, controller_gid, source_uid, source_signer_uid,
        deadline, clock, opening, owner, context, prepared, floor, prepare, anchor, source,
        hello_io, prepare_io, anchor_io, complete_io, finish_io, posts, clock_posts, cleanup, armed, ..
    } = attempt;

    *clock = Some(observe_root_first_source_successor_clock_v2(None));
    let original_clock = *clock.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    if request[..8] != *ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2 || request[8..24] == [0; 16]
        || request[24..] != [0; 8] || startup.is_none() || *controller_uid == 0
        || *controller_gid == 0 || *source_uid == 0 || *source_signer_uid == 0
    { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    let before = RootFirstSourceSuccessorBookendV2 {
        owner: None, startup: *startup, controller_uid: *controller_uid, controller_gid: *controller_gid,
        deadline: *deadline, clock: original_clock,
    };
    before.post(stream, posts, clock_posts).map_err(|_| SourceGenesisErrorV1::Stale)?;
    posts.push(aos_sandbox::policy_compiler::require_no_fixed_closed_policy_binding_hold_v1()
        .map_err(|_| SourceGenesisErrorV1::AdmissionClosed));
    before.post(stream, posts, clock_posts).map_err(|_| SourceGenesisErrorV1::Stale)?;
    let opened = opening.open_into(owner, *controller_uid, *source_uid);
    // Startup/peer/clock remain independent even if protected opening failed.
    let opening_post = before.post(stream, posts, clock_posts);
    if opened.is_err() || opening_post.is_err() { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    let owner = owner.as_mut().ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
    let nonce = owner.nonce();
    hello_io.outgoing.resize(56, 0);
    hello_io.outgoing[..8].copy_from_slice(ROOT_FIRST_SOURCE_SUCCESSOR_HELLO_MAGIC_V2);
    hello_io.outgoing[8..10].copy_from_slice(&2_u16.to_be_bytes());
    hello_io.outgoing[16..32].copy_from_slice(&request[8..24]);
    hello_io.outgoing[32..48].copy_from_slice(&nonce);
    hello_io.outgoing[48..52].copy_from_slice(&source_uid.to_be_bytes());
    hello_io.outgoing[52..56].copy_from_slice(&controller_uid.to_be_bytes());
    {
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(&*owner), ..before };
        hello_io.write(stream, &held).map_err(|_| SourceGenesisErrorV1::Stale)?;
        prepare_io.read(stream, &held, Phase::Prepare, nonce).map_err(|_| SourceGenesisErrorV1::Stale)?;
    }
    *context = Some(match route {
        RootFirstSourceSuccessorRouteV2::Current => owner.first_source_successor_context_v2(&prepare_io.incoming[32..]),
        RootFirstSourceSuccessorRouteV2::Historical => owner.historical_first_source_successor_context_v2(&prepare_io.incoming[32..]),
    });
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(&*owner), ..before };
    let context_post = held.post(stream, posts, clock_posts);
    let original = context.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Conflict)?;
    context_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    source[0] = Some(request_root_source_first_successor_readback_v2(
        nonce, original, owner.source_readback_pin(), *source_signer_uid, *controller_gid,
    ));
    let source_post = held.post(stream, posts, clock_posts);
    let source_before = source[0].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    source_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    if matches!(route, RootFirstSourceSuccessorRouteV2::Historical) {
        posts.push(aos_sandbox::policy_compiler::verify_source_first_successor_readback_v2(
            source_before, owner.source_readback_pin(), nonce, original,
        ).and_then(|observed| {
            if observed.phase() == aos_sandbox::policy_compiler::SourceFirstSuccessorReadbackPhaseV2::Before {
                Err(SourceGenesisErrorV1::AdmissionClosed)
            } else { Ok(()) }
        }));
        held.post(stream, posts, clock_posts).map_err(|_| SourceGenesisErrorV1::Stale)?;
    }
    *prepared = Some(owner.prepare_first_successor_v2(
        original, &prepare_io.incoming[32..], source_before, &before.clock, &before.deadline, prepare,
    ));
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(&*owner), ..before };
    let prepared_post = held.post(stream, posts, clock_posts);
    let original = prepared.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Conflict)?;
    prepared_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    prepare_io.send(stream, &held, Phase::Prepared, nonce, original.as_bytes()).map_err(|_| SourceGenesisErrorV1::Stale)?;
    anchor_io.read(stream, &held, Phase::Anchor, nonce).map_err(|_| SourceGenesisErrorV1::Stale)?;
    source[1] = Some(request_root_source_first_successor_readback_v2(
        nonce, original, owner.source_readback_pin(), *source_signer_uid, *controller_gid,
    ));
    let source_post = held.post(stream, posts, clock_posts);
    let source_after = source[1].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    source_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    *floor = Some(owner.anchor_first_successor_v2(
        original, &anchor_io.incoming[32..], source_after, &before.clock, &before.deadline, anchor,
    ));
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(&*owner), ..before };
    let floor_post = held.post(stream, posts, clock_posts);
    let floor = floor.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Conflict)?;
    floor_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    anchor_io.send(stream, &held, Phase::Anchored, nonce, floor.as_bytes()).map_err(|_| SourceGenesisErrorV1::Stale)?;
    complete_io.read(stream, &held, Phase::Complete, nonce).map_err(|_| SourceGenesisErrorV1::Stale)?;
    source[2] = Some(request_root_source_first_successor_readback_v2(
        nonce, original, owner.source_readback_pin(), *source_signer_uid, *controller_gid,
    ));
    let source_post = held.post(stream, posts, clock_posts);
    let acknowledged = source[2].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    source_post.map_err(|_| SourceGenesisErrorV1::Stale)?;

    // This short actual current-floor Result cannot be stored inside its own
    // writer. Keep it named locally through Finish, including every failure.
    let current_result = owner.current_anchored_first_successor_floor_v2(
        original, &complete_io.incoming[32..], acknowledged, floor,
    );
    let current_post = held.post(stream, posts, clock_posts);
    let Ok(current) = &current_result else { terminate_first_successor_root(); };
    if current_post.is_err() { terminate_first_successor_root(); }
    let completion = current.completion();
    let sent = complete_io.send(stream, &held, Phase::Completed, nonce, completion);
    let current_after_send = current.recheck();
    posts.push(current_after_send);
    let independent = held.post(stream, posts, clock_posts);
    if sent.is_err() || independent.is_err() { terminate_first_successor_root(); }
    let received = finish_io.read(stream, &held, Phase::Finish, nonce);
    posts.push(current.recheck());
    let independent = held.post(stream, posts, clock_posts);
    if received.is_err() || independent.is_err() || &finish_io.incoming[32..] != completion {
        terminate_first_successor_root();
    }
    let sent = finish_io.send(stream, &held, Phase::Finish, nonce, completion);
    posts.push(current.recheck());
    let independent = held.post(stream, posts, clock_posts);
    if sent.is_err() || independent.is_err() { terminate_first_successor_root(); }
    *cleanup = Some(stream.shutdown(Shutdown::Both));
    // Shutdown does not renew admission or dispose Root on a negative result.
    if !matches!(cleanup, Some(Ok(()))) { terminate_first_successor_root(); }
    *armed = false;
    Ok(())
}

fn terminate_first_successor_root() -> ! {
    // Called only while the same whole attempt and named current-floor Result
    // are resident. Fallible diagnostics never choose an ordinary error return.
    std::process::exit(1)
}

/// Joins actual existing gen1 observations inside the original Q04 Root owner.
///
/// The caller first parks its accepted socket and genuine startup in the
/// shared negative attempt. Each RPC borrows that same Root owner; its actual
/// returned `Result` is moved immediately into the loan before postchecks.
/// This prelude neither prepares new genesis nor issues Stage/publication.
/// It leaves Root owned for the later fully funded policy continuation.
///
/// # Errors
/// Retains missing existing floor/Complete/ACK, malformed original packets,
/// changed fixed custody or the actual Source RPC error in the same attempt.
/// The caller must terminate without dropping the failed attempt or retrying.
pub fn prepare_root_create_q04_existing_gen1_v1(
    attempt: &mut aos_sandbox::policy_compiler::OriginalRootCreateQ04AttemptV1<'_>,
    source_signer_uid: u32,
    controller_gid: u32,
) -> Result<(), ()> {
    attempt.begin_existing_gen1()?;
    let preparation = attempt.read_existing_source_preparation()?;
    observe_root_create_q04_source(preparation, source_signer_uid, controller_gid)?;
    attempt.send_existing_anchor()?;

    let completion = attempt.read_existing_source_completion()?;
    observe_root_create_q04_source(completion, source_signer_uid, controller_gid)?;
    attempt.send_existing_completion()
}

/// Rejoins fresh gen1 DATA after one permitted original Controller/Source write.
///
/// The same original Root stream and owners remain retained. This calls the
/// unchanged fixed Source signer engine and parks its returned result before
/// any later check. It does not replace held Claim/ACK phase authentication,
/// authorize a logical transition or renew the original deadline.
///
/// # Errors
/// Retains malformed fresh Complete, mismatched Source/current floor, changed
/// actual names/owners, original RPC cause or the unchanged original cutoff.
pub fn refresh_root_create_q04_gen1_v1(
    attempt: &mut aos_sandbox::policy_compiler::OriginalRootCreateQ04AttemptV1<'_>,
    source_signer_uid: u32,
    controller_gid: u32,
) -> Result<(), ()> {
    let observation = attempt.read_current_gen1_refresh()?;
    observe_root_create_q04_source(observation, source_signer_uid, controller_gid)?;
    attempt.send_current_gen1_refresh()
}

fn observe_root_create_q04_source(
    observation: aos_sandbox::policy_compiler::RootCreateQ04SourceObservationLoanV1<'_, '_>,
    source_signer_uid: u32,
    controller_gid: u32,
) -> Result<(), ()> {
    let (challenge, project, context, signer) = observation.request();
    let returned = request_root_source_tree_genesis_readback_v2(
        challenge, Some(project), Some(context), signer, source_signer_uid, controller_gid,
    );
    observation.park_result(returned)
}

// The client's original 60-second deadline starts before connection. Root's
// phase deadline begins later and is 65 seconds; it never expires before the
// client's maximum custody interval. Every stream fragment uses its remaining
// bound. Blocking owner/signature RPC work may delay release, but cannot admit
// a late phase or extend the client's original custody deadline.
const ROOT_HOLD_LIMIT: Duration = Duration::from_secs(65);

/// Serves genuine genesis preparation, anchoring and ACK readback under Root.
///
/// This must be called only by the existing normal Root daemon after its fixed
/// Controller peer check. Source's physical owner UID is explicitly the same
/// privileged configuration used by its Controller-owned journal/view; the
/// separate Source signer UID identifies only the readback endpoint process.
/// The original accepted stream is shut down before Root's writer is released
/// on success, error or unwind. It is never forked, handed off or duplicated.
///
/// # Errors
/// Rejects malformed phases, a different original nonce or input, changed
/// actual owner cuts/pins, unavailable current admission for new mutation,
/// insufficient reserved suffixes, unanchored final ACKs or transport loss.
pub fn serve_root_source_genesis_flight_v1(
    stream: &mut UnixStream,
    startup: Option<&crate::production_normal_root::ProductionNormalRootStartupV1>,
    client_nonce: [u8; 16],
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    source_signer_uid: u32,
) -> Result<(), SourceGenesisErrorV1> {
    serve(
        stream,
        startup,
        client_nonce,
        controller_uid,
        controller_gid,
        source_uid,
        source_signer_uid,
        AdmissionScope::Current,
    )
}

/// Serves only exact materialized genesis recovery when current inputs are absent.
///
/// # Errors
/// Rejects every current Empty or vacant admission packet, missing original
/// receipt/intent/floor custody, and the same unsafe owner/transport conditions
/// as the normal flight. This entry cannot admit a new expired genesis.
pub fn serve_root_source_genesis_recovery_v1(
    stream: &mut UnixStream,
    startup: Option<&crate::production_normal_root::ProductionNormalRootStartupV1>,
    client_nonce: [u8; 16],
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    source_signer_uid: u32,
) -> Result<(), SourceGenesisErrorV1> {
    serve(
        stream,
        startup,
        client_nonce,
        controller_uid,
        controller_gid,
        source_uid,
        source_signer_uid,
        AdmissionScope::HistoricalOnly,
    )
}

enum AdmissionScope {
    Current,
    HistoricalOnly,
}

fn serve(
    stream: &mut UnixStream,
    startup: Option<&crate::production_normal_root::ProductionNormalRootStartupV1>,
    client_nonce: [u8; 16],
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    source_signer_uid: u32,
    scope: AdmissionScope,
) -> Result<(), SourceGenesisErrorV1> {
    let stream = ClosingOriginalStream(stream);
    if client_nonce == [0; 16]
        || controller_uid == 0
        || controller_gid == 0
        || source_uid == 0
        || source_signer_uid == 0
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let peer = rustix::net::sockopt::socket_peercred(&*stream.0).map_err(std::io::Error::from)?;
    if peer.uid.as_raw() != controller_uid || peer.gid.as_raw() != controller_gid {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let owner = RootSourceGenesisAuthorityV1::open_fixed(controller_uid, source_uid)?;
    let mut flight = RootHeldStreamFlight {
        stream,
        startup,
        owner,
        deadline: Instant::now() + ROOT_HOLD_LIMIT,
        source_signer_uid,
        controller_gid,
        scope,
    };
    let nonce = flight.owner.nonce();
    let mut hello = [0; 56];
    hello[..8].copy_from_slice(ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1);
    hello[8..10].copy_from_slice(&1_u16.to_be_bytes());
    hello[16..32].copy_from_slice(&client_nonce);
    hello[32..48].copy_from_slice(&nonce);
    hello[48..52].copy_from_slice(&source_uid.to_be_bytes());
    hello[52..56].copy_from_slice(&controller_uid.to_be_bytes());
    flight.write(&hello)?;

    let prepared = flight.read(RootSourceGenesisFrameKindV1::Prepare)?;
    let source = flight.source_observation(&prepared)?;
    let floor = if let Some(floor) = flight
        .owner
        .recover_floor(source.as_ref().map(|packet| packet.as_slice()))?
    {
        floor
    } else {
        flight.recheck()?;
        let intent = flight
            .owner
            .prepare(source.as_ref().map(|packet| packet.as_slice()))?;
        let expires = flight.owner.current_admission_expiry()?;
        let mut payload = Vec::with_capacity(8 + intent.record_bytes().len());
        payload.extend_from_slice(&expires.to_be_bytes());
        payload.extend_from_slice(intent.record_bytes());
        flight.send(RootSourceGenesisFrameKindV1::Prepared, &payload)?;

        let appended = flight.read(RootSourceGenesisFrameKindV1::Anchor)?;
        let source = flight
            .source_observation(&appended)?
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        flight.recheck()?;
        flight.owner.anchor(&source)?
    };
    flight.send(RootSourceGenesisFrameKindV1::Anchored, floor.record_bytes())?;

    let completed = flight.read(RootSourceGenesisFrameKindV1::Complete)?;
    let source = flight
        .source_observation(&completed)?
        .ok_or(SourceGenesisErrorV1::Conflict)?;
    flight.recheck()?;
    // Borrow the actual settled Root row through the original final exchange.
    // This stays local; the client independently verifies original-stream
    // custody. Neither this record nor its signature grants a later read.
    let current = flight.owner.current_anchored_floor(&source)?;
    if current.floor() != &floor {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    current.recheck()?;
    flight.send(
        RootSourceGenesisFrameKindV1::Completed,
        current.floor().digest().as_bytes(),
    )?;
    let final_ack = flight.read(RootSourceGenesisFrameKindV1::Finish)?;
    require_final_ack(&final_ack, current.floor())?;
    current.recheck()?;
    flight.recheck()
}

// Field drop order is deliberate: closing the original receive queue must
// precede releasing Root's actual writer on every return/unwind path.
struct RootHeldStreamFlight<'stream, 'startup> {
    stream: ClosingOriginalStream<'stream>,
    startup: Option<&'startup crate::production_normal_root::ProductionNormalRootStartupV1>,
    owner: RootSourceGenesisAuthorityV1,
    deadline: Instant,
    source_signer_uid: u32,
    controller_gid: u32,
    scope: AdmissionScope,
}

struct ClosingOriginalStream<'stream>(&'stream mut UnixStream);

impl Drop for ClosingOriginalStream<'_> {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

impl RootHeldStreamFlight<'_, '_> {
    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        crate::production_normal_root::recheck_optional(self.startup)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if Instant::now() >= self.deadline {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.owner.recheck()
    }

    fn set_remaining_timeout(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(SourceGenesisErrorV1::Stale)?;
        self.stream.0.set_read_timeout(Some(remaining))?;
        self.stream.0.set_write_timeout(Some(remaining))?;
        Ok(())
    }

    fn read(&self, kind: RootSourceGenesisFrameKindV1) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        let mut frame = vec![0; ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + kind.payload_bytes()];
        let mut received = 0;
        let mut stream = &*self.stream.0;
        while received < frame.len() {
            self.set_remaining_timeout()?;
            match stream.read(&mut frame[received..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original Root genesis request ended before its exact frame",
                    )
                    .into());
                }
                Ok(count) => received += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        self.recheck()?;
        decode_root_source_genesis_frame_v1(&frame, kind, self.owner.nonce()).map(Vec::from)
    }

    fn write(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        let mut written = 0;
        let mut stream = &*self.stream.0;
        while written < bytes.len() {
            self.set_remaining_timeout()?;
            match stream.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "original Root genesis reply made no progress",
                    )
                    .into());
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        self.recheck()
    }

    fn send(
        &self,
        kind: RootSourceGenesisFrameKindV1,
        payload: &[u8],
    ) -> Result<(), SourceGenesisErrorV1> {
        let frame = encode_root_source_genesis_frame_v1(kind, self.owner.nonce(), payload)?;
        self.write(&frame)
    }

    fn source_observation(
        &mut self,
        controller_packet: &[u8],
    ) -> Result<Option<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1]>, SourceGenesisErrorV1> {
        self.recheck()?;
        let probe = match self.scope {
            AdmissionScope::Current => self.owner.accept_controller_readback(controller_packet)?,
            AdmissionScope::HistoricalOnly => self
                .owner
                .accept_historical_controller_readback(controller_packet)?,
        };
        let observed = probe
            .map(|(project, challenge)| {
                let context = project
                    .map(|_| self.owner.source_genesis_intent_context_v1())
                    .transpose()?;
                request_root_source_tree_genesis_readback_v2(
                    challenge,
                    project,
                    context.as_ref(),
                    self.owner.source_readback_pin(),
                    self.source_signer_uid,
                    self.controller_gid,
                )
                .map_err(SourceGenesisErrorV1::from)
            })
            .transpose()?;
        self.recheck()?;
        Ok(observed)
    }
}

fn require_final_ack(
    payload: &[u8],
    floor: &SourceHierarchyFloorRecordV1,
) -> Result<(), SourceGenesisErrorV1> {
    if payload != floor.digest().as_bytes() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_endpoint_closes_when_hold_scope_exits() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        {
            let _held = ClosingOriginalStream(&mut server);
        }
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        assert_eq!(
            server.write(&[1]).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
