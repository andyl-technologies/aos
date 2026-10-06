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
    terminal_native: Option<io::Error>,
    timeouts: Vec<Result<(), io::Error>>,
    posts: Vec<Result<(), SourceGenesisErrorV1>>,
    clock_posts: Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    decoded: Option<Result<(), SourceGenesisErrorV1>>,
    selected_failure: Option<SelectedRootIoFailureV3>,
}

#[derive(Clone, Copy)]
enum SelectedRootIoFailureV3 { Native, Zero, Timeout(usize), Decode, Owner(usize), Clock(usize) }

enum RootPostSiteV3<'site> {
    Io(&'site mut Option<SelectedRootIoFailureV3>),
    Project(&'site mut Option<RootProjectGenesisAttemptSiteV3>),
    Successor(&'site mut Option<RootProjectSuccessorSiteV3>),
}

impl RootPostSiteV3<'_> {
    fn owner(&mut self, index: usize, failed: bool) {
        if !failed { return; }
        match self {
            Self::Io(site) => { site.get_or_insert(SelectedRootIoFailureV3::Owner(index)); }
            Self::Project(site) => { site.get_or_insert(RootProjectGenesisAttemptSiteV3::Owner(index)); }
            Self::Successor(site) => { site.get_or_insert(RootProjectSuccessorSiteV3::Owner(index)); }
        }
    }

    fn clock(&mut self, index: usize, failed: bool) {
        if !failed { return; }
        match self {
            Self::Io(site) => { site.get_or_insert(SelectedRootIoFailureV3::Clock(index)); }
            Self::Project(site) => { site.get_or_insert(RootProjectGenesisAttemptSiteV3::PostClock(index)); }
            Self::Successor(site) => { site.get_or_insert(RootProjectSuccessorSiteV3::PostClock(index)); }
        }
    }
}

#[derive(Clone, Copy)]
enum RootFrameRecipeV3 {
    FirstSuccessor(RootFirstSourceSuccessorFrameKindV2),
    ProjectSuccessor(RootFirstSourceSuccessorFrameKindV2),
    ProjectGenesis(RootSourceGenesisFrameKindV1),
    ResourceGlobalGenesis(RootSourceGenesisFrameKindV1),
}

impl RootFrameRecipeV3 {
    fn payload_bytes(self) -> usize {
        match self { Self::FirstSuccessor(phase) | Self::ProjectSuccessor(phase) => phase.payload_bytes(), Self::ProjectGenesis(phase) | Self::ResourceGlobalGenesis(phase) => phase.payload_bytes() }
    }

    fn selected(self) -> bool { !matches!(self, Self::FirstSuccessor(_)) }
}

#[derive(Clone, Copy)]
enum RootSuccessorRecipeV3 { StrictV2, MixedV3 }

#[derive(Clone, Copy)]
enum RootProjectSuccessorSiteV3 {
    Clock, Opening, Context, Source(usize), Prepared, Anchored, Io(usize),
    Owner(usize), PostClock(usize), Returned,
}

fn latch_project_successor_v3(
    recipe: RootSuccessorRecipeV3, first: &mut Option<RootProjectSuccessorSiteV3>,
    site: RootProjectSuccessorSiteV3, failed: bool,
) {
    if matches!(recipe, RootSuccessorRecipeV3::MixedV3) && failed { first.get_or_insert(site); }
}

fn successor_bookend_v3(
    recipe: RootSuccessorRecipeV3, held: &RootFirstSourceSuccessorBookendV2<'_, '_>, stream: &UnixStream,
    posts: &mut Vec<Result<(), SourceGenesisErrorV1>>,
    clocks: &mut Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    first: &mut Option<RootProjectSuccessorSiteV3>,
) -> Result<(), ()> {
    match recipe {
        RootSuccessorRecipeV3::StrictV2 => held.post(stream, posts, clocks),
        RootSuccessorRecipeV3::MixedV3 => held.post_with_site(stream, posts, clocks, Some(RootPostSiteV3::Successor(first))),
    }
}

impl RootSuccessorRecipeV3 {
    fn frame(self, phase: RootFirstSourceSuccessorFrameKindV2) -> RootFrameRecipeV3 {
        match self { Self::StrictV2 => RootFrameRecipeV3::FirstSuccessor(phase), Self::MixedV3 => RootFrameRecipeV3::ProjectSuccessor(phase) }
    }
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
        self.post_with_site(stream, posts, clock_posts, None)
    }

    fn post_with_site(
        &self, stream: &UnixStream, posts: &mut Vec<Result<(), SourceGenesisErrorV1>>,
        clock_posts: &mut Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
        mut site: Option<RootPostSiteV3<'_>>,
    ) -> Result<(), ()> {
        // Obtain residency before slow checks and the final genuine sample.
        // None is an empty slot, never a successful clock/currentness Result.
        let clock_index = clock_posts.len();
        clock_posts.push(None);
        let clock_slot = clock_posts.last_mut().ok_or(())?;
        // Attempt every independent supplier after the original action Result
        // is resident; none replaces the action's first cause.
        posts.push(crate::production_normal_root::recheck_optional(self.startup)
            .map_err(|_| SourceGenesisErrorV1::Stale));
        if let Some(site) = &mut site { site.owner(posts.len() - 1, posts.last().is_some_and(Result::is_err)); }
        posts.push(self.owner.map_or(Ok(()), RootSourceGenesisAuthorityV1::recheck));
        if let Some(site) = &mut site { site.owner(posts.len() - 1, posts.last().is_some_and(Result::is_err)); }
        posts.push((|| {
            let peer = rustix::net::sockopt::socket_peercred(stream).map_err(io::Error::from)?;
            if peer.uid.as_raw() != self.controller_uid || peer.gid.as_raw() != self.controller_gid
                || Instant::now() >= self.deadline
            { return Err(SourceGenesisErrorV1::Stale); }
            Ok(())
        })());
        if let Some(site) = &mut site { site.owner(posts.len() - 1, posts.last().is_some_and(Result::is_err)); }
        // Peer/owner failure cannot suppress this independent actual sample.
        *clock_slot = Some(observe_root_first_source_successor_clock_v2(Some(self.clock)).and_then(|current| {
            if Instant::now() >= self.deadline { return Err(SourceGenesisErrorV1::Stale); }
            Ok(current)
        }));
        if let Some(site) = &mut site { site.clock(clock_index, clock_slot.as_ref().is_some_and(Result::is_err)); }
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
        self.read_with_recipe(stream, bookend, RootFrameRecipeV3::FirstSuccessor(phase), nonce)
    }

    fn read_with_recipe(
        &mut self, stream: &UnixStream, bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>,
        recipe: RootFrameRecipeV3, nonce: [u8; 16],
    ) -> Result<(), ()> {
        if !self.incoming.is_empty() || self.decoded.is_some() { return Err(()); }
        let project_genesis = matches!(recipe, RootFrameRecipeV3::ProjectGenesis(_) | RootFrameRecipeV3::ResourceGlobalGenesis(_));
        self.incoming.resize(if project_genesis { 32 } else { 32 + recipe.payload_bytes() }, 0);
        let mut received = 0;
        let mut original = stream;
        while received < self.incoming.len() {
            self.recipe_post(stream, bookend, recipe)?;
            self.timeouts.push(stream.set_read_timeout(Some(bookend.remaining()?)));
            self.latch_selected_timeout(recipe);
            self.recipe_post(stream, bookend, recipe)?;
            if self.timeouts.last().is_some_and(Result::is_err) { return Err(()); }
            self.native = Some(original.read(&mut self.incoming[received..]));
            self.latch_selected_native(recipe);
            let post = self.recipe_post(stream, bookend, recipe);
            match &self.native {
                Some(Ok(count)) if *count > 0 => { received += *count; post?; }
                Some(Err(error)) if error.kind() == io::ErrorKind::Interrupted => { post?; }
                _ => return Err(()),
            }
            // Only a checked successful fragment or recognized nonconsuming
            // interrupt may release its count. A fatal actual Result remains.
            self.native = None;
            if !project_genesis && received == self.incoming.len()
                && self.incoming.len() == 32 + recipe.payload_bytes()
                && matches!(self.incoming.get(8..10), Some([0, 4] | [0, 5]))
            {
                let (phase, mixed) = match recipe {
                    RootFrameRecipeV3::FirstSuccessor(phase) => (phase, false),
                    RootFrameRecipeV3::ProjectSuccessor(phase) => (phase, true),
                    _ => return Err(()),
                };
                // Retain the original fixed legacy receive engine. Only an
                // explicit resource header sizes an additional bounded body;
                // complete signed owner joins follow the complete frame.
                let width = aos_sandbox::policy_compiler::root_resource_successor_payload_bytes_v4(
                    &self.incoming[..32], phase, nonce, mixed,
                );
                let payload_bytes = width.as_ref().ok().copied();
                self.decoded = Some(width.map(|_| ()));
                if self.decoded.as_ref().is_some_and(Result::is_err) {
                    if recipe.selected() { self.selected_failure.get_or_insert(SelectedRootIoFailureV3::Decode); }
                    self.recipe_post(stream, bookend, recipe)?;
                    return Err(());
                }
                let payload_bytes = payload_bytes.ok_or(())?;
                self.incoming.resize(32 + payload_bytes, 0);
                self.decoded = None;
            }
            if project_genesis && self.incoming.len() == 32 && received == 32 {
                let width = match recipe {
                    RootFrameRecipeV3::ProjectGenesis(phase) => aos_sandbox::policy_compiler::root_source_project_genesis_payload_bytes_v3(
                        &self.incoming, phase, nonce,
                    ),
                    RootFrameRecipeV3::ResourceGlobalGenesis(phase) => aos_sandbox::policy_compiler::root_source_resource_genesis_payload_bytes_v2(
                        &self.incoming, phase, nonce,
                    ),
                    _ => return Err(()),
                };
                let payload_bytes = width.as_ref().ok().copied();
                self.decoded = Some(width.map(|_| ()));
                if self.decoded.as_ref().is_some_and(Result::is_err) && self.selected_failure.is_none() {
                    self.selected_failure = Some(SelectedRootIoFailureV3::Decode);
                }
                self.recipe_post(stream, bookend, recipe)?;
                let payload_bytes = payload_bytes.ok_or(())?;
                self.incoming.resize(32 + payload_bytes, 0);
                // Only a checked positive header result can leave its slot.
                self.decoded = None;
            }
        }
        self.decoded = Some(match recipe {
            RootFrameRecipeV3::FirstSuccessor(phase) => decode_root_first_source_successor_frame_v2(&self.incoming, phase, nonce).map(|_| ()),
            RootFrameRecipeV3::ProjectSuccessor(phase) => aos_sandbox::policy_compiler::decode_root_project_source_successor_frame_v3(&self.incoming, phase, nonce).map(|_| ()),
            RootFrameRecipeV3::ProjectGenesis(phase) => aos_sandbox::policy_compiler::decode_root_source_project_genesis_frame_v3(&self.incoming, phase, nonce).map(|_| ()),
            RootFrameRecipeV3::ResourceGlobalGenesis(phase) => aos_sandbox::policy_compiler::decode_root_source_genesis_frame_v2(&self.incoming, phase, nonce).map(|_| ()),
        });
        if recipe.selected() && self.decoded.as_ref().is_some_and(Result::is_err) && self.selected_failure.is_none() {
            self.selected_failure = Some(SelectedRootIoFailureV3::Decode);
        }
        self.recipe_post(stream, bookend, recipe)?;
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
        self.write_with_recipe(stream, bookend, RootFrameRecipeV3::FirstSuccessor(RootFirstSourceSuccessorFrameKindV2::Finish))
    }

    fn write_with_recipe(&mut self, stream: &UnixStream, bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>, recipe: RootFrameRecipeV3) -> Result<(), ()> {
        let mut written = 0;
        let mut original = stream;
        while written < self.outgoing.len() {
            self.recipe_post(stream, bookend, recipe)?;
            self.timeouts.push(stream.set_write_timeout(Some(bookend.remaining()?)));
            self.latch_selected_timeout(recipe);
            self.recipe_post(stream, bookend, recipe)?;
            if self.timeouts.last().is_some_and(Result::is_err) { return Err(()); }
            self.native = Some(original.write(&self.outgoing[written..]));
            self.latch_selected_native(recipe);
            let post = self.recipe_post(stream, bookend, recipe);
            match &self.native {
                Some(Ok(count)) if *count > 0 => { written += *count; post?; }
                Some(Err(error)) if error.kind() == io::ErrorKind::Interrupted => { post?; }
                _ => return Err(()),
            }
            self.native = None;
        }
        Ok(())
    }

    fn recipe_post(&mut self, stream: &UnixStream, bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>, recipe: RootFrameRecipeV3) -> Result<(), ()> {
        if recipe.selected() {
            return bookend.post_with_site(stream, &mut self.posts, &mut self.clock_posts, Some(RootPostSiteV3::Io(&mut self.selected_failure)));
        }
        bookend.post(stream, &mut self.posts, &mut self.clock_posts)
    }

    fn latch_selected_native(&mut self, recipe: RootFrameRecipeV3) {
        if recipe.selected() && self.selected_failure.is_none()
            && self.native.as_ref().is_some_and(|result| match result {
                Ok(count) => *count == 0,
                Err(error) => error.kind() != io::ErrorKind::Interrupted,
            })
        {
            if matches!(self.native, Some(Ok(0))) {
                self.terminal_native = Some(io::Error::new(io::ErrorKind::UnexpectedEof, "original selected Root stream returned zero"));
                self.selected_failure = Some(SelectedRootIoFailureV3::Zero);
            } else {
                self.selected_failure = Some(SelectedRootIoFailureV3::Native);
            }
        }
    }

    fn latch_selected_timeout(&mut self, recipe: RootFrameRecipeV3) {
        if recipe.selected() && self.selected_failure.is_none()
            && self.timeouts.last().is_some_and(Result::is_err)
        { self.selected_failure = Some(SelectedRootIoFailureV3::Timeout(self.timeouts.len() - 1)); }
    }

    fn selected_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.selected_failure? {
            SelectedRootIoFailureV3::Native => self.native.as_ref()?.as_ref().err().map(|e| e as _),
            SelectedRootIoFailureV3::Zero => self.terminal_native.as_ref().map(|e| e as _),
            SelectedRootIoFailureV3::Timeout(index) => self.timeouts.get(index)?.as_ref().err().map(|e| e as _),
            SelectedRootIoFailureV3::Decode => self.decoded.as_ref()?.as_ref().err().map(|e| e as _),
            SelectedRootIoFailureV3::Owner(index) => self.posts.get(index)?.as_ref().err().map(|e| e as _),
            SelectedRootIoFailureV3::Clock(index) => self.clock_posts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }

    fn send_project_genesis_v3(
        &mut self, stream: &UnixStream, bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>,
        phase: RootSourceGenesisFrameKindV1, nonce: [u8; 16], payload: &[u8],
    ) -> Result<(), ()> {
        let recipe = RootFrameRecipeV3::ProjectGenesis(phase);
        self.decoded = Some(aos_sandbox::policy_compiler::encode_root_source_project_genesis_frame_v3(&mut self.outgoing, phase, nonce, payload));
        if self.decoded.as_ref().is_some_and(Result::is_err) { self.selected_failure = Some(SelectedRootIoFailureV3::Decode); }
        let post = self.recipe_post(stream, bookend, recipe);
        if self.selected_failure.is_some() { return Err(()); }
        post?;
        self.write_with_recipe(stream, bookend, recipe)
    }

    fn send_resource_global_genesis_v2(
        &mut self,
        stream: &UnixStream,
        bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>,
        phase: RootSourceGenesisFrameKindV1,
        nonce: [u8; 16],
        payload: &[u8],
    ) -> Result<(), ()> {
        let recipe = RootFrameRecipeV3::ResourceGlobalGenesis(phase);
        self.decoded = Some(aos_sandbox::policy_compiler::encode_root_source_genesis_frame_v2(
            phase, nonce, payload,
        ).map(|frame| { self.outgoing = frame; }));
        if self.decoded.as_ref().is_some_and(Result::is_err) {
            self.selected_failure.get_or_insert(SelectedRootIoFailureV3::Decode);
        }
        let post = self.recipe_post(stream, bookend, recipe);
        if self.selected_failure.is_some() {
            return Err(());
        }
        post?;
        self.write_with_recipe(stream, bookend, recipe)
    }

    fn send_successor_with_recipe_v3(
        &mut self, stream: &UnixStream, bookend: &RootFirstSourceSuccessorBookendV2<'_, '_>,
        phase: RootFirstSourceSuccessorFrameKindV2, nonce: [u8; 16], payload: &[u8], recipe: RootSuccessorRecipeV3,
    ) -> Result<(), ()> {
        match recipe {
            RootSuccessorRecipeV3::StrictV2 => self.send(stream, bookend, phase, nonce, payload),
            RootSuccessorRecipeV3::MixedV3 => {
                self.decoded = Some(aos_sandbox::policy_compiler::encode_root_project_source_successor_frame_v3(&mut self.outgoing, phase, nonce, payload));
                if self.decoded.as_ref().is_some_and(Result::is_err) { self.selected_failure.get_or_insert(SelectedRootIoFailureV3::Decode); }
                let post = self.recipe_post(stream, bookend, recipe.frame(phase));
                if self.selected_failure.is_some() { return Err(()); }
                post?;
                self.write_with_recipe(stream, bookend, recipe.frame(phase))
            }
        }
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
    source: [Option<Result<SourceSuccessorObservationPacketV4, io::Error>>; 3],
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
    recipe: RootSuccessorRecipeV3,
    selected_first: Option<RootProjectSuccessorSiteV3>,
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
            recipe: RootSuccessorRecipeV3::StrictV2,
            selected_first: None,
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
        if let Err(error) = returned {
            self.cause.get_or_insert(error);
            latch_project_successor_v3(self.recipe, &mut self.selected_first, RootProjectSuccessorSiteV3::Returned, true);
        }
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

/// Retains the selected mixed successor on the same installed Root endpoint.
#[must_use = "retain the actual accepted mixed Root attempt until terminal settlement"]
pub struct RootProjectSuccessorAttemptV3<'stream, 'startup> {
    common: RootFirstSourceSuccessorAttemptV2<'stream, 'startup>,
}

impl<'stream, 'startup> RootProjectSuccessorAttemptV3<'stream, 'startup> {
    /// Parks the actual accepted stream before any selected-purpose admission.
    pub fn new(
        stream: &'stream mut UnixStream,
        startup: Option<&'startup crate::production_normal_root::ProductionNormalRootStartupV1>,
        request: [u8; 32], route: RootFirstSourceSuccessorRouteV2,
        controller_uid: u32, controller_gid: u32, source_uid: u32, source_signer_uid: u32,
    ) -> Self {
        let mut common = RootFirstSourceSuccessorAttemptV2::new(stream, startup, request, route,
            controller_uid, controller_gid, source_uid, source_signer_uid);
        common.recipe = RootSuccessorRecipeV3::MixedV3;
        Self { common }
    }

    /// Runs the same original producer without retrying ambiguous mutation.
    ///
    /// # Errors
    /// Retains the accepted stream, actual Root writer and all failed Results.
    pub fn serve_once(&mut self) -> Result<(), ()> { self.common.serve_once() }
    /// Borrows actual retained failure without creating new observations.
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let original = &self.common;
        match original.selected_first? {
            RootProjectSuccessorSiteV3::Clock => original.clock.as_ref()?.as_ref().err().map(|error| error as _),
            RootProjectSuccessorSiteV3::Opening => original.opening.error(),
            RootProjectSuccessorSiteV3::Context => original.context.as_ref()?.as_ref().err().map(|error| error as _),
            RootProjectSuccessorSiteV3::Source(index) => original.source.get(index)?.as_ref()?.as_ref().err().map(|error| error as _),
            RootProjectSuccessorSiteV3::Prepared => original.prepare.error(),
            RootProjectSuccessorSiteV3::Anchored => original.anchor.error(),
            RootProjectSuccessorSiteV3::Io(index) => match index {
                0 => original.hello_io.selected_error(), 1 => original.prepare_io.selected_error(),
                2 => original.anchor_io.selected_error(), 3 => original.complete_io.selected_error(),
                4 => original.finish_io.selected_error(), _ => None,
            },
            RootProjectSuccessorSiteV3::Owner(index) => original.posts.get(index)?.as_ref().err().map(|error| error as _),
            RootProjectSuccessorSiteV3::PostClock(index) => original.clock_posts.get(index)?.as_ref()?.as_ref().err().map(|error| error as _),
            RootProjectSuccessorSiteV3::Returned => original.cause.as_ref().map(|error| error as _),
        }
    }
    /// Borrows independent original-clock debt without clearing transport poison.
    pub fn clock_post_failures(&self) -> impl Iterator<Item = &SourceGenesisErrorV1> { self.common.clock_post_failures() }
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

enum CurrentSuccessorOwnerV3<'root> {
    Strict(aos_sandbox::policy_compiler::CurrentRootFirstSourceSuccessorFloorV2<'root>),
    Mixed(aos_sandbox::policy_compiler::CurrentRootProjectSuccessorFloorV3<'root>),
}

impl CurrentSuccessorOwnerV3<'_> {
    fn completion(&self) -> &[u8; 96] {
        match self { Self::Strict(owner) => owner.completion(), Self::Mixed(owner) => owner.completion() }
    }

    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        match self { Self::Strict(owner) => owner.recheck(), Self::Mixed(owner) => owner.recheck() }
    }
}

enum SourceSuccessorObservationPacketV4 {
    Legacy([u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2]),
    Resource(Vec<u8>),
}

impl SourceSuccessorObservationPacketV4 {
    fn bytes(&self) -> &[u8] {
        match self { Self::Legacy(bytes) => bytes, Self::Resource(bytes) => bytes }
    }
}

fn request_successor_source_with_recipe_v3(
    recipe: RootSuccessorRecipeV3, nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    signer: &aos_sandbox::policy_compiler::PinnedSourceHoldReadbackSignerV1,
    signer_uid: u32, socket_gid: u32,
) -> io::Result<SourceSuccessorObservationPacketV4> {
    if context.as_bytes().len() == 1424 {
        return crate::source_signer_exchange::request_root_source_resource_successor_readback_v4(
            nonce, context, signer, signer_uid, socket_gid,
            matches!(recipe, RootSuccessorRecipeV3::MixedV3),
        ).map(SourceSuccessorObservationPacketV4::Resource);
    }
    match recipe {
        RootSuccessorRecipeV3::StrictV2 => request_root_source_first_successor_readback_v2(nonce, context, signer, signer_uid, socket_gid).map(SourceSuccessorObservationPacketV4::Legacy),
        RootSuccessorRecipeV3::MixedV3 => crate::source_signer_exchange::request_root_source_project_continuation_readback_v3(nonce, context, signer, signer_uid, socket_gid).map(SourceSuccessorObservationPacketV4::Legacy),
    }
}

fn serve_first_successor(attempt: &mut RootFirstSourceSuccessorAttemptV2<'_, '_>) -> Result<(), SourceGenesisErrorV1> {
    use RootFirstSourceSuccessorFrameKindV2 as Phase;
    let RootFirstSourceSuccessorAttemptV2 {
        stream, startup, request, route, controller_uid, controller_gid, source_uid, source_signer_uid,
        deadline, clock, opening, owner, context, prepared, floor, prepare, anchor, source,
        hello_io, prepare_io, anchor_io, complete_io, finish_io, posts, clock_posts, cleanup, armed, recipe, selected_first, ..
    } = attempt;

    *clock = Some(observe_root_first_source_successor_clock_v2(None));
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Clock, matches!(clock, Some(Err(_))));
    let original_clock = *clock.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    let query_magic = match recipe {
        RootSuccessorRecipeV3::StrictV2 => ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2,
        RootSuccessorRecipeV3::MixedV3 => aos_sandbox::policy_compiler::ROOT_PROJECT_SOURCE_SUCCESSOR_QUERY_MAGIC_V3,
    };
    if request[..8] != *query_magic || request[8..24] == [0; 16]
        || request[24..] != [0; 8] || startup.is_none() || *controller_uid == 0
        || *controller_gid == 0 || *source_uid == 0 || *source_signer_uid == 0
    { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    let before = RootFirstSourceSuccessorBookendV2 {
        owner: None, startup: *startup, controller_uid: *controller_uid, controller_gid: *controller_gid,
        deadline: *deadline, clock: original_clock,
    };
    successor_bookend_v3(*recipe, &before, stream, posts, clock_posts, selected_first).map_err(|_| SourceGenesisErrorV1::Stale)?;
    posts.push(aos_sandbox::policy_compiler::require_no_fixed_closed_policy_binding_hold_v1()
        .map_err(|_| SourceGenesisErrorV1::AdmissionClosed));
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Owner(posts.len() - 1), posts.last().is_some_and(Result::is_err));
    successor_bookend_v3(*recipe, &before, stream, posts, clock_posts, selected_first).map_err(|_| SourceGenesisErrorV1::Stale)?;
    let opened = match recipe {
        RootSuccessorRecipeV3::StrictV2 => opening.open_into(owner, *controller_uid, *source_uid),
        RootSuccessorRecipeV3::MixedV3 => opening.open_project_successor_into_v3(owner, *controller_uid, *source_uid),
    };
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Opening, opened.is_err());
    // Startup/peer/clock remain independent even if protected opening failed.
    let opening_post = successor_bookend_v3(*recipe, &before, stream, posts, clock_posts, selected_first);
    if opened.is_err() || opening_post.is_err() { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    let owner = owner.as_mut().ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
    let nonce = owner.nonce();
    hello_io.outgoing.resize(56, 0);
    let (hello_magic, version) = match recipe {
        RootSuccessorRecipeV3::StrictV2 => (ROOT_FIRST_SOURCE_SUCCESSOR_HELLO_MAGIC_V2, 2_u16),
        RootSuccessorRecipeV3::MixedV3 => (aos_sandbox::policy_compiler::ROOT_PROJECT_SOURCE_SUCCESSOR_HELLO_MAGIC_V3, 3_u16),
    };
    hello_io.outgoing[..8].copy_from_slice(hello_magic);
    hello_io.outgoing[8..10].copy_from_slice(&version.to_be_bytes());
    hello_io.outgoing[16..32].copy_from_slice(&request[8..24]);
    hello_io.outgoing[32..48].copy_from_slice(&nonce);
    hello_io.outgoing[48..52].copy_from_slice(&source_uid.to_be_bytes());
    hello_io.outgoing[52..56].copy_from_slice(&controller_uid.to_be_bytes());
    {
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(&*owner), ..before };
        let sent = hello_io.write_with_recipe(stream, &held, recipe.frame(Phase::Prepare));
        latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(0), sent.is_err());
        sent.map_err(|_| SourceGenesisErrorV1::Stale)?;
        let received = prepare_io.read_with_recipe(stream, &held, recipe.frame(Phase::Prepare), nonce);
        latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(1), received.is_err());
        received.map_err(|_| SourceGenesisErrorV1::Stale)?;
    }
    *context = Some(match (*recipe, *route) {
        (RootSuccessorRecipeV3::StrictV2, RootFirstSourceSuccessorRouteV2::Current) => owner.first_source_successor_context_v2(&prepare_io.incoming[32..]),
        (RootSuccessorRecipeV3::StrictV2, RootFirstSourceSuccessorRouteV2::Historical) => owner.historical_first_source_successor_context_v2(&prepare_io.incoming[32..]),
        (RootSuccessorRecipeV3::MixedV3, RootFirstSourceSuccessorRouteV2::Current) => owner.project_successor_context_v3(&prepare_io.incoming[32..]),
        (RootSuccessorRecipeV3::MixedV3, RootFirstSourceSuccessorRouteV2::Historical) => owner.historical_project_successor_context_v3(&prepare_io.incoming[32..]),
    });
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Context, matches!(context, Some(Err(_))));
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(&*owner), ..before };
    let context_post = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    let original = context.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Conflict)?;
    context_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    source[0] = Some(request_successor_source_with_recipe_v3(*recipe, nonce, original, owner.source_readback_pin(), *source_signer_uid, *controller_gid));
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Source(0), matches!(source[0], Some(Err(_))));
    let source_post = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    let source_before = source[0].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?.bytes();
    source_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    if matches!(route, RootFirstSourceSuccessorRouteV2::Historical) {
        let resource = original.as_bytes().len() == 1424;
        posts.push(match (*recipe, resource) {
            (RootSuccessorRecipeV3::StrictV2, false) => aos_sandbox::policy_compiler::verify_source_first_successor_readback_v2(source_before, owner.source_readback_pin(), nonce, original).map(|observed| observed.phase()),
            (RootSuccessorRecipeV3::MixedV3, false) => aos_sandbox::policy_compiler::verify_source_project_continuation_readback_v3(source_before, owner.source_readback_pin(), nonce, original).map(|observed| observed.phase()),
            (RootSuccessorRecipeV3::StrictV2, true) => aos_sandbox::policy_compiler::verify_source_resource_first_successor_readback_v4(source_before, owner.source_readback_pin(), nonce, original).map(|observed| observed.phase()),
            (RootSuccessorRecipeV3::MixedV3, true) => aos_sandbox::policy_compiler::verify_source_resource_project_continuation_readback_v5(source_before, owner.source_readback_pin(), nonce, original).map(|observed| observed.phase()),
        }.and_then(|phase| if phase == aos_sandbox::policy_compiler::SourceFirstSuccessorReadbackPhaseV2::Before { Err(SourceGenesisErrorV1::AdmissionClosed) } else { Ok(()) }));
        latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Owner(posts.len() - 1), posts.last().is_some_and(Result::is_err));
        successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first).map_err(|_| SourceGenesisErrorV1::Stale)?;
    }
    *prepared = Some(match recipe {
        RootSuccessorRecipeV3::StrictV2 => owner.prepare_first_successor_v2(original, &prepare_io.incoming[32..], source_before, &before.clock, &before.deadline, prepare),
        RootSuccessorRecipeV3::MixedV3 => owner.prepare_project_successor_v3(original, &prepare_io.incoming[32..], source_before, &before.clock, &before.deadline, prepare),
    });
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Prepared, matches!(prepared, Some(Err(_))));
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(&*owner), ..before };
    let prepared_post = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    let original = prepared.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Conflict)?;
    prepared_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    let sent = prepare_io.send_successor_with_recipe_v3(stream, &held, Phase::Prepared, nonce, original.as_bytes(), *recipe);
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(1), sent.is_err());
    sent.map_err(|_| SourceGenesisErrorV1::Stale)?;
    let received = anchor_io.read_with_recipe(stream, &held, recipe.frame(Phase::Anchor), nonce);
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(2), received.is_err());
    received.map_err(|_| SourceGenesisErrorV1::Stale)?;
    source[1] = Some(request_successor_source_with_recipe_v3(*recipe, nonce, original, owner.source_readback_pin(), *source_signer_uid, *controller_gid));
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Source(1), matches!(source[1], Some(Err(_))));
    let source_post = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    let source_after = source[1].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?.bytes();
    source_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    *floor = Some(match recipe {
        RootSuccessorRecipeV3::StrictV2 => owner.anchor_first_successor_v2(original, &anchor_io.incoming[32..], source_after, &before.clock, &before.deadline, anchor),
        RootSuccessorRecipeV3::MixedV3 => owner.anchor_project_successor_v3(original, &anchor_io.incoming[32..], source_after, &before.clock, &before.deadline, anchor),
    });
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Anchored, matches!(floor, Some(Err(_))));
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(&*owner), ..before };
    let floor_post = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    let floor = floor.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Conflict)?;
    floor_post.map_err(|_| SourceGenesisErrorV1::Stale)?;
    let sent = anchor_io.send_successor_with_recipe_v3(stream, &held, Phase::Anchored, nonce, floor.as_bytes(), *recipe);
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(2), sent.is_err());
    sent.map_err(|_| SourceGenesisErrorV1::Stale)?;
    let received = complete_io.read_with_recipe(stream, &held, recipe.frame(Phase::Complete), nonce);
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(3), received.is_err());
    received.map_err(|_| SourceGenesisErrorV1::Stale)?;
    source[2] = Some(request_successor_source_with_recipe_v3(*recipe, nonce, original, owner.source_readback_pin(), *source_signer_uid, *controller_gid));
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Source(2), matches!(source[2], Some(Err(_))));
    let source_post = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    let acknowledged = source[2].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?.bytes();
    source_post.map_err(|_| SourceGenesisErrorV1::Stale)?;

    // This short actual current-floor Result cannot be stored inside its own
    // writer. Keep it named locally through Finish, including every failure.
    let current_result = match recipe {
        RootSuccessorRecipeV3::StrictV2 => owner.current_anchored_first_successor_floor_v2(original, &complete_io.incoming[32..], acknowledged, floor).map(CurrentSuccessorOwnerV3::Strict),
        RootSuccessorRecipeV3::MixedV3 => owner.current_project_successor_floor_v3(original, &complete_io.incoming[32..], acknowledged, floor).map(CurrentSuccessorOwnerV3::Mixed),
    };
    let current_post = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    let Ok(current) = &current_result else { terminate_first_successor_root(); };
    if current_post.is_err() { terminate_first_successor_root(); }
    let completion = current.completion();
    let sent = complete_io.send_successor_with_recipe_v3(stream, &held, Phase::Completed, nonce, completion, *recipe);
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(3), sent.is_err());
    let current_after_send = current.recheck();
    posts.push(current_after_send);
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Owner(posts.len() - 1), posts.last().is_some_and(Result::is_err));
    let independent = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    if sent.is_err() || independent.is_err() { terminate_first_successor_root(); }
    let received = finish_io.read_with_recipe(stream, &held, recipe.frame(Phase::Finish), nonce);
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(4), received.is_err());
    posts.push(current.recheck());
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Owner(posts.len() - 1), posts.last().is_some_and(Result::is_err));
    let independent = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
    if received.is_err() || independent.is_err() || &finish_io.incoming[32..] != completion {
        terminate_first_successor_root();
    }
    let sent = finish_io.send_successor_with_recipe_v3(stream, &held, Phase::Finish, nonce, completion, *recipe);
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Io(4), sent.is_err());
    posts.push(current.recheck());
    latch_project_successor_v3(*recipe, selected_first, RootProjectSuccessorSiteV3::Owner(posts.len() - 1), posts.last().is_some_and(Result::is_err));
    let independent = successor_bookend_v3(*recipe, &held, stream, posts, clock_posts, selected_first);
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

/// Retains the actual Root03 initial-project producer through final consumption.
///
/// Construction parks the same accepted stream/startup before any selected
/// opening or signer RPC. No scalar project/instance is an owner constructor.
#[must_use = "retain the failed whole selected Root producer until termination"]
pub struct RootProjectGenesisAttemptV3<'stream, 'startup> {
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
    contexts: [Option<Result<(aos_sandbox::policy_compiler::SourceProjectGenesisChallengeV3, aos_sandbox::policy_compiler::SourceTreeGenesisIntentContextV1), SourceGenesisErrorV1>>; 3],
    source: [Option<Result<aos_sandbox::policy_compiler::SourceProjectGenesisReadbackPacketV4, io::Error>>; 3],
    prepared: Option<Result<aos_sandbox::policy_compiler::RootSourceGenesisIntentRecordV1, ()>>,
    floor_selection: Option<Result<bool, SourceGenesisErrorV1>>,
    anchored: Option<Result<SourceHierarchyFloorRecordV1, ()>>,
    prepare: aos_sandbox::policy_compiler::RootProjectGenesisMutationResultsV3,
    anchor: aos_sandbox::policy_compiler::RootProjectGenesisMutationResultsV3,
    io: [RootFirstSourceSuccessorIoV2; 5],
    posts: Vec<Result<(), SourceGenesisErrorV1>>,
    clock_posts: Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    returned: Option<Result<(), SourceGenesisErrorV1>>,
    first_failure: Option<RootProjectGenesisAttemptSiteV3>,
    cleanup: Option<Result<(), io::Error>>,
    armed: bool,
}

#[derive(Clone, Copy)]
enum RootProjectGenesisAttemptSiteV3 { Clock, Opening, Context(usize), Source(usize), FloorSelection, Prepare, Anchor, Io(usize), Owner(usize), PostClock(usize), Returned }

impl<'stream, 'startup> RootProjectGenesisAttemptV3<'stream, 'startup> {
    /// Parks only actual originals; it performs no protected open or issuance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream: &'stream mut UnixStream,
        startup: Option<&'startup crate::production_normal_root::ProductionNormalRootStartupV1>,
        request: [u8; 32], route: RootFirstSourceSuccessorRouteV2,
        controller_uid: u32, controller_gid: u32, source_uid: u32, source_signer_uid: u32,
    ) -> Self {
        Self {
            stream, startup, request, route, controller_uid, controller_gid, source_uid, source_signer_uid,
            deadline: Instant::now() + ROOT_HOLD_LIMIT, clock: None, opening: RootFirstSourceSuccessorOpeningV2::new(), owner: None,
            contexts: std::array::from_fn(|_| None), source: std::array::from_fn(|_| None), prepared: None, floor_selection: None, anchored: None,
            prepare: aos_sandbox::policy_compiler::RootProjectGenesisMutationResultsV3::new(),
            anchor: aos_sandbox::policy_compiler::RootProjectGenesisMutationResultsV3::new(),
            io: std::array::from_fn(|_| RootFirstSourceSuccessorIoV2::default()), posts: Vec::new(), clock_posts: Vec::new(),
            returned: None, first_failure: None, cleanup: None, armed: true,
        }
    }

    /// Runs the actual selected original producer once without redispatch.
    ///
    /// # Errors
    /// Returns a marker with every actual Result and genuine owner resident.
    pub fn serve_once(&mut self) -> Result<(), ()> {
        if self.returned.is_some() { return Err(()); }
        self.returned = Some(serve_project_genesis_v3(self));
        if self.returned.as_ref().is_some_and(Result::is_err) {
            if self.first_failure.is_none() { self.first_failure = Some(RootProjectGenesisAttemptSiteV3::Returned); }
            self.cleanup = Some(self.stream.shutdown(Shutdown::Both));
            return Err(());
        }
        Ok(())
    }

    /// Borrows the same chronologically selected cause without new observations.
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            RootProjectGenesisAttemptSiteV3::Clock => self.clock.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::Opening => self.opening.error(),
            RootProjectGenesisAttemptSiteV3::Context(index) => self.contexts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::Source(index) => self.source.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::FloorSelection => self.floor_selection.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::Prepare => self.prepare.error(),
            RootProjectGenesisAttemptSiteV3::Anchor => self.anchor.error(),
            RootProjectGenesisAttemptSiteV3::Io(index) => self.io.get(index)?.selected_error(),
            RootProjectGenesisAttemptSiteV3::Owner(index) => self.posts.get(index)?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::PostClock(index) => self.clock_posts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::Returned => self.returned.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }
}

impl Drop for RootProjectGenesisAttemptV3<'_, '_> {
    fn drop(&mut self) { if self.armed { std::process::abort(); } }
}

fn project_genesis_bookend_v3(
    held: &RootFirstSourceSuccessorBookendV2<'_, '_>, stream: &UnixStream,
    posts: &mut Vec<Result<(), SourceGenesisErrorV1>>,
    clocks: &mut Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    first: &mut Option<RootProjectGenesisAttemptSiteV3>,
) -> Result<(), SourceGenesisErrorV1> {
    let returned = held.post_with_site(stream, posts, clocks, Some(RootPostSiteV3::Project(first)));
    returned.map_err(|_| SourceGenesisErrorV1::Stale)
}

fn serve_project_genesis_v3(attempt: &mut RootProjectGenesisAttemptV3<'_, '_>) -> Result<(), SourceGenesisErrorV1> {
    use RootSourceGenesisFrameKindV1 as Phase;
    let RootProjectGenesisAttemptV3 {
        stream, startup, request, route, controller_uid, controller_gid, source_uid, source_signer_uid, deadline,
        clock, opening, owner, contexts, source, prepared, floor_selection, anchored, prepare, anchor, io, posts, clock_posts, first_failure, cleanup, armed, ..
    } = attempt;
    *clock = Some(observe_root_first_source_successor_clock_v2(None));
    if clock.as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Clock); }
    let actual_clock = *clock.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    if request[..8] != *aos_sandbox::policy_compiler::ROOT_SOURCE_PROJECT_GENESIS_QUERY_MAGIC_V3
        || request[8..24] == [0; 16] || request[24..] != [0; 8]
        || matches!(route, RootFirstSourceSuccessorRouteV2::Current) && startup.is_none()
        || *controller_uid == 0 || *controller_gid == 0 || *source_uid == 0 || *source_signer_uid == 0
    { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    let before = RootFirstSourceSuccessorBookendV2 {
        owner: None, startup: *startup, controller_uid: *controller_uid, controller_gid: *controller_gid,
        deadline: *deadline, clock: actual_clock,
    };
    project_genesis_bookend_v3(&before, stream, posts, clock_posts, first_failure)?;
    let boundary = posts.len();
    posts.push(aos_sandbox::policy_compiler::require_no_fixed_closed_policy_binding_hold_v1()
        .map_err(|_| SourceGenesisErrorV1::AdmissionClosed));
    if posts[boundary].is_err() && first_failure.is_none() {
        *first_failure = Some(RootProjectGenesisAttemptSiteV3::Owner(boundary));
    }
    let independent = project_genesis_bookend_v3(&before, stream, posts, clock_posts, first_failure);
    if posts[boundary].is_err() { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    independent?;
    let open_result = opening.open_project_genesis_into_v3(owner, *controller_uid, *source_uid);
    if open_result.is_err() { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Opening); }
    let independent = project_genesis_bookend_v3(&before, stream, posts, clock_posts, first_failure);
    if open_result.is_err() { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    independent?;
    let owner = owner.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
    let nonce = owner.nonce();
    io[0].outgoing.resize(56, 0);
    io[0].outgoing[..8].copy_from_slice(aos_sandbox::policy_compiler::ROOT_SOURCE_PROJECT_GENESIS_HELLO_MAGIC_V3);
    io[0].outgoing[8..10].copy_from_slice(&3_u16.to_be_bytes());
    io[0].outgoing[16..32].copy_from_slice(&request[8..24]);
    io[0].outgoing[32..48].copy_from_slice(&nonce);
    io[0].outgoing[48..52].copy_from_slice(&source_uid.to_be_bytes());
    io[0].outgoing[52..56].copy_from_slice(&controller_uid.to_be_bytes());
    {
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        if io[0].write_with_recipe(stream, &held, RootFrameRecipeV3::ProjectGenesis(Phase::Prepare)).is_err() {
            *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(0)); return Err(SourceGenesisErrorV1::Stale);
        }
        if io[1].read_with_recipe(stream, &held, RootFrameRecipeV3::ProjectGenesis(Phase::Prepare), nonce).is_err() {
            *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(1)); return Err(SourceGenesisErrorV1::Stale);
        }
    }
    contexts[0] = Some(owner.accept_controller_project_genesis_v3(&io[1].incoming[32..]));
    if contexts[0].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Context(0)); }
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    let (challenge, context) = contexts[0].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    if matches!(route, RootFirstSourceSuccessorRouteV2::Historical) && challenge.intent().is_none() { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    source[0] = Some(crate::source_signer_exchange::request_root_source_project_genesis_readback_v4(*challenge, context, owner.source_readback_pin(), *source_signer_uid, *controller_gid));
    if source[0].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Source(0)); }
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    let packet = source[0].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    *floor_selection = Some(owner.project_genesis_floor_present_v3());
    if floor_selection.as_ref().is_some_and(Result::is_err) && first_failure.is_none() {
        *first_failure = Some(RootProjectGenesisAttemptSiteV3::FloorSelection);
    }
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    let has_floor = *floor_selection.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    // Only an actual settled floor skips Prepared. A historical challenge may
    // instead name an unanchored intent and cannot choose that shortcut.
    let floor = if has_floor {
        *anchored = Some(owner.anchor_project_genesis_v3(packet.as_ref(), &actual_clock, *deadline, anchor));
        if anchored.as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Anchor); }
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
        let floor = anchored.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        floor
    } else {
        *prepared = Some(owner.prepare_project_genesis_v3(packet.as_ref(), &actual_clock, *deadline, prepare));
        if prepared.as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Prepare); }
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
        let intent = prepared.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        let mut payload = [0; 976];
        let payload_bytes = 8 + intent.record_bytes().len();
        payload[..8].copy_from_slice(&owner.current_admission_expiry()?.to_be_bytes());
        payload[8..payload_bytes].copy_from_slice(intent.record_bytes());
        if io[1].send_project_genesis_v3(stream, &held, Phase::Prepared, nonce, &payload[..payload_bytes]).is_err() {
            *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(1)); return Err(SourceGenesisErrorV1::Stale);
        }
        if io[2].read_with_recipe(stream, &held, RootFrameRecipeV3::ProjectGenesis(Phase::Anchor), nonce).is_err() {
            *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(2)); return Err(SourceGenesisErrorV1::Stale);
        }
        contexts[1] = Some(owner.accept_controller_project_genesis_v3(&io[2].incoming[32..]));
        if contexts[1].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Context(1)); }
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
        let (challenge, context) = contexts[1].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        source[1] = Some(crate::source_signer_exchange::request_root_source_project_genesis_readback_v4(*challenge, context, owner.source_readback_pin(), *source_signer_uid, *controller_gid));
        if source[1].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Source(1)); }
        let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
        let packet = source[1].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        *anchored = Some(owner.anchor_project_genesis_v3(packet.as_ref(), &actual_clock, *deadline, anchor));
        if anchored.as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Anchor); }
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
        let floor = anchored.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        floor
    };
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
    // Either branch owns this exact floor in the resident Anchor Result.
    let outgoing_index = if io[2].incoming.is_empty() { 1 } else { 2 };
    let outgoing = &mut io[outgoing_index];
    if outgoing.send_project_genesis_v3(stream, &held, Phase::Anchored, nonce, floor.record_bytes()).is_err() {
        *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(outgoing_index)); return Err(SourceGenesisErrorV1::Stale);
    }
    if io[3].read_with_recipe(stream, &held, RootFrameRecipeV3::ProjectGenesis(Phase::Complete), nonce).is_err() {
        *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(3)); return Err(SourceGenesisErrorV1::Stale);
    }
    contexts[2] = Some(owner.accept_controller_project_genesis_v3(&io[3].incoming[32..]));
    if contexts[2].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Context(2)); }
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    let (challenge, context) = contexts[2].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    source[2] = Some(crate::source_signer_exchange::request_root_source_project_genesis_readback_v4(*challenge, context, owner.source_readback_pin(), *source_signer_uid, *controller_gid));
    if source[2].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Source(2)); }
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    let packet = source[2].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    // The genuine current-floor Result borrows this owner and stays a named
    // local through terminal failure and Finish, avoiding any self-borrow.
    let current_result = owner.current_project_genesis_floor_v3(packet.as_ref());
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    let Ok(current) = &current_result else { terminate_first_successor_root(); };
    if independent.is_err() || current.floor() != floor { terminate_first_successor_root(); }
    let sent = io[3].send_project_genesis_v3(stream, &held, Phase::Completed, nonce, current.floor().digest().as_bytes());
    if sent.is_err() { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Io(3)); }
    posts.push(current.recheck());
    if posts.last().is_some_and(Result::is_err) { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Owner(posts.len() - 1)); }
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    if sent.is_err() || posts.iter().any(Result::is_err) || independent.is_err() { terminate_first_successor_root(); }
    let received = io[4].read_with_recipe(stream, &held, RootFrameRecipeV3::ProjectGenesis(Phase::Finish), nonce);
    if received.is_err() { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Io(4)); }
    posts.push(current.recheck());
    if posts.last().is_some_and(Result::is_err) { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Owner(posts.len() - 1)); }
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    if received.is_err() || posts.iter().any(Result::is_err) || independent.is_err()
        || &io[4].incoming[32..] != current.floor().digest().as_bytes() { terminate_first_successor_root(); }
    let sent = io[4].send_project_genesis_v3(stream, &held, Phase::Finish, nonce, current.floor().digest().as_bytes());
    if sent.is_err() { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Io(4)); }
    posts.push(current.recheck());
    if posts.last().is_some_and(Result::is_err) { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Owner(posts.len() - 1)); }
    let independent = project_genesis_bookend_v3(&held, stream, posts, clock_posts, first_failure);
    if sent.is_err() || posts.iter().any(Result::is_err) || independent.is_err() { terminate_first_successor_root(); }
    *cleanup = Some(stream.shutdown(Shutdown::Both));
    if !matches!(cleanup, Some(Ok(()))) { terminate_first_successor_root(); }
    *armed = false;
    Ok(())
}

#[must_use = "retain the failed whole resource-Global Root producer until termination"]
/// Retains the actual strict resource-Global stream, writer and native outcomes.
pub struct RootGlobalGenesisAttemptV2<'stream, 'startup> {
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
    contexts: [Option<Result<(Option<aos_sandbox_core::ProjectId>, aos_sandbox::policy_compiler::SourceTreeGenesisChallengeV1, Option<aos_sandbox::policy_compiler::SourceTreeGenesisIntentContextV1>), SourceGenesisErrorV1>>; 3],
    source: [Option<Result<aos_sandbox::policy_compiler::SourceTreeGenesisReadbackPacketV2, io::Error>>; 3],
    prepared: Option<Result<aos_sandbox::policy_compiler::RootSourceGenesisIntentRecordV1, ()>>,
    floor_selection: Option<Result<bool, SourceGenesisErrorV1>>,
    anchored: Option<Result<SourceHierarchyFloorRecordV1, ()>>,
    prepare: aos_sandbox::policy_compiler::RootProjectGenesisMutationResultsV3,
    anchor: aos_sandbox::policy_compiler::RootProjectGenesisMutationResultsV3,
    io: [RootFirstSourceSuccessorIoV2; 5],
    posts: Vec<Result<(), SourceGenesisErrorV1>>,
    clock_posts: Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    returned: Option<Result<(), SourceGenesisErrorV1>>,
    first_failure: Option<RootProjectGenesisAttemptSiteV3>,
    cleanup: Option<Result<(), io::Error>>,
    armed: bool,
}

impl<'stream, 'startup> RootGlobalGenesisAttemptV2<'stream, 'startup> {
    /// Parks only actual originals; it performs no protected open or issuance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream: &'stream mut UnixStream,
        startup: Option<&'startup crate::production_normal_root::ProductionNormalRootStartupV1>,
        request: [u8; 32],
        route: RootFirstSourceSuccessorRouteV2,
        controller_uid: u32,
        controller_gid: u32,
        source_uid: u32,
        source_signer_uid: u32,
    ) -> Self {
        Self {
            stream, startup, request, route, controller_uid, controller_gid, source_uid, source_signer_uid,
            deadline: Instant::now() + ROOT_HOLD_LIMIT,
            clock: None,
            opening: RootFirstSourceSuccessorOpeningV2::new(),
            owner: None,
            contexts: std::array::from_fn(|_| None),
            source: std::array::from_fn(|_| None),
            prepared: None,
            floor_selection: None,
            anchored: None,
            prepare: aos_sandbox::policy_compiler::RootProjectGenesisMutationResultsV3::new(),
            anchor: aos_sandbox::policy_compiler::RootProjectGenesisMutationResultsV3::new(),
            io: std::array::from_fn(|_| RootFirstSourceSuccessorIoV2::default()),
            posts: Vec::new(),
            clock_posts: Vec::new(),
            returned: None,
            first_failure: None,
            cleanup: None,
            armed: true,
        }
    }

    /// Runs the actual selected original producer once without redispatch.
    ///
    /// # Errors
    /// Returns a marker with every actual Result and genuine owner resident.
    pub fn serve_once(&mut self) -> Result<(), ()> {
        if self.returned.is_some() {
            return Err(());
        }
        self.returned = Some(serve_resource_global_genesis_v2(self));
        if self.returned.as_ref().is_some_and(Result::is_err) {
            if self.first_failure.is_none() { self.first_failure = Some(RootProjectGenesisAttemptSiteV3::Returned); }
            self.cleanup = Some(self.stream.shutdown(Shutdown::Both));
            self.post_available_originals();
            return Err(());
        }
        Ok(())
    }

    // A failed first sample cannot lend a positive cut. It still must not
    // suppress available startup, writer, peer or final clock observations.
    fn post_available_originals(&mut self) {
        let original_clock = self.clock.as_ref().and_then(|result| result.as_ref().ok()).copied();
        if let Some(clock) = original_clock {
            let held = RootFirstSourceSuccessorBookendV2 {
                owner: self.owner.as_ref(),
                startup: self.startup,
                controller_uid: self.controller_uid,
                controller_gid: self.controller_gid,
                deadline: self.deadline, clock,
            };
            let _post = resource_global_genesis_bookend_v2(
                &held, self.stream, &mut self.posts, &mut self.clock_posts, &mut self.first_failure,
            );
            return;
        }

        let clock_index = self.clock_posts.len();
        self.clock_posts.push(None);
        self.posts.push(crate::production_normal_root::recheck_optional(self.startup)
            .map_err(|_| SourceGenesisErrorV1::Stale));
        self.posts.push(self.owner.as_ref().map_or(Ok(()), RootSourceGenesisAuthorityV1::recheck));
        self.posts.push((|| {
            let peer = rustix::net::sockopt::socket_peercred(&*self.stream).map_err(io::Error::from)?;
            if peer.uid.as_raw() != self.controller_uid || peer.gid.as_raw() != self.controller_gid
                || Instant::now() >= self.deadline
            { return Err(SourceGenesisErrorV1::Stale); }
            Ok(())
        })());
        // This sample is diagnostic only. The original failure remains parked
        // and no subsequent action is entered from this negative branch.
        self.clock_posts[clock_index] = Some(observe_root_first_source_successor_clock_v2(None));
    }

    /// Borrows the same chronologically selected cause without new observations.
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            RootProjectGenesisAttemptSiteV3::Clock => self.clock.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::Opening => self.opening.error(),
            RootProjectGenesisAttemptSiteV3::Context(index) => self.contexts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::Source(index) => self.source.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::FloorSelection => self.floor_selection.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::Prepare => self.prepare.error(),
            RootProjectGenesisAttemptSiteV3::Anchor => self.anchor.error(),
            RootProjectGenesisAttemptSiteV3::Io(index) => self.io.get(index)?.selected_error(),
            RootProjectGenesisAttemptSiteV3::Owner(index) => self.posts.get(index)?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::PostClock(index) => self.clock_posts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisAttemptSiteV3::Returned => self.returned.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }
}

impl Drop for RootGlobalGenesisAttemptV2<'_, '_> {
    fn drop(&mut self) { if self.armed { std::process::abort(); } }
}

fn resource_global_genesis_bookend_v2(
    held: &RootFirstSourceSuccessorBookendV2<'_, '_>,
    stream: &UnixStream,
    posts: &mut Vec<Result<(), SourceGenesisErrorV1>>,
    clocks: &mut Vec<Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>>,
    first: &mut Option<RootProjectGenesisAttemptSiteV3>,
) -> Result<(), SourceGenesisErrorV1> {
    let returned = held.post_with_site(stream, posts, clocks, Some(RootPostSiteV3::Project(first)));
    returned.map_err(|_| SourceGenesisErrorV1::Stale)
}

fn serve_resource_global_genesis_v2(attempt: &mut RootGlobalGenesisAttemptV2<'_, '_>) -> Result<(), SourceGenesisErrorV1> {
    use RootSourceGenesisFrameKindV1 as Phase;
    let RootGlobalGenesisAttemptV2 {
        stream, startup, request, route, controller_uid, controller_gid, source_uid, source_signer_uid, deadline,
        clock, opening, owner, contexts, source, prepared, floor_selection, anchored, prepare, anchor, io, posts, clock_posts, first_failure, cleanup, armed, ..
    } = attempt;
    *clock = Some(observe_root_first_source_successor_clock_v2(None));
    if clock.as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Clock); }
    let actual_clock = *clock.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    if request[..8] != *aos_sandbox::policy_compiler::ROOT_SOURCE_RESOURCE_GENESIS_QUERY_MAGIC_V2
        || request[8..24] == [0; 16] || request[24..] != [0; 8]
        || matches!(route, RootFirstSourceSuccessorRouteV2::Current) && startup.is_none()
        || *controller_uid == 0 || *controller_gid == 0 || *source_uid == 0 || *source_signer_uid == 0
    { return Err(SourceGenesisErrorV1::AdmissionClosed); }
    let before = RootFirstSourceSuccessorBookendV2 {
        owner: None,
        startup: *startup,
        controller_uid: *controller_uid,
        controller_gid: *controller_gid,
        deadline: *deadline,
        clock: actual_clock,
    };
    resource_global_genesis_bookend_v2(&before, stream, posts, clock_posts, first_failure)?;
    let boundary = posts.len();
    posts.push(aos_sandbox::policy_compiler::require_no_fixed_closed_policy_binding_hold_v1()
        .map_err(|_| SourceGenesisErrorV1::AdmissionClosed));
    if posts[boundary].is_err() && first_failure.is_none() {
        *first_failure = Some(RootProjectGenesisAttemptSiteV3::Owner(boundary));
    }
    let independent = resource_global_genesis_bookend_v2(&before, stream, posts, clock_posts, first_failure);
    if posts[boundary].is_err() {
        return Err(SourceGenesisErrorV1::AdmissionClosed);
    }
    independent?;
    let open_result = opening.open_into(owner, *controller_uid, *source_uid);
    if open_result.is_err() { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Opening); }
    let independent = resource_global_genesis_bookend_v2(&before, stream, posts, clock_posts, first_failure);
    if open_result.is_err() {
        return Err(SourceGenesisErrorV1::AdmissionClosed);
    }
    independent?;
    let owner = owner.as_mut().ok_or(SourceGenesisErrorV1::Stale)?;
    let nonce = owner.nonce();
    io[0].outgoing.resize(56, 0);
    io[0].outgoing[..8].copy_from_slice(aos_sandbox::policy_compiler::ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1);
    io[0].outgoing[8..10].copy_from_slice(&1_u16.to_be_bytes());
    io[0].outgoing[16..32].copy_from_slice(&request[8..24]);
    io[0].outgoing[32..48].copy_from_slice(&nonce);
    io[0].outgoing[48..52].copy_from_slice(&source_uid.to_be_bytes());
    io[0].outgoing[52..56].copy_from_slice(&controller_uid.to_be_bytes());
    {
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        if io[0].write_with_recipe(stream, &held, RootFrameRecipeV3::ResourceGlobalGenesis(Phase::Prepare)).is_err() {
            *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(0)); return Err(SourceGenesisErrorV1::Stale);
        }
        if io[1].read_with_recipe(stream, &held, RootFrameRecipeV3::ResourceGlobalGenesis(Phase::Prepare), nonce).is_err() {
            *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(1)); return Err(SourceGenesisErrorV1::Stale);
        }
    }
    contexts[0] = Some(resource_global_source_context_v2(owner, &io[1].incoming[32..], *route));
    if contexts[0].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Context(0)); }
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    let (project, challenge, context) = contexts[0].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    if matches!(route, RootFirstSourceSuccessorRouteV2::Historical) && challenge.intent().is_none() {
        return Err(SourceGenesisErrorV1::AdmissionClosed);
    }
    source[0] = Some(crate::source_signer_exchange::request_root_source_tree_genesis_readback_v3(*challenge, *project, context.as_ref(), owner.source_readback_pin(), *source_signer_uid, *controller_gid));
    if source[0].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Source(0)); }
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    let packet = source[0].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    *floor_selection = Some(owner.resource_global_floor_present_v2());
    if floor_selection.as_ref().is_some_and(Result::is_err) && first_failure.is_none() {
        *first_failure = Some(RootProjectGenesisAttemptSiteV3::FloorSelection);
    }
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    let has_floor = *floor_selection.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    // Only an actual settled floor skips Prepared. A historical challenge may
    // instead name an unanchored intent and cannot choose that shortcut.
    let floor = if has_floor {
        *anchored = Some(owner.anchor_global_genesis_v2(packet.as_ref(), &actual_clock, *deadline, anchor));
        if anchored.as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Anchor); }
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
        let floor = anchored.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        floor
    } else {
        *prepared = Some(owner.prepare_global_genesis_v2(packet.as_ref(), &actual_clock, *deadline, prepare));
        if prepared.as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Prepare); }
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
        let intent = prepared.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        let mut payload = [0; 976];
        let payload_bytes = 8 + intent.record_bytes().len();
        payload[..8].copy_from_slice(&owner.current_admission_expiry()?.to_be_bytes());
        payload[8..payload_bytes].copy_from_slice(intent.record_bytes());
        if io[1].send_resource_global_genesis_v2(stream, &held, Phase::Prepared, nonce, &payload[..payload_bytes]).is_err() {
            *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(1)); return Err(SourceGenesisErrorV1::Stale);
        }
        if io[2].read_with_recipe(stream, &held, RootFrameRecipeV3::ResourceGlobalGenesis(Phase::Anchor), nonce).is_err() {
            *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(2)); return Err(SourceGenesisErrorV1::Stale);
        }
        contexts[1] = Some(resource_global_source_context_v2(owner, &io[2].incoming[32..], *route));
        if contexts[1].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Context(1)); }
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
        let (project, challenge, context) = contexts[1].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        source[1] = Some(crate::source_signer_exchange::request_root_source_tree_genesis_readback_v3(*challenge, *project, context.as_ref(), owner.source_readback_pin(), *source_signer_uid, *controller_gid));
        if source[1].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Source(1)); }
        let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
        let packet = source[1].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        *anchored = Some(owner.anchor_global_genesis_v2(packet.as_ref(), &actual_clock, *deadline, anchor));
        if anchored.as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Anchor); }
        let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
        let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
        let floor = anchored.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        independent?;
        floor
    };
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
    // Either branch owns this exact floor in the resident Anchor Result.
    let outgoing_index = if io[2].incoming.is_empty() { 1 } else { 2 };
    let outgoing = &mut io[outgoing_index];
    if outgoing.send_resource_global_genesis_v2(stream, &held, Phase::Anchored, nonce, floor.record_bytes()).is_err() {
        *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(outgoing_index)); return Err(SourceGenesisErrorV1::Stale);
    }
    if io[3].read_with_recipe(stream, &held, RootFrameRecipeV3::ResourceGlobalGenesis(Phase::Complete), nonce).is_err() {
        *first_failure = Some(RootProjectGenesisAttemptSiteV3::Io(3)); return Err(SourceGenesisErrorV1::Stale);
    }
    contexts[2] = Some(resource_global_source_context_v2(owner, &io[3].incoming[32..], *route));
    if contexts[2].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Context(2)); }
    let held = RootFirstSourceSuccessorBookendV2 { owner: Some(owner), ..before };
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    let (project, challenge, context) = contexts[2].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    source[2] = Some(crate::source_signer_exchange::request_root_source_tree_genesis_readback_v3(*challenge, *project, context.as_ref(), owner.source_readback_pin(), *source_signer_uid, *controller_gid));
    if source[2].as_ref().is_some_and(Result::is_err) { *first_failure = Some(RootProjectGenesisAttemptSiteV3::Source(2)); }
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    let packet = source[2].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
    independent?;
    // The genuine current-floor Result borrows this owner and stays a named
    // local through terminal failure and Finish, avoiding any self-borrow.
    let current_result = owner.current_anchored_floor(packet.as_ref());
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    let Ok(current) = &current_result else { terminate_first_successor_root(); };
    if independent.is_err() || current.floor() != floor { terminate_first_successor_root(); }
    let sent = io[3].send_resource_global_genesis_v2(stream, &held, Phase::Completed, nonce, current.floor().digest().as_bytes());
    if sent.is_err() { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Io(3)); }
    posts.push(current.recheck());
    if posts.last().is_some_and(Result::is_err) { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Owner(posts.len() - 1)); }
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    if sent.is_err() || posts.iter().any(Result::is_err) || independent.is_err() { terminate_first_successor_root(); }
    let received = io[4].read_with_recipe(stream, &held, RootFrameRecipeV3::ResourceGlobalGenesis(Phase::Finish), nonce);
    if received.is_err() { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Io(4)); }
    posts.push(current.recheck());
    if posts.last().is_some_and(Result::is_err) { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Owner(posts.len() - 1)); }
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    if received.is_err() || posts.iter().any(Result::is_err) || independent.is_err()
        || &io[4].incoming[32..] != current.floor().digest().as_bytes() { terminate_first_successor_root(); }
    let sent = io[4].send_resource_global_genesis_v2(stream, &held, Phase::Finish, nonce, current.floor().digest().as_bytes());
    if sent.is_err() { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Io(4)); }
    posts.push(current.recheck());
    if posts.last().is_some_and(Result::is_err) { first_failure.get_or_insert(RootProjectGenesisAttemptSiteV3::Owner(posts.len() - 1)); }
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    if sent.is_err() || posts.iter().any(Result::is_err) || independent.is_err() { terminate_first_successor_root(); }
    *cleanup = Some(stream.shutdown(Shutdown::Both));
    let independent = resource_global_genesis_bookend_v2(&held, stream, posts, clock_posts, first_failure);
    if !matches!(cleanup, Some(Ok(()))) || independent.is_err() { terminate_first_successor_root(); }
    *armed = false;
    Ok(())
}

fn resource_global_source_context_v2(
    owner: &mut RootSourceGenesisAuthorityV1,
    packet: &[u8],
    route: RootFirstSourceSuccessorRouteV2,
) -> Result<(
    Option<aos_sandbox_core::ProjectId>, aos_sandbox::policy_compiler::SourceTreeGenesisChallengeV1,
    Option<aos_sandbox::policy_compiler::SourceTreeGenesisIntentContextV1>,
), SourceGenesisErrorV1> {
    let (project, challenge) = owner.accept_controller_resource_global_v2(
        packet, matches!(route, RootFirstSourceSuccessorRouteV2::Historical),
    )?;
    let context = project.map(|_| owner.source_genesis_intent_context_v1()).transpose()?;
    Ok((project, challenge, context))
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
    let returned = crate::source_signer_exchange::request_root_source_tree_genesis_readback_v3(
        challenge, Some(project), Some(context), signer, source_signer_uid, controller_gid,
    );
    observation.park_result_v2(returned)
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
