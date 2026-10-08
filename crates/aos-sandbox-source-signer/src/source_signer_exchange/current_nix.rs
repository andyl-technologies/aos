//! Retained CurrentNix Source16 transport and native-result custody.
//!
//! The client attempt, bounded I/O reservoirs, and retained signer recipe own
//! their original results together. The selected parent service still refuses
//! Source16 before context growth, key access, or native Source observation.
//!
//! ```text
//! AOSSSR16 | context280 | intent-slot1424
//! AOSSSP16 | context + native observation + signature
//! ```

use std::error::Error;
use std::io::{self, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use aos_sandbox::policy_compiler::RootFirstSourceSuccessorIntentV2;
use rustix::net::sockopt::socket_peercred;

use crate::source_signer_credential::SourceSignerCredentialV1;

use super::{
    REQUEST_BYTES, REQUEST_CURRENT_NIX_MAGIC_V1, SOURCE_SIGNER_SOCKET_PATH_V1,
    require_socket_path_custody,
};

// The original request, key/native/parser Results and reply owner remain on
// this service frame until every send/shutdown post has run. A failed entered
// selected attempt terminates without ordinary unwinding of uncertain custody,
// just as the existing selected successor service does; it never retries.
// Each successful transfer makes at least one byte of progress. A failed,
// interrupted or zero-progress call is retained and refuses without retry.
// The fixed cell bound is reserved before the first clock or I/O crossing.
struct CurrentNixSourceIoV1 {
    cells: Option<Result<Vec<aos_sandbox::policy_compiler::CurrentNixSourceIoCellV1>, std::collections::TryReserveError>>,
    refusal: Option<aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1>,
}

enum CurrentNixSourceIoBodyV1<'body> {
    Receive(&'body mut [u8]),
    Send(&'body [u8]),
    Eof,
    ShutdownWrite,
}

impl CurrentNixSourceIoV1 {
    fn empty() -> Self {
        Self { cells: None, refusal: None }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.cells.as_ref() {
            Some(Err(error)) => return Some(error),
            Some(Ok(cells)) => {
                for cell in cells {
                    if let Err(error) = &cell.clock { return Some(error); }
                    if let Some(Err(error)) = &cell.pair { return Some(error); }
                    if let Some(Err(error)) = &cell.timeout { return Some(error); }
                    if let Some(Err(error)) = &cell.transferred { return Some(error); }
                    if let Some(Err(error)) = &cell.shutdown { return Some(error); }
                }
            }
            None => {}
        }
        self.refusal.as_ref().map(|error| error as _)
    }

    fn run_once(
        &mut self,
        stream: &mut UnixStream,
        context: &aos_sandbox::policy_compiler::CurrentNixPreflightContextV1,
        mut body: CurrentNixSourceIoBodyV1<'_>,
    ) -> Result<(), ()> {
        use aos_sandbox::policy_compiler::{
            CurrentNixPreflightDataErrorV1 as DataError,
            CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1,
            observe_root_first_source_successor_clock_v2,
        };
        if self.cells.is_some() {
            self.refusal = Some(DataError::Repeated);
            return Err(());
        }
        let length = match &body {
            CurrentNixSourceIoBodyV1::Receive(bytes) => bytes.len(),
            CurrentNixSourceIoBodyV1::Send(bytes) => bytes.len(),
            CurrentNixSourceIoBodyV1::Eof | CurrentNixSourceIoBodyV1::ShutdownWrite => 1,
        };
        if length == 0 || length > CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1 {
            self.refusal = Some(DataError::Changed);
            return Err(());
        }
        let mut cells = Vec::new();
        let reserved = cells.try_reserve_exact(length);
        self.cells = Some(reserved.map(|()| cells));
        let Some(Ok(cells)) = self.cells.as_mut() else { return Err(()); };

        let mut cursor = 0;
        for _ in 0..length {
            cells.push(aos_sandbox::policy_compiler::CurrentNixSourceIoCellV1 {
                clock: observe_root_first_source_successor_clock_v2(None),
                pair: None, timeout: None, transferred: None,
                eof_byte: [0; 1], shutdown: None,
            });
            let Some(cell) = cells.last_mut() else { return Err(()); };
            let Ok(native) = cell.clock.as_ref() else { return Err(()); };
            cell.pair = Some(context.require_original_kernel_sample_data_v1(*native));
            if !matches!(cell.pair, Some(Ok(()))) { return Err(()); }
            if matches!(&body, CurrentNixSourceIoBodyV1::ShutdownWrite) {
                cell.shutdown = Some(stream.shutdown(std::net::Shutdown::Write));
                return if matches!(cell.shutdown, Some(Ok(()))) { Ok(()) } else { Err(()) };
            }
            let Some(remaining) = context.original_deadline_data()
                .checked_sub(native.boottime_nanoseconds()).filter(|value| *value != 0)
            else {
                self.refusal = Some(DataError::Changed);
                return Err(());
            };
            let timeout = Some(Duration::from_nanos(remaining));
            cell.timeout = Some(match &body {
                CurrentNixSourceIoBodyV1::Send(_) => stream.set_write_timeout(timeout),
                _ => stream.set_read_timeout(timeout),
            });
            if !matches!(cell.timeout, Some(Ok(()))) { return Err(()); }

            cell.transferred = Some(match &mut body {
                CurrentNixSourceIoBodyV1::Receive(bytes) => stream.read(&mut bytes[cursor..]),
                CurrentNixSourceIoBodyV1::Send(bytes) => stream.write(&bytes[cursor..]),
                CurrentNixSourceIoBodyV1::Eof => stream.read(&mut cell.eof_byte),
                CurrentNixSourceIoBodyV1::ShutdownWrite => return Err(()),
            });
            let Some(Ok(count)) = cell.transferred.as_ref() else { return Err(()); };
            if matches!(&body, CurrentNixSourceIoBodyV1::Eof) {
                if *count == 0 { return Ok(()); }
                self.refusal = Some(DataError::Changed);
                return Err(());
            }
            if *count == 0 || *count > length - cursor {
                self.refusal = Some(DataError::Changed);
                return Err(());
            }
            cursor += *count;
            if cursor == length { return Ok(()); }
        }
        self.refusal = Some(DataError::Changed);
        Err(())
    }
}

/// Retains one original Root-to-Source16 exchange and every entered native cause.
///
/// The socket is created and connected once at the fixed signer endpoint. A
/// pending nonblocking connect is completed on that same socket, never retried.
/// Reply bytes are DATA: only the still-held Root and Source originals can join
/// them to current policy, and this owner supplies no paid or currentness loan.
pub struct CurrentNixSourceExchangeAttemptV1 {
    entered: bool,
    refusal: Option<aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1>,
    request: [u8; aos_sandbox::policy_compiler::CURRENT_NIX_SOURCE_REQUEST_BYTES_V1],
    reply: [u8; aos_sandbox::policy_compiler::CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1],
    reply_len: usize,
    path: Option<io::Result<()>>,
    address: Option<Result<rustix::net::SocketAddrUnix, rustix::io::Errno>>,
    socket: Option<io::Result<UnixStream>>,
    socket_clock: Option<Result<aos_sandbox_core::ownership_lease::RawPairedClockSample,
        aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    socket_pair: Option<Result<(), aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1>>,
    connect_clock: Option<Result<aos_sandbox_core::ownership_lease::RawPairedClockSample,
        aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    connect_pair: Option<Result<(), aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1>>,
    connected: Option<Result<(), rustix::io::Errno>>,
    poll_clock: Option<Result<aos_sandbox_core::ownership_lease::RawPairedClockSample,
        aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    poll_pair: Option<Result<(), aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1>>,
    polled: Option<Result<usize, rustix::io::Errno>>,
    poll_events: Option<rustix::event::PollFlags>,
    connect_error: Option<Result<Result<(), rustix::io::Errno>, rustix::io::Errno>>,
    blocking: Option<io::Result<()>>,
    peer: Option<Result<rustix::net::UCred, rustix::io::Errno>>,
    send_io: CurrentNixSourceIoV1,
    shutdown_io: CurrentNixSourceIoV1,
    header_io: CurrentNixSourceIoV1,
    body_io: CurrentNixSourceIoV1,
    eof_io: CurrentNixSourceIoV1,
    action: Option<Result<(), ()>>,
    path_post: Option<io::Result<()>>,
    peer_post: Option<Result<rustix::net::UCred, rustix::io::Errno>>,
    peer_binding_post: Option<Result<(), aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1>>,
    clock_post: Option<Result<aos_sandbox_core::ownership_lease::RawPairedClockSample,
        aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    pair_post: Option<Result<(), aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1>>,
}

impl CurrentNixSourceExchangeAttemptV1 {
    /// Prearms inert fixed request/reply and native-result destinations.
    pub fn empty() -> Self {
        Self {
            entered: false, refusal: None, request: [0; 1712], reply: [0; 3492], reply_len: 0,
            path: None, address: None, socket: None, socket_clock: None, socket_pair: None,
            connect_clock: None, connect_pair: None,
            connected: None, poll_clock: None, poll_pair: None, polled: None, poll_events: None,
            connect_error: None, blocking: None, peer: None,
            send_io: CurrentNixSourceIoV1::empty(), shutdown_io: CurrentNixSourceIoV1::empty(),
            header_io: CurrentNixSourceIoV1::empty(), body_io: CurrentNixSourceIoV1::empty(),
            eof_io: CurrentNixSourceIoV1::empty(), action: None, path_post: None,
            peer_post: None, peer_binding_post: None, clock_post: None, pair_post: None,
        }
    }

    /// Performs the closed request once, retaining ambiguity and independent posts.
    ///
    /// # Errors
    /// Refuses reused custody, substituted intent/context, fixed-endpoint or peer
    /// failure, incomplete/trailing reply, and the original boot/deadline debt.
    /// The marker never replaces any whole native Result retained in this owner.
    pub fn request_once(
        &mut self,
        signer_uid: u32,
        socket_gid: u32,
        context: &aos_sandbox::policy_compiler::CurrentNixPreflightContextV1,
        original: &RootFirstSourceSuccessorIntentV2,
    ) -> Result<(), ()> {
        use aos_sandbox::policy_compiler::{
            CurrentNixPreflightDataErrorV1 as DataError,
            observe_root_first_source_successor_clock_v2,
        };
        if self.entered {
            self.refusal = Some(DataError::Repeated);
            return Err(());
        }
        self.entered = true;
        let action = self.request_inner(signer_uid, socket_gid, context, original);
        self.action = Some(action);
        if matches!(self.action, Some(Err(()))) && self.failure().is_none() {
            self.refusal = Some(DataError::Changed);
        }
        self.path_post = Some(require_socket_path_custody(signer_uid, socket_gid));
        if let Some(Ok(stream)) = self.socket.as_ref() {
            self.peer_post = Some(socket_peercred(stream));
        }
        self.peer_binding_post = Some(if matches!((&self.peer, &self.peer_post),
            (Some(Ok(before)), Some(Ok(after))) if before.uid == after.uid
                && before.gid == after.gid && before.pid == after.pid)
        { Ok(()) } else { Err(DataError::Changed) });
        self.clock_post = Some(observe_root_first_source_successor_clock_v2(None));
        if let Some(Ok(native)) = self.clock_post.as_ref() {
            self.pair_post = Some(context.require_original_kernel_sample_data_v1(*native));
        }
        if !matches!(self.action, Some(Ok(()))) || !matches!(self.path_post, Some(Ok(())))
            || !matches!(self.pair_post, Some(Ok(()))) || !matches!(self.peer_binding_post, Some(Ok(())))
        {
            return Err(());
        }
        Ok(())
    }

    fn request_inner(
        &mut self, signer_uid: u32, socket_gid: u32,
        context: &aos_sandbox::policy_compiler::CurrentNixPreflightContextV1,
        original: &RootFirstSourceSuccessorIntentV2,
    ) -> Result<(), ()> {
        use aos_sandbox::policy_compiler::observe_root_first_source_successor_clock_v2;
        use rustix::net::{AddressFamily, SocketFlags, SocketType};
        if signer_uid == 0 || socket_gid == 0 || context.project_data() != original.project()
            || matches!(context.bytes()[10], 3 | 4) != original.approval_packet().has_resource_authorization()
        { return Err(()); }
        self.request[..8].copy_from_slice(REQUEST_CURRENT_NIX_MAGIC_V1);
        self.request[8..288].copy_from_slice(context.bytes());
        self.request[288..288 + original.as_bytes().len()].copy_from_slice(original.as_bytes());
        self.path = Some(require_socket_path_custody(signer_uid, socket_gid));
        if !matches!(self.path, Some(Ok(()))) { return Err(()); }
        self.address = Some(rustix::net::SocketAddrUnix::new(SOURCE_SIGNER_SOCKET_PATH_V1));
        self.socket_clock = Some(observe_root_first_source_successor_clock_v2(None));
        let Some(Ok(native)) = self.socket_clock.as_ref() else { return Err(()); };
        self.socket_pair = Some(context.require_original_kernel_sample_data_v1(*native));
        if !matches!(self.socket_pair, Some(Ok(()))) { return Err(()); }
        self.socket = Some(rustix::net::socket_with(
            AddressFamily::UNIX, SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK, None,
        ).map(UnixStream::from).map_err(io::Error::from));
        let (Some(Ok(address)), Some(Ok(stream))) = (&self.address, &mut self.socket) else {
            return Err(());
        };
        self.connect_clock = Some(observe_root_first_source_successor_clock_v2(None));
        let Some(Ok(native)) = self.connect_clock.as_ref() else { return Err(()); };
        self.connect_pair = Some(context.require_original_kernel_sample_data_v1(*native));
        if !matches!(self.connect_pair, Some(Ok(()))) { return Err(()); }
        self.connected = Some(rustix::net::connect(&*stream, address));
        match self.connected {
            Some(Ok(())) => {}
            Some(Err(rustix::io::Errno::INPROGRESS)) => {
                self.poll_clock = Some(observe_root_first_source_successor_clock_v2(None));
                let Some(Ok(native)) = self.poll_clock.as_ref() else { return Err(()); };
                self.poll_pair = Some(context.require_original_kernel_sample_data_v1(*native));
                if !matches!(self.poll_pair, Some(Ok(()))) { return Err(()); }
                let remaining = context.original_deadline_data()
                    .checked_sub(native.boottime_nanoseconds()).ok_or(())?;
                let duration = Duration::from_nanos(remaining);
                let timeout = rustix::event::Timespec {
                    tv_sec: i64::try_from(duration.as_secs()).map_err(|_| ())?,
                    tv_nsec: i64::from(duration.subsec_nanos()),
                };
                let mut descriptors = [rustix::event::PollFd::new(&*stream, rustix::event::PollFlags::OUT)];
                self.polled = Some(rustix::event::poll(&mut descriptors, Some(&timeout)));
                self.poll_events = Some(descriptors[0].revents());
                if !matches!(self.polled, Some(Ok(1)))
                    || !matches!(self.poll_events, Some(events) if events.contains(rustix::event::PollFlags::OUT)
                        && !events.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::HUP | rustix::event::PollFlags::NVAL))
                { return Err(()); }
                self.connect_error = Some(rustix::net::sockopt::socket_error(&*stream));
                if !matches!(self.connect_error, Some(Ok(Ok(())))) { return Err(()); }
            }
            _ => return Err(()),
        }
        self.blocking = Some(stream.set_nonblocking(false));
        self.peer = Some(socket_peercred(&*stream));
        if !matches!(self.blocking, Some(Ok(())))
            || !matches!(self.peer, Some(Ok(peer)) if peer.uid.as_raw() == signer_uid && peer.gid.as_raw() == socket_gid)
        { return Err(()); }
        self.send_io.run_once(stream, context, CurrentNixSourceIoBodyV1::Send(&self.request))?;
        self.shutdown_io.run_once(stream, context, CurrentNixSourceIoBodyV1::ShutdownWrite)?;
        self.header_io.run_once(stream, context, CurrentNixSourceIoBodyV1::Receive(&mut self.reply[..292]))?;
        if self.reply[..8] != *b"AOSSSP16" || self.reply[8..288] != *context.bytes() { return Err(()); }
        let mut width = [0; 4];
        width.copy_from_slice(&self.reply[288..292]);
        self.reply_len = usize::try_from(u32::from_be_bytes(width)).map_err(|_| ())?
            .checked_add(356).ok_or(())?;
        if !matches!(self.reply_len, 3140 | 3316 | 3492) { return Err(()); }
        self.body_io.run_once(stream, context,
            CurrentNixSourceIoBodyV1::Receive(&mut self.reply[292..self.reply_len]))?;
        self.eof_io.run_once(stream, context, CurrentNixSourceIoBodyV1::Eof)
    }

    /// Borrows complete reply DATA without releasing its original transport.
    pub fn reply_data(&self) -> Option<&[u8]> {
        if self.refusal.is_some() || !matches!(self.action, Some(Ok(()))) { return None; }
        Some(&self.reply[..self.reply_len])
    }

    /// Borrows the earliest original cause without losing pending-connect evidence.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(error)) = &self.path { return Some(error); }
        if let Some(Err(error)) = &self.address { return Some(error); }
        if let Some(Err(error)) = &self.socket_clock { return Some(error); }
        if let Some(Err(error)) = &self.socket_pair { return Some(error); }
        if let Some(Err(error)) = &self.socket { return Some(error); }
        if let Some(Err(error)) = &self.connect_clock { return Some(error); }
        if let Some(Err(error)) = &self.connect_pair { return Some(error); }
        if let Some(Err(error)) = &self.connected {
            if *error != rustix::io::Errno::INPROGRESS { return Some(error); }
        }
        if let Some(Err(error)) = &self.poll_clock { return Some(error); }
        if let Some(Err(error)) = &self.poll_pair { return Some(error); }
        if let Some(Err(error)) = &self.polled { return Some(error); }
        match &self.connect_error {
            Some(Err(error)) | Some(Ok(Err(error))) => return Some(error),
            _ => {}
        }
        if let Some(Err(error)) = &self.blocking { return Some(error); }
        if let Some(Err(error)) = &self.peer { return Some(error); }
        if let Some(error) = self.send_io.failure() { return Some(error); }
        if let Some(error) = self.shutdown_io.failure() { return Some(error); }
        if let Some(error) = self.header_io.failure() { return Some(error); }
        if let Some(error) = self.body_io.failure() { return Some(error); }
        if let Some(error) = self.eof_io.failure() { return Some(error); }
        // A pure phase/shape refusal precedes the independent outward posts.
        if let Some(error) = &self.refusal { return Some(error); }
        if let Some(Err(error)) = &self.path_post { return Some(error); }
        if let Some(Err(error)) = &self.peer_post { return Some(error); }
        if let Some(Err(error)) = &self.peer_binding_post { return Some(error); }
        if let Some(Err(error)) = &self.clock_post { return Some(error); }
        self.pair_post.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
    }

    /// Prices concrete transport representations before entering this exchange.
    ///
    /// Includes both fixed attempts and every maximum positive-progress native
    /// cell on client and signer. Read-only replay, parser/runtime scratch and
    /// allocator overhead are separate priced obligations, not hidden in bytes.
    ///
    /// # Errors
    /// Rejects representation-size arithmetic overflow. This logical extent
    /// creates no allowance and cannot substitute for the original paid intake.
    pub fn structural_resident_bytes_v1() -> Result<usize,
        aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1>
    {
        use aos_sandbox::policy_compiler::{
            CurrentNixPreflightDataErrorV1 as DataError, CurrentNixSourceObservationAttemptV1,
        };
        // Client request1712 + reply3492 + shutdown1 + EOF1; the header/body
        // are disjoint reads into one fixed reply. Signer intent1424 + reply3492
        // + shutdown1 + EOF1. Vec capacity is reserved for these exact counts.
        let cells = 1712_usize.checked_add(3492).and_then(|n| n.checked_add(2))
            .and_then(|n| n.checked_add(1424 + 3492 + 2)).ok_or(DataError::Changed)?;
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<CurrentNixSourceObservationAttemptV1>())
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<CurrentNixSourceIoV1>()))
            .and_then(|bytes| bytes.checked_add(1712 + REQUEST_BYTES))
            .and_then(|bytes| bytes.checked_add(cells.checked_mul(std::mem::size_of::<aos_sandbox::policy_compiler::CurrentNixSourceIoCellV1>())?))
            .and_then(|bytes| bytes.checked_add(3136 + 3492))
            .ok_or(DataError::Changed)
    }
}

fn serve_current_nix_source_request_v1(
    stream: &mut UnixStream,
    prefix: &[u8; REQUEST_BYTES],
    initial_read: io::Result<()>,
    original_peer: &rustix::net::UCred,
    controller_uid: u32,
    credentials: &SourceSignerCredentialV1,
) -> Result<(), Box<dyn Error>> {
    use aos_sandbox::policy_compiler::{
        CURRENT_NIX_SOURCE_REQUEST_BYTES_V1, CurrentNixPreflightContextV1,
        CurrentNixSourceObservationAttemptV1, observe_fixed_current_nix_source_into_v1,
        observe_root_first_source_successor_clock_v2,
    };

    let mut observation = CurrentNixSourceObservationAttemptV1::empty();
    let mut remainder_io = CurrentNixSourceIoV1::empty();
    let mut eof_io = CurrentNixSourceIoV1::empty();
    let mut send_io = CurrentNixSourceIoV1::empty();
    let mut shutdown_io = CurrentNixSourceIoV1::empty();
    let mut expanded = [0; CURRENT_NIX_SOURCE_REQUEST_BYTES_V1];
    expanded[..REQUEST_BYTES].copy_from_slice(prefix);
    // The inherited ingress timeout applies only until the bounded context is
    // known. Every remaining syscall then borrows its same original boot and D.
    let context_read = initial_read.as_ref().ok()
        .map(|()| stream.read_exact(&mut expanded[REQUEST_BYTES..288]));
    let context = context_read.as_ref().and_then(|r| r.as_ref().ok())
        .map(|()| CurrentNixPreflightContextV1::decode(&expanded[8..288]));
    let remainder = context.as_ref().and_then(|r| r.as_ref().ok()).map(|context| {
        remainder_io.run_once(stream, context,
            CurrentNixSourceIoBodyV1::Receive(&mut expanded[288..]))
    });
    let request_eof = if matches!(remainder, Some(Ok(()))) {
        context.as_ref().and_then(|r| r.as_ref().ok()).map(|context| {
            eof_io.run_once(stream, context, CurrentNixSourceIoBodyV1::Eof)
        })
    } else { None };
    let original = if matches!(request_eof, Some(Ok(()))) {
        let Some(Ok(context)) = context.as_ref() else { std::process::exit(1); };
        let resource = matches!(context.bytes()[10], 3 | 4);
        let width = if resource { 1424 } else { 1248 };
        Some(if !resource && expanded[288 + width..].iter().any(|byte| *byte != 0) {
            Err(crate::source_signer_exchange::invalid_data("nonzero legacy Nix intent padding"))
        } else {
            RootFirstSourceSuccessorIntentV2::decode(&expanded[288..288 + width])
                .map_err(io::Error::other)
        })
    } else { None };
    let signing_key_result = credentials.signing_key();
    let observed = match (&context, &original, &signing_key_result) {
        (Some(Ok(context)), Some(Ok(original)), Ok(key)) => Some(
            observe_fixed_current_nix_source_into_v1(
                &mut observation, controller_uid, context, original,
                credentials.generation(), key,
            ),
        ),
        _ => None,
    };

    // These are independent posts even when receive, parsing, credentials or
    // the actual native observation failed. The raw clock is observed LAST.
    let credential_post = credentials.signing_key();
    let peer_post = socket_peercred(&*stream);
    let clock_post = observe_root_first_source_successor_clock_v2(None);
    let pair_post = match (&context, &clock_post) {
        (Some(Ok(context)), Ok(native)) => Some(
            context.require_original_kernel_sample_data_v1(*native),
        ),
        _ => None,
    };
    let Some(Ok(())) = observed.as_ref() else { std::process::exit(1); };
    let Ok(key) = &signing_key_result else { std::process::exit(1); };
    let Ok(later_key) = &credential_post else { std::process::exit(1); };
    let Ok(peer) = &peer_post else { std::process::exit(1); };
    if clock_post.is_err() || !matches!(pair_post, Some(Ok(())))
        || key.verifying_key() != later_key.verifying_key()
        || peer.uid != original_peer.uid || peer.gid != original_peer.gid
        || peer.pid != original_peer.pid
    { std::process::exit(1); }

    let Some(reply) = observation.reply_data() else { std::process::exit(1); };
    let Some(Ok(context)) = context.as_ref() else { std::process::exit(1); };
    let sent = send_io.run_once(stream, context, CurrentNixSourceIoBodyV1::Send(reply));
    let shutdown = sent.as_ref().ok()
        .map(|()| shutdown_io.run_once(stream, context, CurrentNixSourceIoBodyV1::ShutdownWrite));
    let source_final = observation.recheck_after_response_v1(context);
    let credential_final = credentials.signing_key();
    let peer_final = socket_peercred(&*stream);
    let clock_final = observe_root_first_source_successor_clock_v2(None);
    let pair_final = match &clock_final {
        Ok(native) => Some(
            context.require_original_kernel_sample_data_v1(*native),
        ),
        _ => None,
    };
    if sent.is_err() || !matches!(shutdown, Some(Ok(()))) || source_final.is_err() || clock_final.is_err()
        || !matches!(pair_final, Some(Ok(())))
    { std::process::exit(1); }
    let Ok(final_key) = &credential_final else { std::process::exit(1); };
    let Ok(final_peer) = &peer_final else { std::process::exit(1); };
    if final_key.verifying_key() != key.verifying_key()
        || final_peer.uid != peer.uid || final_peer.gid != peer.gid || final_peer.pid != peer.pid
    { std::process::exit(1); }
    Ok(())
}
