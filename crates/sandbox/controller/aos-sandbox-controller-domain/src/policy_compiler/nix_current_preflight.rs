//! Original current-Nix preflight context and retained input comparisons.
//!
//! The fixed packets are comparison DATA. A live preflight must also retain
//! the same CurrentStart, Source writer, Root writer and Policy writer through
//! independent posts and the original deadline; decoding a packet supplies none
//! of those owners or a resource-bank loan.
//!
//! ```text
//! AOSNCP01[280]: version1 | recipe1..4 | reserved | Root nonce16 |
//! operation/project/sandbox16 | Start/assignment/Spec digest32 |
//! clock-format1 + zero6 + boot16 + wall8 + BOOTTIME8 | original D8 |
//! Root-floor32 | Source-sequence8 | Root-sequence8 | zero8
//! AOSNCR01[552]: version1 + zero6 | Controller signer-generation8 |
//! Controller/Source UID4 | context280 | Controller/Source names48 |
//! Controller/Source sequence8 | publisher-head32 | original-lease32 |
//! distinct Controller-purpose signature64
//! ```

use aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1;
use aos_sandbox_policy::nix_current_data::{
    CurrentNixPreflightContextV1, CurrentNixPreflightDataErrorV1,
    VerifiedCurrentNixControllerReceiptV1, VerifiedCurrentNixSourceObservationV1,
    CURRENT_NIX_PREFLIGHT_CONTEXT_BYTES_V1, CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1,
    CURRENT_NIX_SOURCE_REQUEST_BYTES_V1, CURRENT_NIX_SOURCE_LEGACY_REPLY_BYTES_V1,
    CURRENT_NIX_SOURCE_LEGACY_GENESIS_REPLY_BYTES_V1, CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1,
    CONTROLLER_SIGNATURE_DOMAIN, CONTROLLER_BODY_BYTES, CONTROLLER_CLOCK_PROVENANCE,
};

mod input;

use aos_sandbox_model::bounded_codec::checked_byte_region;
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, SandboxId};
use aos_sandbox_model::ownership_lease::{
    OwnershipLeaseVerificationError, RawClockProvenance, RawPairedClockSample,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::journal::ProtectedJournalNamesV1;
use crate::JournalError;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

use super::consumer_read_flight::ConsumerReadFlightErrorV1;

use super::source_hold_readback::PinnedSourceHoldReadbackSignerV1;
use super::source_successor_readback::{
    VerifiedSourceFirstSuccessorReadbackV2, VerifiedSourceProjectContinuationReadbackV3,
};

/// Selects the distinct fixed current-Nix bootstrap on the existing Policy endpoint.
pub const CURRENT_NIX_PREFLIGHT_BOOTSTRAP_MAGIC_V1: [u8; 8] = *b"AOSNCQ01";

const FRAME_MAGIC: &[u8; 8] = b"AOSNCF01";
const FRAME_HEADER_BYTES: usize = 48;
const MAXIMUM_FRAME_READS: usize = 38;
const MAXIMUM_FRAME_WRITES: usize = 44;
const MAXIMUM_FRAME_HEADERS: usize = 22;
const MAXIMUM_CANDIDATE_BYTES: usize = 8_388_608;

type CurrentNixPeerCheck<'check> = dyn FnMut(
        &aos_linux_descriptors::unix_stream::RetainedUnixStream,
        Option<&aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk>,
    ) -> Result<(), super::consumer_read_flight::TransportFault>
    + 'check;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CurrentNixPhaseV1 {
    Hello = 1,
    Select = 2,
    RootArchive = 3,
    Deployment = 4,
    Node = 5,
    Site = 6,
    Backend = 7,
    Catalog = 8,
    Project = 9,
    ProjectInput = 10,
    RolePins = 11,
    Start = 12,
    Specification = 13,
    Context = 15,
    Controller = 16,
    Source = 17,
    Derivation = 18,
    Rejoin = 19,
    Finished = 20,
    Acknowledge = 21,
    Abort = 22,
}

impl CurrentNixPhaseV1 {
    fn require_length(self, length: usize) -> Result<(), CurrentNixPreflightDataErrorV1> {
        let valid = match self {
            Self::Hello => length == 16,
            Self::Select => length == 48,
            Self::RootArchive => matches!(length, 1936 | 2112),
            Self::Deployment => length == 224,
            Self::Node | Self::Site | Self::Backend | Self::Catalog => (1..=65_536).contains(&length),
            Self::Project => length == 328,
            Self::ProjectInput => (1..=3072).contains(&length),
            Self::RolePins => length == 240,
            Self::Start | Self::Specification => (1..=1_048_576).contains(&length),
            Self::Context | Self::Rejoin => length == CURRENT_NIX_PREFLIGHT_CONTEXT_BYTES_V1,
            Self::Controller => length == CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1,
            Self::Source => matches!(length, 3140 | 3316 | 3492),
            Self::Derivation => (356..=356 + MAXIMUM_CANDIDATE_BYTES).contains(&length),
            Self::Finished | Self::Acknowledge | Self::Abort => length == 0,
        };
        if valid { Ok(()) } else { Err(CurrentNixPreflightDataErrorV1::Changed) }
    }
}

#[derive(Clone, Copy)]
struct CurrentNixCorrelationV1 {
    client_nonce: [u8; 16],
    cutoff: u64,
}

impl CurrentNixCorrelationV1 {
    fn decode(bootstrap: &[u8; 32]) -> Result<Self, CurrentNixPreflightDataErrorV1> {
        if bootstrap[..8] != CURRENT_NIX_PREFLIGHT_BOOTSTRAP_MAGIC_V1
            || bootstrap[8..24] == [0; 16]
        { return Err(CurrentNixPreflightDataErrorV1::Changed); }
        Ok(Self { client_nonce: take(bootstrap, 8)?, cutoff: u64::from_be_bytes(take(bootstrap, 24)?) })
    }

    fn header(self, phase: CurrentNixPhaseV1, length: usize)
        -> Result<[u8; FRAME_HEADER_BYTES], CurrentNixPreflightDataErrorV1>
    {
        phase.require_length(length)?;
        let length = u32::try_from(length).map_err(|_| CurrentNixPreflightDataErrorV1::Changed)?;
        let mut bytes = [0; FRAME_HEADER_BYTES];
        bytes[..8].copy_from_slice(FRAME_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = phase as u8;
        bytes[16..32].copy_from_slice(&self.client_nonce);
        bytes[32..40].copy_from_slice(&self.cutoff.to_be_bytes());
        bytes[40..44].copy_from_slice(&length.to_be_bytes());
        Ok(bytes)
    }

    fn require_header(self, bytes: &[u8], phase: CurrentNixPhaseV1)
        -> Result<usize, CurrentNixPreflightDataErrorV1>
    {
        if bytes.len() != FRAME_HEADER_BYTES || bytes[..8] != *FRAME_MAGIC
            || bytes[8..10] != 1_u16.to_be_bytes() || bytes[10] != phase as u8
            || bytes[11..16] != [0; 5] || bytes[16..32] != self.client_nonce
            || u64::from_be_bytes(take(bytes, 32)?) != self.cutoff || bytes[44..48] != [0; 4]
        { return Err(CurrentNixPreflightDataErrorV1::Changed); }
        // Tag14 has no enum arm and cannot alias the former Manifest proposal.
        let length = u32::from_be_bytes(take(bytes, 40)?) as usize;
        phase.require_length(length)?;
        Ok(length)
    }
}

#[derive(Clone, Copy)]
enum CurrentNixCarrierFailureV1 {
    Correlation,
    Deadline,
    Open,
    Read(usize),
    Header(usize),
    Write(usize),
    Shutdown,
    Eof,
    Refusal,
}

// One fixed frame vocabulary over the existing strict ancillary/native engine.
// Partial receive buffers and native causes stay in that original carrier; the
// arrays below retain every returned Result before any independent post.
struct CurrentNixPreflightCarrierV1 {
    original: super::consumer_read_flight::RetainedCarrier,
    entered: bool,
    correlation: Option<Result<CurrentNixCorrelationV1, CurrentNixPreflightDataErrorV1>>,
    deadline: Option<Result<super::consumer_read_flight::Deadline, ConsumerReadFlightErrorV1>>,
    open: Option<Result<(), ConsumerReadFlightErrorV1>>,
    reads:
        [Option<Result<usize, super::consumer_read_flight::TransportFault>>; MAXIMUM_FRAME_READS],
    headers: [Option<Result<usize, CurrentNixPreflightDataErrorV1>>; MAXIMUM_FRAME_HEADERS],
    sent_headers: [Option<[u8; FRAME_HEADER_BYTES]>; MAXIMUM_FRAME_HEADERS],
    writes: [Option<Result<(), super::consumer_read_flight::TransportFault>>; MAXIMUM_FRAME_WRITES],
    shutdown: Option<Result<(), ConsumerReadFlightErrorV1>>,
    eof: Option<Result<(), super::consumer_read_flight::TransportFault>>,
    used_reads: usize,
    used_headers: usize,
    used_sent_headers: usize,
    used_writes: usize,
    refusal: Option<CurrentNixPreflightDataErrorV1>,
    first: Option<CurrentNixCarrierFailureV1>,
}

impl CurrentNixPreflightCarrierV1 {
    fn empty() -> Self {
        Self {
            original: super::consumer_read_flight::RetainedCarrier::empty(),
            entered: false, correlation: None, deadline: None, open: None,
            reads: [const { None }; MAXIMUM_FRAME_READS],
            headers: [const { None }; MAXIMUM_FRAME_HEADERS],
            sent_headers: [None; MAXIMUM_FRAME_HEADERS],
            writes: [const { None }; MAXIMUM_FRAME_WRITES], shutdown: None, eof: None,
            used_reads: 0, used_headers: 0, used_sent_headers: 0, used_writes: 0,
            refusal: None, first: None,
        }
    }

    fn accepted(original: std::os::unix::net::UnixStream) -> Self {
        Self { original: super::consumer_read_flight::RetainedCarrier::accepted(original), ..Self::empty() }
    }

    fn begin(&mut self, bootstrap: &[u8; 32], connect: bool) -> Result<(), ()> {
        if self.entered { return self.refuse(); }
        self.entered = true;
        self.correlation = Some(CurrentNixCorrelationV1::decode(bootstrap));
        if matches!(self.correlation, Some(Err(_))) {
            self.first = Some(CurrentNixCarrierFailureV1::Correlation);
            return Err(());
        }
        let Some(Ok(correlation)) = self.correlation else { return self.refuse(); };
        self.deadline = Some(super::consumer_read_flight::Deadline::capture(correlation.cutoff));
        if matches!(self.deadline, Some(Err(_))) {
            self.first = Some(CurrentNixCarrierFailureV1::Deadline);
            return Err(());
        }
        let Some(Ok(deadline)) = self.deadline else { return self.refuse(); };
        self.open = Some(if connect { self.original.connect(deadline) } else { self.original.adopt(deadline) });
        if matches!(self.open, Some(Err(_))) {
            self.first = Some(CurrentNixCarrierFailureV1::Open);
            return Err(());
        }
        Ok(())
    }

    fn refuse<T>(&mut self) -> Result<T, ()> {
        self.refusal = Some(CurrentNixPreflightDataErrorV1::Repeated);
        if self.first.is_none() { self.first = Some(CurrentNixCarrierFailureV1::Refusal); }
        Err(())
    }

    fn read(&mut self, length: usize, check: &mut CurrentNixPeerCheck<'_>) -> Result<usize, ()> {
        if self.first.is_some() || self.used_reads == MAXIMUM_FRAME_READS { return self.refuse(); }
        let slot = self.used_reads;
        self.used_reads += 1;
        self.reads[slot] = Some(self.original.read_exact(length, check));
        match &self.reads[slot] {
            Some(Ok(index)) => Ok(*index),
            _ => { self.first = Some(CurrentNixCarrierFailureV1::Read(slot)); Err(()) }
        }
    }

    fn receive(&mut self, phase: CurrentNixPhaseV1, check: &mut CurrentNixPeerCheck<'_>)
        -> Result<Option<usize>, ()>
    {
        if self.used_headers == MAXIMUM_FRAME_HEADERS { return self.refuse(); }
        let slot = self.used_headers;
        self.used_headers += 1;
        let header = self.read(FRAME_HEADER_BYTES, check)?;
        let returned = match (&self.correlation, self.original.bytes(header)) {
            (Some(Ok(correlation)), Ok(bytes)) => correlation.require_header(bytes, phase),
            _ => Err(CurrentNixPreflightDataErrorV1::Changed),
        };
        self.headers[slot] = Some(returned);
        let length = match &self.headers[slot] {
            Some(Ok(length)) => *length,
            _ => { self.first = Some(CurrentNixCarrierFailureV1::Header(slot)); return Err(()); }
        };
        if length == 0 { Ok(None) } else { self.read(length, check).map(Some) }
    }

    fn write(&mut self, bytes: &[u8], check: &mut CurrentNixPeerCheck<'_>) -> Result<(), ()> {
        if self.first.is_some() || self.used_writes == MAXIMUM_FRAME_WRITES { return self.refuse(); }
        let slot = self.used_writes;
        self.used_writes += 1;
        self.writes[slot] = Some(self.original.write(bytes, check));
        if matches!(self.writes[slot], Some(Ok(()))) { Ok(()) }
        else { self.first = Some(CurrentNixCarrierFailureV1::Write(slot)); Err(()) }
    }

    fn send(&mut self, phase: CurrentNixPhaseV1, bytes: &[u8], check: &mut CurrentNixPeerCheck<'_>)
        -> Result<(), ()>
    {
        if self.used_sent_headers == MAXIMUM_FRAME_HEADERS || self.first.is_some() { return self.refuse(); }
        let slot = self.used_sent_headers;
        self.used_sent_headers += 1;
        let header = match &self.correlation {
            Some(Ok(correlation)) => correlation.header(phase, bytes.len()),
            _ => Err(CurrentNixPreflightDataErrorV1::Changed),
        };
        let header = match header {
            Ok(header) => header,
            Err(error) => {
                self.refusal = Some(error);
                self.first = Some(CurrentNixCarrierFailureV1::Refusal);
                return Err(());
            }
        };
        self.sent_headers[slot] = Some(header);
        self.write(&header, check)?;
        if bytes.is_empty() { Ok(()) } else { self.write(bytes, check) }
    }

    fn finish_sending(&mut self) -> Result<(), ()> {
        if self.shutdown.is_some() { return self.refuse(); }
        self.shutdown = Some(self.original.finish_sending());
        if matches!(self.shutdown, Some(Ok(()))) { Ok(()) }
        else { if self.first.is_none() { self.first = Some(CurrentNixCarrierFailureV1::Shutdown); } Err(()) }
    }

    fn require_eof(&mut self, check: &mut CurrentNixPeerCheck<'_>) -> Result<(), ()> {
        if self.eof.is_some() { return self.refuse(); }
        self.eof = Some(self.original.require_eof(check));
        if matches!(self.eof, Some(Ok(()))) { Ok(()) }
        else { if self.first.is_none() { self.first = Some(CurrentNixCarrierFailureV1::Eof); } Err(()) }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            CurrentNixCarrierFailureV1::Correlation => self.correlation.as_ref()?.as_ref().err().map(|e| e as _),
            CurrentNixCarrierFailureV1::Deadline => self.deadline.as_ref()?.as_ref().err().map(|e| e as _),
            CurrentNixCarrierFailureV1::Open => self.open.as_ref()?.as_ref().err().map(|e| e as _),
            CurrentNixCarrierFailureV1::Read(slot) => {
                if let Some(error) = self.original.receive_failure() { return Some(error); }
                self.reads[slot].as_ref()?.as_ref().err().map(|e| e as _)
            }
            CurrentNixCarrierFailureV1::Header(slot) => self.headers[slot].as_ref()?.as_ref().err().map(|e| e as _),
            CurrentNixCarrierFailureV1::Write(slot) => self.writes[slot].as_ref()?.as_ref().err().map(|e| e as _),
            CurrentNixCarrierFailureV1::Shutdown => self.shutdown.as_ref()?.as_ref().err().map(|e| e as _),
            CurrentNixCarrierFailureV1::Eof => {
                if let Some(error) = self.original.receive_failure() { return Some(error); }
                self.eof.as_ref()?.as_ref().err().map(|e| e as _)
            }
            CurrentNixCarrierFailureV1::Refusal => self.refusal.as_ref().map(|e| e as _),
        }
    }
}

/// Retains one current-Start preflight outside the Session-owned paid intake.
///
/// The actual CurrentStart lends its Controller fields only during private
/// entry and later bookends. This owner borrows the same Source inventory, not
/// CurrentStart, so the original Current can be reborrowed without a second
/// mutable loan or a self-reference in the intake archive. Only its genuine
/// CurrentStart handoff can populate the initial capture.
pub struct CurrentNixPreflightAttemptV1<'source> {
    entered: bool,
    paid_entry_refusal: Option<crate::ResourceReservationErrorV1>,
    paid_entry_refusal_first: bool,
    paid_source_result: Option<Result<(), crate::ResourceReservationErrorV1>>,
    paid_source_refusal_first: bool,
    input: input::CurrentNixInputAttemptV1<'source>,
    current_before:
        Option<Result<(), crate::production_operation_compiler::NixStartContinuationErrorV2>>,
    original_clock: Option<RawPairedClockSample>,
    original_deadline: u64,
    controller_sequence: u64,
    metadata: Option<Result<(), CurrentNixPreflightDataErrorV1>>,
    source_after_failed_entry: Option<Result<(), JournalError>>,
    current_posts:
        [Option<Result<(), crate::production_operation_compiler::NixStartContinuationErrorV2>>; 3],
    used_current_posts: usize,
    carrier: CurrentNixPreflightCarrierV1,
    context: Option<Result<CurrentNixPreflightContextV1, CurrentNixPreflightDataErrorV1>>,
    receipt: Option<PreparedCurrentNixControllerReceiptV1>,
    refusal: Option<CurrentNixPreflightDataErrorV1>,
}

/// Archives the same reached preflight payloads without a Current or Source loan.
///
/// This consuming closure is diagnostic custody, not a Root/currentness or
/// bank permission. The retained transport still owns its shutdown result and
/// original descriptors; no naked socket or decoded derivation is extracted.
pub struct CurrentNixPreflightOriginalsV1 {
    paid_entry_refusal: Option<crate::ResourceReservationErrorV1>,
    paid_entry_refusal_first: bool,
    paid_source_result: Option<Result<(), crate::ResourceReservationErrorV1>>,
    paid_source_refusal_first: bool,
    input: input::CurrentNixInputOriginalsV1,
    current_before:
        Option<Result<(), crate::production_operation_compiler::NixStartContinuationErrorV2>>,
    original_clock: Option<RawPairedClockSample>,
    original_deadline: u64,
    controller_sequence: u64,
    metadata: Option<Result<(), CurrentNixPreflightDataErrorV1>>,
    source_after_failed_entry: Option<Result<(), JournalError>>,
    current_posts:
        [Option<Result<(), crate::production_operation_compiler::NixStartContinuationErrorV2>>; 3],
    carrier: CurrentNixPreflightCarrierV1,
    context: Option<Result<CurrentNixPreflightContextV1, CurrentNixPreflightDataErrorV1>>,
    receipt: Option<PreparedCurrentNixControllerReceiptV1>,
    refusal: Option<CurrentNixPreflightDataErrorV1>,
}

// Live and archived custody project the same original errors. The view has
// only borrowed slots; it cannot recheck or recreate either former lender.
struct CurrentNixPreflightFailureViewV1<'original> {
    paid_entry_refusal: &'original Option<crate::ResourceReservationErrorV1>,
    paid_entry_refusal_first: bool,
    paid_source_result: &'original Option<Result<(), crate::ResourceReservationErrorV1>>,
    paid_source_refusal_first: bool,
    current_before: &'original Option<
        Result<(), crate::production_operation_compiler::NixStartContinuationErrorV2>,
    >,
    metadata: &'original Option<Result<(), CurrentNixPreflightDataErrorV1>>,
    source_after_failed_entry: &'original Option<Result<(), JournalError>>,
    input_failure: Option<&'original (dyn std::error::Error + 'static)>,
    carrier: &'original CurrentNixPreflightCarrierV1,
    context:
        &'original Option<Result<CurrentNixPreflightContextV1, CurrentNixPreflightDataErrorV1>>,
    current_posts: &'original [Option<
        Result<(), crate::production_operation_compiler::NixStartContinuationErrorV2>,
    >; 3],
    refusal: &'original Option<CurrentNixPreflightDataErrorV1>,
}

impl<'original> CurrentNixPreflightFailureViewV1<'original> {
    fn failure(self) -> Option<&'original (dyn std::error::Error + 'static)> {
        if self.paid_entry_refusal_first {
            return self.paid_entry_refusal.as_ref().map(|error| error as _);
        }
        if self.paid_source_refusal_first {
            return self.paid_source_result.as_ref()?.as_ref().err().map(|error| error as _);
        }
        if let Some(Err(error)) = self.current_before { return Some(error); }
        if let Some(Err(error)) = self.metadata { return Some(error); }
        if let Some(Err(error)) = self.source_after_failed_entry { return Some(error); }
        if let Some(error) = self.input_failure { return Some(error); }
        if let Some(error) = self.carrier.failure() { return Some(error); }
        if let Some(Err(error)) = self.context { return Some(error); }
        for result in self.current_posts.iter().flatten() {
            if let Err(error) = result { return Some(error); }
        }
        self.refusal.as_ref().map(|error| error as _)
            .or_else(|| self.paid_entry_refusal.as_ref().map(|error| error as _))
            .or_else(|| self.paid_source_result.as_ref()?.as_ref().err().map(|error| error as _))
    }
}

impl CurrentNixPreflightOriginalsV1 {
    /// Borrows the actual retained capture or closure cause without observation.
    ///
    /// The same original native errors survive the consuming archive transfer;
    /// this projection supplies no former Current, Source or Root permission.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        CurrentNixPreflightFailureViewV1 {
            paid_entry_refusal: &self.paid_entry_refusal,
            paid_entry_refusal_first: self.paid_entry_refusal_first,
            paid_source_result: &self.paid_source_result,
            paid_source_refusal_first: self.paid_source_refusal_first,
            current_before: &self.current_before, metadata: &self.metadata,
            source_after_failed_entry: &self.source_after_failed_entry,
            input_failure: self.input.failure(), carrier: &self.carrier,
            context: &self.context, current_posts: &self.current_posts,
            refusal: &self.refusal,
        }.failure()
    }
}

impl<'source> CurrentNixPreflightAttemptV1<'source> {
    /// Prices only the reached current-Start and Source-inventory capture.
    ///
    /// The same intake prices this supplement before either capture grows.
    /// The existing intake recipe supplies the shared journal/carrier copy
    /// accounting; decoded input and Tree containers are charged separately.
    /// This does not price or admit the Root flight, Source16, signatures or
    /// compiler. Their receiving origin and complete demand remain separate.
    /// CPU execution stays under the original intake's already priced cgroup
    /// interval; this supplement is not a syscall/work bound or physical peak.
    ///
    /// # Errors
    /// Refuses representation arithmetic overflow or existing journal bounds.
    /// A large valid cut may exceed I; no journal or image ceiling is raised.
    pub(crate) fn input_capture_demand_v1(
        controller: &crate::journal::JournalShape,
        source: &crate::journal::JournalShape,
    ) -> Result<aos_sandbox_model::ResourceVector, crate::ResourceReservationErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_ledger_replay::replay::hierarchy_records::{HierarchyJournalReplayTransactionV1, HierarchyProtectedJournalEnvelopeV1, HierarchyProtectedJournalSchemaV1};
        use aos_sandbox_protocol::domain_ledger::records::ProtectedCurrentRecordCandidateV1;

        let refused = || crate::ResourceReservationErrorV1::Conflict;
        let owner_bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<CurrentNixPreflightOriginalsV1>())
            .ok_or_else(refused)?;
        let copies = crate::production_operation_compiler::ControllerNixStartRecipeSelectorV2::
            original_start_intake_demand(controller, source, ResourceVector::ZERO, owner_bytes)?;

        // Encoded bytes bound logical entries, not allocator nodes. Charge an
        // entry of every reached decoded representation per source byte, with
        // four co-resident construction/validation copies. This deliberately
        // overprices sparse histories rather than assuming Vec/BTree metadata
        // disappears when only their final inventory is returned.
        let decoded_cell_bytes = std::mem::size_of::<crate::sandbox_spec_state::DurableSandboxSpecV1>()
            .checked_add(std::mem::size_of::<crate::runtime_authority::RuntimeAuthorityBindingV1>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HierarchyProtectedJournalEnvelopeV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HierarchyJournalReplayTransactionV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                ProtectedCurrentRecordCandidateV1<HierarchyProtectedJournalSchemaV1>,
            >()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_ledger_replay::hierarchy::graph::SandboxTreeV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_model::source_tree_model::SandboxTreeRecordV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(SandboxId, usize, [usize; 6])>()))
            .ok_or_else(refused)?;
        let decoded_cells = controller
            .retained_bytes
            .checked_add(source.retained_bytes)
            .and_then(|bytes| bytes.checked_add(1_048_576))
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or_else(refused)?;
        let decoded_bytes = decoded_cells
            .checked_mul(decoded_cell_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(refused)?;
        let decoded_cells = u64::try_from(decoded_cells).map_err(|_| refused())?;

        // Capture reuses held writers and starts no worker, socket or append.
        // The ordinary intake owns those costs and its whole CPU interval.
        Ok(copies
            .with(D::CpuMicrosPerPeriod, 0)
            .with(D::Pids, 0)
            .with(D::OpenFiles, 0)
            .with(D::StorageBytes, 0)
            .with(D::ConcurrentOperations, 0)
            .with(
                D::MemoryBytes,
                copies
                    .get(D::MemoryBytes)
                    .checked_add(decoded_bytes)
                    .ok_or_else(refused)?,
            )
            .with(
                D::MetadataEntries,
                copies
                    .get(D::MetadataEntries)
                    .checked_add(decoded_cells)
                    .ok_or_else(refused)?,
            )
            .with(
                D::PublicationStagingBytes,
                copies
                    .get(D::PublicationStagingBytes)
                    .checked_add(decoded_bytes)
                    .ok_or_else(refused)?,
            )
            .with(
                D::LogBytes,
                copies
                    .get(D::LogBytes)
                    .checked_add(decoded_bytes)
                    .ok_or_else(refused)?,
            )
            .with(
                D::OutputBytes,
                copies
                    .get(D::OutputBytes)
                    .checked_add(decoded_bytes)
                    .ok_or_else(refused)?,
            ))
    }

    /// Prearms original capture and flight destinations without any observation.
    pub fn empty() -> Self {
        Self {
            entered: false,
            paid_entry_refusal: None,
            paid_entry_refusal_first: false,
            paid_source_result: None,
            paid_source_refusal_first: false,
            input: input::CurrentNixInputAttemptV1::empty(),
            current_before: None,
            original_clock: None,
            original_deadline: 0,
            controller_sequence: 0,
            metadata: None,
            source_after_failed_entry: None,
            current_posts: [const { None }; 3],
            used_current_posts: 0,
            carrier: CurrentNixPreflightCarrierV1::empty(),
            context: None,
            receipt: None,
            refusal: None,
        }
    }

    /// Parks the original paid-entry refusal without entering any observation.
    ///
    /// The caller returns before Current recheck or Source capture. This closes
    /// the same attempt while preserving every earlier resident cause.
    ///
    /// # Errors
    /// Always returns a marker; the first whole intake error remains resident.
    pub(crate) fn park_paid_entry_refusal(
        &mut self,
        error: crate::ResourceReservationErrorV1,
    ) -> Result<(), ()> {
        if self.paid_entry_refusal.is_none() {
            self.paid_entry_refusal_first = self.failure().is_none();
            self.paid_entry_refusal = Some(error);
        }
        self.entered = true;
        Err(())
    }

    /// Parks the paid intake's whole original Source-binding comparison.
    ///
    /// The genuine Current handoff supplies this result after checking that I
    /// remains open. This pure park neither borrows nor observes either owner.
    ///
    /// # Errors
    /// Refuses repeated entry or a failed comparison before Current recheck and
    /// Source capture; the original result and earlier cause remain resident.
    pub(crate) fn park_paid_source_result(
        &mut self,
        result: Result<(), crate::ResourceReservationErrorV1>,
    ) -> Result<(), ()> {
        if self.entered || self.paid_source_result.is_some() {
            self.entered = true;
            self.refusal.get_or_insert(CurrentNixPreflightDataErrorV1::Repeated);
            return Err(());
        }
        let failed = result.is_err();
        if failed {
            self.paid_source_refusal_first = self.failure().is_none();
        }
        self.paid_source_result = Some(result);
        if failed {
            self.entered = true;
            Err(())
        } else {
            Ok(())
        }
    }

    // Only CurrentRetainedNixStart's installed handoff calls this method. The
    // original receipt fields are not caller-selected authority or a new grant.
    pub(crate) fn capture_current_originals_once(
        &mut self,
        controller: &mut crate::Journal,
        source: &'source mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        carrier: &crate::production_operation_compiler::NixStartAdmissionCarrierV2,
        binding: &crate::runtime_authority::RuntimeAuthorityBindingV1,
        original_clock: Option<RawPairedClockSample>,
        original_deadline: u64,
        before: Result<(), crate::production_operation_compiler::NixStartContinuationErrorV2>,
    ) -> Result<(), ()> {
        if self.entered || !matches!(self.paid_source_result, Some(Ok(()))) {
            self.entered = true;
            self.refusal.get_or_insert(CurrentNixPreflightDataErrorV1::Repeated);
            return Err(());
        }
        self.entered = true;
        self.current_before = Some(before);
        self.original_clock = original_clock;
        self.original_deadline = original_deadline;
        self.controller_sequence = controller.snapshot_sequence();
        self.metadata = Some(if original_clock.is_some_and(|clock| {
            clock.provenance().as_bytes() == CONTROLLER_CLOCK_PROVENANCE
                && original_deadline > clock.boottime_nanoseconds()
        }) {
            Ok(())
        } else {
            Err(CurrentNixPreflightDataErrorV1::Changed)
        });

        if !matches!(self.current_before, Some(Ok(())))
            || !matches!(self.metadata, Some(Ok(())))
        {
            // No replay follows a failed original admission. The independent
            // Source-name observation remains resident even on that route.
            self.source_after_failed_entry = Some(source.require_fixed_named_writer_v1());
            return Err(());
        }
        self.input.capture_once(controller, source, carrier, binding)
    }

    /// Borrows the earliest retained capture cause without another observation.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        CurrentNixPreflightFailureViewV1 {
            paid_entry_refusal: &self.paid_entry_refusal,
            paid_entry_refusal_first: self.paid_entry_refusal_first,
            paid_source_result: &self.paid_source_result,
            paid_source_refusal_first: self.paid_source_refusal_first,
            current_before: &self.current_before, metadata: &self.metadata,
            source_after_failed_entry: &self.source_after_failed_entry,
            input_failure: self.input.failure(), carrier: &self.carrier,
            context: &self.context, current_posts: &self.current_posts,
            refusal: &self.refusal,
        }.failure()
    }

    // The Current owner parks these actual evaluator/bookend Results. A
    // refusing post never overwrites an earlier cause or reopens this attempt.
    pub(crate) fn park_current_post(
        &mut self,
        result: Result<(), crate::production_operation_compiler::NixStartContinuationErrorV2>,
    ) -> Result<(), ()> {
        if !self.entered || self.used_current_posts == self.current_posts.len() {
            self.refusal.get_or_insert(CurrentNixPreflightDataErrorV1::Repeated);
            return Err(());
        }
        let slot = self.used_current_posts;
        self.used_current_posts += 1;
        self.current_posts[slot] = Some(result);
        if self.failure().is_some() { Err(()) } else { Ok(()) }
    }

    /// Consumes only nonborrowing payloads into the original intake archive.
    ///
    /// An unfinished flight is shut down on its same original carrier, retaining
    /// ambiguity. This does not acknowledge a derivation or release a paid claim.
    /// The caller still observes its genuine Current clock after this closure.
    pub fn into_retained_originals(mut self) -> CurrentNixPreflightOriginalsV1 {
        self.carrier.original.end();
        CurrentNixPreflightOriginalsV1 {
            paid_entry_refusal: self.paid_entry_refusal,
            paid_entry_refusal_first: self.paid_entry_refusal_first,
            paid_source_result: self.paid_source_result,
            paid_source_refusal_first: self.paid_source_refusal_first,
            input: self.input.into_retained_originals(),
            current_before: self.current_before,
            original_clock: self.original_clock,
            original_deadline: self.original_deadline,
            controller_sequence: self.controller_sequence,
            metadata: self.metadata,
            source_after_failed_entry: self.source_after_failed_entry,
            current_posts: self.current_posts,
            carrier: self.carrier,
            context: self.context,
            receipt: self.receipt,
            refusal: self.refusal,
        }
    }
}

/// Retains one accepted current-Nix Root flight and its actual two writers.
///
/// This is an external prearmed destination, not an authority packet. The same
/// endpoint, startup/peer, existing Policy writer and last-acquired Root writer
/// stay resident on success and failure. A derivation reply will not release
/// either writer before the dependent original consumer and terminal ACK/EOF.
pub struct CurrentNixRootPreflightAttemptV1<'startup> {
    carrier: Option<CurrentNixPreflightCarrierV1>,
    bootstrap: Option<[u8; 32]>,
    startup: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    peer: Option<
        Result<
            crate::normal_root::OriginalControllerPolicyPeerV1<'startup>,
            crate::normal_root::NormalRootStartupErrorV1,
        >,
    >,
    policy_opening: aos_sandbox_policy::native::CurrentNixPolicyOpeningV1,
    policy: Option<(
        super::PolicyCompilerStateReadbackOwnerV1,
        aos_sandbox_broker::canonical_journal::RecoveryReport,
    )>,
    root_opening: aos_sandbox_policy::native::RootFirstSourceSuccessorOpeningV2,
    root: Option<aos_sandbox_policy::native::RootSourceGenesisAuthorityV1>,
    transport_root_check: Option<Result<(), SourceGenesisErrorV1>>,
    actions: [Option<Result<(), ()>>; 4],
    challenge: Option<Result<[u8; 16], SourceGenesisErrorV1>>,
    archive: aos_sandbox_policy::native::CurrentNixRootArchiveAttemptV1,
    selection: Option<Result<[u8; 48], CurrentNixPreflightDataErrorV1>>,
    context: Option<Result<CurrentNixPreflightContextV1, CurrentNixPreflightDataErrorV1>>,
    start: Option<
        Result<
            Option<crate::production_operation_compiler::NixStartAdmissionCarrierV2>,
            crate::production_operation_compiler::NixStartAdmissionErrorV2,
        >,
    >,
    manifest: Option<
        Result<
            aos_sandbox_model::CanonicalAssignmentManifestV1,
            aos_sandbox_model::CanonicalCborError,
        >,
    >,
    received_specification:
        Option<Result<aos_sandbox_model::model::SandboxSpec, aos_sandbox_model::CanonicalCborError>>,
    association: Option<Result<(), CurrentNixPreflightDataErrorV1>>,
    policy_posts: [Option<Result<(), aos_sandbox_policy::native::PolicyCompilerJournalErrorV1>>; 4],
    root_posts: [Option<Result<(), SourceGenesisErrorV1>>; 4],
    peer_posts: [Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>; 4],
    clocks: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 4],
    pairs: [Option<Result<(), CurrentNixPreflightDataErrorV1>>; 4],
    used_posts: usize,
    source_requested: bool,
    refusal: Option<CurrentNixPreflightDataErrorV1>,
}

impl<'startup> CurrentNixRootPreflightAttemptV1<'startup> {
    /// Prearms all opening, framing, signature and independent post destinations.
    pub fn empty() -> Self {
        Self {
            carrier: None, bootstrap: None, startup: None, peer: None,
            policy_opening: aos_sandbox_policy::native::CurrentNixPolicyOpeningV1::empty(), policy: None,
            root_opening: aos_sandbox_policy::native::RootFirstSourceSuccessorOpeningV2::new(), root: None,
            transport_root_check: None, actions: [None; 4],
            challenge: None, archive: aos_sandbox_policy::native::CurrentNixRootArchiveAttemptV1::empty(),
            selection: None, context: None, start: None, manifest: None,
            received_specification: None, association: None,
            policy_posts: [const { None }; 4],
            root_posts: [const { None }; 4], peer_posts: [const { None }; 4],
            clocks: [const { None }; 4], pairs: [const { None }; 4],
            used_posts: 0, source_requested: false, refusal: None,
        }
    }

    /// Parks the same accepted endpoint before any selected opening or observation.
    ///
    /// This future API is not connected to the installed dispatcher. Its startup
    /// recheck is unfinanced: the genuine original Root receiving R is missing.
    /// It must remain inactive until that original pays its verification prefix;
    /// Controller flight payment or decoded requests do not finance this entry.
    ///
    /// # Errors
    /// Retains actual transport/startup/peer/Policy/Root errors and refuses an
    /// occupied destination, invalid bootstrap, foreign subject or lost writer.
    pub fn accept_once(
        &mut self,
        original: std::os::unix::net::UnixStream,
        startup: &'startup crate::normal_root::ProductionNormalRootStartupV1,
        bootstrap: [u8; 32],
        controller_uid: u32,
        source_uid: u32,
    ) -> Result<(), ()> {
        if self.carrier.is_some() {
            self.refusal = Some(CurrentNixPreflightDataErrorV1::Repeated);
            return Err(());
        }
        self.carrier = Some(CurrentNixPreflightCarrierV1::accepted(original));
        self.bootstrap = Some(bootstrap);
        self.startup = Some(startup.recheck());
        let result = (|| {
            if !matches!(self.startup, Some(Ok(()))) { return Err(()); }
            let carrier = self.carrier.as_mut().ok_or(())?;
            carrier.begin(&bootstrap, false)?;
            self.peer = Some(startup.observe_controller_policy_peer(carrier.original.stream().map_err(|_| ())?));
            if !matches!(self.peer, Some(Ok(_))) { return Err(()); }
            self.policy_opening.open_into(&mut self.policy)?;
            // Controller and Source are already held by the original caller;
            // Policy precedes this one actual last-acquired Root writer.
            self.root_opening.open_project_successor_into_v3(&mut self.root, controller_uid, source_uid)?;
            let root = self.root.as_ref().ok_or(())?;
            self.challenge = Some(root.current_nix_challenge_data_v1().map_err(SourceGenesisErrorV1::from));
            let challenge = *self.challenge.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
            let peer = self.peer.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
            let root_check = &mut self.transport_root_check;
            let mut check = |stream: &_, chunk: Option<&aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk>| {
                let observed = match chunk {
                    Some(chunk) => peer.require_chunk(stream, chunk),
                    None => peer.recheck_stream(stream),
                };
                observed.map_err(ConsumerReadFlightErrorV1::from)?;
                if matches!(root_check, Some(Err(_))) {
                    return Err(ConsumerReadFlightErrorV1::Protocol.into());
                }
                // A successful unit check has no payload to retain. Its first
                // failed original Result stays here, not in a Protocol marker.
                *root_check = Some(root.recheck().map_err(SourceGenesisErrorV1::from));
                if !matches!(root_check, Some(Ok(()))) {
                    return Err(ConsumerReadFlightErrorV1::Protocol.into());
                }
                Ok(())
            };
            carrier.send(CurrentNixPhaseV1::Hello, &challenge, &mut check)?;
            let selection = carrier.receive(CurrentNixPhaseV1::Select, &mut check)?.ok_or(())?;
            self.selection = Some(carrier.original.bytes(selection)
                .map_err(|_| CurrentNixPreflightDataErrorV1::Changed)
                .and_then(|bytes| take(bytes, 0)));
            let selection = self.selection.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
            if selection.chunks_exact(16).any(|identity| identity == [0; 16]) {
                self.refusal = Some(CurrentNixPreflightDataErrorV1::Changed);
                return Err(());
            }
            root.capture_current_nix_archive_into_v1(
                &mut self.archive, ProjectId::from_bytes(take(selection, 16).map_err(|_| ())?),
            )
        })();
        self.actions[0] = Some(result);
        self.posts();
        if !matches!(self.actions[0], Some(Ok(()))) || self.failure().is_some() {
            Err(())
        } else {
            Ok(())
        }
    }

    // All available posts run on the same originals after earlier failure. The
    // actual native pair is last; no normalized peer DATA supplies this sample.
    fn posts(&mut self) {
        if self.used_posts == self.root_posts.len() {
            if self.refusal.is_none() { self.refusal = Some(CurrentNixPreflightDataErrorV1::Repeated); }
            return;
        }
        let slot = self.used_posts;
        self.used_posts += 1;
        if let Some((policy, _)) = &self.policy {
            self.policy_posts[slot] = Some(self.policy_opening.recheck_transferred_original(policy));
        }
        if let Some(root) = &self.root { self.root_posts[slot] = Some(root.recheck().map_err(SourceGenesisErrorV1::from)); }
        if let (Some(Ok(peer)), Some(carrier)) = (&self.peer, &self.carrier) {
            if let Ok(stream) = carrier.original.stream() {
                self.peer_posts[slot] = Some(peer.recheck_stream(stream));
            }
        }
        self.clocks[slot] = Some(super::observe_root_first_source_successor_clock_v2(None));
        if let (Some(Ok(context)), Some(Ok(clock))) = (&self.context, &self.clocks[slot]) {
            self.pairs[slot] = Some(context.require_original_kernel_sample_data_v1(*clock));
        }
    }

    /// Borrows resident opening and transport causes without replacing any owner.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.startup { return Some(error); }
        if let Some(Err(error)) = &self.transport_root_check { return Some(error); }
        if let Some(error) = self.carrier.as_ref().and_then(CurrentNixPreflightCarrierV1::failure) { return Some(error); }
        if let Some(Err(error)) = &self.peer { return Some(error); }
        if let Some(error) = self.policy_opening.failure() { return Some(error); }
        if let Some(error) = self.root_opening.error() { return Some(error); }
        if let Some(Err(error)) = &self.challenge { return Some(error); }
        if let Some(Err(error)) = &self.selection { return Some(error); }
        if let Some(error) = self.archive.failure() { return Some(error); }
        for slot in 0..self.used_posts {
            if let Some(Err(error)) = &self.policy_posts[slot] { return Some(error); }
            if let Some(Err(error)) = &self.root_posts[slot] { return Some(error); }
            if let Some(Err(error)) = &self.peer_posts[slot] { return Some(error); }
            if let Some(Err(error)) = &self.clocks[slot] { return Some(error); }
            if let Some(Err(error)) = &self.pairs[slot] { return Some(error); }
        }
        self.refusal.as_ref().map(|error| error as _)
    }
}

// It owns all signature preimage bytes before the original clock is checked.
struct PreparedCurrentNixControllerReceiptV1 {
    bytes: [u8; CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1],
    message: [u8; CONTROLLER_SIGNATURE_DOMAIN.len() + CONTROLLER_BODY_BYTES],
}

impl PreparedCurrentNixControllerReceiptV1 {
    fn sign(&mut self, key: &SigningKey) {
        let signature = key.sign(&self.message);
        self.bytes[CONTROLLER_BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    }
}


pub(super) fn take<const N: usize>(
    bytes: &[u8], offset: usize,
) -> Result<[u8; N], CurrentNixPreflightDataErrorV1> {
    let (value, _) = checked_byte_region(bytes, offset, N)
        .map_err(|_| CurrentNixPreflightDataErrorV1::Changed)?;
    value
        .try_into()
        .map_err(|_| CurrentNixPreflightDataErrorV1::Changed)
}
