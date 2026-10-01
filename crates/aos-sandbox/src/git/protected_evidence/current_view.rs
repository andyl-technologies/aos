//! Borrows current Git comparison DATA on one retained normal-Root flight.
//!
//! The original startup/peer, exclusive deadline, returned writer and failed
//! receive custody remain resident. Neither metadata nor terminal EOF grants
//! authority, rollback resistance, an effect, remote release, ACK or Drain.
//! Earlier bootstrap, opener and partial lower-adoption failures remain outside
//! this returned-owner boundary. Root abandonment aborts before fields drop.
//!
//! ```text
//! bootstrap32 = AOSGQV01 | client-nonce16 | BOOTTIME-cutoff:u64be
//! header72 = AOSGVF01 | version:u16be(1) | phase:u8 | zero5 |
//!            client-nonce16 | root-nonce16 | cutoff:u64be |
//!            sequence:u32be | payload-length:u32be | zero8
//! HELLO(1):boot16; RECORD(2):AOSGITE1; CHECK(3):empty;
//! CHECKED(4), RELEASE(5), RELEASED(6), TERMINAL(7):record-digest32
//! ```

#[cfg(test)]
mod tests;

use std::fmt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};

use super::{
    DecodedGitEvidenceV1, FixedLiveAuthorityClockV1, GitProtectedEvidenceErrorV1,
    LiveAuthorityClockSampleV1, PROTECTED_GIT_EVIDENCE_JOURNAL,
    PROTECTED_GIT_EVIDENCE_KEY, PROTECTED_GIT_EVIDENCE_ROOT, decode_evidence,
    fixed_live_authority_clock_v1, git_evidence_journal_limits, read_exact_evidence_record,
    validate_bracketed_samples_v1, validate_currentness,
};
use crate::journal::{Journal, ProtectedJournalSnapshot, RecordNamespace, RecoveryReport};
use crate::normal_root::{
    OriginalControllerPolicyPeerV1, OriginalNormalRootPeerV1,
    ProductionControllerNormalRootProfileV1, ProductionNormalRootStartupV1,
};
use crate::policy_compiler::consumer_read_flight::{
    ConsumerReadFlightErrorV1 as CarrierError, Deadline, RetainedCarrier, TransportFault,
};
use crate::policy_compiler::{
    PolicyCompilerJournalErrorV1, fresh_root_nonce, require_no_fixed_closed_policy_binding_hold_v1,
};

/// Discriminates complete inert Git metadata bootstrap DATA at the Root listener.
pub const GIT_EVIDENCE_VIEW_BOOTSTRAP_MAGIC_V1: &[u8; 8] = b"AOSGQV01";

const HEADER_MAGIC: &[u8; 8] = b"AOSGVF01";
const HEADER_BYTES: usize = 72;
const MAXIMUM_CHECKS: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Hello = 1,
    Record = 2,
    Check = 3,
    Checked = 4,
    Release = 5,
    Released = 6,
    Terminal = 7,
}

impl Phase {
    fn decode(code: u8) -> Result<Self, Failure> {
        match code {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Record),
            3 => Ok(Self::Check),
            4 => Ok(Self::Checked),
            5 => Ok(Self::Release),
            6 => Ok(Self::Released),
            7 => Ok(Self::Terminal),
            _ => Err(Failure::Protocol),
        }
    }

    fn require_length(self, length: usize) -> Result<(), Failure> {
        let valid = match self {
            Self::Hello => length == 16,
            Self::Record => (super::FIXED_PREFIX_BYTES + super::DIGEST_BYTES
                ..=git_evidence_journal_limits().maximum_record_bytes).contains(&length),
            Self::Check => length == 0,
            Self::Checked | Self::Release | Self::Released | Self::Terminal => length == 32,
        };
        if valid {
            Ok(())
        } else {
            Err(Failure::Protocol)
        }
    }
}

#[derive(Clone, Copy)]
struct Coordinates {
    client: [u8; 16],
    root: [u8; 16],
    cutoff: u64,
}

impl Coordinates {
    fn bootstrap(bytes: &[u8; 32]) -> Result<Self, Failure> {
        let client = take(bytes, 8)?;
        let cutoff = u64::from_be_bytes(take(bytes, 24)?);
        if &bytes[..8] != GIT_EVIDENCE_VIEW_BOOTSTRAP_MAGIC_V1
            || client == [0; 16] || cutoff == 0
        {
            return Err(Failure::Protocol);
        }
        Ok(Self {
            client,
            root: [0; 16],
            cutoff,
        })
    }

    fn encode_bootstrap(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(GIT_EVIDENCE_VIEW_BOOTSTRAP_MAGIC_V1);
        bytes[8..24].copy_from_slice(&self.client);
        bytes[24..].copy_from_slice(&self.cutoff.to_be_bytes());
        bytes
    }

    fn header(self, phase: Phase, sequence: u32, length: usize) -> Result<[u8; HEADER_BYTES], Failure> {
        phase.require_length(length)?;
        require_sequence(phase, sequence)?;
        if self.client == [0; 16] || self.root == [0; 16] || self.cutoff == 0 {
            return Err(Failure::Protocol);
        }
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(HEADER_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = phase as u8;
        bytes[16..32].copy_from_slice(&self.client);
        bytes[32..48].copy_from_slice(&self.root);
        bytes[48..56].copy_from_slice(&self.cutoff.to_be_bytes());
        bytes[56..60].copy_from_slice(&sequence.to_be_bytes());
        bytes[60..64].copy_from_slice(&u32::try_from(length).map_err(|_| Failure::Protocol)?.to_be_bytes());
        Ok(bytes)
    }

    fn decode_header(self, bytes: &[u8], adopt_hello: bool)
        -> Result<(Phase, u32, usize, [u8; 16]), Failure>
    {
        if bytes.len() != HEADER_BYTES || &bytes[..8] != HEADER_MAGIC
            || u16::from_be_bytes(take(bytes, 8)?) != 1
            || bytes[11..16] != [0; 5] || bytes[64..] != [0; 8]
            || take::<16>(bytes, 16)? != self.client
            || u64::from_be_bytes(take(bytes, 48)?) != self.cutoff
        {
            return Err(Failure::Protocol);
        }
        let phase = Phase::decode(bytes[10])?;
        let root = take(bytes, 32)?;
        let sequence = u32::from_be_bytes(take(bytes, 56)?);
        let length = usize::try_from(u32::from_be_bytes(take(bytes, 60)?))
            .map_err(|_| Failure::Protocol)?;
        let wrong_root = if adopt_hello {
            self.root != [0; 16] || phase != Phase::Hello
        } else {
            root != self.root
        };
        if root == [0; 16] || wrong_root {
            return Err(Failure::Protocol);
        }
        phase.require_length(length)?;
        require_sequence(phase, sequence)?;
        Ok((phase, sequence, length, root))
    }
}

fn require_sequence(phase: Phase, sequence: u32) -> Result<(), Failure> {
    let valid = match phase {
        Phase::Hello | Phase::Record => sequence == 0,
        Phase::Check | Phase::Checked => (1..=MAXIMUM_CHECKS).contains(&sequence),
        Phase::Release | Phase::Released | Phase::Terminal => (1..=MAXIMUM_CHECKS + 1).contains(&sequence),
    };
    if valid {
        Ok(())
    } else {
        Err(Failure::Protocol)
    }
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Failure> {
    let end = offset.checked_add(N).ok_or(Failure::Protocol)?;
    bytes.get(offset..end).ok_or(Failure::Protocol)?
        .try_into().map_err(|_| Failure::Protocol)
}

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error(transparent)]
    Transport(#[from] TransportFault),
    #[error(transparent)]
    Carrier(#[from] CarrierError),
    #[error(transparent)]
    Evidence(#[from] GitProtectedEvidenceErrorV1),
    #[error(transparent)]
    Startup(#[from] crate::normal_root::NormalRootStartupErrorV1),
    #[error(transparent)]
    Gate(#[from] PolicyCompilerJournalErrorV1),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Git metadata frame or phase differs")]
    Protocol,
    #[error("Git metadata attempt cannot resume")]
    State,
    #[error("Git metadata method did not finish")]
    Unfinished,
}

/// Borrows a redacted observation of the first resident failed attempt.
///
/// The underlying typed cause and both receive/shutdown owners remain in the
/// attempt. This view is tied to its borrow and grants no retirement or release.
pub struct GitRootEvidenceViewErrorV1<'attempt> {
    first: &'attempt Failure,
    receive: Option<&'attempt RetainedSeqpacketReceiveErrorV1>,
    shutdown: Option<&'attempt std::io::Error>,
}

impl GitRootEvidenceViewErrorV1<'_> {
    /// Borrows the first recorded cleanup failure without claiming clean shutdown.
    #[must_use]
    pub fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.shutdown
    }
}

impl fmt::Debug for GitRootEvidenceViewErrorV1<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitRootEvidenceViewErrorV1")
            .field("shutdown_failed", &self.shutdown.is_some()).finish_non_exhaustive()
    }
}

impl fmt::Display for GitRootEvidenceViewErrorV1<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("original Git metadata flight failed; custody remains retained")
    }
}

impl std::error::Error for GitRootEvidenceViewErrorV1<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.first, Failure::Transport(TransportFault::RetainedReceive)) {
            self.receive.map(|error| error as &dyn std::error::Error)
        } else {
            Some(self.first)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    New,
    Unfinished,
    Active,
    Failed,
    Complete,
}

// Prearmed before a mutable method's first fallible action. A caught unwind
// leaves Unfinished and is never converted into an invented I/O failure.
struct Latch {
    state: State,
    first: Option<Failure>,
    unfinished: Failure,
}

impl Latch {
    fn new() -> Self {
        Self {
            state: State::New,
            first: None,
            unfinished: Failure::Unfinished,
        }
    }

    fn begin(&mut self, expected: State) -> Result<(), Failure> {
        if self.state != expected {
            return Err(Failure::State);
        }
        self.state = State::Unfinished;
        Ok(())
    }

    fn finish(&mut self, result: Result<(), Failure>, success: State, carrier: &mut RetainedCarrier) {
        match result {
            Ok(()) => self.state = success,
            Err(error) => {
                if self.first.is_none() {
                    self.first = Some(error);
                }
                self.state = State::Failed;
                carrier.end();
            }
        }
    }

    fn error<'a>(&'a self, carrier: &'a RetainedCarrier) -> GitRootEvidenceViewErrorV1<'a> {
        GitRootEvidenceViewErrorV1 {
            first: self.first.as_ref().unwrap_or(&self.unfinished),
            receive: carrier.receive_failure(),
            shutdown: carrier.shutdown_failure(),
        }
    }
}

enum Peer<'origin> {
    Root(OriginalNormalRootPeerV1<'origin>),
    Controller(OriginalControllerPolicyPeerV1<'origin>),
}

impl Peer<'_> {
    fn check(&self, stream: &RetainedUnixStream, chunk: Option<&UnixStreamSubjectChunk>)
        -> Result<(), CarrierError>
    {
        match (self, chunk) {
            (Self::Root(peer), Some(chunk)) => peer.require_chunk(stream, chunk)?,
            (Self::Root(peer), None) => peer.recheck_stream(stream)?,
            (Self::Controller(peer), Some(chunk)) => peer.require_chunk(stream, chunk)?,
            (Self::Controller(peer), None) => peer.recheck_stream(stream)?,
        }
        Ok(())
    }
}

// Exactly one record backing per endpoint. Controller borrows its carrier's
// resident assembled bytes; Root owns the sole canonical protected read.
enum Record {
    Received(usize),
    Protected(Vec<u8>),
}

struct Flight<'origin> {
    carrier: RetainedCarrier,
    peer: Option<Peer<'origin>>,
    coordinates: Option<Coordinates>,
    outgoing: Option<[u8; HEADER_BYTES]>,
    bootstrap: Option<[u8; 32]>,
    record: Option<Record>,
    decoded: Option<DecodedGitEvidenceV1>,
    clock: Option<FixedLiveAuthorityClockV1>,
    last_sample: Option<LiveAuthorityClockSampleV1>,
    latch: Latch,
}

impl<'origin> Flight<'origin> {
    fn new(carrier: RetainedCarrier) -> Self {
        Self {
            carrier,
            peer: None,
            coordinates: None,
            outgoing: None,
            bootstrap: None,
            record: None,
            decoded: None,
            clock: None,
            last_sample: None,
            latch: Latch::new(),
        }
    }

    fn bytes(&self) -> Result<&[u8], Failure> {
        match self.record.as_ref().ok_or(Failure::State)? {
            Record::Received(index) => Ok(self.carrier.bytes(*index)?),
            Record::Protected(bytes) => Ok(bytes),
        }
    }

    fn digest(&self) -> Result<[u8; 32], Failure> {
        let bytes = self.bytes()?;
        take(bytes, bytes.len().checked_sub(super::DIGEST_BYTES).ok_or(Failure::Protocol)?)
    }

    fn check(&mut self, root: Option<&mut RootRecord>) -> Result<(), Failure> {
        let mut check = checker(&self.peer, &mut self.clock, &mut self.last_sample, &self.decoded, &self.record, root);
        self.carrier.checked(&mut check)?;
        Ok(())
    }

    fn send(&mut self, phase: Phase, sequence: u32, payload: &[u8], root: Option<&mut RootRecord>)
        -> Result<(), Failure>
    {
        self.outgoing = Some(self.coordinates.ok_or(Failure::State)?.header(phase, sequence, payload.len())?);
        let mut check = checker(&self.peer, &mut self.clock, &mut self.last_sample, &self.decoded, &self.record, root);
        self.carrier.write(self.outgoing.as_ref().ok_or(Failure::State)?, &mut check)?;
        self.carrier.write(payload, &mut check)?;
        Ok(())
    }

    fn send_record(&mut self, root: &mut RootRecord) -> Result<(), Failure> {
        let bytes = match &self.record {
            Some(Record::Protected(bytes)) => bytes,
            _ => return Err(Failure::State),
        };
        self.outgoing = Some(self.coordinates.ok_or(Failure::State)?.header(Phase::Record, 0, bytes.len())?);
        let mut check = checker(&self.peer, &mut self.clock, &mut self.last_sample, &self.decoded, &self.record, Some(root));
        self.carrier.write(self.outgoing.as_ref().ok_or(Failure::State)?, &mut check)?;
        self.carrier.write(bytes, &mut check)?;
        Ok(())
    }

    fn header(&mut self, adopt: bool, root: Option<&mut RootRecord>)
        -> Result<(Phase, u32, usize), Failure>
    {
        let mut check = checker(&self.peer, &mut self.clock, &mut self.last_sample, &self.decoded, &self.record, root);
        let index = self.carrier.read_exact(HEADER_BYTES, &mut check)?;
        let coordinates = self.coordinates.ok_or(Failure::State)?;
        let (phase, sequence, length, nonce) = coordinates.decode_header(self.carrier.bytes(index)?, adopt)?;
        if adopt {
            self.coordinates.as_mut().ok_or(Failure::State)?.root = nonce;
        }
        Ok((phase, sequence, length))
    }

    fn payload(&mut self, length: usize, root: Option<&mut RootRecord>) -> Result<usize, Failure> {
        let mut check = checker(&self.peer, &mut self.clock, &mut self.last_sample, &self.decoded, &self.record, root);
        Ok(self.carrier.read_exact(length, &mut check)?)
    }

    fn commitment(&mut self, length: usize, root: Option<&mut RootRecord>) -> Result<(), Failure> {
        if length != 32 {
            return Err(Failure::Protocol);
        }
        let index = self.payload(length, root)?;
        if self.carrier.bytes(index)? != self.digest()? {
            return Err(Failure::Protocol);
        }
        Ok(())
    }

    fn eof(&mut self, root: Option<&mut RootRecord>) -> Result<(), Failure> {
        let mut check = checker(&self.peer, &mut self.clock, &mut self.last_sample, &self.decoded, &self.record, root);
        self.carrier.require_eof(&mut check)?;
        // Include this capsule's own shutdown bookend before clean completion.
        // The already parked lower Closed result and both of its debts stay put.
        self.carrier.end();
        if self.carrier.shutdown_failure().is_some() {
            return Err(Failure::Protocol);
        }
        Ok(())
    }
}

fn checker<'a, 'origin: 'a>(
    peer: &'a Option<Peer<'origin>>,
    clock: &'a mut Option<FixedLiveAuthorityClockV1>,
    last: &'a mut Option<LiveAuthorityClockSampleV1>,
    decoded: &'a Option<DecodedGitEvidenceV1>,
    record: &'a Option<Record>,
    mut root: Option<&'a mut RootRecord>,
) -> impl FnMut(&RetainedUnixStream, Option<&UnixStreamSubjectChunk>) -> Result<(), TransportFault> + 'a {
    move |stream, chunk| {
        clock_check(clock, last, decoded)?;
        peer.as_ref().ok_or(CarrierError::Protocol)?.check(stream, chunk)?;
        if let Some(root) = root.as_mut() {
            let Some(Record::Protected(bytes)) = record else {
                return Err(CarrierError::Protocol.into());
            };
            root.recheck(bytes)?;
        }
        clock_check(clock, last, decoded).map_err(TransportFault::from)
    }
}

fn clock_check(
    clock: &mut Option<FixedLiveAuthorityClockV1>,
    last: &mut Option<LiveAuthorityClockSampleV1>,
    decoded: &Option<DecodedGitEvidenceV1>,
) -> Result<(), GitProtectedEvidenceErrorV1> {
    let current = clock.as_mut().ok_or(GitProtectedEvidenceErrorV1::InvalidEvidence)?
        .sample().map_err(|_| GitProtectedEvidenceErrorV1::InvalidEvidence)?;
    if let Some(before) = *last {
        validate_bracketed_samples_v1(before, current)
            .map_err(|_| GitProtectedEvidenceErrorV1::InvalidEvidence)?;
    }
    if let Some(evidence) = decoded {
        validate_currentness(evidence, current)?;
    }
    *last = Some(current);
    Ok(())
}

// Returned Journal parks in Root's capsule before this record/snapshot work.
// Snapshot validation is used only as an existing healthy read comparison; no
// effect preflight/token leaves this module and no earlier writer is acquired.
struct RootRecord {
    journal: Journal,
    recovery: RecoveryReport,
    snapshot: Option<ProtectedJournalSnapshot>,
}

impl RootRecord {
    fn recheck(&mut self, expected: &[u8]) -> Result<(), GitProtectedEvidenceErrorV1> {
        self.journal.validate_held_root_owned_at(
            Path::new(PROTECTED_GIT_EVIDENCE_ROOT), PROTECTED_GIT_EVIDENCE_JOURNAL,
        )?;
        self.journal.require_fixed_git_evidence_namespace_v1()?;
        let authority = self.journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
        authority.validate_snapshot_for_effect(self.snapshot.as_ref()
            .ok_or(GitProtectedEvidenceErrorV1::InvalidEvidence)?)?;
        if authority.records()?.take(2).count() != 1
            || authority.get(PROTECTED_GIT_EVIDENCE_KEY)? != Some(expected)
        {
            return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
        }
        drop(authority);
        self.journal.validate_held_root_owned_at(
            Path::new(PROTECTED_GIT_EVIDENCE_ROOT), PROTECTED_GIT_EVIDENCE_JOURNAL,
        )?;
        Ok(())
    }
}

/// Borrows exact canonical metadata and independently decoded comparison DATA.
///
/// It is not a protected claim, signer, authenticated time, currentness token,
/// read permit or effect input. Its borrow ends before a mutating flight method.
pub struct GitRootEvidenceMetadataV1<'metadata> {
    bytes: &'metadata [u8],
    decoded: &'metadata DecodedGitEvidenceV1,
}

impl GitRootEvidenceMetadataV1<'_> {
    /// Borrows the exact original canonical record without restamping expiry.
    #[must_use]
    pub fn encoded_record(&self) -> &[u8] {
        self.bytes
    }

    /// Returns validator, boot and boot-attestation comparison commitments.
    #[must_use]
    pub fn commitments(&self) -> (ObjectDigest, ObjectDigest, ObjectDigest) {
        (self.decoded.validator_attestation, self.decoded.current_boot, self.decoded.boot_attestation)
    }

    /// Returns recorded BOOTTIME and the original authenticated validity interval.
    #[must_use]
    pub fn recorded_times(&self) -> (u64, u64, u64) {
        (self.decoded.current_boottime.get(), self.decoded.authenticated_at_unix_seconds,
            self.decoded.valid_until_unix_seconds)
    }

    /// Borrows sorted predecessor, graph, ancestry and validation-report sets.
    #[must_use]
    pub fn accepted_sets(&self) -> (&[ObjectDigest], &[ObjectDigest], &[ObjectDigest], &[ObjectDigest]) {
        (&self.decoded.predecessor_boots, &self.decoded.accepted_graphs,
            &self.decoded.accepted_ancestry, &self.decoded.accepted_validation_reports)
    }
}

/// Owns one nonretryable metadata flight under genuine Controller profile custody.
pub struct GitRootEvidenceViewAttemptV1<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    flight: Flight<'profile>,
    checks: u32,
}

impl<'profile> GitRootEvidenceViewAttemptV1<'profile> {
    /// Parks genuine profile custody before clock, entropy or endpoint work.
    #[must_use]
    pub fn new(profile: &'profile ProductionControllerNormalRootProfileV1) -> Self {
        Self {
            profile,
            flight: Flight::new(RetainedCarrier::empty()),
            checks: 0,
        }
    }

    /// Acquires exact metadata once on the fixed original normal-Root endpoint.
    ///
    /// # Errors
    /// Borrows the first failure on changed original custody, expiry, framing,
    /// canonical evidence, allocation or I/O. Failed attempts cannot restart.
    pub fn acquire_once(&mut self) -> Result<(), GitRootEvidenceViewErrorV1<'_>> {
        let result = self.acquire();
        self.finish(result, State::Active)
    }

    fn acquire(&mut self) -> Result<(), Failure> {
        self.flight.latch.begin(State::New)?;
        self.flight.clock = Some(fixed_live_authority_clock_v1());
        let deadline = Deadline::new_metadata()?;
        self.profile.recheck()?;
        let nonce = fresh_root_nonce()?;
        if nonce == [0; 16] {
            return Err(Failure::Protocol);
        }
        self.flight.coordinates = Some(Coordinates { client: nonce, root: [0; 16], cutoff: deadline.cutoff() });
        self.flight.bootstrap = Some(self.flight.coordinates.ok_or(Failure::State)?.encode_bootstrap());
        self.flight.carrier.connect(deadline)?;
        self.flight.peer = Some(Peer::Root(self.profile.observe_original_peer(self.flight.carrier.stream()?)?));
        {
            let flight = &mut self.flight;
            let mut check = checker(&flight.peer, &mut flight.clock, &mut flight.last_sample, &flight.decoded, &flight.record, None);
            flight.carrier.write(flight.bootstrap.as_ref().ok_or(Failure::State)?, &mut check)?;
        }
        if self.flight.header(true, None)? != (Phase::Hello, 0, 16) {
            return Err(Failure::Protocol);
        }
        let hello = self.flight.payload(16, None)?;
        if self.flight.carrier.bytes(hello)? != deadline.boot() {
            return Err(Failure::Protocol);
        }
        let (phase, sequence, length) = self.flight.header(false, None)?;
        if phase != Phase::Record || sequence != 0 {
            return Err(Failure::Protocol);
        }
        let record = self.flight.payload(length, None)?;
        self.flight.record = Some(Record::Received(record));
        self.flight.decoded = Some(decode_evidence(self.flight.bytes()?)?);
        self.flight.check(None)
    }

    /// Borrows metadata only after fresh local clock, original-peer and expiry bookends.
    ///
    /// # Errors
    /// Borrows a resident failure outside Active or after any failed bookend.
    /// This local observation is not a fresh remote Root response or authority.
    pub fn current_metadata(&mut self) -> Result<GitRootEvidenceMetadataV1<'_>, GitRootEvidenceViewErrorV1<'_>> {
        let result = self.flight.latch.begin(State::Active).and_then(|()| self.flight.check(None));
        self.flight.latch.finish(result, State::Active, &mut self.flight.carrier);
        if self.flight.latch.state != State::Active {
            return Err(self.flight.latch.error(&self.flight.carrier));
        }
        match (self.flight.bytes(), self.flight.decoded.as_ref()) {
            (Ok(bytes), Some(decoded)) => Ok(GitRootEvidenceMetadataV1 { bytes, decoded }),
            _ => Err(self.flight.latch.error(&self.flight.carrier)),
        }
    }

    /// Rechecks the same remote record with the next bounded original-flight sequence.
    ///
    /// # Errors
    /// Borrows the first failed local/remote comparison, exhausted sequence or I/O.
    pub fn recheck_current(&mut self) -> Result<(), GitRootEvidenceViewErrorV1<'_>> {
        let result = (|| {
            self.flight.latch.begin(State::Active)?;
            let next = self.checks.checked_add(1).filter(|next| *next <= MAXIMUM_CHECKS).ok_or(Failure::Protocol)?;
            self.flight.send(Phase::Check, next, &[], None)?;
            if self.flight.header(false, None)? != (Phase::Checked, next, 32) {
                return Err(Failure::Protocol);
            }
            self.flight.commitment(32, None)?;
            self.flight.check(None)?;
            self.checks = next;
            Ok(())
        })();
        self.finish(result, State::Active)
    }

    /// Makes local metadata unavailable after the exact terminal exchange.
    ///
    /// Success is local completion only, not Root postcheck/release, ACK or Drain.
    ///
    /// # Errors
    /// Borrows the first phase, peer, deadline, record or shutdown-debt failure.
    pub fn release_once(&mut self) -> Result<(), GitRootEvidenceViewErrorV1<'_>> {
        let result = (|| {
            self.flight.latch.begin(State::Active)?;
            let next = self.checks.checked_add(1).ok_or(Failure::Protocol)?;
            let digest = self.flight.digest()?;
            self.flight.send(Phase::Release, next, &digest, None)?;
            if self.flight.header(false, None)? != (Phase::Released, next, 32) {
                return Err(Failure::Protocol);
            }
            self.flight.commitment(32, None)?;
            self.flight.check(None)?;
            self.flight.send(Phase::Terminal, next, &digest, None)?;
            self.flight.carrier.finish_sending()?;
            self.flight.eof(None)?;
            self.flight.check(None)
        })();
        self.finish(result, State::Complete)
    }

    fn finish(&mut self, result: Result<(), Failure>, success: State) -> Result<(), GitRootEvidenceViewErrorV1<'_>> {
        self.flight.latch.finish(result, success, &mut self.flight.carrier);
        if self.flight.latch.state == success {
            Ok(())
        } else {
            Err(self.flight.latch.error(&self.flight.carrier))
        }
    }
}

/// Prearms one recognized original Root exchange before fallible admission.
///
/// Failure, abandonment or unwinding aborts before the retained fields drop.
/// The daemon exits while an Err attempt remains resident. This is not a public
/// listener or a factory for claim/effect/currentness/rollback-floor authority.
pub struct RootGitEvidenceViewAttemptV1<'startup> {
    startup: Option<&'startup ProductionNormalRootStartupV1>,
    flight: Flight<'startup>,
    root: Option<RootRecord>,
    armed: bool,
}

impl<'startup> RootGitEvidenceViewAttemptV1<'startup> {
    /// Parks actual selected startup, accepted stream and complete bootstrap.
    ///
    /// No purpose validation or startup/gate check precedes this ownership move.
    #[must_use]
    pub fn new(startup: Option<&'startup ProductionNormalRootStartupV1>, original: UnixStream, bootstrap: [u8; 32]) -> Self {
        let mut flight = Flight::new(RetainedCarrier::accepted(original));
        flight.bootstrap = Some(bootstrap);
        Self {
            startup,
            flight,
            root: None,
            armed: true,
        }
    }

    /// Serves one bounded original metadata-only flight and disarms after final bookends.
    ///
    /// The upper flight does not issue metadata mutations. The unchanged lower
    /// Journal opener can truncate and sync an uncommitted tail before returning;
    /// its report remains resident, and any reported tail truncation refuses this
    /// flight. This method does not promise filesystem-wide read-only behavior or
    /// undo opener repairs.
    ///
    /// # Errors
    /// Borrows the first resident admission, returned-writer, evidence, peer,
    /// clock, frame or cleanup failure. Callers must exit without dropping Err.
    pub fn serve_once(&mut self) -> Result<(), GitRootEvidenceViewErrorV1<'_>> {
        self.armed = true;
        let result = self.serve();
        self.flight.latch.finish(result, State::Complete, &mut self.flight.carrier);
        if self.flight.latch.state == State::Complete {
            self.armed = false;
            Ok(())
        } else {
            Err(self.flight.latch.error(&self.flight.carrier))
        }
    }

    fn serve(&mut self) -> Result<(), Failure> {
        self.flight.latch.begin(State::New)?;
        self.flight.clock = Some(fixed_live_authority_clock_v1());
        let startup = self.startup.ok_or(Failure::State)?;
        startup.recheck()?;
        require_no_fixed_closed_policy_binding_hold_v1()?;
        let mut coordinates = Coordinates::bootstrap(self.flight.bootstrap.as_ref().ok_or(Failure::State)?)?;
        let deadline = Deadline::capture_metadata(coordinates.cutoff)?;
        self.flight.carrier.adopt(deadline)?;
        self.flight.peer = Some(Peer::Controller(startup.observe_controller_policy_peer(self.flight.carrier.stream()?)?));
        coordinates.root = fresh_root_nonce()?;
        if coordinates.root == [0; 16] {
            return Err(Failure::Protocol);
        }
        self.flight.coordinates = Some(coordinates);
        self.flight.send(Phase::Hello, 0, &deadline.boot(), None)?;

        // Root is LAST. No Controller/Source/Cache/policy acquisition or Root
        // RPC reentry occurs after this fixed, existing-only successful open.
        let (journal, recovery) = Journal::open_existing_protected_at(
            Path::new(PROTECTED_GIT_EVIDENCE_ROOT), PROTECTED_GIT_EVIDENCE_JOURNAL,
            git_evidence_journal_limits(),
        ).map_err(GitProtectedEvidenceErrorV1::from)?;
        self.root = Some(RootRecord { journal, recovery, snapshot: None });
        let root = self.root.as_mut().ok_or(Failure::State)?;
        // The unchanged lower opener can already have truncated/synced an
        // uncommitted tail. Retain that actual report/writer and refuse here;
        // this returned-owner boundary cannot retroactively undo that mutation.
        if root.recovery.truncated_bytes != 0 {
            return Err(GitProtectedEvidenceErrorV1::InvalidEvidence.into());
        }
        self.flight.record = Some(Record::Protected(read_exact_evidence_record(&mut root.journal)?));
        self.flight.decoded = Some(decode_evidence(self.flight.bytes()?)?);
        root.snapshot = Some(root.journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)
            .map_err(GitProtectedEvidenceErrorV1::from)?
            .snapshot().map_err(GitProtectedEvidenceErrorV1::from)?);
        self.flight.check(Some(&mut *root))?;
        self.flight.send_record(root)?;
        self.flight.check(Some(&mut *root))?;

        let mut sequence = 1;
        loop {
            let (phase, actual, length) = self.flight.header(false, Some(&mut *root))?;
            if actual != sequence {
                return Err(Failure::Protocol);
            }
            match phase {
                Phase::Check if sequence <= MAXIMUM_CHECKS && length == 0 => {
                    self.flight.check(Some(&mut *root))?;
                    let digest = self.flight.digest()?;
                    self.flight.send(Phase::Checked, sequence, &digest, Some(&mut *root))?;
                    self.flight.check(Some(&mut *root))?;
                    sequence = sequence.checked_add(1).ok_or(Failure::Protocol)?;
                }
                Phase::Release => {
                    self.flight.commitment(length, Some(&mut *root))?;
                    self.flight.check(Some(&mut *root))?;
                    let digest = self.flight.digest()?;
                    self.flight.send(Phase::Released, sequence, &digest, Some(&mut *root))?;
                    if self.flight.header(false, Some(&mut *root))? != (Phase::Terminal, sequence, 32) {
                        return Err(Failure::Protocol);
                    }
                    self.flight.commitment(32, Some(&mut *root))?;
                    self.flight.eof(Some(&mut *root))?;
                    self.flight.check(Some(&mut *root))?;
                    // The owning Closed result remains resident on success.
                    // Its lower shutdown can expose client EOF before these
                    // final Root bookends: client success is LOCAL only.
                    return Ok(());
                }
                _ => return Err(Failure::Protocol),
            }
        }
    }
}

impl Drop for RootGitEvidenceViewAttemptV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}
