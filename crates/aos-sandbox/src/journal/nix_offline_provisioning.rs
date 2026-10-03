//! Original, fixed-name native custody for the manual Nix hardware job.
//!
//! The genuine externally retained startup and independently delivered approval
//! remain borrowed. Original files, parsed history and partial read buffers stay
//! resident on failure. This module reuses the Journal's sole durable parser,
//! materializer and eight-limit geometry. Its native bytes are neither an NV
//! floor nor a live Session and never authorize an unrelated journal writer.
//! Current state 3 records the two final durable TPM observations, not successful
//! process retirement: the installed coordinator still requires each original
//! terminal ACK, exact-child wait and final original rechecks before returning.
//!
//! ```text
//! namespace76, AOSNPR05/version5:
//! header16/job16/approval32/prior-history32/boot16/M0u64be/Du64be/
//! body-lengthu32be/body<=8192/digest32 (maximum8356)
//! Admission/Current/Recovery keys: AOSNPA05|AOSNPH05|AOSNRA05 + job16
//! Effect keys: Q|T + job16 + attempt1|2 + ordinalu16be1..6
//! ```

use std::fs::File;
use std::io::{self, Seek as _, SeekFrom};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::pidfd::{PidFdInfo, PidFdProcObservationsV1};
use aos_sandbox_linux::process::{
    FixedLiveChild, FixedNixOfflineSessionOwnerV1, FixedProcessRetainedSessionOutcome,
    FixedProcessCaptureV1, FixedProcessRequest, FixedProcessSessionRequest,
};
use aos_sandbox_linux::seqpacket::{ReceivedRecord, SeqpacketSocket};
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1;
use aos_sandbox_linux::protected_file::{
    ExactReadFailure, open_nofollow_child, read_exact_positioned_retaining_cause,
};
use rustix::fs::{FileType, FlockOperation, Mode, OFlags, ResolveFlags, flock, fsync};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::immutable_image::{ImmutableImageErrorV1, PendingImmutableFileV1};
use crate::normal_root::{
    OfflineNixHardwareOriginV5, OfflineNixPrepareStartupErrorV3,
    NixOfflineApprovedDataErrorV4, NixOfflineEffectApprovalKindV4,
    NixOfflineJobIdentityDataV5, inspect_nix_offline_job_identity_v5,
    nix_offline_job_has_original_label_v5, require_nix_offline_effect_approval_v4,
    require_nix_offline_static_approval_v3,
};
use crate::production_operation_compiler::{
    NixFixedDomainPinsDataV2, NixFixedDomainPinsDecodeErrorV2,
};

use super::{
    BTreeMap, DeploymentHistoryObserverV1, FileIdentity, Journal,
    JournalAuthorityInstance, JournalError, JournalLimits, JournalRecord, JournalTransaction,
    RootOwnerEdge, CacheMutationGateV1,
    ProtectedJournalLocation, RecordNamespace, open_protected_file_into,
    replay_original_observed, validate_limits, validate_protected_fd,
};
use super::runtime_deployment_history::{OriginalCompactionSelectionV1, ReadAtCursorV1};

const DIRECTORY: &str = "/var/lib/aos/sandbox-nix-floor-provision";
const NAME: &str = "provisioning-v4.journal";
const LOCK_NAME: &str = "provisioning-v4.journal.lock";
const NAMESPACE: RecordNamespace = RecordNamespace::NixOfflineProvisioning;
const FILES: [(&str, usize, u32); 5] = [
    ("candidate-private-v3", 336, 0o600),
    ("candidate-public-v3", 268, 0o400),
    ("approved-job-v3", 1332, 0o400),
    ("approved-effect-v4", 304, 0o400),
    ("approved-recovery-v4", 304, 0o400),
];
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.native-record.v5\0";
const TX_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.native-transaction.v5\0";
const CLOSURE_DATA_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.closure-preview-data.v5\0";
const HISTORY_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.offline-native-history.v4\0";
const MAXIMUM_NAMED_FILES: usize = 273;
const MAXIMUM_INPUT_BYTES: usize = 1332;
const LIMITS: JournalLimits = JournalLimits {
    maximum_journal_bytes: 4_194_304,
    maximum_record_bytes: 16_384,
    maximum_key_bytes: 26,
    maximum_records_per_transaction: 2,
    maximum_transaction_bytes: 33_792,
    maximum_transactions: 256,
    maximum_materialized_bytes: 262_144,
    maximum_materialized_records: 32,
};

/// Retains an actual original native admission or persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum NixOfflineNativeJobErrorV5 {
    /// The borrowed startup keeps its original actual cause and partial custody.
    #[error("original offline hardware startup is fenced")]
    Startup,
    /// A new original observation failed with its actual typed startup cause.
    #[error("offline native original startup observation failed")]
    Origin(#[from] OfflineNixPrepareStartupErrorV3),
    /// An original named file, allocation, lock or durability operation failed.
    #[error("offline native original I/O failed")]
    Io(#[from] io::Error),
    /// The sole positioned reader retains its original native cause.
    #[error("offline native original read failed")]
    Read(#[from] ExactReadFailure),
    /// An actual original kernel descriptor or mount observation failed.
    #[error("offline native kernel observation failed")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The actual retained nonblocking helper transport failed.
    #[error("offline native original helper transport failed")]
    Socket(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
    /// A returned record does not belong to its original receiving socket.
    #[error("offline native original record binding differs")]
    Binding(#[from] aos_sandbox_linux::seqpacket::RecordBindingError),
    /// The measured same child reported its original TSS code, errno and stage.
    #[error("offline measured helper reported an uncertain negative result")]
    Helper {
        /// Original nonzero TSS code or the fixed unknown-error marker.
        return_code: u32,
        /// Original C errno copied before cleanup.
        errno: i32,
        /// Original bounded bootstrap/action stage.
        stage: u32,
    },
    /// The actual external resident run owns the original process failure.
    #[error("offline original process run is not successfully retired")]
    Process,
    /// The original immutable profile could not be retained or revalidated.
    #[error("offline native immutable original differs")]
    Image(#[from] ImmutableImageErrorV1),
    /// The sole canonical approval/candidate/signature engine rejected the input.
    #[error("offline native independent approval differs")]
    Approval(#[from] NixOfflineApprovedDataErrorV4),
    /// The sole fixed-domain DATA codec rejected the retained credential.
    #[error("offline native original domain differs")]
    Domain(#[from] NixFixedDomainPinsDecodeErrorV2),
    /// The existing durable parser, schema or geometry rejected the original cut.
    #[error("offline native journal differs")]
    Journal(#[from] JournalError),
    /// A fixed role, name, mode, coordinate or original association differs.
    #[error("offline native original association differs")]
    Rejected,
    /// This attempt failed, was interrupted or is being reused.
    #[error("offline native owner is fenced")]
    Fenced,
}

impl From<rustix::io::Errno> for NixOfflineNativeJobErrorV5 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

type Error = NixOfflineNativeJobErrorV5;

/// Borrows one durably recorded contact's bounded transport DATA.
///
/// This value has no independent constructor and exposes no authorization
/// secret. Native debt does not authenticate an executed child, a response,
/// initialized hardware, a Session or a rollback-resistant floor.
pub struct NixOfflineContactDataV5 {
    attempt: u8,
    slot: u8,
    cut: u64,
    nonce: [u8; 32],
    header: [u8; 152],
    hello: [u8; 232],
    request: Vec<u8>,
    observations: Option<PidFdProcObservationsV1>,
    original_child: Option<PidFdInfo>,
    auth: Zeroizing<[u8; 320]>,
    authorized: bool,
    settled: bool,
    terminal_acknowledged: bool,
    terminal_ack_attempted: bool,
    observation: Option<[u8; 388]>,
}

impl NixOfflineContactDataV5 {
    /// Returns the original cumulative attempt and fixed contact slot.
    pub const fn coordinates(&self) -> (u8, u8) {
        (self.attempt, self.slot)
    }

    /// Returns this contact's absolute original MONOTONIC cutoff.
    pub const fn cut(&self) -> u64 {
        self.cut
    }

    /// Borrows the nonsecret HELLO bound to the original profile and lock loans.
    pub fn hello(&self) -> &[u8] {
        &self.hello
    }

    /// Borrows the exact nonsecret action request retained in native debt.
    pub fn request(&self) -> &[u8] {
        &self.request
    }
}

/// Parks only descriptors produced by the genuine admitted native job.
///
/// This external move-only reservoir is mechanical DATA. The actual native
/// owner alone fills its private slots; it authenticates no child, successful
/// execution or TPM result. Returned prefixes survive errors and caught unwind
/// when its caller keeps this reservoir resident until explicit process exit.
pub struct NixOfflineHelperLaunchV5 {
    attempted: bool,
    ready: bool,
    transferred: bool,
    executable: Option<OwnedFd>,
    child_locks: [Option<OwnedFd>; 2],
    hello_locks: [Option<OwnedFd>; 2],
    roles: Vec<OwnedFd>,
    path: PathBuf,
    cut: u64,
}

impl NixOfflineHelperLaunchV5 {
    /// Creates empty resident slots without selecting a file or invoking I/O.
    #[must_use]
    pub fn new() -> Self {
        Self {
            attempted: false, ready: false, transferred: false,
            executable: None,
            child_locks: [None, None], hello_locks: [None, None],
            roles: Vec::new(), path: PathBuf::new(), cut: 0,
        }
    }

    /// Moves the exact native-produced roles into the sole selected supervisor.
    ///
    /// The real parent control descriptor and child endpoint remain supplied
    /// by the retained pair owner. This DATA handoff does not validate that
    /// pair; native same-child/record binding remains mandatory before AUTH.
    ///
    /// # Errors
    /// Refuses unprepared/reused slots before moving any descriptor. No
    /// caller-selected executable, argument, environment or deadline exists.
    pub fn retain_run<'resources, O, E>(
        &'resources mut self,
        control: BorrowedFd<'resources>,
        endpoint: &mut Option<OwnedFd>,
        capture: &'resources mut FixedProcessCaptureV1,
    ) -> Result<(
        FixedNixOfflineSessionOwnerV1<'resources, 'resources, O, E>,
        [BorrowedFd<'resources>; 2],
    ), Error> {
        if !self.ready || self.transferred || self.executable.is_none()
            || self.child_locks.iter().any(Option::is_none)
            || endpoint.is_none()
            || self.roles.capacity() < 3 || !self.roles.is_empty()
        {
            return Err(Error::Fenced);
        }
        let locks = [
            self.hello_locks[0].as_ref().ok_or(Error::Rejected)?.as_fd(),
            self.hello_locks[1].as_ref().ok_or(Error::Rejected)?.as_fd(),
        ];
        self.transferred = true;
        let process = FixedProcessRequest {
            executable: &self.path,
            arguments: &[],
            timeout: std::time::Duration::from_secs(30),
            maximum_stdout_bytes: 262_144,
            maximum_stderr_bytes: 262_144,
        };
        let endpoint = match endpoint.take() {
            Some(endpoint) => endpoint,
            None => return Err(Error::Fenced),
        };
        self.roles.push(endpoint);
        for slot in &mut self.child_locks {
            if let Some(original) = slot.take() {
                self.roles.push(original);
            }
        }
        // The complete table/slots were checked above. Every following move
        // is infallible; no new original is dropped by a post-handoff gate.
        let executable = match self.executable.take() {
            Some(executable) => executable,
            None => return Err(Error::Fenced),
        };
        let request = FixedProcessSessionRequest {
            process, stdin: None, inherited: std::mem::take(&mut self.roles), control,
        };
        let run = request.retain_nix_offline_before_monotonic_cut_v1(
            executable, std::time::Duration::from_nanos(self.cut), capture,
        );
        Ok((run, locks))
    }
}

impl Default for NixOfflineHelperLaunchV5 {
    fn default() -> Self {
        Self::new()
    }
}

impl NixOfflineContactDataV5 {
    fn empty() -> Self {
        Self {
            attempt: 0, slot: 0, cut: 0, nonce: [0; 32], header: [0; 152],
            hello: [0; 232], request: Vec::new(),
            observations: None, original_child: None,
            auth: Zeroizing::new([0; 320]), authorized: false, settled: false,
            terminal_acknowledged: false,
            terminal_ack_attempted: false,
            observation: None,
        }
    }
}

/// Owns one fixed native job while borrowing its genuine hardware startup.
///
/// Empty construction performs no I/O or approval. All acquisition/read prefixes
/// and the first returned cause remain resident until the explicit process exit.
/// No raw writer, hierarchy secret, credential, file or scalar authority factory
/// is exposed. Native admission does not initialize a TPM or establish a floor.
pub struct NixOfflineNativeJobV5<'startup> {
    origin: OfflineNixHardwareOriginV5<'startup>,
    attempted: bool,
    usable: bool,
    first_failure: Option<Error>,
    directory: Option<File>,
    directory_identity: Option<NixOfflineJobIdentityDataV5>,
    directory_mount: Option<MountId>,
    installation_lock: Option<File>,
    installation_identity: Option<NixOfflineJobIdentityDataV5>,
    native_lock: Option<File>,
    native_file: Option<File>,
    journal: Option<Journal>,
    authority: Arc<JournalAuthorityInstance>,
    files: [Option<File>; 5],
    identities: [Option<NixOfflineJobIdentityDataV5>; 5],
    inputs: [Zeroizing<Vec<u8>>; 5],
    named: Vec<File>,
    named_pending: Option<File>,
    named_bytes: Vec<Zeroizing<Vec<u8>>>,
    named_reads: usize,
    derived: [u8; 268],
    static_preimage: [u8; 1317],
    effect_preimage: [u8; b"aos.sandbox.nix-floor.approved-effect.v4\0".len() + 240],
    history_bytes: Vec<u8>,
    readback_bytes: Vec<u8>,
    history: NativeHistoryV5,
    closure: Vec<JournalTransaction>,
    transition: Option<JournalTransaction>,
    completed_transitions: Vec<JournalTransaction>,
    admission_committed: bool,
    contacts: [NixOfflineContactDataV5; 10],
    active_contact: Option<usize>,
    old_profile: PendingImmutableFileV1,
    node: [u8; 16],
    approval: [u8; 48],
    job: [u8; 16],
    boot: [u8; 16],
    first: u64,
    deadline: u64,
    prior: [u8; 32],
}

impl<'startup> NixOfflineNativeJobV5<'startup> {
    /// Parks empty native slots with the actual previously admitted startup loan.
    #[must_use]
    pub fn new(origin: OfflineNixHardwareOriginV5<'startup>) -> Self {
        Self {
            origin,
            attempted: false,
            usable: false,
            first_failure: None,
            directory: None,
            directory_identity: None,
            directory_mount: None,
            installation_lock: None,
            installation_identity: None,
            native_lock: None,
            native_file: None,
            journal: None,
            authority: Arc::new(JournalAuthorityInstance),
            files: std::array::from_fn(|_| None),
            identities: [None; 5],
            inputs: std::array::from_fn(|_| Zeroizing::new(Vec::new())),
            named: Vec::new(),
            named_pending: None,
            named_bytes: Vec::new(),
            named_reads: 0,
            derived: [0; 268],
            static_preimage: [0; 1317],
            effect_preimage: [0; b"aos.sandbox.nix-floor.approved-effect.v4\0".len() + 240],
            history_bytes: Vec::new(),
            readback_bytes: Vec::new(),
            history: NativeHistoryV5::new(),
            closure: Vec::new(),
            transition: None,
            completed_transitions: Vec::new(),
            admission_committed: false,
            contacts: std::array::from_fn(|_| NixOfflineContactDataV5::empty()),
            active_contact: None,
            old_profile: PendingImmutableFileV1::default(),
            node: [0; 16],
            approval: [0; 48],
            job: [0; 16],
            boot: [0; 16],
            first: 0,
            deadline: 0,
            prior: [0; 32],
        }
    }

    /// Admits the actual fixed originals and complete cold native history once.
    ///
    /// No TPM/device/helper contact occurs here. The installed coordinator must
    /// fund and persist contact debt before invoking the actual helper engine.
    ///
    /// # Errors
    /// Keeps the original first failure and acquired partials. Foreign files,
    /// torn tails, changed names, incorrect independent approval and renewed
    /// clocks refuse without cleanup, overwrite, truncation or recovery retry.
    pub fn admit_original(&mut self) -> Result<(), &Error> {
        if self.attempted {
            self.usable = false;
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.attempted = true;
        match self.admit_inner() {
            Ok(()) => {
                self.usable = true;
                Ok(())
            }
            Err(error) => {
                self.first_failure.get_or_insert(error);
                Err(self.first_failure.get_or_insert(Error::Fenced))
            }
        }
    }

    /// Borrows the actual first native failure without moving its resident cause.
    pub fn failure(&self) -> Option<&Error> {
        self.first_failure.as_ref()
    }

    /// Borrows the actual underlying startup cause when that original is fenced.
    pub fn startup_failure(&self) -> Option<&OfflineNixPrepareStartupErrorV3> {
        self.origin.first_failure()
    }

    /// Persists the independently approved original admission and current cut.
    ///
    /// Initialize creates one immutable Admission. Recover appends its one
    /// independently signed Recovery admission to the already verified native
    /// history. Neither route contacts the TPM or returns a funding permit.
    /// The exact transaction stays resident across append, sync and readback.
    ///
    /// # Errors
    /// Fences on changed original custody, exhausted closure, invalid ancestry,
    /// duplicate admission, I/O ambiguity or an interrupted operation. No
    /// immutable row is overwritten and no retry or cutoff renewal is allowed.
    pub fn persist_admission(&mut self) -> Result<(), &Error> {
        if !self.usable || self.admission_committed || self.transition.is_some() {
            self.usable = false;
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.usable = false;
        let result = self.persist_admission_inner();
        match result {
            Ok(()) => {
                self.admission_committed = true;
                self.usable = true;
                Ok(())
            }
            Err(error) => {
                self.first_failure.get_or_insert(error);
                Err(self.first_failure.get_or_insert(Error::Fenced))
            }
        }
    }

    /// Records the next fixed contact before its helper or device is opened.
    ///
    /// The nonce is caller-retained random DATA, not approval. Purpose, slot,
    /// original approval, request, immutable cutoff and transaction identity
    /// are selected from this owner's original admission and held Current.
    /// The actual post-Pending remaining suffix is preflighted again.
    ///
    /// # Errors
    /// Fences a zero/repeated nonce, an outstanding or uncertain contact,
    /// exhausted fixed slots, unavailable original Create output, changed
    /// originals, invalid history, expired cutoff or ambiguous persistence.
    pub fn begin_contact(&mut self, nonce: [u8; 32]) -> Result<(), &Error> {
        if !self.usable || !self.admission_committed || self.active_contact.is_some()
            || self.transition.is_some()
        {
            self.usable = false;
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.usable = false;
        let result = self.begin_contact_inner(nonce);
        match result {
            Ok(()) => {
                self.usable = true;
                Ok(())
            }
            Err(error) => {
                self.first_failure.get_or_insert(error);
                Err(self.first_failure.get_or_insert(Error::Fenced))
            }
        }
    }

    /// Borrows this owner's active, durably recorded transport DATA.
    ///
    /// # Errors
    /// Refuses missing debt or a failed/interrupted owner. This borrow does not
    /// authorize an ACK, response or helper; those require actual live custody.
    pub fn contact(&self) -> Result<&NixOfflineContactDataV5, Error> {
        if !self.usable {
            return Err(Error::Fenced);
        }
        self.contacts.get(self.active_contact.ok_or(Error::Rejected)?)
            .ok_or(Error::Rejected)
    }

    /// Parks fixed launch originals selected by this same admitted native job.
    ///
    /// # Errors
    /// Keeps the actual first cause and every returned descriptor prefix on
    /// changed images/locks, allocation failure, duplicate failure or reuse.
    /// This preparation itself executes no child or device operation.
    pub fn prepare_launch(&mut self, launch: &mut NixOfflineHelperLaunchV5) -> Result<(), &Error> {
        if !self.usable || launch.attempted || self.active_contact.is_none() {
            self.usable = false;
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.usable = false;
        launch.attempted = true;
        let result = self.prepare_launch_inner(launch);
        match result {
            Ok(()) => {
                launch.ready = true;
                self.usable = true;
                Ok(())
            }
            Err(error) => Err(self.first_failure.get_or_insert(error)),
        }
    }

    fn prepare_launch_inner(&self, launch: &mut NixOfflineHelperLaunchV5) -> Result<(), Error> {
        let index = self.active_contact.ok_or(Error::Rejected)?;
        self.require_current_time()?;
        launch.roles.try_reserve_exact(3).map_err(io::Error::other)?;
        let (image, loader) = self.origin.helper_originals()?;
        image.revalidate()?;
        loader.revalidate()?;
        launch.path = image.path().to_path_buf();
        launch.cut = self.contacts[index].cut;
        image.duplicate_nix_offline_original_into(&mut launch.executable)?;
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        for (index, original) in [
            self.installation_lock.as_ref().ok_or(Error::Rejected)?, &journal._lock,
        ].into_iter().enumerate() {
            launch.child_locks[index] = Some(rustix::io::fcntl_dupfd_cloexec(original, 3)?);
            launch.hello_locks[index] = Some(rustix::io::fcntl_dupfd_cloexec(original, 3)?);
            let expected = inspect_nix_offline_job_identity_v5(original)?;
            for observed in [&launch.child_locks[index], &launch.hello_locks[index]] {
                let observed = rustix::fs::fstat(observed.as_ref().ok_or(Error::Rejected)?)?;
                if observed.st_dev != expected.0 || observed.st_ino != expected.1
                    || observed.st_uid != expected.2 || observed.st_gid != expected.3
                    || observed.st_mode != expected.4 || observed.st_nlink != expected.5
                    || observed.st_size != 0
                {
                    return Err(Error::Rejected);
                }
            }
            if expected.2 != 0 || expected.3 != 0 || expected.6 != 0 {
                return Err(Error::Rejected);
            }
        }
        image.revalidate()?;
        loader.revalidate()?;
        self.require_current_time()
    }

    /// Measures the actual descriptor-supervised child before its HELLO.
    ///
    /// Executable, loader maps, subject, same cgroup and original pidfd checks
    /// run outside the nonblocking exchange callback. Every returned metadata
    /// original enters this contact's resident reservoir before postchecks.
    ///
    /// # Errors
    /// Fences a reused measurement, wrong child or cutoff, unavailable original
    /// image/metadata, changed startup or actual kernel observation failure.
    pub fn observe_helper_before_hello(&mut self, child: &FixedLiveChild<'_>)
        -> Result<(), &Error>
    {
        if !self.usable {
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.usable = false;
        let result = self.observe_helper_inner(child);
        match result {
            Ok(()) => {
                self.usable = true;
                Ok(())
            }
            Err(error) => {
                self.first_failure.get_or_insert(error);
                Err(self.first_failure.get_or_insert(Error::Fenced))
            }
        }
    }

    fn observe_helper_inner(&mut self, child: &FixedLiveChild<'_>) -> Result<(), Error> {
        let index = self.require_contact_child(child)?;
        let contact = &mut self.contacts[index];
        if contact.observations.is_some() || contact.original_child.is_some() {
            return Err(Error::Rejected);
        }
        contact.observations = Some(child.pidfd().prepare_proc_observations_v1());

        // Advance the same resident originals before any purpose comparison.
        // A failed capture leaves its partial files and closed phase parked.
        let observations = contact.observations.as_mut().ok_or(Error::Rejected)?;
        observations.capture_stat(child.pidfd())?;
        observations.capture_context(child.pidfd())?;
        observations.capture_nix_offline_helper_originals_v1(child.pidfd())?;
        self.origin.require_helper_before_hello(
            child.pidfd(), observations,
        ).map_err(|_| Error::Startup)?;
        contact.original_child = Some(child.initial_info());
        self.require_contact_child(child)?;
        Ok(())
    }

    /// Sends secret AUTH only after the actual nondumpable same-child ACK.
    ///
    /// The original received record remains borrowed from its resident exchange
    /// owner. Same-socket binding, kernel subject nomination, live child and
    /// same-FD metadata checks precede constructing and sending the resident
    /// zeroizing frame. No hierarchy key or arbitrary authorization is returned.
    ///
    /// # Errors
    /// Fences absent measurement, crossed ACK, changed/expired child, original
    /// metadata failure, reused AUTH or an actual nonblocking send failure.
    pub fn authorize_acknowledgment(
        &mut self, socket: &mut SeqpacketSocket, acknowledgment: &ReceivedRecord,
        child: &FixedLiveChild<'_>,
    ) -> Result<(), &Error> {
        if !self.usable {
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.usable = false;
        let result = self.authorize_acknowledgment_inner(socket, acknowledgment, child);
        match result {
            Ok(()) => {
                self.usable = true;
                Ok(())
            }
            Err(error) => {
                self.first_failure.get_or_insert(error);
                Err(self.first_failure.get_or_insert(Error::Fenced))
            }
        }
    }

    fn authorize_acknowledgment_inner(
        &mut self, socket: &mut SeqpacketSocket, acknowledgment: &ReceivedRecord,
        child: &FixedLiveChild<'_>,
    ) -> Result<(), Error> {
        let index = self.require_received_child(socket, acknowledgment, child)?;
        let contact = &mut self.contacts[index];
        if contact.authorized || contact.settled {
            return Err(Error::Rejected);
        }
        require_contact_reply(contact, acknowledgment.payload(), 2)?;
        if acknowledgment.payload().len() != 160
            || acknowledgment.payload()[148..152] != [0; 4]
        {
            return Err(Error::Rejected);
        }
        self.origin.require_helper_continued(
            child.pidfd(), contact.observations.as_mut().ok_or(Error::Rejected)?,
        ).map_err(|_| Error::Startup)?;
        contact.auth[..152].copy_from_slice(&contact.header);
        contact.auth[10] = 3;
        contact.auth[144..148].copy_from_slice(&168_u32.to_be_bytes());
        contact.auth[152..160].copy_from_slice(&contact.cut.to_be_bytes());
        contact.auth[160..192].copy_from_slice(self.origin.hierarchy_original()?);
        contact.auth[192..320].copy_from_slice(&self.inputs[0][208..336]);
        self.require_contact_child(child)?;
        socket.send(self.contacts[index].auth.as_ref())?;
        self.contacts[index].authorized = true;
        Ok(())
    }

    /// Persists a measured same-child RESULT before the child may be reaped.
    ///
    /// The actual record, original child and same-FD metadata are checked before
    /// the strict Terminal/Current transition. A negative C result is recorded
    /// as uncertainty, not rollback or success, and retains its original cause.
    /// The child remains externally resident awaiting the terminal ACK.
    ///
    /// # Errors
    /// Fences crossed/unmeasured/expired replies, malformed fixed output,
    /// incorrect original state, exhausted closure, persistence ambiguity or
    /// the measured helper's actual negative result. No retry is authorized.
    pub fn settle_contact(
        &mut self, socket: &mut SeqpacketSocket, result: &ReceivedRecord,
        child: &FixedLiveChild<'_>,
    ) -> Result<(), &Error> {
        if !self.usable || self.transition.is_some() {
            self.usable = false;
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.usable = false;
        let settled = self.settle_contact_inner(socket, result, child);
        match settled {
            Ok(()) => {
                self.usable = true;
                Ok(())
            }
            Err(error) => {
                self.first_failure.get_or_insert(error);
                Err(self.first_failure.get_or_insert(Error::Fenced))
            }
        }
    }

    fn settle_contact_inner(
        &mut self, socket: &mut SeqpacketSocket, result: &ReceivedRecord,
        child: &FixedLiveChild<'_>,
    ) -> Result<(), Error> {
        let index = self.require_received_child(socket, result, child)?;
        let contact = &mut self.contacts[index];
        if !contact.authorized || contact.settled {
            return Err(Error::Rejected);
        }
        require_contact_reply(contact, result.payload(), 5)?;
        require_result_envelope(contact.slot, result.payload())?;
        self.origin.require_helper_continued(
            child.pidfd(), contact.observations.as_mut().ok_or(Error::Rejected)?,
        ).map_err(|_| Error::Startup)?;
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_named_originals()?;
        self.require_current_time()?;
        self.require_contact_child(child)?;

        let contact = &self.contacts[index];
        let success = result.payload()[148..152] == [0; 4];
        if success && matches!(contact.slot, 1 | 2 | 9 | 10) {
            self.require_observed_state(contact.slot, &result.payload()[152..])?;
            self.contacts[index].observation = Some(array(result.payload(), 152)?);
        } else if success && matches!(contact.slot, 4 | 7) {
            let ordinal = if contact.slot == 4 { 1 } else { 4 };
            let created = self.original_effect_result(ordinal)?.ok_or(Error::Rejected)?;
            if result.payload()[160..194] != created[42..76]
                || result.payload()[198..] != created[372..656]
            {
                return Err(Error::Rejected);
            }
        }
        let contact = &self.contacts[index];
        let current_key = native_key(b"AOSNPH05", &self.job)?;
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        let original = journal.state.get(&(NAMESPACE, current_key.clone()))
            .ok_or(Error::Rejected)?;
        let original = decode_record(&current_key, original)?;
        let mut current: [u8; 2320] = array(original.body, 0)?;
        let offset = 48 + ((usize::from(contact.attempt) - 1) * 10 + index) * 112;
        if current[offset + 4] != 1 || current[offset + 8..offset + 40] != contact.nonce
            || current[offset + 40..offset + 72] != <[u8; 32]>::from(Sha256::digest(&contact.request))
        {
            return Err(Error::Rejected);
        }
        let terminal_digest: [u8; 32] = Sha256::digest(result.payload()).into();
        current[offset + 4] = if success { 2 } else { 3 };
        current[offset + 72..offset + 104].copy_from_slice(&terminal_digest);
        if !success {
            current[14] = 2;
        } else if contact.slot == 10 {
            current[14] = 3;
        }
        if success {
            current[2288..].copy_from_slice(&terminal_digest);
        }
        let mut records = Vec::new();
        records.try_reserve_exact(2).map_err(io::Error::other)?;
        let prior = self.history.original_digest();
        if (3..=8).contains(&contact.slot) {
            let ordinal = u16::from(contact.slot - 2);
            let key = effect_key(b'T', &self.job, contact.attempt, ordinal)?;
            let pending_key = effect_key(b'Q', &self.job, contact.attempt, ordinal)?;
            let pending = journal.state.get(&(NAMESPACE, pending_key)).ok_or(Error::Rejected)?;
            let mut body = Vec::new();
            body.try_reserve_exact(52 + result.payload().len()).map_err(io::Error::other)?;
            body.extend_from_slice(b"AOSNTP05");
            body.extend_from_slice(&5_u16.to_be_bytes());
            body.push(if success { 2 } else { 3 });
            body.extend_from_slice(&[0; 5]);
            body.extend_from_slice(&Sha256::digest(pending));
            body.extend_from_slice(&(result.payload().len() as u32).to_be_bytes());
            body.extend_from_slice(result.payload());
            records.push(JournalRecord::put(
                NAMESPACE, key.clone(), self.encode_record(
                    &key, 4, contact.header[11], ordinal, prior, &body,
                )?,
            ));
        }
        records.push(JournalRecord::put(
            NAMESPACE, current_key.clone(),
            self.encode_record(&current_key, 2, 0, 0, prior, &current)?,
        ));
        self.park_transition(records)?;
        self.commit_parked_transition()?;
        self.require_native_readback()?;
        if (3..=8).contains(&self.contacts[index].slot) {
            self.origin.recheck().map_err(|_| Error::Startup)?;
            self.require_named_originals()?;
            self.require_current_time()?;
        }
        self.require_contact_child(child)?;
        self.park_completed_transition()?;
        self.contacts[index].settled = true;
        if success {
            Ok(())
        } else {
            Err(Error::Helper {
                return_code: u32::from_be_bytes(array(result.payload(), 148)?),
                errno: i32::from_be_bytes(array(result.payload(), 160)?),
                stage: u32::from_be_bytes(array(result.payload(), 164)?),
            })
        }
    }

    /// Sends the fixed terminal ACK only for this already durable result.
    ///
    /// Negative results may reach this exact closure while their first cause
    /// remains fenced and resident. The same measured child and record must
    /// still exist; this does not assert rollback, release debt or prove Drain.
    ///
    /// # Errors
    /// Refuses missing durable settlement, reuse, wrong socket/child, expired
    /// cutoff, unavailable original metadata or an actual nonblocking send error.
    pub fn acknowledge_terminal(
        &mut self, socket: &mut SeqpacketSocket, result: &ReceivedRecord,
        child: &FixedLiveChild<'_>,
    ) -> Result<(), Error> {
        let index = self.active_contact.ok_or(Error::Rejected)?;
        let contact = &mut self.contacts[index];
        if !contact.settled || contact.terminal_ack_attempted {
            return Err(Error::Rejected);
        }
        // This closure is allowed once even when a negative result already
        // fenced the owner. Err or unwind must not permit a second send.
        contact.terminal_ack_attempted = true;
        self.require_received_child(socket, result, child)?;
        let contact = &mut self.contacts[index];
        self.origin.require_helper_continued(
            child.pidfd(), contact.observations.as_mut().ok_or(Error::Rejected)?,
        ).map_err(|_| Error::Startup)?;
        require_contact_reply(contact, result.payload(), 5)?;
        let mut acknowledgment = [0; 160];
        acknowledgment[..152].copy_from_slice(&contact.header);
        acknowledgment[10] = 6;
        acknowledgment[144..148].copy_from_slice(&8_u32.to_be_bytes());
        acknowledgment[152..].copy_from_slice(&contact.cut.to_be_bytes());
        self.require_contact_child(child)?;
        socket.send(&acknowledgment)?;
        self.contacts[index].terminal_acknowledged = true;
        Ok(())
    }

    /// Advances only after the same actual successful run is mechanically retired.
    ///
    /// The external run and its errors stay resident on refusal. The native
    /// result and terminal ACK must already exist; no caller scalar can stand
    /// in for the supervisor's actual exact-child wait and bounded capture.
    ///
    /// # Errors
    /// Fences missing settlement/ACK, negative child status, incomplete run,
    /// unavailable original capture or retirement failure. This is not Drain.
    pub fn retire_contact<O, E>(
        &mut self, run: &mut FixedNixOfflineSessionOwnerV1<'_, '_, O, E>,
    ) -> Result<(), &Error>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        if !self.usable {
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.usable = false;
        let complete = self.active_contact.and_then(|index| self.contacts.get(index))
            .is_some_and(|contact| contact.settled && contact.terminal_acknowledged);
        if !complete || !matches!(
            run.outcome(),
            Some(FixedProcessRetainedSessionOutcome::Completed {
                exit_code: Some(0), signal: None, ..
            }),
        ) || run.retire_completed().is_err() {
            return Err(self.first_failure.get_or_insert(Error::Process));
        }
        self.active_contact = None;
        self.usable = true;
        Ok(())
    }

    /// Verifies both final returned observations after all actual contacts retire.
    ///
    /// # Errors
    /// Retains the first failure on incomplete contacts, changed original
    /// approval/history, expired original job cut or mismatched public Names.
    /// Success describes this offline job only, never a runtime Session floor.
    pub fn finish_job(&mut self) -> Result<(), &Error> {
        if !self.usable || self.active_contact.is_some() || !self.admission_committed {
            self.usable = false;
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.usable = false;
        let result = self.finish_job_inner();
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(self.first_failure.get_or_insert(error)),
        }
    }

    fn finish_job_inner(&mut self) -> Result<(), Error> {
        let controller = self.contacts[8].observation.as_ref().ok_or(Error::Rejected)?;
        let owner = self.contacts[9].observation.as_ref().ok_or(Error::Rejected)?;
        self.require_observed_state(9, controller)?;
        self.require_observed_state(10, owner)?;
        // Each purpose has independently created salt and NV objects. Equal
        // Names cannot serve as two independent rollback-resistant domains.
        if controller[12..46] == owner[12..46] || controller[46..80] == owner[46..80] {
            return Err(Error::Rejected);
        }
        if !self.contacts[8].terminal_acknowledged || !self.contacts[9].terminal_acknowledged {
            return Err(Error::Rejected);
        }
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_named_originals()?;
        self.require_current_time()?;
        self.require_native_readback()
    }

    fn original_effect_result(&self, ordinal: u16) -> Result<Option<&[u8]>, Error> {
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        for attempt in [2, 1] {
            let key = effect_key(b'T', &self.job, attempt, ordinal)?;
            if let Some(bytes) = journal.state.get(&(NAMESPACE, key.clone())) {
                let row = decode_record(&key, bytes)?;
                if row.body[10] == 2 {
                    let result = terminal_result(row.body)?;
                    return Ok(Some(&result[152..]));
                }
            }
        }
        Ok(None)
    }

    fn require_observed_state(&self, slot: u8, body: &[u8]) -> Result<(), Error> {
        if body.len() != 388 {
            return Err(Error::Rejected);
        }
        let flags = u32::from_be_bytes(array(body, 8)?);
        if !self.origin.recovery() && matches!(slot, 1 | 2) {
            return if flags == 0 { Ok(()) } else { Err(Error::Rejected) };
        }
        if matches!(slot, 9 | 10) && flags != 3 {
            return Err(Error::Rejected);
        }
        let ordinal = if matches!(slot, 1 | 9) { 1 } else { 4 };
        if flags & 1 != 0 {
            // A lost Persist may have completed. Its independently observed
            // object must still equal the exact original Create output, never
            // merely a valid RSA template found at the fixed handle.
            let created = self.original_effect_result(ordinal)?.ok_or(Error::Rejected)?;
            if body[12..46] != created[42..76] || body[88..372] != created[372..656] {
                return Err(Error::Rejected);
            }
        }
        if flags & 2 != 0 {
            let defined = self.original_effect_result(ordinal + 2)?;
            if let Some(defined) = defined {
                if body[46..80] != defined[8..42] || body[372..] != defined[42..58] {
                    return Err(Error::Rejected);
                }
            } else if !self.origin.recovery() || !self.has_original_pending(ordinal + 2)? {
                // An uncertain Define can be resolved only by this fresh
                // authenticated observation and the actual fixed C validator.
                return Err(Error::Rejected);
            } else if matches!(slot, 9 | 10) {
                let initial = self.contacts[if slot == 9 { 0 } else { 1 }]
                    .observation.as_ref().ok_or(Error::Rejected)?;
                if body[46..80] != initial[46..80] || body[372..] != initial[372..] {
                    return Err(Error::Rejected);
                }
            }
        }
        Ok(())
    }

    fn has_original_pending(&self, ordinal: u16) -> Result<bool, Error> {
        let key = effect_key(b'Q', &self.job, 1, ordinal)?;
        Ok(self.journal.as_ref().ok_or(Error::Rejected)?.state.contains_key(&(NAMESPACE, key)))
    }

    fn next_contact_slot(&self) -> Result<usize, Error> {
        for slot in 1..=10 {
            if self.contacts[slot - 1].slot != 0 {
                continue;
            }
            if self.origin.recovery() && (3..=8).contains(&slot) {
                let observation = self.contacts[if slot <= 5 { 0 } else { 1 }]
                    .observation.as_ref().ok_or(Error::Rejected)?;
                let flags = u32::from_be_bytes(array(observation, 8)?);
                let action = (slot - 3) % 3;
                if (action <= 1 && flags & 1 != 0) || (action == 2 && flags & 2 != 0) {
                    continue;
                }
            }
            return Ok(slot);
        }
        Err(Error::Rejected)
    }

    fn require_contact_child(&self, child: &FixedLiveChild<'_>) -> Result<usize, Error> {
        let index = self.active_contact.ok_or(Error::Rejected)?;
        let contact = self.contacts.get(index).ok_or(Error::Rejected)?;
        let now = self.origin.observation_time()?;
        if now < self.first || now >= contact.cut || contact.cut > self.deadline
            || child.deadline() != std::time::Duration::from_nanos(contact.cut)
            || !child.pidfd().is_alive()?
            || child.pidfd().info()? != child.initial_info()
            || contact.original_child.is_some_and(|original| original != child.initial_info())
        {
            return Err(Error::Rejected);
        }
        Ok(index)
    }

    fn require_received_child(
        &self, socket: &mut SeqpacketSocket, record: &ReceivedRecord,
        child: &FixedLiveChild<'_>,
    ) -> Result<usize, Error> {
        let index = self.require_contact_child(child)?;
        let contact = &self.contacts[index];
        socket.require_nix_offline_received_original_v5(record)?;
        let subject = record.subject();
        let credentials = subject.credentials();
        if contact.original_child != Some(child.initial_info())
            || credentials.pid().get() != child.initial_info().pid()
            || credentials.uid() != 0 || credentials.gid() != 0
            || subject.initial_info() != child.initial_info()
            || subject.pidfd().info()? != child.initial_info() || !subject.is_alive()?
        {
            return Err(Error::Rejected);
        }
        self.require_contact_child(child)?;
        Ok(index)
    }

    fn begin_contact_inner(&mut self, nonce: [u8; 32]) -> Result<(), Error> {
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_named_originals()?;
        self.require_current_time()?;
        self.preflight_remaining_closure()?;
        let attempt = if self.origin.recovery() { 2_u8 } else { 1_u8 };
        let current_key = native_key(b"AOSNPH05", &self.job)?;
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        let original = journal.state.get(&(NAMESPACE, current_key.clone()))
            .ok_or(Error::Rejected)?;
        let original = decode_record(&current_key, original)?;
        let mut current: [u8; 2320] = array(original.body, 0)?;
        if current[14] != 1 || nonce == [0; 32]
            || current[48..2288].chunks_exact(112).any(|entry| {
                entry[4] == 1 || entry[8..40] == nonce
            })
        {
            return Err(Error::Rejected);
        }
        let start = (usize::from(attempt) - 1) * 10;
        let slot = self.next_contact_slot()?;
        let index = slot - 1;
        if self.contacts[index].slot != 0 || current[48 + (start + index) * 112 + 4] != 0 {
            return Err(Error::Rejected);
        }
        self.active_contact = Some(index);
        self.prepare_contact_data(index, attempt, slot as u8, nonce)?;
        let contact = &self.contacts[index];
        let offset = 48 + (start + index) * 112;
        let entry = &mut current[offset..offset + 112];
        entry[4] = 1;
        entry[8..40].copy_from_slice(&nonce);
        entry[40..72].copy_from_slice(&Sha256::digest(&contact.request));
        current[11 + usize::from(attempt)] += 1;

        let mut records = Vec::new();
        records.try_reserve_exact(2).map_err(io::Error::other)?;
        let prior = self.history.original_digest();
        if (3..=8).contains(&slot) {
            let ordinal = (slot - 2) as u16;
            let key = effect_key(b'Q', &self.job, attempt, ordinal)?;
            let mut body = Vec::new();
            body.try_reserve_exact(24 + contact.hello.len() + contact.request.len())
                .map_err(io::Error::other)?;
            body.extend_from_slice(b"AOSNQP05");
            body.extend_from_slice(&5_u16.to_be_bytes());
            body.extend_from_slice(&[0; 6]);
            body.extend_from_slice(&(contact.hello.len() as u32).to_be_bytes());
            body.extend_from_slice(&contact.hello);
            body.extend_from_slice(&(contact.request.len() as u32).to_be_bytes());
            body.extend_from_slice(&contact.request);
            records.push(JournalRecord::put(
                NAMESPACE, key.clone(), self.encode_record(
                    &key, 3, contact.header[11], ordinal, prior, &body,
                )?,
            ));
        }
        records.push(JournalRecord::put(
            NAMESPACE, current_key.clone(),
            self.encode_record(&current_key, 2, 0, 0, prior, &current)?,
        ));
        self.park_transition(records)?;
        self.commit_parked_transition()?;
        self.require_native_readback()?;
        self.preflight_remaining_closure()?;

        // Observe uses one prelaunch flight. Effect Pending uses a distinct
        // second bookend after its actual durable/read-back transition.
        if (3..=8).contains(&slot) {
            self.origin.recheck().map_err(|_| Error::Startup)?;
            self.require_named_originals()?;
            self.require_current_time()?;
        }
        self.park_completed_transition()
    }

    fn prepare_contact_data(
        &mut self, index: usize, attempt: u8, slot: u8, nonce: [u8; 32],
    ) -> Result<(), Error> {
        let now = self.origin.observation_time()?;
        let cut = now.checked_add(30_000_000_000).ok_or(Error::Rejected)?.min(self.deadline);
        if now < self.first || now >= cut || self.boot != self.origin.original_boot()? {
            return Err(Error::Rejected);
        }
        let purpose = if matches!(slot, 1 | 3 | 4 | 5 | 9) { 1 } else { 2 };
        let ordinal = if (3..=8).contains(&slot) { u16::from(slot - 2) } else { 0 };
        let approval: [u8; 32] = Sha256::digest(
            &self.inputs[if attempt == 1 { 3 } else { 4 }],
        ).into();
        let contact = self.contacts.get_mut(index).ok_or(Error::Rejected)?;
        contact.attempt = attempt;
        contact.slot = slot;
        contact.cut = cut;
        contact.nonce = nonce;
        contact.header[..8].copy_from_slice(b"AOSNVP05");
        contact.header[8..10].copy_from_slice(&5_u16.to_be_bytes());
        contact.header[11] = purpose;
        contact.header[12] = attempt;
        contact.header[13] = slot;
        contact.header[14..16].copy_from_slice(&ordinal.to_be_bytes());
        contact.header[16..32].copy_from_slice(&self.node);
        contact.header[32..48].copy_from_slice(&self.job);
        contact.header[48..80].copy_from_slice(&approval);
        contact.header[80..112].copy_from_slice(&nonce);
        contact.header[112..128].copy_from_slice(&self.boot);
        contact.header[128..136].copy_from_slice(&self.first.to_be_bytes());
        contact.header[136..144].copy_from_slice(&self.deadline.to_be_bytes());
        contact.hello[..152].copy_from_slice(&contact.header);
        contact.hello[10] = 1;
        contact.hello[144..148].copy_from_slice(&80_u32.to_be_bytes());
        contact.hello[152..160].copy_from_slice(&cut.to_be_bytes());
        contact.hello[160..192].copy_from_slice(&self.origin.compiled_contract()?);
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        for (index, file) in [
            self.installation_lock.as_ref().ok_or(Error::Rejected)?, &journal._lock,
        ].into_iter().enumerate() {
            let identity = inspect_nix_offline_job_identity_v5(file)?;
            if identity.2 != 0 || identity.3 != 0 || identity.6 != 0 {
                return Err(Error::Rejected);
            }
            let offset = 192 + index * 20;
            contact.hello[offset..offset + 8].copy_from_slice(&identity.0.to_be_bytes());
            contact.hello[offset + 8..offset + 16].copy_from_slice(&identity.1.to_be_bytes());
            contact.hello[offset + 16..offset + 20].copy_from_slice(&identity.2.to_be_bytes());
        }
        contact.request.extend_from_slice(&contact.header);
        contact.request[10] = 4;
        if matches!(slot, 4 | 7) {
            let key = effect_key(b'T', &self.job, attempt, ordinal - 1)?;
            let original = journal.state.get(&(NAMESPACE, key.clone())).ok_or(Error::Rejected)?;
            let original = decode_record(&key, original)?;
            let result = terminal_result(original.body)?;
            if result.len() < 152 + 659 || result[148..152] != [0; 4] {
                return Err(Error::Rejected);
            }
            contact.request.extend_from_slice(&result[152..]);
            contact.request[152..160].copy_from_slice(&cut.to_be_bytes());
        } else {
            contact.request.extend_from_slice(&cut.to_be_bytes());
        }
        let body = u32::try_from(contact.request.len() - 152).map_err(|_| Error::Rejected)?;
        contact.request[144..148].copy_from_slice(&body.to_be_bytes());
        Ok(())
    }

    fn park_completed_transition(&mut self) -> Result<(), Error> {
        if self.completed_transitions.len() == self.completed_transitions.capacity() {
            return Err(Error::Rejected);
        }
        self.completed_transitions.push(self.transition.take().ok_or(Error::Rejected)?);
        Ok(())
    }

    fn persist_admission_inner(&mut self) -> Result<(), Error> {
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_named_originals()?;
        self.require_current_time()?;
        self.preflight_remaining_closure()?;

        let (key, body, kind, prior) = if self.origin.recovery() {
            (native_key(b"AOSNRA05", &self.job)?, self.recovery_body()?, 5, self.prior)
        } else {
            (native_key(b"AOSNPA05", &self.job)?, self.admission_body()?, 1, [0; 32])
        };
        let immutable = JournalRecord::put(
            NAMESPACE, key.clone(), self.encode_record(&key, kind, 0, 0, prior, &body)?,
        );
        let current_key = native_key(b"AOSNPH05", &self.job)?;
        let current_body = if self.origin.recovery() {
            let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
            let original = journal.state.get(&(NAMESPACE, current_key.clone()))
                .ok_or(Error::Rejected)?;
            let original = decode_record(&current_key, original)?;
            let mut current: [u8; 2320] = array(original.body, 0)?;
            if current[11] != 0 {
                return Err(Error::Rejected);
            }
            current[11] = 1;
            current[14] = 1;
            current[16..48].copy_from_slice(&Sha256::digest(&self.inputs[4]));
            current
        } else {
            empty_current()
        };
        let current = JournalRecord::put(
            NAMESPACE, current_key.clone(),
            self.encode_record(&current_key, 2, 0, 0, prior, &current_body)?,
        );
        let mut records = Vec::new();
        records.try_reserve_exact(2).map_err(io::Error::other)?;
        records.push(immutable);
        records.push(current);
        self.park_transition(records)?;
        self.commit_parked_transition()?;
        self.require_native_readback()?;

        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_named_originals()?;
        self.require_current_time()?;
        self.preflight_remaining_closure()?;
        self.park_completed_transition()?;
        if self.origin.recovery() {
            self.settle_original_uncertainty()?;
        }
        Ok(())
    }

    fn settle_original_uncertainty(&mut self) -> Result<(), Error> {
        let current_key = native_key(b"AOSNPH05", &self.job)?;
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        let original = journal.state.get(&(NAMESPACE, current_key.clone()))
            .ok_or(Error::Rejected)?;
        let row = decode_record(&current_key, original)?;
        let mut current: [u8; 2320] = array(row.body, 0)?;
        let Some(index) = current[48..1168].chunks_exact(112).position(|entry| entry[4] == 1) else {
            return Ok(());
        };
        if current[11] != 1 {
            return Err(Error::Rejected);
        }

        // The actual new invocation, exclusive original installation/native
        // locks and two complete stopped-service/startup flights precede this
        // uncertainty closure. It asserts neither TPM rollback nor Drain.
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_named_originals()?;
        self.require_current_time()?;
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        let slot = index + 1;
        let offset = 48 + index * 112;
        let prior = self.history.original_digest();
        let mut records = Vec::new();
        records.try_reserve_exact(2).map_err(io::Error::other)?;
        let unknown_digest: [u8; 32] = if (3..=8).contains(&slot) {
            let ordinal = (slot - 2) as u16;
            let pending_key = effect_key(b'Q', &self.job, 1, ordinal)?;
            let terminal_key = effect_key(b'T', &self.job, 1, ordinal)?;
            let pending = journal.state.get(&(NAMESPACE, pending_key)).ok_or(Error::Rejected)?;
            if journal.state.contains_key(&(NAMESPACE, terminal_key.clone())) {
                return Err(Error::Rejected);
            }
            let mut body = [0; 52];
            body[..8].copy_from_slice(b"AOSNTP05");
            body[8..10].copy_from_slice(&5_u16.to_be_bytes());
            body[10] = 3;
            body[16..48].copy_from_slice(&Sha256::digest(pending));
            records.push(JournalRecord::put(
                NAMESPACE, terminal_key.clone(), self.encode_record(
                    &terminal_key, 4, if ordinal <= 3 { 1 } else { 2 }, ordinal, prior, &body,
                )?,
            ));
            Sha256::digest(body).into()
        } else {
            digest(
                b"aos.sandbox.nix-floor.unobserved-contact.v5\0",
                &current[offset..offset + 112],
            )
        };
        current[offset + 4] = 3;
        current[offset + 72..offset + 104].copy_from_slice(&unknown_digest);
        records.push(JournalRecord::put(
            NAMESPACE, current_key.clone(),
            self.encode_record(&current_key, 2, 0, 0, prior, &current)?,
        ));
        self.park_transition(records)?;
        self.commit_parked_transition()?;
        self.require_native_readback()?;
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_named_originals()?;
        self.require_current_time()?;
        self.preflight_remaining_closure()?;
        self.park_completed_transition()
    }

    fn admission_body(&self) -> Result<Vec<u8>, Error> {
        let path = self.origin.profile_original()?.path().to_str().ok_or(Error::Rejected)?;
        let length = u16::try_from(path.len()).map_err(|_| Error::Rejected)?;
        if length == 0 || length > 4096 {
            return Err(Error::Rejected);
        }
        let mut body = Vec::new();
        body.try_reserve_exact(2130 + path.len()).map_err(io::Error::other)?;
        body.extend_from_slice(b"AOSNAD05");
        body.extend_from_slice(&5_u16.to_be_bytes());
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&Sha256::digest(&self.inputs[0]));
        body.extend_from_slice(&self.inputs[1]);
        body.extend_from_slice(&self.inputs[2]);
        body.extend_from_slice(&self.inputs[3]);
        body.extend_from_slice(&self.approval);
        body.extend_from_slice(&Sha256::digest(self.origin.hierarchy_original()?));
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(path.as_bytes());
        body.extend_from_slice(&digest(
            b"aos.sandbox.nix-floor.offline-profile.v4\0", self.origin.profile_original_bytes()?,
        ));
        body.extend_from_slice(&digest(
            b"aos.sandbox.nix-floor.fixed-domain.v4\0", self.origin.domain_original()?,
        ));
        body.extend_from_slice(&self.origin.compiled_contract()?);
        Ok(body)
    }

    fn recovery_body(&self) -> Result<Vec<u8>, Error> {
        let path = self.origin.profile_original()?.path().to_str().ok_or(Error::Rejected)?;
        let length = u16::try_from(path.len()).map_err(|_| Error::Rejected)?;
        if length == 0 || length > 4096 || self.prior == [0; 32] {
            return Err(Error::Rejected);
        }
        let original_key = native_key(b"AOSNPA05", &self.job)?;
        let original = self.journal.as_ref().ok_or(Error::Rejected)?.state
            .get(&(NAMESPACE, original_key)).ok_or(Error::Rejected)?;
        let mut body = Vec::new();
        body.try_reserve_exact(418 + path.len()).map_err(io::Error::other)?;
        body.extend_from_slice(b"AOSNRA05");
        body.extend_from_slice(&5_u16.to_be_bytes());
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&self.inputs[4]);
        body.extend_from_slice(&self.prior);
        body.extend_from_slice(&Sha256::digest(original));
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(path.as_bytes());
        body.extend_from_slice(&digest(
            b"aos.sandbox.nix-floor.offline-profile.v4\0", self.origin.profile_original_bytes()?,
        ));
        Ok(body)
    }

    fn encode_record(
        &self,
        key: &[u8],
        kind: u8,
        purpose: u8,
        ordinal: u16,
        prior: [u8; 32],
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if body.len() > 8192 {
            return Err(Error::Rejected);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(164 + body.len()).map_err(io::Error::other)?;
        bytes.extend_from_slice(b"AOSNPR05");
        bytes.extend_from_slice(&5_u16.to_be_bytes());
        bytes.extend_from_slice(&[kind, purpose]);
        bytes.extend_from_slice(&ordinal.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.job);
        bytes.extend_from_slice(&Sha256::digest(&self.inputs[3]));
        bytes.extend_from_slice(&prior);
        bytes.extend_from_slice(&self.boot);
        bytes.extend_from_slice(&self.first.to_be_bytes());
        bytes.extend_from_slice(&self.deadline.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(body);
        let mut hash = Sha256::new();
        hash.update(RECORD_DOMAIN);
        hash.update((key.len() as u16).to_be_bytes());
        hash.update(key);
        hash.update(&bytes);
        bytes.extend_from_slice(&hash.finalize());
        decode_record(key, &bytes)?;
        Ok(bytes)
    }

    fn park_transition(&mut self, records: Vec<JournalRecord>) -> Result<(), Error> {
        if self.transition.is_some() {
            return Err(Error::Rejected);
        }
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        let current = records.last().ok_or(Error::Rejected)?;
        let before = journal.state.get(&(NAMESPACE, current.key().to_vec()))
            .map(|bytes| decode_record(current.key(), bytes)).transpose()?;
        let identifier = expected_record_transaction_id(
            before.as_ref().map(|record| record.body), &records, journal.next_sequence,
        )?;
        self.transition = Some(JournalTransaction::new(identifier, records)?);
        Ok(())
    }

    fn commit_parked_transition(&mut self) -> Result<(), Error> {
        let transaction = self.transition.as_ref().ok_or(Error::Rejected)?;
        let journal = self.journal.as_mut().ok_or(Error::Rejected)?;
        journal.preflight_with_cache_gate(
            std::slice::from_ref(transaction), None, false, false, None, None, None,
            Some(RootOwnerEdge::NixOffline), CacheMutationGateV1::Ordinary,
        )?;
        journal.commit_with_cache_gate(
            transaction, None, false, false, false, false, false,
            super::SourceProjectAdmissionTransition::None,
            super::controller_source_genesis::ControllerSourceGenesisTransition::None,
            super::source_tree_genesis::SourceGenesisTransitionV1::None,
            super::RootSourceGenesisTransitionV1::None,
            Some(RootOwnerEdge::NixOffline), CacheMutationGateV1::Ordinary,
        )?;
        Ok(())
    }

    fn require_native_readback(&mut self) -> Result<(), Error> {
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        let before = FileIdentity::of(&journal.file)?;
        if before.size > LIMITS.maximum_journal_bytes {
            return Err(Error::Rejected);
        }
        self.readback_bytes.resize(before.size as usize, 0);
        read_exact_positioned_retaining_cause(&journal.file, &mut self.readback_bytes)?;
        let mut observer = NativeHistoryV5::new();
        let mut cursor = ReadAtCursorV1::new(&journal.file, before.size);
        let replay = replay_original_observed(
            &mut cursor, LIMITS, None,
            Some(DeploymentHistoryObserverV1::NixOffline(&mut observer)),
        )?;
        observer.finish(&replay)?;
        if FileIdentity::of(&journal.file)? != before
            || replay.durable_end != before.size || replay.state != journal.state
            || replay.next_sequence != journal.next_sequence
            || replay.committed_transactions != journal.committed_transactions
            || observer.original_digest() != digest(HISTORY_DOMAIN, &self.readback_bytes)
        {
            return Err(Error::Rejected);
        }
        self.history = observer;
        Ok(())
    }

    fn directory(&self) -> Result<&File, Error> {
        self.directory.as_ref()
            .or_else(|| self.journal.as_ref()?.protected.as_ref().map(|held| &held.directory))
            .ok_or(Error::Rejected)
    }

    fn admit_inner(&mut self) -> Result<(), Error> {
        self.origin.recheck().map_err(|_| Error::Startup)?;
        let (node, approval) = self.origin.public_originals()?;
        self.node = node;
        self.approval = approval;
        self.boot = self.origin.original_boot()?;
        for (buffer, (_, length, _)) in self.inputs.iter_mut().zip(FILES) {
            buffer.try_reserve_exact(length).map_err(io::Error::other)?;
            buffer.resize(length, 0);
        }
        self.named.try_reserve_exact(MAXIMUM_NAMED_FILES).map_err(io::Error::other)?;
        self.named_bytes.try_reserve_exact(MAXIMUM_NAMED_FILES).map_err(io::Error::other)?;
        for _ in 0..MAXIMUM_NAMED_FILES {
            let mut bytes = Zeroizing::new(Vec::new());
            bytes.try_reserve_exact(MAXIMUM_INPUT_BYTES).map_err(io::Error::other)?;
            self.named_bytes.push(bytes);
        }
        self.history_bytes.try_reserve_exact(LIMITS.maximum_journal_bytes as usize)
            .map_err(io::Error::other)?;
        self.readback_bytes.try_reserve_exact(LIMITS.maximum_journal_bytes as usize)
            .map_err(io::Error::other)?;
        self.closure.try_reserve_exact(42).map_err(io::Error::other)?;
        self.completed_transitions.try_reserve_exact(42).map_err(io::Error::other)?;
        for contact in &mut self.contacts {
            contact.request.try_reserve_exact(2360).map_err(io::Error::other)?;
        }

        self.directory = Some(File::from(rustix::fs::openat2(
            rustix::fs::CWD, DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(), ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?));
        let directory = self.directory.as_ref().ok_or(Error::Rejected)?;
        validate_protected_fd(directory, 0, FileType::Directory, Mode::RWXU)?;
        if !nix_offline_job_has_original_label_v5(directory)? {
            return Err(Error::Rejected);
        }
        self.directory_identity = Some(inspect_nix_offline_job_identity_v5(directory)?);
        self.directory_mount = Some(MountId::from_fd(directory.as_fd())?);
        open_protected_file_into(
            directory, "installation.lock", 0, false, false, false,
            &mut self.installation_lock,
        )?;
        let lock = self.installation_lock.as_ref().ok_or(Error::Rejected)?;
        flock(lock, FlockOperation::NonBlockingLockExclusive)?;
        let identity = inspect_nix_offline_job_identity_v5(lock)?;
        if identity.6 != 0 || !nix_offline_job_has_original_label_v5(lock)? {
            return Err(Error::Rejected);
        }
        self.installation_identity = Some(identity);

        for index in 0..if self.origin.recovery() { 5 } else { 4 } {
            self.capture_input(index)?;
        }
        self.job.copy_from_slice(&self.inputs[1][12..28]);
        require_nix_offline_static_approval_v3(
            &self.inputs[0], &self.inputs[1], &self.inputs[2],
            &self.node, &self.approval, &mut self.derived, &mut self.static_preimage,
        )?;
        let domain = NixFixedDomainPinsDataV2::decode(
            self.origin.domain_original()?,
        )?;
        if domain.node().as_bytes() != &self.node {
            return Err(Error::Rejected);
        }
        let manifest = BrokerSessionManifestV1::decode(&self.inputs[2][348..1268])
            .map_err(NixOfflineApprovedDataErrorV4::from)?;
        if manifest.domain_id() != *domain.domain().as_bytes()
            || manifest.route_id() != *domain.endpoint().as_bytes()
            || manifest.node_id() != self.node
        {
            return Err(Error::Rejected);
        }

        self.open_native()?;
        if self.origin.recovery() {
            self.require_recovery_original()?;
        } else {
            let (first, deadline) = self.origin.initial_cut()?
                .ok_or(Error::Rejected)?;
            self.first = first;
            self.deadline = deadline;
        }
        self.require_approvals()?;
        self.origin.recheck().map_err(|_| Error::Startup)?;
        self.require_named_originals()?;
        self.require_current_time()?;
        self.preflight_remaining_closure()
    }

    fn capture_input(&mut self, index: usize) -> Result<(), Error> {
        let (name, length, mode) = *FILES.get(index).ok_or(Error::Rejected)?;
        self.files[index] = Some(File::from(open_nofollow_child(self.directory()?, name)?));
        let file = self.files[index].as_ref().ok_or(Error::Rejected)?;
        let identity = inspect_nix_offline_job_identity_v5(file)?;
        if !file.metadata()?.is_file() || identity.2 != 0 || identity.3 != 0
            || identity.4 & 0o7777 != mode || identity.5 != 1 || identity.6 != length as u64
            || !nix_offline_job_has_original_label_v5(file)?
            || Some(MountId::from_fd(file.as_fd())?) != self.directory_mount
        {
            return Err(Error::Rejected);
        }
        self.identities[index] = Some(identity);
        read_exact_positioned_retaining_cause(file, &mut self.inputs[index])?;
        if inspect_nix_offline_job_identity_v5(file)? != identity {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn open_native(&mut self) -> Result<(), Error> {
        let initialize = !self.origin.recovery();
        validate_limits(LIMITS)?;
        let directory = self.directory.as_ref().ok_or(Error::Rejected)?;
        open_protected_file_into(
            directory, LOCK_NAME, 0, initialize, initialize, false, &mut self.native_lock,
        )?;
        let lock = self.native_lock.as_ref().ok_or(Error::Rejected)?;
        flock(lock, FlockOperation::NonBlockingLockExclusive)?;
        if lock.metadata()?.len() != 0 || !nix_offline_job_has_original_label_v5(lock)? {
            return Err(Error::Rejected);
        }
        open_protected_file_into(
            directory, NAME, 0, initialize, initialize, false, &mut self.native_file,
        )?;
        if initialize {
            fsync(directory)?;
        }
        let original = self.native_file.as_ref().ok_or(Error::Rejected)?;
        if !nix_offline_job_has_original_label_v5(original)? {
            return Err(Error::Rejected);
        }
        let physical = FileIdentity::of(original)?;
        if physical.size > LIMITS.maximum_journal_bytes || (initialize && physical.size != 0) {
            return Err(Error::Rejected);
        }
        self.history_bytes.resize(physical.size as usize, 0);
        read_exact_positioned_retaining_cause(original, &mut self.history_bytes)?;
        let mut cursor = ReadAtCursorV1::new(original, physical.size);
        let replay = replay_original_observed(
            &mut cursor, LIMITS, None,
            Some(DeploymentHistoryObserverV1::NixOffline(&mut self.history)),
        )?;
        if replay.durable_end != physical.size || FileIdentity::of(original)? != physical {
            return Err(Error::Rejected);
        }
        self.history.finish(&replay)?;
        if self.history.original_digest() != digest(HISTORY_DOMAIN, &self.history_bytes) {
            return Err(Error::Rejected);
        }
        if initialize && replay.committed_transactions != 0 {
            return Err(Error::Rejected);
        }
        self.prior = if initialize { [0; 32] } else {
            digest(HISTORY_DOMAIN, &self.history_bytes)
        };
        self.native_file.as_mut().ok_or(Error::Rejected)?.seek(SeekFrom::End(0))?;
        let path = PathBuf::from(NAME);
        let name = NAME.to_owned();
        let selection = OriginalCompactionSelectionV1::capture(Path::new(DIRECTORY), NAME);
        let authority = Arc::clone(&self.authority);

        // All fallible replay/read/identity checks precede this atomic owner
        // assembly. Nothing may remove any original and then perform a check.
        let originals = (self.directory.take(), self.native_file.take(), self.native_lock.take());
        let (directory, file, lock) = match originals {
            (Some(directory), Some(file), Some(lock)) => (directory, file, lock),
            (directory, file, lock) => {
                self.directory = directory;
                self.native_file = file;
                self.native_lock = lock;
                return Err(Error::Rejected);
            }
        };
        let protected = Some(ProtectedJournalLocation {
            directory, name, expected_uid: 0,
            original_compaction_selection: selection,
        });
        self.journal = Some(journal_from_original_replay!(
            path, file, lock, LIMITS, protected, replay, authority
        ));
        Ok(())
    }

    fn require_recovery_original(&mut self) -> Result<(), Error> {
        let key = [b"AOSNPA05".as_slice(), self.job.as_slice()].concat();
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        let bytes = journal.state.get(&(NAMESPACE, key.clone())).ok_or(Error::Rejected)?;
        let record = decode_record(&key, bytes)?;
        if record.kind != 1 || record.boot != self.boot || record.job != self.job
            || self.history.recovery || record.body.len() < 2130
            || record.prior != [0; 32]
            || record.approval != <[u8; 32]>::from(Sha256::digest(&self.inputs[3]))
            || record.body[..8] != *b"AOSNAD05"
            || record.body[8..10] != 5_u16.to_be_bytes()
            || record.body[10..16] != [0; 6]
        {
            return Err(Error::Rejected);
        }
        self.first = record.first;
        self.deadline = record.deadline;
        let path_length = usize::from(u16::from_be_bytes(array(record.body, 2032)?));
        let end = 2034_usize.checked_add(path_length).ok_or(Error::Rejected)?;
        if path_length == 0 || path_length > 4096 || record.body.len() != end + 96
            || record.body[48..316] != *self.inputs[1].as_slice()
            || record.body[316..1648] != *self.inputs[2].as_slice()
            || record.body[1648..1952] != *self.inputs[3].as_slice()
            || record.body[1952..2000] != self.approval
            || record.body[16..48] != <[u8; 32]>::from(Sha256::digest(&self.inputs[0]))
            || record.body[2000..2032] != <[u8; 32]>::from(Sha256::digest(
                self.origin.hierarchy_original()?,
            ))
        {
            return Err(Error::Rejected);
        }
        let path = std::str::from_utf8(&record.body[2034..end]).map_err(|_| Error::Rejected)?;
        self.old_profile.open_and_measure(PathBuf::from(path), None, 1024 * 1024, false)?;
        self.old_profile.read_bounded()?;
        if record.body[end..end + 32] != digest(
            b"aos.sandbox.nix-floor.offline-profile.v4\0", self.old_profile.bytes(),
        ) || record.body[end + 32..end + 64] != digest(
            b"aos.sandbox.nix-floor.fixed-domain.v4\0", self.origin.domain_original()?,
        ) || record.body[end + 64..end + 96] != self.origin.compiled_contract()? {
            return Err(Error::Rejected);
        }
        self.origin.require_initialize_profile(self.old_profile.bytes())?;
        Ok(())
    }

    fn require_approvals(&mut self) -> Result<(), Error> {
        let static_digest = digest(
            b"aos.sandbox.nix-floor.approved-static-job.v4\0", &self.inputs[2],
        );
        let domain = digest(
            b"aos.sandbox.nix-floor.fixed-domain.v4\0",
            self.origin.domain_original()?,
        );
        let contract = self.origin.compiled_contract()?;
        let initialize_profile = if self.origin.recovery() {
            self.old_profile.bytes()
        } else {
            self.origin.profile_original_bytes()?
        };
        let initialize = [
            static_digest,
            digest(b"aos.sandbox.nix-floor.offline-profile.v4\0", initialize_profile),
            domain, contract, [0; 32],
        ];
        require_nix_offline_effect_approval_v4(
            &self.inputs[3], &self.approval, &self.job, &self.node, &initialize,
            NixOfflineEffectApprovalKindV4::Initialize, &mut self.effect_preimage,
        )?;
        if self.origin.recovery() {
            let recovery = [
                static_digest,
                digest(b"aos.sandbox.nix-floor.offline-profile.v4\0",
                    self.origin.profile_original_bytes()?),
                domain, contract, self.prior,
            ];
            require_nix_offline_effect_approval_v4(
                &self.inputs[4], &self.approval, &self.job, &self.node, &recovery,
                NixOfflineEffectApprovalKindV4::Recover, &mut self.effect_preimage,
            )?;
        }
        Ok(())
    }

    fn require_named_originals(&mut self) -> Result<(), Error> {
        let directory = self.directory()?;
        if Some(inspect_nix_offline_job_identity_v5(directory)?) != self.directory_identity
            || Some(MountId::from_fd(directory.as_fd())?) != self.directory_mount
            || !nix_offline_job_has_original_label_v5(directory)?
            || Some(inspect_nix_offline_job_identity_v5(
                self.installation_lock.as_ref().ok_or(Error::Rejected)?,
            )?) != self.installation_identity
        {
            return Err(Error::Rejected);
        }
        let count = if self.origin.recovery() { 5 } else { 4 };
        for index in 0..count {
            let (name, length, _) = FILES[index];
            if self.named.len() == MAXIMUM_NAMED_FILES
                || self.named_reads == self.named_bytes.len()
                || length > MAXIMUM_INPUT_BYTES
            {
                return Err(Error::Rejected);
            }
            let descriptor = File::from(open_nofollow_child(self.directory()?, name)?);
            self.named.push(descriptor);
            let named = self.named.last().ok_or(Error::Rejected)?;
            if Some(inspect_nix_offline_job_identity_v5(named)?) != self.identities[index]
                || !nix_offline_job_has_original_label_v5(named)?
            {
                return Err(Error::Rejected);
            }
            let bytes = self.named_bytes.get_mut(self.named_reads).ok_or(Error::Rejected)?;
            self.named_reads += 1;
            bytes.resize(length, 0);
            read_exact_positioned_retaining_cause(named, bytes)?;
            if bytes.as_slice() != self.inputs[index].as_slice()
                || Some(inspect_nix_offline_job_identity_v5(named)?) != self.identities[index]
            {
                return Err(Error::Rejected);
            }
        }
        for (name, lock) in [(NAME, false), (LOCK_NAME, true)] {
            if self.named.len() == MAXIMUM_NAMED_FILES || self.named_pending.is_some() {
                return Err(Error::Rejected);
            }
            let directory = self.directory.as_ref().or_else(|| {
                self.journal.as_ref()?.protected.as_ref().map(|held| &held.directory)
            }).ok_or(Error::Rejected)?;
            open_protected_file_into(
                directory, name, 0, false, false, false, &mut self.named_pending,
            )?;
            self.named.push(self.named_pending.take().ok_or(Error::Rejected)?);
            let named = self.named.last().ok_or(Error::Rejected)?;
            let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
            let original = if lock { &journal._lock } else { &journal.file };
            if FileIdentity::of(named)? != FileIdentity::of(original)?
                || Some(MountId::from_fd(named.as_fd())?) != self.directory_mount
                || !nix_offline_job_has_original_label_v5(named)?
                || (lock && named.metadata()?.len() != 0)
            {
                return Err(Error::Rejected);
            }
        }
        Ok(())
    }

    fn require_current_time(&self) -> Result<(), Error> {
        let now = self.origin.observation_time()?;
        if self.boot != self.origin.original_boot()?
            || self.first == 0 || self.first > now || now >= self.deadline
            || self.first.checked_add(300_000_000_000) != Some(self.deadline)
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn preflight_remaining_closure(&mut self) -> Result<(), Error> {
        // These records are upper-size DATA only. No prospective output is
        // parsed as an authentic observation, committed or exposed as a token.
        // The real next edge is separately strict-preflighted before commit.
        self.closure.clear();
        let journal = self.journal.as_ref().ok_or(Error::Rejected)?;
        let current_key = native_key(b"AOSNPH05", &self.job)?;
        let current = journal.state.get(&(NAMESPACE, current_key.clone()))
            .map(|bytes| decode_record(&current_key, bytes)).transpose()?;
        let current_body = current.as_ref().map(|record| record.body);
        let mut sequence = journal.next_sequence;

        let admission_key = native_key(b"AOSNPA05", &self.job)?;
        if !journal.state.contains_key(&(NAMESPACE, admission_key.clone())) {
            push_closure_data(
                &mut self.closure, &self.job, &current_key,
                Some((admission_key, 6390)), &mut sequence,
            )?;
        }
        let first_attempt = if self.origin.recovery() { 2_u8 } else { 1_u8 };
        for attempt in first_attempt..=2 {
            if attempt == 2 {
                let recovery_key = native_key(b"AOSNRA05", &self.job)?;
                if !journal.state.contains_key(&(NAMESPACE, recovery_key.clone())) {
                    push_closure_data(
                        &mut self.closure, &self.job, &current_key,
                        Some((recovery_key, 4678)), &mut sequence,
                    )?;
                }
                if self.origin.recovery() {
                    // There can be one original unperformed Terminal. Its
                    // original key and debt are not replaced by attempt2.
                    for ordinal in 1..=6 {
                        let pending = effect_key(b'Q', &self.job, 1, ordinal)?;
                        let terminal = effect_key(b'T', &self.job, 1, ordinal)?;
                        if journal.state.contains_key(&(NAMESPACE, pending))
                            && !journal.state.contains_key(&(NAMESPACE, terminal.clone()))
                        {
                            push_closure_data(
                                &mut self.closure, &self.job, &current_key,
                                Some((terminal, 8356)), &mut sequence,
                            )?;
                        }
                    }
                    if current_body.is_some_and(|body| {
                        body[48..1168].chunks_exact(112).any(|entry| {
                            entry[4] == 1 && matches!(entry[1], 1 | 2 | 9 | 10)
                        })
                    }) {
                        push_closure_data(
                            &mut self.closure, &self.job, &current_key, None, &mut sequence,
                        )?;
                    }
                }
            }
            for slot in 1_u8..=10 {
                if matches!(slot, 1 | 2 | 9 | 10) {
                    let index = (usize::from(attempt) - 1) * 10 + usize::from(slot) - 1;
                    let state = current_body.map_or(0, |body| body[48 + index * 112 + 4]);
                    if state == 0 {
                        push_closure_data(
                            &mut self.closure, &self.job, &current_key, None, &mut sequence,
                        )?;
                    }
                    if state <= 1 {
                        push_closure_data(
                            &mut self.closure, &self.job, &current_key, None, &mut sequence,
                        )?;
                    }
                } else {
                    for prefix in [b'Q', b'T'] {
                        let key = effect_key(prefix, &self.job, attempt, u16::from(slot - 2))?;
                        if !journal.state.contains_key(&(NAMESPACE, key.clone())) {
                            push_closure_data(
                                &mut self.closure, &self.job, &current_key,
                                Some((key, 8356)), &mut sequence,
                            )?;
                        }
                    }
                }
            }
        }
        if journal.committed_transactions.checked_add(self.closure.len())
            .is_none_or(|count| count > 42)
        {
            return Err(Error::Rejected);
        }
        journal.preflight_with_cache_gate(
            &self.closure, None, false, false, None, None, None,
            Some(RootOwnerEdge::NixOfflineClosureData), CacheMutationGateV1::Ordinary,
        )?;
        Ok(())
    }
}

fn native_key(prefix: &[u8; 8], job: &[u8; 16]) -> Result<Vec<u8>, Error> {
    let mut key = Vec::new();
    key.try_reserve_exact(24).map_err(io::Error::other)?;
    key.extend_from_slice(prefix);
    key.extend_from_slice(job);
    Ok(key)
}

fn effect_key(prefix: u8, job: &[u8; 16], attempt: u8, ordinal: u16) -> Result<Vec<u8>, Error> {
    let mut key = Vec::new();
    key.try_reserve_exact(20).map_err(io::Error::other)?;
    key.push(prefix);
    key.extend_from_slice(job);
    key.push(attempt);
    key.extend_from_slice(&ordinal.to_be_bytes());
    Ok(key)
}

fn sizing_value(length: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn push_closure_data(
    closure: &mut Vec<JournalTransaction>,
    job: &[u8; 16],
    current_key: &[u8],
    immutable: Option<(Vec<u8>, usize)>,
    sequence: &mut u64,
) -> Result<(), Error> {
    if closure.len() == 42 {
        return Err(Error::Rejected);
    }
    let mut records = Vec::new();
    records.try_reserve_exact(2).map_err(io::Error::other)?;
    if let Some((key, maximum)) = immutable {
        records.push(JournalRecord::put(NAMESPACE, key, sizing_value(maximum)?));
    }
    records.push(JournalRecord::put(NAMESPACE, current_key.to_vec(), sizing_value(2484)?));
    let mut hash = Sha256::new();
    hash.update(CLOSURE_DATA_DOMAIN);
    hash.update(job);
    hash.update(sequence.to_be_bytes());
    let full: [u8; 32] = hash.finalize().into();
    let identifier = full[..16].try_into().map_err(|_| Error::Rejected)?;
    *sequence = sequence.checked_add(records.len() as u64 + 2).ok_or(Error::Rejected)?;
    closure.push(JournalTransaction::new(identifier, records)?);
    Ok(())
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn empty_current() -> [u8; 2320] {
    let mut current = [0; 2320];
    current[..8].copy_from_slice(b"AOSNCT05");
    current[8..10].copy_from_slice(&5_u16.to_be_bytes());
    current[10] = 20;
    current[14] = 1;
    for (index, entry) in current[48..2288].chunks_exact_mut(112).enumerate() {
        let attempt = index / 10 + 1;
        let slot = index % 10 + 1;
        let ordinal = if (3..=8).contains(&slot) { slot - 2 } else { 0 };
        let action = if ordinal == 0 { 0 } else { (ordinal - 1) % 3 + 1 };
        entry[..4].copy_from_slice(&[attempt as u8, slot as u8, action as u8, ordinal as u8]);
    }
    current
}

fn require_contact_reply(
    contact: &NixOfflineContactDataV5, bytes: &[u8], kind: u8,
) -> Result<(), Error> {
    if bytes.len() < 160 || bytes.len() > 2360
        || bytes[..10] != contact.header[..10] || bytes[10] != kind
        || bytes[11..144] != contact.header[11..144]
        || u32::from_be_bytes(array(bytes, 144)?) as usize != bytes.len() - 152
        || bytes[152..160] != contact.cut.to_be_bytes()
    {
        return Err(Error::Rejected);
    }
    Ok(())
}

// These are fixed carrier extents, not another TPM MU decoder. The sole measured
// C helper performs official MU canonical decode/reencode and Name validation.
fn require_result_envelope(slot: u8, bytes: &[u8]) -> Result<(), Error> {
    let body = bytes.get(152..).ok_or(Error::Rejected)?;
    let status = u32::from_be_bytes(array(bytes, 148)?);
    if status != 0 {
        if body.len() != 16 || u32::from_be_bytes(array(body, 12)?) > 2 {
            return Err(Error::Rejected);
        }
        return Ok(());
    }
    match slot {
        1 | 2 | 9 | 10 => {
            if body.len() != 388 {
                return Err(Error::Rejected);
            }
            let flags = u32::from_be_bytes(array(body, 8)?);
            if flags > 3
                || (flags & 1 == 0 && (body[12..46] != [0; 34]
                    || body[80..84] != [0; 4] || body[88..372] != [0; 284]))
                || (flags & 1 != 0 && (body[12..14] != [0, 11]
                    || body[80..84] != 284_u32.to_be_bytes()))
                || (flags & 2 == 0 && (body[46..80] != [0; 34]
                    || body[84..88] != [0; 4] || body[372..] != [0; 16]))
                || (flags & 2 != 0 && (body[46..48] != [0, 11]
                    || body[84..88] != 16_u32.to_be_bytes()))
            {
                return Err(Error::Rejected);
            }
        }
        3 | 6 => {
            if body.len() < 659 || body.len() > 2208
                || body[8..10] != [0, 11] || body[42..44] != [0, 11]
                || body[8..42] == body[42..76]
                || body[76..80] != 284_u32.to_be_bytes()
                || body[80..84] != 284_u32.to_be_bytes()
            {
                return Err(Error::Rejected);
            }
            let private_length = u32::from_be_bytes(array(body, 84)?) as usize;
            if !(3..=1552).contains(&private_length) || body.len() != 656 + private_length {
                return Err(Error::Rejected);
            }
        }
        4 | 7 => {
            if body.len() != 330 || body[8..10] != [0, 11]
                || body[42..46] != 284_u32.to_be_bytes()
            {
                return Err(Error::Rejected);
            }
        }
        5 | 8 => {
            if body.len() != 58 || body[8..10] != [0, 11]
                || body[42..44] != 14_u16.to_be_bytes()
            {
                return Err(Error::Rejected);
            }
        }
        _ => return Err(Error::Rejected),
    }
    Ok(())
}

fn terminal_result(body: &[u8]) -> Result<&[u8], Error> {
    terminal_payload(body)?.ok_or(Error::Rejected)
}

fn terminal_payload(body: &[u8]) -> Result<Option<&[u8]>, Error> {
    if body.len() < 52 || body.len() > 2412 || body[..8] != *b"AOSNTP05"
        || body[8..10] != 5_u16.to_be_bytes() || !matches!(body[10], 2 | 3)
        || body[11..16] != [0; 5] || body[16..48] == [0; 32]
    {
        return Err(Error::Rejected);
    }
    let length = u32::from_be_bytes(array(body, 48)?) as usize;
    if length == 0 && body.len() == 52 && body[10] == 3 {
        // Cold, independently admitted recovery records unobserved ambiguity.
        // No result, errno, TSS code or successful effect is fabricated here.
        return Ok(None);
    }
    if body.len() != 52 + length || length < 160 || length > 2360 {
        return Err(Error::Rejected);
    }
    Ok(Some(&body[52..]))
}

fn array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], JournalError> {
    let end = start.checked_add(N).ok_or(JournalError::ProtectedBoundary)?;
    bytes.get(start..end).ok_or(JournalError::ProtectedBoundary)?
        .try_into().map_err(|_| JournalError::ProtectedBoundary)
}

struct NativeRecordV5<'bytes> {
    kind: u8,
    job: [u8; 16],
    approval: [u8; 32],
    prior: [u8; 32],
    boot: [u8; 16],
    first: u64,
    deadline: u64,
    body: &'bytes [u8],
}

// This fixed historical link is DATA from an already canonical Q row. It
// retains no live child or authority and never reconstructs a helper session.
#[derive(Clone, Copy)]
struct NativeEffectLinkV5 {
    pending_digest: [u8; 32],
    request_header: [u8; 152],
    cut: [u8; 8],
}

impl NativeEffectLinkV5 {
    fn from_pending(key: &[u8], bytes: &[u8]) -> Result<Self, JournalError> {
        let row = decode_record(key, bytes)?;
        if row.kind != 3 {
            return Err(JournalError::ProtectedBoundary);
        }
        let (_, request) = pending_frames(row.body)?;
        Ok(Self {
            pending_digest: Sha256::digest(bytes).into(),
            request_header: array(request, 0)?,
            cut: array(request, 152)?,
        })
    }

    fn require_terminal(&self, row: &NativeRecordV5<'_>) -> Result<(), JournalError> {
        let result = terminal_payload(row.body).map_err(|_| JournalError::ProtectedBoundary)?;
        if row.body[16..48] != self.pending_digest {
            return Err(JournalError::ProtectedBoundary);
        }
        let Some(result) = result else {
            return Ok(());
        };
        if result[..10] != self.request_header[..10]
            || result[10] != 5 || result[11..144] != self.request_header[11..144]
            || result[152..160] != self.cut
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

fn pending_frames(body: &[u8]) -> Result<(&[u8], &[u8]), JournalError> {
    if body.len() < 416 || body.len() > 2616 || body[..8] != *b"AOSNQP05"
        || body[8..10] != 5_u16.to_be_bytes() || body[10..16] != [0; 6]
        || body[16..20] != 232_u32.to_be_bytes()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let request_length = u32::from_be_bytes(array(body, 252)?) as usize;
    if !(160..=2360).contains(&request_length) || body.len() != 256 + request_length {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok((&body[20..252], &body[256..]))
}

fn require_historical_frame(
    key: &[u8], row: &NativeRecordV5<'_>, frame: &[u8], kind: u8,
) -> Result<(), JournalError> {
    if frame.len() < 160 || frame.len() > 2360 || frame[..8] != *b"AOSNVP05"
        || frame[8..10] != 5_u16.to_be_bytes() || frame[10] != kind
        || frame[11] != if key[19] <= 3 { 1 } else { 2 }
        || frame[12] != key[17] || frame[13] != key[19] + 2
        || frame[14..16] != key[18..20] || frame[16..32] == [0; 16]
        || frame[32..48] != row.job || frame[48..80] == [0; 32]
        || (key[17] == 1 && frame[48..80] != row.approval)
        || frame[80..112] == [0; 32] || frame[112..128] != row.boot
        || frame[128..136] != row.first.to_be_bytes()
        || frame[136..144] != row.deadline.to_be_bytes()
        || u32::from_be_bytes(array(frame, 144)?) as usize != frame.len() - 152
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let cut = u64::from_be_bytes(array(frame, 152)?);
    if cut <= row.first || cut > row.deadline {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn decode_record<'bytes>(key: &[u8], bytes: &'bytes [u8]) -> Result<NativeRecordV5<'bytes>, JournalError> {
    let reject = || JournalError::ProtectedBoundary;
    if bytes.len() < 164 || bytes.len() > 8356 || bytes[..8] != *b"AOSNPR05"
        || bytes[8..10] != 5_u16.to_be_bytes() || bytes[14..16] != [0; 2]
    {
        return Err(reject());
    }
    let length = u32::from_be_bytes(array(bytes, 128)?) as usize;
    if length > 8192 || bytes.len() != 164 + length {
        return Err(reject());
    }
    let mut hash = Sha256::new();
    hash.update(RECORD_DOMAIN);
    hash.update((key.len() as u16).to_be_bytes());
    hash.update(key);
    hash.update(&bytes[..132 + length]);
    if bytes[132 + length..] != hash.finalize().as_slice() {
        return Err(reject());
    }
    let job = array(bytes, 16)?;
    let first = u64::from_be_bytes(array(bytes, 112)?);
    let deadline = u64::from_be_bytes(array(bytes, 120)?);
    if job == [0; 16] || bytes[32..64] == [0; 32] || bytes[96..112] == [0; 16]
        || first == 0 || first.checked_add(300_000_000_000) != Some(deadline)
    {
        return Err(reject());
    }
    let kind = bytes[10];
    if key.len() == 24 {
        let expected = match &key[..8] {
            b"AOSNPA05" => 1,
            b"AOSNPH05" => 2,
            b"AOSNRA05" => 5,
            _ => return Err(reject()),
        };
        if kind != expected || bytes[11..14] != [0; 3] || key[8..] != job {
            return Err(reject());
        }
        if kind == 2 {
            require_current_body(&bytes[132..132 + length])?;
        }
    } else if key.len() == 20 {
        let ordinal = u16::from_be_bytes(array(key, 18)?);
        let role = if ordinal <= 3 { 1 } else { 2 };
        if !matches!(key[0], b'Q' | b'T') || key[1..17] != job
            || !matches!(key[17], 1 | 2) || !(1..=6).contains(&ordinal)
            || bytes[11] != role || bytes[12..14] != ordinal.to_be_bytes()
            || kind != if key[0] == b'Q' { 3 } else { 4 }
        {
            return Err(reject());
        }
    } else {
        return Err(reject());
    }
    let decoded = NativeRecordV5 {
        kind, job, approval: array(bytes, 32)?, prior: array(bytes, 64)?,
        boot: array(bytes, 96)?, first, deadline,
        body: &bytes[132..132 + length],
    };
    if matches!(decoded.kind, 1 | 5) {
        let body = decoded.body;
        let (prefix, path_offset, tail) = if decoded.kind == 1 {
            (b"AOSNAD05", 2032, 96)
        } else {
            (b"AOSNRA05", 384, 32)
        };
        if body.len() < path_offset + 2 + tail || body[..8] != *prefix
            || body[8..10] != 5_u16.to_be_bytes() || body[10..16] != [0; 6]
        {
            return Err(reject());
        }
        let path_length = usize::from(u16::from_be_bytes(array(body, path_offset)?));
        let end = path_offset + 2 + path_length;
        if path_length == 0 || path_length > 4096 || body.len() != end + tail
            || body[end..].chunks_exact(32).any(|digest| digest == [0; 32])
        {
            return Err(reject());
        }
        let path = std::str::from_utf8(&body[path_offset + 2..end]).map_err(|_| reject())?;
        if !path.starts_with("/nix/store/") || path.as_bytes().contains(&0) {
            return Err(reject());
        }
        if decoded.kind == 1 && (body[48..56] != *b"AOSNPC03"
            || body[60..76] != decoded.job
            || Sha256::digest(&body[1648..1952]).as_slice() != decoded.approval)
        {
            return Err(reject());
        }
        if decoded.kind == 5 && (body[320..352] != decoded.prior || body[352..384] == [0; 32]) {
            return Err(reject());
        }
    } else if decoded.kind == 3 {
        let (hello, request) = pending_frames(decoded.body)?;
        require_historical_frame(key, &decoded, hello, 1)?;
        require_historical_frame(key, &decoded, request, 4)?;
        if hello[..10] != request[..10] || hello[11..144] != request[11..144]
            || hello[148..152] != [0; 4] || request[148..152] != [0; 4]
            || hello[152..160] != request[152..160] || hello[160..192] == [0; 32]
            || (key[19] != 2 && key[19] != 5 && request.len() != 160)
        {
            return Err(reject());
        }
    } else if decoded.kind == 4 {
        if let Some(result) = terminal_payload(decoded.body).map_err(|_| reject())? {
            require_historical_frame(key, &decoded, result, 5)?;
            require_result_envelope(key[19] + 2, result).map_err(|_| reject())?;
            if (decoded.body[10] == 2) != (result[148..152] == [0; 4]) {
                return Err(reject());
            }
        }
    }
    Ok(decoded)
}

fn require_current_body(bytes: &[u8]) -> Result<(), JournalError> {
    if bytes.len() != 2320 || bytes[..8] != *b"AOSNCT05"
        || bytes[8..10] != 5_u16.to_be_bytes() || bytes[10] != 20
        || bytes[11] > 1 || bytes[12] > 10 || bytes[13] > 10
        || !matches!(bytes[14], 1..=3) || bytes[15] != 0
        || (bytes[11] == 0 && (bytes[16..48] != [0; 32] || bytes[13] != 0))
        || (bytes[11] == 1 && bytes[16..48] == [0; 32])
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let mut counts = [0_u8; 2];
    for (index, entry) in bytes[48..2288].chunks_exact(112).enumerate() {
        let attempt = index / 10 + 1;
        let slot = index % 10 + 1;
        let ordinal = if (3..=8).contains(&slot) { slot - 2 } else { 0 };
        let action = if ordinal == 0 { 0 } else { (ordinal - 1) % 3 + 1 };
        if entry[..4] != [attempt as u8, slot as u8, action as u8, ordinal as u8]
            || entry[4] > 3 || entry[5..8] != [0; 3] || entry[104..] != [0; 8]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if entry[4] == 0 {
            if entry[8..104] != [0; 96] {
                return Err(JournalError::ProtectedBoundary);
            }
        } else {
            counts[attempt - 1] += 1;
            if entry[8..40] == [0; 32] || entry[40..72] == [0; 32]
                || (entry[4] == 1 && entry[72..104] != [0; 32])
                || (entry[4] >= 2 && entry[72..104] == [0; 32])
            {
                return Err(JournalError::ProtectedBoundary);
            }
            if bytes[48..48 + index * 112].chunks_exact(112)
                .any(|earlier| earlier[4] != 0 && earlier[8..40] == entry[8..40])
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    if counts != [bytes[12], bytes[13]] {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn require_current_progress(before: Option<&[u8]>, after: &[u8]) -> Result<(), JournalError> {
    require_current_body(after)?;
    let Some(before) = before else {
        if after[11..14] != [0; 3] || after[14] != 1
            || after[48..2288].chunks_exact(112).any(|entry| entry[4] != 0)
            || after[2288..] != [0; 32]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        return Ok(());
    };
    require_current_body(before)?;
    if before[11] > after[11] || before[12] > after[12] || before[13] > after[13]
        || (before[11] == after[11] && before[16..48] != after[16..48])
        || (before[14] != 1 && after[14] == 1 && !(before[11] == 0 && after[11] == 1))
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let mut active = 0;
    let mut changed = 0;
    let mut transition = None;
    for (old, new) in before[48..2288].chunks_exact(112).zip(after[48..2288].chunks_exact(112)) {
        if new[4] == 1 {
            active += 1;
        }
        if old == new {
            continue;
        }
        changed += 1;
        transition = Some((old, new));
        if old[..4] != new[..4]
            || (old[4] == 0 && new[4] != 1)
            || (old[4] == 1 && (!matches!(new[4], 2 | 3) || old[8..72] != new[8..72]))
            || old[4] >= 2
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    if changed > 1 || active > 1 || (before[11] != after[11] && changed != 0) {
        return Err(JournalError::ProtectedBoundary);
    }
    if let Some((old, new)) = transition {
        let attempt = usize::from(new[0]);
        if old[4] == 0 {
            if before[14] != 1 || after[14] != 1 || new[0] != after[11] + 1
                || after[11 + attempt] != before[11 + attempt].checked_add(1)
                    .ok_or(JournalError::ProtectedBoundary)?
                || after[11 + (3 - attempt)] != before[11 + (3 - attempt)]
                || before[2288..] != after[2288..]
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let base = 48 + (attempt - 1) * 1120;
            let previous = &before[base..base + (usize::from(new[1]) - 1) * 112];
            if previous.chunks_exact(112).any(|entry| {
                entry[4] == 1 || entry[4] == 3
                    || ((attempt == 1 || matches!(entry[1], 1 | 2 | 9 | 10)) && entry[4] != 2)
            }) {
                return Err(JournalError::ProtectedBoundary);
            }
        } else {
            let cold_unknown = attempt == 1 && before[11] == 1 && new[4] == 3;
            let expected_state = if cold_unknown { before[14] } else if new[4] == 3 { 2 }
                else if new[1] == 10 { 3 } else { before[14] };
            let expected_terminal = if new[4] == 2 { &new[72..104] } else { &before[2288..] };
            if before[12..14] != after[12..14] || after[14] != expected_state
                || after[2288..] != *expected_terminal
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    } else if before[11] != 0 || after[11] != 1 || after[13] != 0
        || before[12] != after[12] || after[14] != 1 || before[2288..] != after[2288..]
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn expected_transaction_id(
    before: Option<&[u8]>, transaction: &JournalTransaction, sequence: u64,
) -> Result<[u8; 16], JournalError> {
    expected_record_transaction_id(before, transaction.records(), sequence)
}

fn expected_record_transaction_id(
    before: Option<&[u8]>, records: &[JournalRecord], sequence: u64,
) -> Result<[u8; 16], JournalError> {
    let current = records.last().ok_or(JournalError::ProtectedBoundary)?;
    let decoded = decode_record(current.key(), current.value().ok_or(JournalError::ProtectedBoundary)?)?;
    if decoded.kind != 2 {
        return Err(JournalError::ProtectedBoundary);
    }
    let (attempt, kind, slot) = if records.len() == 2 {
        let first = records.first().ok_or(JournalError::ProtectedBoundary)?;
        let row = decode_record(first.key(), first.value().ok_or(JournalError::ProtectedBoundary)?)?;
        if row.job != decoded.job || row.boot != decoded.boot || row.approval != decoded.approval
            || row.first != decoded.first || row.deadline != decoded.deadline
        {
            return Err(JournalError::ProtectedBoundary);
        }
        match row.kind {
            1 if before.is_none() => (1, 1, 0),
            5 if before.is_some_and(|old| old[11] == 0) && decoded.body[11] == 1 => {
                if decoded.body[16..48] != Sha256::digest(&row.body[16..320]).as_slice() {
                    return Err(JournalError::ProtectedBoundary);
                }
                (2, 2, 0)
            }
            3 | 4 if before.is_some() => {
                let ordinal = u16::from_be_bytes(array(first.key(), 18)?) as u8;
                let attempt = first.key()[17];
                let index = (usize::from(attempt) - 1) * 10 + usize::from(ordinal) + 1;
                let entry = decoded.body.get(48 + index * 112..48 + (index + 1) * 112)
                    .ok_or(JournalError::ProtectedBoundary)?;
                if (row.kind == 3 && entry[4] != 1) || (row.kind == 4 && !matches!(entry[4], 2 | 3)) {
                    return Err(JournalError::ProtectedBoundary);
                }
                let frame = if row.kind == 3 {
                    Some(pending_frames(row.body)?.1)
                } else {
                    terminal_payload(row.body).map_err(|_| JournalError::ProtectedBoundary)?
                };
                if let Some(frame) = frame {
                    if entry[8..40] != frame[80..112]
                        || (attempt == 2 && frame[48..80] != decoded.body[16..48])
                        || (row.kind == 3 && entry[40..72] != Sha256::digest(frame).as_slice())
                        || (row.kind == 4 && (entry[72..104] != Sha256::digest(frame).as_slice()
                            || entry[4] != row.body[10]))
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                } else if attempt != 1 || decoded.body[11] != 1 || entry[4] != 3
                    || entry[72..104] != Sha256::digest(row.body).as_slice()
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                (attempt, if row.kind == 3 { 5 } else { 6 }, ordinal + 2)
            }
            _ => return Err(JournalError::ProtectedBoundary),
        }
    } else if records.len() == 1 {
        let old = before.ok_or(JournalError::ProtectedBoundary)?;
        let mut changed = old[48..2288].chunks_exact(112)
            .zip(decoded.body[48..2288].chunks_exact(112))
            .filter(|(old, new)| old != new);
        let (_, entry) = changed.next().ok_or(JournalError::ProtectedBoundary)?;
        if changed.next().is_some() || entry[3] != 0 || !matches!(entry[1], 1 | 2 | 9 | 10) {
            return Err(JournalError::ProtectedBoundary);
        }
        (entry[0], if entry[4] == 1 { 3 } else { 4 }, entry[1])
    } else {
        return Err(JournalError::ProtectedBoundary);
    };
    let approval = if attempt == 1 { decoded.approval } else {
        if decoded.body[11] != 1 {
            return Err(JournalError::ProtectedBoundary);
        }
        array(decoded.body, 16)?
    };
    let mut hash = Sha256::new();
    hash.update(TX_DOMAIN);
    hash.update(decoded.job);
    hash.update([attempt, kind, slot, 0]);
    hash.update(sequence.to_be_bytes());
    hash.update(approval);
    let full: [u8; 32] = hash.finalize().into();
    let id: [u8; 16] = full[..16].try_into().map_err(|_| JournalError::ProtectedBoundary)?;
    if id == [0; 16] {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(id)
}

pub(super) fn require_native_identifier(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    sequence: u64,
) -> Result<(), JournalError> {
    let current = transaction.records().last().ok_or(JournalError::ProtectedBoundary)?;
    let before = state.get(&(NAMESPACE, current.key().to_vec()))
        .map(|bytes| decode_record(current.key(), bytes)).transpose()?;
    let expected = expected_transaction_id(before.as_ref().map(|record| record.body), transaction, sequence)?;
    if transaction.id() != &expected {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

// This is only sizing DATA in the sole preflight engine. Commit rejects its
// private disposition before effects, and real transitions use require_native_edge.
pub(super) fn require_closure_data_edge(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    if limits != LIMITS || transaction.records().is_empty()
        || transaction.records().len() > 2
        || state.keys().any(|(namespace, _)| *namespace != NAMESPACE)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let current = transaction.records().last().ok_or(JournalError::ProtectedBoundary)?;
    if current.key().len() != 24 || current.key()[..8] != *b"AOSNPH05"
        || current.key()[8..] == [0; 16]
        || current.value().is_none_or(|value| value.len() != 2484)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    if transaction.records().len() == 2
        && transaction.records()[0].key() == current.key()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    for record in transaction.records() {
        let key = record.key();
        let maximum = if key.len() == 24 && key[8..] == current.key()[8..] {
            match &key[..8] {
                b"AOSNPA05" => 6390,
                b"AOSNRA05" => 4678,
                b"AOSNPH05" => 2484,
                _ => return Err(JournalError::ProtectedBoundary),
            }
        } else if key.len() == 20 && key[1..17] == current.key()[8..]
            && matches!(key[0], b'Q' | b'T') && matches!(key[17], 1 | 2)
            && (1..=6).contains(&u16::from_be_bytes(array(key, 18)?))
        {
            8356
        } else {
            return Err(JournalError::ProtectedBoundary);
        };
        if record.namespace() != NAMESPACE
            || record.value().is_none_or(|value| value.len() != maximum)
            || (key != current.key() && state.contains_key(&(NAMESPACE, key.to_vec())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(())
}

// This private edge is reachable only from the genuine retained native owner;
// generic Journal authority claims and mutations of namespace76 are denied.
pub(super) fn require_native_edge(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    if limits != LIMITS || transaction.records().is_empty() || transaction.records().len() > 2
        || state.keys().any(|(namespace, _)| *namespace != NAMESPACE)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let current = transaction.records().last().ok_or(JournalError::ProtectedBoundary)?;
    let current_value = current.value().ok_or(JournalError::ProtectedBoundary)?;
    let decoded_current = decode_record(current.key(), current_value)?;
    if decoded_current.kind != 2 {
        return Err(JournalError::ProtectedBoundary);
    }
    let before = state.get(&(NAMESPACE, current.key().to_vec()))
        .map(|bytes| decode_record(current.key(), bytes)).transpose()?;
    require_current_progress(before.as_ref().map(|record| record.body), decoded_current.body)?;
    for record in transaction.records() {
        if record.namespace() != NAMESPACE {
            return Err(JournalError::ProtectedBoundary);
        }
        let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
        let decoded = decode_record(record.key(), value)?;
        if decoded.kind != 2 && state.contains_key(&(NAMESPACE, record.key().to_vec())) {
            return Err(JournalError::ProtectedBoundary);
        }
        if decoded.kind == 4 {
            let mut key = record.key().to_vec();
            key[0] = b'Q';
            let original = state.get(&(NAMESPACE, key.clone()))
                .ok_or(JournalError::ProtectedBoundary)?;
            NativeEffectLinkV5::from_pending(&key, original)?.require_terminal(&decoded)?;
            if terminal_payload(decoded.body).map_err(|_| JournalError::ProtectedBoundary)?.is_none()
                && (record.key()[17] != 1 || before.as_ref().is_none_or(|row| row.body[11] != 1))
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        if let Some(original) = state.get(&(NAMESPACE, record.key().to_vec())) {
            let old = decode_record(record.key(), original)?;
            if old.job != decoded.job || old.boot != decoded.boot
                || old.first != decoded.first || old.deadline != decoded.deadline
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    if before.is_none() && (transaction.records().len() != 2
        || decode_record(
            transaction.records()[0].key(),
            transaction.records()[0].value().ok_or(JournalError::ProtectedBoundary)?,
        )?.kind != 1)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

// An observational reducer, not a second journal/materialized map. The sole
// parser supplies validated transactions; fixed current bytes and immutable
// key identities are retained before the next historical crossing.
pub(super) struct NativeHistoryV5 {
    commits: usize,
    last_sequence: u64,
    job: Option<[u8; 16]>,
    coordinates: Option<([u8; 16], u64, u64)>,
    approval: Option<[u8; 32]>,
    current: Option<[u8; 2320]>,
    keys: [Option<([u8; 24], usize)>; 26],
    keys_used: usize,
    recovery: bool,
    original_hash: Sha256,
    original_end: u64,
    effects: [Option<NativeEffectLinkV5>; 12],
    admission_digest: Option<[u8; 32]>,
    node: Option<[u8; 16]>,
    contract: Option<[u8; 32]>,
}

impl NativeHistoryV5 {
    fn new() -> Self {
        let mut original_hash = Sha256::new();
        original_hash.update(HISTORY_DOMAIN);
        Self {
            commits: 0, last_sequence: 1, job: None, coordinates: None,
            approval: None,
            current: None, keys: [None; 26], keys_used: 0, recovery: false,
            original_hash, original_end: 0, effects: [None; 12],
            admission_digest: None, node: None, contract: None,
        }
    }

    pub(super) fn observe(
        &mut self, transaction: &JournalTransaction, sequence: u64,
        begin_offset: u64, end_offset: u64,
    )
        -> Result<(), JournalError>
    {
        if self.commits >= 42 || sequence != self.last_sequence
            || begin_offset != self.original_end
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let current = transaction.records().last().ok_or(JournalError::ProtectedBoundary)?;
        let decoded_current = decode_record(
            current.key(), current.value().ok_or(JournalError::ProtectedBoundary)?,
        )?;
        if decoded_current.kind != 2 || transaction.records().len() > 2 {
            return Err(JournalError::ProtectedBoundary);
        }
        require_current_progress(self.current.as_ref().map(|bytes| bytes.as_slice()), decoded_current.body)?;
        if transaction.id() != &expected_transaction_id(
            self.current.as_ref().map(|bytes| bytes.as_slice()), transaction, sequence,
        )? {
            return Err(JournalError::ProtectedBoundary);
        }
        let prior = if self.commits == 0 { [0; 32] } else { self.original_digest() };
        for record in transaction.records() {
            if record.namespace() != NAMESPACE {
                return Err(JournalError::ProtectedBoundary);
            }
            let decoded = decode_record(record.key(), record.value().ok_or(JournalError::ProtectedBoundary)?)?;
            if decoded.kind == 1 {
                if self.admission_digest.is_some() || self.commits != 0 {
                    return Err(JournalError::ProtectedBoundary);
                }
                self.admission_digest = Some(Sha256::digest(
                    record.value().ok_or(JournalError::ProtectedBoundary)?,
                ).into());
                self.node = Some(array(decoded.body, 76)?);
                self.contract = Some(array(decoded.body, decoded.body.len() - 32)?);
            } else if decoded.kind == 5 {
                if Some(array(decoded.body, 352)?) != self.admission_digest {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            if matches!(decoded.kind, 3 | 4) {
                let index = (usize::from(record.key()[17]) - 1) * 6
                    + usize::from(record.key()[19]) - 1;
                if decoded.kind == 3 {
                    if self.effects[index].is_some() {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    let (hello, _) = pending_frames(decoded.body)?;
                    if Some(array(hello, 16)?) != self.node
                        || Some(array(hello, 160)?) != self.contract
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    self.effects[index] = Some(NativeEffectLinkV5::from_pending(
                        record.key(), record.value().ok_or(JournalError::ProtectedBoundary)?,
                    )?);
                } else {
                    if terminal_payload(decoded.body).map_err(|_| JournalError::ProtectedBoundary)?.is_none()
                        && (record.key()[17] != 1 || !self.recovery)
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    self.effects[index].as_ref().ok_or(JournalError::ProtectedBoundary)?
                        .require_terminal(&decoded)?;
                }
            }
            let coordinates = (decoded.boot, decoded.first, decoded.deadline);
            if self.job.is_some_and(|job| job != decoded.job)
                || self.coordinates.is_some_and(|old| old != coordinates)
                || self.approval.is_some_and(|old| old != decoded.approval)
                || decoded.prior != prior
            {
                return Err(JournalError::ProtectedBoundary);
            }
            self.job = Some(decoded.job);
            self.coordinates = Some(coordinates);
            self.approval = Some(decoded.approval);
            if decoded.kind == 2 {
                self.current = Some(array(decoded.body, 0)?);
                self.recovery = decoded.body[11] != 0;
            } else {
                let mut key = [0; 24];
                key[..record.key().len()].copy_from_slice(record.key());
                let entry = (key, record.key().len());
                if self.keys[..self.keys_used].contains(&Some(entry)) || self.keys_used == self.keys.len() {
                    return Err(JournalError::ProtectedBoundary);
                }
                self.keys[self.keys_used] = Some(entry);
                self.keys_used += 1;
            }
        }
        self.commits += 1;
        self.last_sequence = sequence.checked_add(transaction.records().len() as u64 + 2)
            .ok_or(JournalError::SequenceExhausted)?;
        // Reuse the sole encoder. The final whole-file digest comparison also
        // rejects any alternate physical spelling of an otherwise equal map.
        for frame in super::encode_transaction(transaction, sequence)? {
            self.original_end = self.original_end.checked_add(frame.len() as u64)
                .ok_or(JournalError::JournalTooLarge)?;
            self.original_hash.update(&frame);
        }
        if self.original_end != end_offset {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn original_digest(&self) -> [u8; 32] {
        self.original_hash.clone().finalize().into()
    }

    fn finish(&self, replay: &super::ReplayState) -> Result<(), JournalError> {
        if self.commits != replay.committed_transactions || self.last_sequence != replay.next_sequence
            || self.original_end != replay.durable_end
            || (self.commits != 0 && self.current.is_none())
            || replay.state.keys().any(|(namespace, _)| *namespace != NAMESPACE)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These fixtures exercise only bounded native/transport DATA. They create
    // no startup, independently approved job, executed child or floor owner.
    fn pending_current(slot: usize, nonce: u8) -> [u8; 2320] {
        let mut current = empty_current();
        current[12] = 1;
        let offset = 48 + (slot - 1) * 112;
        current[offset + 4] = 1;
        current[offset + 8..offset + 40].fill(nonce);
        current[offset + 40..offset + 72].fill(7);
        current
    }

    #[test]
    fn empty_current_has_exact_twenty_closed_coordinates() {
        let current = empty_current();

        assert_eq!(current.len(), 2320);
        assert!(require_current_body(&current).is_ok());
        assert!(require_current_progress(None, &current).is_ok());
        for (index, entry) in current[48..2288].chunks_exact(112).enumerate() {
            assert_eq!(entry[0], (index / 10 + 1) as u8);
            assert_eq!(entry[1], (index % 10 + 1) as u8);
        }
    }

    #[test]
    fn initialize_cannot_skip_its_first_observation() {
        let empty = empty_current();
        let first = pending_current(1, 1);
        let second = pending_current(2, 2);

        assert!(require_current_progress(Some(&empty), &first).is_ok());
        assert!(require_current_progress(Some(&empty), &second).is_err());
    }

    #[test]
    fn duplicate_contact_nonce_is_not_a_new_contact() {
        let mut current = pending_current(1, 3);
        current[48 + 4] = 2;
        current[48 + 72..48 + 104].fill(9);
        let second = 48 + 112;
        current[second + 4] = 1;
        current[second + 8..second + 40].fill(3);
        current[second + 40..second + 72].fill(8);
        current[12] = 2;

        assert!(require_current_body(&current).is_err());
    }

    #[test]
    fn original_pending_can_become_unknown_only_after_recovery_admission() {
        let before = pending_current(1, 4);
        let mut recovered = before;
        recovered[11] = 1;
        recovered[16..48].fill(5);
        let mut unknown = recovered;
        unknown[48 + 4] = 3;
        unknown[48 + 72..48 + 104].fill(6);

        assert!(require_current_progress(Some(&before), &recovered).is_ok());
        assert!(require_current_progress(Some(&recovered), &unknown).is_ok());
        assert!(require_current_progress(Some(&before), &unknown).is_err());
    }

    #[test]
    fn recovery_admission_cannot_reset_original_contact_count() {
        let before = pending_current(1, 4);
        let mut after = before;
        after[11] = 1;
        after[16..48].fill(5);
        after[12] = 0;

        assert!(require_current_progress(Some(&before), &after).is_err());
    }

    #[test]
    fn present_nv_name_keeps_its_complete_nonzero_digest_tail() {
        let mut frame = [0; 152 + 388];
        let body = &mut frame[152..];
        body[8..12].copy_from_slice(&2_u32.to_be_bytes());
        body[46..48].copy_from_slice(&[0, 11]);
        body[48..80].fill(17);
        body[84..88].copy_from_slice(&16_u32.to_be_bytes());

        assert!(require_result_envelope(1, &frame).is_ok());
        frame[152 + 8..152 + 12].fill(0);
        assert!(require_result_envelope(1, &frame).is_err());
    }

    #[test]
    fn cold_unknown_terminal_contains_no_fabricated_result() {
        let mut body = [0; 52];
        body[..8].copy_from_slice(b"AOSNTP05");
        body[8..10].copy_from_slice(&5_u16.to_be_bytes());
        body[10] = 3;
        body[16..48].fill(1);

        assert!(terminal_payload(&body).unwrap().is_none());
        assert!(terminal_result(&body).is_err());
        body[10] = 2;
        assert!(terminal_payload(&body).is_err());
    }

    #[test]
    fn returned_negative_result_retains_errno_and_stage_extent() {
        let mut frame = [0; 168];
        frame[148..152].copy_from_slice(&0x0000_0902_u32.to_be_bytes());
        frame[160..164].copy_from_slice(&5_i32.to_be_bytes());
        frame[164..168].copy_from_slice(&2_u32.to_be_bytes());

        assert!(require_result_envelope(3, &frame).is_ok());
        frame[164..168].copy_from_slice(&3_u32.to_be_bytes());
        assert!(require_result_envelope(3, &frame).is_err());
        assert!(require_result_envelope(3, &frame[..164]).is_err());
    }
}
