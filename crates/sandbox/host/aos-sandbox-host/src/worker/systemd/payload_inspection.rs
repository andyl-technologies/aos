//! Shares Linux payload discovery while retaining every failed native prefix.
//!
//! The ordinary backend lends local destinations to these same routines. The
//! selected backend keeps two snapshots, the current candidate and any chosen
//! leader until the unchanged reducer finishes both snapshots and liveness.

use super::*;
use aos_sandbox_linux::path::{
    BeneathRootOwnedOriginalV2, BeneathRootResolveOriginalV2, BeneathStreamReadOriginalV2,
};
use aos_sandbox_linux::pidfd::{PidFdNamespaceOriginalV2, PidFdOpenAttemptV1};
use std::cell::RefCell;

#[derive(Debug, thiserror::Error)]
enum InspectionFailure {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    Native(#[from] aos_linux_descriptors::Error),
    #[error(transparent)]
    Descriptor(#[from] rustix::io::Errno),
    #[error("{context}: {source}")]
    Directory {
        context: &'static str,
        #[source]
        source: rustix::io::Errno,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Status(#[from] PayloadStatusReadErrorV2),
}

type InspectionResult<T> = std::result::Result<T, InspectionFailure>;

fn missing() -> HostError {
    resident_readback_missing("payload inspection original")
}

/// Bounds actual discovered entries and resident native pins before traversal.
///
/// These bounds restrict the existing kernel scan. They supply neither launch
/// admission nor a receiving reservation; the genuine caller funds the whole
/// compiled supplier before entering any selected native operation.
#[derive(Clone, Copy)]
pub(crate) struct PayloadInspectionLimitsV2 {
    directories: usize,
    pending: usize,
    processes: usize,
    entries: usize,
}

impl PayloadInspectionLimitsV2 {
    pub(crate) fn new(
        directories: usize,
        pending: usize,
        processes: usize,
        entries: usize,
    ) -> Option<Self> {
        if directories == 0
            || directories > MAXIMUM_PAYLOAD_CGROUPS
            || pending == 0
            || pending > directories
            || processes == 0
            || processes > MAXIMUM_PAYLOAD_PROCESSES
            || entries == 0
        {
            return None;
        }
        Some(Self {
            directories,
            pending,
            processes,
            entries,
        })
    }

    /// Bounds co-resident originals and the unchanged reducer's own copies.
    ///
    /// Two complete snapshots coexist with reducer copies and candidate hints.
    /// Pending roots, the current directory/iterator/reader and two full leader
    /// candidates determine the descriptor peak. Namespace entries count actual
    /// directory names, cgroup.procs/proc paths and PID candidate indexes.
    pub(crate) fn receiving_obligations_v2(self) -> Option<(usize, usize, usize)> {
        let hint = 4096_usize;
        let candidate = std::mem::size_of::<PayloadCandidate>().checked_add(hint)?;
        let candidates = candidate.checked_mul(self.processes.max(4))?.checked_mul(8)?;
        let retired = std::mem::size_of::<PayloadEvidence>()
            .checked_mul(self.processes.max(4))?
            .checked_mul(3)?;
        // An emptied first snapshot keeps VecDeque backing. During the second
        // queue's growth its old/new buffers can coexist with that first backing.
        let pending = std::mem::size_of::<(BeneathRoot, String)>()
            .checked_mul(self.pending.max(4))?
            .checked_mul(5)?
            .checked_add(hint.checked_mul(self.pending)?)?;
        // rustix Linux-raw getdents doubles its buffer while below 1024
        // linux_dirent64 records (24 bytes); 64 KiB covers that physical peak.
        // Both bounded stream readers include their one-byte overflow probe.
        let cgroup_bytes = MAXIMUM_CGROUP_PROCS_BYTES.checked_add(1)?;
        let status_bytes = MAXIMUM_PROC_STATUS_BYTES.checked_add(1)?;
        // A preallocated cgroup reader can coexist with the selected status
        // reader. Two candidate status readers instead allow one current Vec
        // growth (old+new backing) beside the selected resident Vec.
        let readers = cgroup_bytes.checked_add(status_bytes.checked_mul(2)?)?
            .max(status_bytes.checked_mul(5)?)
            .checked_add(64 * 1024)?;
        let cgroup_values = MAXIMUM_CGROUP_PROCS_BYTES / 2;
        let status_values = MAXIMUM_PROC_STATUS_BYTES / 2;
        let parsed_values = cgroup_values.checked_mul(3)?
            .checked_add(status_values.checked_mul(2)?)?
            .max(status_values.checked_mul(5)?)
            .checked_mul(std::mem::size_of::<NonZeroU32>())?;
        let bytes = std::mem::size_of::<HostPayloadInspectionOriginalV2>()
            .checked_mul(2)?
            .checked_add(candidates)?
            .checked_add(retired)?
            .checked_add(pending)?
            .checked_add(readers)?
            .checked_add(parsed_values)?
            .checked_add(hint.checked_mul(8)?)?;
        let descriptors = self.pending.checked_add(22)?;
        let names = self
            .entries
            .checked_add(1)? // a refused over-limit DirEntry is still resident
            .checked_add(self.directories)?
            .checked_mul(2)?
            .checked_add(self.processes.checked_mul(8)?)?;
        Some((bytes, descriptors, names))
    }
}

#[derive(Default)]
struct SnapshotOriginal {
    root: BeneathRootOwnedOriginalV2,
    pending: VecDeque<(BeneathRoot, String)>,
    directory: Option<(BeneathRoot, String)>,
    processes: BeneathStreamReadOriginalV2,
    parsed_processes: Vec<NonZeroU32>,
    entries: Option<rustix::fs::Dir>,
    entry: Option<rustix::fs::DirEntry>,
    child: BeneathRootResolveOriginalV2,
    candidates: Vec<PayloadCandidate>,
    directories_seen: usize,
    entries_seen: usize,
}

impl SnapshotOriginal {
    fn run(
        &mut self,
        root: &BeneathRoot,
        limits: Option<PayloadInspectionLimitsV2>,
    ) -> InspectionResult<Vec<PayloadCandidate>> {
        let duplicate = root.as_fd().try_clone_to_owned()?;
        self.root.from_owned_once(duplicate)?;
        self.pending.push_back((
            self.root.take_completed_once().ok_or_else(missing)?,
            String::new(),
        ));
        while let Some(directory) = self.pending.pop_front() {
            self.directory = Some(directory);
            self.directories_seen = self.directories_seen.checked_add(1).ok_or_else(missing)?;
            if self.directories_seen > limits.map_or(MAXIMUM_PAYLOAD_CGROUPS, |v| v.directories) {
                return Err(HostError::Worker(
                    "payload cgroup tree exceeds its fixed bound".to_owned(),
                )
                .into());
            }
            let (directory, hint) = self.directory.as_ref().ok_or_else(missing)?;
            match limits {
                Some(_) => self.processes.capture_once(
                    directory, Path::new("cgroup.procs"), MAXIMUM_CGROUP_PROCS_BYTES,
                )?,
                None => self.processes.capture_consuming_once_v2(
                    directory, Path::new("cgroup.procs"), MAXIMUM_CGROUP_PROCS_BYTES,
                )?,
            }
            parse_cgroup_processes_into(
                self.processes.completed_bytes().ok_or_else(missing)?,
                &mut self.parsed_processes,
            )?;
            for pid in &self.parsed_processes {
                if self.candidates.len()
                    >= limits.map_or(MAXIMUM_PAYLOAD_PROCESSES, |v| v.processes)
                {
                    return Err(HostError::Worker(
                        "payload process snapshot exceeds its fixed bound".to_owned(),
                    )
                    .into());
                }
                self.candidates.push(PayloadCandidate {
                    pid: *pid,
                    cgroup_id: directory.identity().inode,
                    relative_cgroup_hint: hint.clone(),
                });
            }

            // rustix's Linux-raw Dir::new merely moves this FD into its owner;
            // it performs no fallible check between return and installation.
            let readable = rustix::fs::openat(
                directory.as_fd(),
                ".",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ).map_err(|source| InspectionFailure::Directory {
                context: "open payload cgroup for reading", source,
            })?;
            self.entries = Some(rustix::fs::Dir::new(readable).map_err(|source| {
                InspectionFailure::Directory { context: "iterate payload cgroup", source }
            })?);
            loop {
                let next = self.entries.as_mut().ok_or_else(missing)?.next();
                let Some(entry) = next else { break };
                self.entry = Some(entry.map_err(|source| InspectionFailure::Directory {
                    context: "read payload cgroup entry", source,
                })?);
                self.entries_seen = self.entries_seen.checked_add(1).ok_or_else(missing)?;
                if limits.is_some_and(|v| self.entries_seen > v.entries) {
                    return Err(HostError::Worker(
                        "payload directory entries exceed the admitted bound".to_owned(),
                    )
                    .into());
                }
                let entry = self.entry.as_ref().ok_or_else(missing)?;
                let name = entry.file_name().to_bytes();
                if matches!(name, b"." | b"..") {
                    continue;
                }
                match entry.file_type() {
                    rustix::fs::FileType::Directory => {
                        let name = std::str::from_utf8(name).map_err(|_| {
                            HostError::Worker("payload cgroup name is not UTF-8".to_owned())
                        })?;
                        // Refuse before another descriptor can enlarge the
                        // queue beyond its prepaid physical peak.
                        if limits.is_some_and(|v| self.pending.len() >= v.pending) {
                            return Err(HostError::Worker(
                                "payload pending directories exceed the admitted bound".to_owned(),
                            )
                            .into());
                        }
                        self.child.resolve_once(
                            directory,
                            Path::new(name),
                            ResolveOptions::directory(),
                        )?;
                        let relative = if hint.is_empty() {
                            name.to_owned()
                        } else {
                            format!("{hint}/{name}")
                        };
                        if relative.len() > 4096 {
                            return Err(HostError::Worker(
                                "payload cgroup hint exceeds its fixed bound".to_owned(),
                            )
                            .into());
                        }
                        self.pending.push_back((
                            self.child.take_directory_root_once().ok_or_else(missing)?,
                            relative,
                        ));
                        self.child = BeneathRootResolveOriginalV2::new();
                    }
                    rustix::fs::FileType::Unknown => {
                        return Err(HostError::Worker(
                            "payload cgroup returned an unknown directory-entry type".to_owned(),
                        )
                        .into());
                    }
                    _ => {}
                }
            }
            // EOF, all parsed candidates and every queued child are now held.
            // Only this completed directory's native leaves can be retired.
            self.entry = None;
            self.entries = None;
            self.processes = BeneathStreamReadOriginalV2::new();
            self.parsed_processes = Vec::new();
            self.directory = None;
        }
        Ok(self.candidates.clone())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.root
            .failure()
            .map(|v| v as _)
            .or_else(|| self.processes.failure().map(|v| v as _))
            .or_else(|| self.child.failure().map(|v| v as _))
    }
}

#[derive(Clone, Copy)]
enum CandidateDisposition {
    Ordinary,
    Retained,
}

#[derive(Default)]
struct CandidateOriginal {
    opening: PidFdOpenAttemptV1,
    process: Option<PidFd>,
    status: Option<File>,
    status_bytes: Vec<u8>,
    status_values: Vec<u32>,
    root: Option<OwnedFd>,
    namespaces: [PidFdNamespaceOriginalV2; 4],
    cgroup: BeneathRootOwnedOriginalV2,
    proof: Option<PinnedPayloadLeader>,
}

impl CandidateOriginal {
    fn run(
        &mut self,
        root: &BeneathRoot,
        candidate: PayloadCandidate,
        disposition: CandidateDisposition,
    ) -> InspectionResult<(PayloadEvidence, bool)> {
        self.opening
            .capture_once(candidate.pid)
            .map_err(|_| missing())?;
        self.process = Some(self.opening.take_validated().ok_or_else(missing)?);
        let process = self.process.as_ref().ok_or_else(missing)?;
        let info = process.info()?;
        let cgroup_id = info.cgroup_id().ok_or_else(|| {
            HostError::Worker("kernel omitted payload cgroup identity".to_owned())
        })?;
        let status = File::from(super::open_payload_status_native(candidate.pid)?);
        let nested_pid = match disposition {
            CandidateDisposition::Retained => {
                self.status = Some(status);
                read_nested_pid_from(
                    self.status.as_mut().ok_or_else(missing)?,
                    &mut self.status_bytes, &mut self.status_values, candidate.pid,
                )?
            }
            CandidateDisposition::Ordinary => read_nested_pid_from(
                status, &mut self.status_bytes, &mut self.status_values, candidate.pid,
            )?,
        };
        let mut evidence = PayloadEvidence {
            pid: candidate.pid,
            thread_group_id: info.thread_group_id(),
            parent_pid: info.parent_pid(),
            cgroup_id,
            nested_pid,
            root_device: 0,
            root_inode: 0,
            network_device: 0,
            network_inode: 0,
        };
        if nested_pid != 1 {
            return Ok((evidence, false));
        }

        // Keep the same root pin before fstat and every gated pidfs ioctl.
        // Denied access never falls back to a numeric PID or another namespace.
        self.root = Some(open_payload_root_native(candidate.pid)?);
        let root_identity = rustix::fs::fstat(self.root.as_ref().ok_or_else(missing)?)?;
        for (slot, kind) in self.namespaces.iter_mut().zip([
            NamespaceKind::Network,
            NamespaceKind::Mount,
            NamespaceKind::User,
            NamespaceKind::Pid,
        ]) {
            slot.capture_once(process, kind)?;
        }
        if process.info()? != info {
            return Err(HostError::Worker(
                "payload pidfd identity changed during proof".to_owned(),
            )
            .into());
        }
        self.cgroup
            .from_owned_once(root.as_fd().try_clone_to_owned()?)?;
        // All fallible native work is complete. The owning move below cannot
        // drop an unreturned descriptor between validation and installation.
        let (
            Some(pidfd),
            Some(root),
            Some(cgroup),
            Some(network),
            Some(mount),
            Some(user),
            Some(pid),
        ) = (
            self.process.take(),
            self.root.take(),
            self.cgroup.take_completed_once(),
            self.namespaces[0].take_completed_once(),
            self.namespaces[1].take_completed_once(),
            self.namespaces[2].take_completed_once(),
            self.namespaces[3].take_completed_once(),
        )
        else {
            std::process::abort()
        };
        let network_identity = network.identity();
        evidence.root_device = root_identity.st_dev;
        evidence.root_inode = root_identity.st_ino;
        evidence.network_device = network_identity.device;
        evidence.network_inode = network_identity.inode;
        self.proof = Some(PinnedPayloadLeader {
            pidfd,
            cgroup,
            relative_cgroup_hint: candidate.relative_cgroup_hint,
            root,
            network,
            mount,
            user,
            pid,
        });
        Ok((evidence, true))
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opening
            .failure()
            .map(|v| v as _)
            .or_else(|| {
                self.namespaces
                    .iter()
                    .find_map(|v| v.failure())
                    .map(|v| v as _)
            })
            .or_else(|| self.cgroup.failure().map(|v| v as _))
    }
}

/// Keeps actual snapshot and candidate native owners through reducer refusal.
#[derive(Default)]
pub(crate) struct HostPayloadInspectionOriginalV2 {
    snapshots: [SnapshotOriginal; 2],
    next_snapshot: usize,
    current: Option<CandidateOriginal>,
    selected: Option<CandidateOriginal>,
    retired: Vec<PayloadEvidence>,
    failure: Option<InspectionFailure>,
    entered: bool,
}

impl HostPayloadInspectionOriginalV2 {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn discover_once(
        &mut self,
        root: &BeneathRoot,
        supervisor_pid: u32,
        expected_root: (u64, u64),
        expected_network: (u64, u64),
        limits: PayloadInspectionLimitsV2,
    ) -> Result<PinnedPayloadLeader> {
        self.run_once(root, limits, |backend| {
            discover_payload_leader(backend, supervisor_pid, expected_root, expected_network)
        })
    }

    pub(crate) fn recover_once(
        &mut self,
        root: &BeneathRoot,
        supervisor_pid: u32,
        expected: RuntimeProofSnapshot,
        limits: PayloadInspectionLimitsV2,
    ) -> Result<PinnedPayloadLeader> {
        self.run_once(root, limits, |backend| {
            recover_payload_leader(backend, supervisor_pid, expected)
        })
    }

    fn run_once(
        &mut self,
        root: &BeneathRoot,
        limits: PayloadInspectionLimitsV2,
        reduce: impl FnOnce(&RetainedBackend<'_, '_>) -> Result<ProofSlot>,
    ) -> Result<PinnedPayloadLeader> {
        if self.entered {
            self.failure.get_or_insert_with(|| missing().into());
            return Err(missing());
        }
        self.entered = true;
        let result = {
            let backend = RetainedBackend {
                root,
                limits,
                state: RefCell::new(&mut *self),
            };
            reduce(&backend)
        };
        match result {
            Ok(ProofSlot::Selected) => self
                .selected
                .as_mut()
                .and_then(|v| v.proof.take())
                .ok_or_else(missing),
            Ok(ProofSlot::Current) => {
                self.failure.get_or_insert_with(|| missing().into());
                Err(missing())
            }
            Err(cause) => {
                self.failure.get_or_insert_with(|| cause.into());
                Err(missing())
            }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.snapshots
            .iter()
            .find_map(SnapshotOriginal::failure)
            .or_else(|| self.current.as_ref().and_then(CandidateOriginal::failure))
            .or_else(|| self.selected.as_ref().and_then(CandidateOriginal::failure))
            .or_else(|| self.failure.as_ref().map(|v| v as _))
    }
}

enum ProofSlot {
    Current,
    Selected,
}

struct RetainedBackend<'owner, 'root> {
    root: &'root BeneathRoot,
    limits: PayloadInspectionLimitsV2,
    state: RefCell<&'owner mut HostPayloadInspectionOriginalV2>,
}

impl PayloadInspectionBackend for RetainedBackend<'_, '_> {
    type Proof = ProofSlot;

    fn snapshot(&self) -> Result<Vec<PayloadCandidate>> {
        let mut state = self.state.borrow_mut();
        let index = state.next_snapshot;
        if index >= 2 {
            return Err(missing());
        }
        state.next_snapshot += 1;
        match state.snapshots[index].run(self.root, Some(self.limits)) {
            Ok(snapshot) => Ok(snapshot),
            Err(cause) => {
                state.failure.get_or_insert(cause);
                Err(missing())
            }
        }
    }

    fn prove(&self, candidate: PayloadCandidate) -> Result<(PayloadEvidence, Option<Self::Proof>)> {
        let mut state = self.state.borrow_mut();
        if state.current.is_some() {
            return Err(missing());
        }
        state.current = Some(CandidateOriginal::default());
        match state
            .current
            .as_mut()
            .ok_or_else(missing)?
            .run(self.root, candidate, CandidateDisposition::Retained)
        {
            Ok((evidence, full)) => Ok((evidence, full.then_some(ProofSlot::Current))),
            Err(cause) => {
                state.failure.get_or_insert(cause);
                Err(missing())
            }
        }
    }

    fn retire_irrelevant_candidate(
        &self,
        _: &PayloadCandidate,
        evidence: &PayloadEvidence,
        _: Option<Self::Proof>,
    ) -> Result<()> {
        // Only the generic reducer's completed identity and irrelevance branch
        // reaches this hook. The selected leader remains on a distinct slot.
        let mut state = self.state.borrow_mut();
        if state.current.is_none() {
            return Err(missing());
        }
        // Preserve the actual complete observation and count before physically
        // retiring only its now-irrelevant native leaves and scratch buffers.
        state.retired.push(*evidence);
        state.current.take().ok_or_else(missing)?;
        Ok(())
    }

    fn retain_selected_candidate(&self, proof: Self::Proof) -> Result<Self::Proof> {
        let mut state = self.state.borrow_mut();
        if !matches!(proof, ProofSlot::Current) || state.selected.is_some() {
            return Err(missing());
        }
        state.selected = Some(state.current.take().ok_or_else(missing)?);
        Ok(ProofSlot::Selected)
    }

    fn is_alive(&self, proof: &Self::Proof) -> Result<bool> {
        let mut state = self.state.borrow_mut();
        if !matches!(proof, ProofSlot::Selected) {
            return Err(missing());
        }
        let result = state
            .selected
            .as_ref()
            .and_then(|v| v.proof.as_ref())
            .ok_or_else(missing)?
            .pidfd
            .is_alive();
        match result {
            Ok(value) => Ok(value),
            Err(cause) => {
                state.failure.get_or_insert(cause.into());
                Err(missing())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(path: &Path) -> BeneathRoot {
        BeneathRoot::from_owned(File::open(path).unwrap().into()).unwrap()
    }

    #[test]
    fn failed_real_cgroup_parse_keeps_reader_partial_model_and_same_first_cause() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("cgroup.procs"), b"42\ninvalid\n").unwrap();
        let root = root(directory.path());
        let mut original = HostPayloadInspectionOriginalV2::new();
        let limits = PayloadInspectionLimitsV2::new(2, 1, 4, 16).unwrap();

        assert!(
            original
                .discover_once(&root, 1, (0, 0), (0, 0), limits)
                .is_err()
        );
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        let snapshot = &original.snapshots[0];
        assert_eq!(
            snapshot.processes.completed_bytes().unwrap(),
            b"42\ninvalid\n"
        );
        assert_eq!(snapshot.parsed_processes, [NonZeroU32::new(42).unwrap()]);
        assert!(rustix::fs::fstat(snapshot.directory.as_ref().unwrap().0.as_fd()).is_ok());
        assert!(snapshot.entries.is_none());

        assert!(
            original
                .discover_once(&root, 1, (0, 0), (0, 0), limits)
                .is_err()
        );
        assert_eq!(
            original.failure().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        assert_eq!(original.next_snapshot, 1);
        assert_eq!(original.snapshots[0].parsed_processes.len(), 1);
    }

    #[test]
    fn pending_bound_refusal_keeps_iterator_current_root_and_already_queued_child() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("cgroup.procs"), b"").unwrap();
        std::fs::create_dir(directory.path().join("a")).unwrap();
        std::fs::create_dir(directory.path().join("b")).unwrap();
        let root = root(directory.path());
        let mut original = HostPayloadInspectionOriginalV2::new();
        let limits = PayloadInspectionLimitsV2::new(3, 1, 4, 32).unwrap();

        assert!(
            original
                .discover_once(&root, 1, (0, 0), (0, 0), limits)
                .is_err()
        );

        let snapshot = &original.snapshots[0];
        assert_eq!(snapshot.pending.len(), 1);
        assert!(snapshot.entries.as_ref().unwrap().stat().is_ok());
        assert!(rustix::fs::fstat(snapshot.directory.as_ref().unwrap().0.as_fd()).is_ok());
        assert!(rustix::fs::fstat(snapshot.pending.front().unwrap().0.as_fd()).is_ok());
        assert!(
            original
                .failure()
                .unwrap()
                .to_string()
                .contains("pending directories")
        );
    }
}

impl PayloadInspectionBackend for LinuxPayloadInspector<'_> {
    type Proof = PinnedPayloadLeader;

    fn snapshot(&self) -> Result<Vec<PayloadCandidate>> {
        let mut original = SnapshotOriginal::default();
        original.run(self.payload_root, None).map_err(|cause| {
            HostError::Worker(
                original
                    .failure()
                    .map_or_else(|| cause.to_string(), ToString::to_string),
            )
        })
    }

    fn prove(&self, candidate: PayloadCandidate) -> Result<(PayloadEvidence, Option<Self::Proof>)> {
        let mut original = CandidateOriginal::default();
        let (evidence, full) = original
            .run(self.payload_root, candidate, CandidateDisposition::Ordinary)
            .map_err(|cause| {
                HostError::Worker(
                    original
                        .failure()
                        .map_or_else(|| cause.to_string(), ToString::to_string),
                )
            })?;
        Ok((evidence, if full { original.proof.take() } else { None }))
    }

    fn is_alive(&self, proof: &Self::Proof) -> Result<bool> {
        proof
            .pidfd
            .is_alive()
            .map_err(|cause| HostError::Worker(cause.to_string()))
    }
}
