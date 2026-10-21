//! Retains the measured inputs and signature check of one optional phase-0 report.
//!
//! These are historical comparison facts. The enclosing genuine Source or Host
//! scope admits the complete quote before entry and retains this owner through
//! its own independent posts. No fact constructs backend readiness, a publisher
//! generation, a current service identity or a financial allowance.

use std::error::Error;
use std::fs::{File, Metadata};
use std::mem::size_of;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1;
use aos_sandbox_linux::protected_file::FixedProtectedReadOriginalV3;
use aos_sandbox_linux::selinux_policy::RetainedLiveSelinuxPolicyReadbackV1;
use ed25519_dalek::VerifyingKey;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, statat, open};

use super::{
    PHASE0_PROBE_RECORD_BYTES, Phase0ProbeObservationV2, ProtectedPackagedExecutableHashOriginalV2,
    SignedPhase0ProbeRecordV2,
};
use crate::plan::PackagedNspawnOriginalV2;

const KEY_ROLE: &str = "phase0-probe-public-key-v1";
const PROBE_DIRECTORY: &str = "/var/lib/aos/sandbox-host-phase0";
const PROBE_PATH: &str = "/var/lib/aos/sandbox-host-phase0/probe-v2";

/// Reports an incomplete observation while all reached originals remain held.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("phase-0 deployment facts are incomplete or refused")]
pub struct Phase0DeploymentFactsClosedV2;

/// Borrows no native authority from the signed, measured phase-0 comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Phase0DeploymentFactsDataV2 {
    /// Digest of the exact authenticated AOSHPB02 report.
    pub probe_digest: [u8; 32],
    /// Actual signed report, bound to this boot and these measured packages.
    pub observation: Phase0ProbeObservationV2,
    /// Device of the actual held packaged nspawn executable.
    pub nspawn_device: u64,
    /// Inode of the actual held packaged nspawn executable.
    pub nspawn_inode: u64,
    /// PID1 image digest declared by the verified nspawn package artifact.
    ///
    /// This declaration does not itself compare the running manager image.
    pub declared_pid1_digest: [u8; 32],
    /// Compiler supervisor profile digest from that same package artifact.
    pub supervisor_profile_digest: [u8; 32],
    /// Payload filter source digest from that same package artifact.
    pub payload_filter_digest: [u8; 32],
}

#[derive(Clone, Copy)]
enum First {
    Reentry,
    Paths,
    KeyPresence,
    HostdResolution,
    Key,
    KeyParse,
    Directory,
    DirectoryBefore,
    DirectoryPolicy,
    Probe,
    Boot(usize),
    Nspawn,
    Hostd,
    Inspector,
    Policy(usize),
    Signature,
    DirectoryAfter,
    DirectoryNamedAfter,
    DirectoryComparison,
    BootComparison,
    PolicyComparison,
    Completion,
}

#[derive(Debug, thiserror::Error)]
enum ComparisonFailure {
    #[error("phase-0 input has invalid protected metadata")]
    Metadata,
    #[error("phase-0 package path is not the fixed packaged role")]
    Path,
    #[error("phase-0 verifier key is malformed or weak")]
    Key,
    #[error("phase-0 protected directory changed during observation")]
    DirectoryChanged,
    #[error("phase-0 kernel boot changed during observation")]
    BootChanged,
    #[error("phase-0 live MAC policy changed during observation")]
    PolicyChanged,
    #[error("phase-0 measured facts are incomplete")]
    Incomplete,
}

struct Paths {
    hostd: PathBuf,
    inspector: PathBuf,
    nspawn: String,
    policy: String,
}

struct Measurements {
    key: FixedProtectedInput,
    verifier: Option<Result<VerifyingKey, ComparisonFailure>>,
    directory: Option<rustix::io::Result<File>>,
    directory_before: Option<rustix::io::Result<Stat>>,
    directory_policy: Option<Result<(), ComparisonFailure>>,
    probe: FixedProtectedInput,
    boot: [RootOriginalKernelBootIdAttemptV1; 2],
    boot_entered: bool,
    boot_bytes: [Option<[u8; 16]>; 2],
    nspawn: PackagedNspawnOriginalV2,
    hostd: ProtectedPackagedExecutableHashOriginalV2,
    hostd_entered: bool,
    inspector: ProtectedPackagedExecutableHashOriginalV2,
    inspector_entered: bool,
    policy: [RetainedLiveSelinuxPolicyReadbackV1; 2],
    policy_entered: bool,
    signature: Option<crate::Result<SignedPhase0ProbeRecordV2>>,
    directory_after: Option<rustix::io::Result<Stat>>,
    directory_named_after: Option<rustix::io::Result<Stat>>,
    directory_comparison: Option<Result<(), ComparisonFailure>>,
    boot_comparison: Option<Result<(), ComparisonFailure>>,
    policy_comparison: Option<Result<(), ComparisonFailure>>,
}

impl Measurements {
    fn new() -> Self {
        Self {
            key: FixedProtectedInput::new(),
            verifier: None,
            directory: None,
            directory_before: None,
            directory_policy: None,
            probe: FixedProtectedInput::new(),
            boot: std::array::from_fn(|_| RootOriginalKernelBootIdAttemptV1::new()),
            boot_entered: false,
            boot_bytes: [None; 2],
            nspawn: PackagedNspawnOriginalV2::new(),
            hostd: ProtectedPackagedExecutableHashOriginalV2::new(),
            hostd_entered: false,
            inspector: ProtectedPackagedExecutableHashOriginalV2::new(),
            inspector_entered: false,
            policy: std::array::from_fn(|_| RetainedLiveSelinuxPolicyReadbackV1::new()),
            policy_entered: false,
            signature: None,
            directory_after: None,
            directory_named_after: None,
            directory_comparison: None,
            boot_comparison: None,
            policy_comparison: None,
        }
    }
}

/// Owns a single optional key lookup and every reached measurement prefix.
///
/// Construction is inert and small. The complete measured payload is allocated
/// only after the externally paid lookup observes an existing verifier role.
/// Partial bytes, keys, signatures, native errors and all actual Files stay
/// resident after a refusal. Reentry never replaces the selected first cause.
#[must_use = "retain all native prefixes through the enclosing scope's posts"]
pub struct Phase0DeploymentFactsOriginalV2 {
    key_path: PathBuf,
    paths: Option<Paths>,
    path_policy: Option<Result<(), ComparisonFailure>>,
    key_presence: Option<std::io::Result<Metadata>>,
    running_host_path: Option<std::io::Result<PathBuf>>,
    measurements: Option<Box<Measurements>>,
    facts: Option<Phase0DeploymentFactsDataV2>,
    completion: Option<Result<(), ComparisonFailure>>,
    absent: bool,
    entered: bool,
    first: Option<First>,
}

impl Phase0DeploymentFactsOriginalV2 {
    /// Creates a vacant destination without allocation, path observation or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key_path: PathBuf::new(),
            paths: None,
            path_policy: None,
            key_presence: None,
            running_host_path: None,
            measurements: None,
            facts: None,
            completion: None,
            absent: false,
            entered: false,
            first: None,
        }
    }

    /// Quotes every resident carrier, bounded input and named native path.
    ///
    /// This is passive DATA. Actual Source/Host payment precedes path growth,
    /// payload allocation, native lookup and every subowner's entry. Neither
    /// input traffic nor private Rust field counts are namespace fees. File
    /// input is charged independently from the buffers retaining its bytes.
    #[must_use]
    pub fn receiving_demand_v2(
        credentials: &Path,
        nspawn: &str,
        hostd: &Path,
        policy: &str,
    ) -> Option<ResourceVector> {
        // Computing a quote must not allocate the paths it is about to fund.
        let parent = hostd.parent()?;
        let inspector_bytes = parent
            .as_os_str()
            .len()
            .checked_add(1)?
            .checked_add("aos-sandbox-host-phase0-probe".len())?;
        let key_bytes = credentials
            .as_os_str()
            .len()
            .checked_add(1)?
            .checked_add(KEY_ROLE.len())?;
        let mut bytes = size_of::<Self>()
            .checked_mul(2)?
            .checked_add(size_of::<Measurements>().checked_mul(2)?)?
            .checked_add(size_of::<Paths>())?;
        for len in [
            key_bytes,
            hostd.as_os_str().len(),
            inspector_bytes,
            nspawn.len(),
            policy.len(),
        ] {
            bytes = bytes.checked_add(len.checked_mul(3)?)?;
        }
        let mut quote = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            // The protected probe directory is held independently of files.
            .with(D::OpenFiles, 1)
            .with(
                D::MetadataEntries,
                u64::try_from(Path::new(PROBE_DIRECTORY).components().count()).ok()?,
            );
        for (maximum, names) in [
            (32, credentials.components().count().checked_add(1)?),
            (
                PHASE0_PROBE_RECORD_BYTES,
                Path::new(PROBE_PATH).components().count(),
            ),
        ] {
            let (memory, files) = FixedProtectedReadOriginalV3::receiving_obligations_v3(maximum)?;
            quote = quote
                .checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                        .with(D::OpenFiles, u64::try_from(files).ok()?)
                        .with(D::OutputBytes, u64::try_from(maximum.checked_add(1)?).ok()?)
                        .with(D::MetadataEntries, u64::try_from(names).ok()?),
                )
                .ok()?;
        }
        let host = ProtectedPackagedExecutableHashOriginalV2::receiving_shape_v2(hostd)?;
        // Both fixed siblings have the same path depth. Only the final name's
        // byte backing differs; the shared hasher/native shape is identical.
        let inspector_memory = host
            .memory_bytes
            .checked_sub(u64::try_from(hostd.as_os_str().len()).ok()?)?
            .checked_add(u64::try_from(inspector_bytes).ok()?)?;
        for memory in [host.memory_bytes, inspector_memory] {
            quote = quote
                .checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, memory)
                        .with(D::OpenFiles, host.open_files)
                        .with(D::OutputBytes,
                            ProtectedPackagedExecutableHashOriginalV2::maximum_requested_read_bytes_v2())
                        .with(D::MetadataEntries, host.namespace_entries),
                )
                .ok()?;
        }
        let live = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
        // Two independent before/after samplers remain held; no successful
        // before sample is rearmed or adopted as an after observation.
        let policy_names = Path::new(policy)
            .components()
            .count()
            .checked_add(Path::new("/sys/fs/selinux/policy").components().count())?
            .checked_add(Path::new("/sys/fs/selinux/enforce").components().count())?;
        let paired = ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(
                    live.memory_bytes
                        .checked_add(
                            RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?,
                        )?
                        .checked_mul(2)?,
                )
                .ok()?,
            )
            .with(
                D::OpenFiles,
                u64::try_from(live.open_files.checked_add(1)?.checked_mul(2)?).ok()?,
            )
            .with(
                D::OutputBytes,
                live.input_bytes.checked_add(u64::try_from(
                    RootOriginalKernelBootIdAttemptV1::maximum_requested_read_bytes_v2(),
                ).ok()?)?.checked_mul(2)?,
            )
            .with(
                D::MetadataEntries,
                u64::try_from(policy_names.checked_mul(2)?).ok()?,
            );
        quote
            .checked_add(paired)
            .ok()?
            .checked_add(PackagedNspawnOriginalV2::receiving_demand_v2(nspawn)?)
            .ok()
    }

    /// Measures the optional report once and runs all owed nested posts.
    ///
    /// Returns `None` only when the actual verifier lookup reports NotFound.
    /// Other lookup errors, invalid keys and every entered measurement failure
    /// remain sticky. A complete report is historical DATA, never readiness.
    ///
    /// # Errors
    /// Retains any file/path/package/boot/MAC/signature error and rejects reentry.
    pub fn observe_once_v2(
        &mut self,
        credentials: &Path,
        nspawn: &str,
        hostd: &Path,
        policy: &str,
    ) -> Result<Option<Phase0DeploymentFactsDataV2>, Phase0DeploymentFactsClosedV2> {
        self.observe_engine_v2(credentials, nspawn, Some(hostd), policy)
    }

    // The ordinary Host delegate resolves its actual running image only after
    // the same optional-key lookup. An absent credential does no image IO.
    pub(crate) fn observe_running_host_once_v2(
        &mut self,
        credentials: &Path,
        nspawn: &str,
        policy: &str,
    ) -> Result<Option<Phase0DeploymentFactsDataV2>, Phase0DeploymentFactsClosedV2> {
        self.observe_engine_v2(credentials, nspawn, None, policy)
    }

    fn observe_engine_v2(
        &mut self,
        credentials: &Path,
        nspawn: &str,
        hostd: Option<&Path>,
        policy: &str,
    ) -> Result<Option<Phase0DeploymentFactsDataV2>, Phase0DeploymentFactsClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        self.entered = true;
        self.key_path = credentials.join(KEY_ROLE);
        self.key_presence = Some(std::fs::symlink_metadata(&self.key_path));
        match self.key_presence.as_ref() {
            Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                self.absent = true;
                return Ok(None);
            }
            Some(Ok(_)) => {}
            _ => {
                self.first = Some(First::KeyPresence);
                return Err(Phase0DeploymentFactsClosedV2);
            }
        }
        let hostd = match hostd {
            Some(path) => path,
            None => {
                self.running_host_path = Some(std::env::current_exe());
                let Some(Ok(path)) = self.running_host_path.as_ref() else {
                    self.first = Some(First::HostdResolution);
                    return Err(Phase0DeploymentFactsClosedV2);
                };
                path.as_path()
            }
        };
        // Missing optional keys preserve the original observation-only route;
        // fixed role checks and other measurements belong to the present case.
        self.path_policy = Some(if packaged_role(hostd, "/bin/aos-sandbox-hostd") {
            Ok(())
        } else {
            Err(ComparisonFailure::Path)
        });
        if !matches!(self.path_policy, Some(Ok(()))) {
            self.first = Some(First::Paths);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        let Some(parent) = hostd.parent() else {
            self.first = Some(First::Paths);
            return Err(Phase0DeploymentFactsClosedV2);
        };
        self.paths = Some(Paths {
            hostd: hostd.to_owned(),
            inspector: parent.join("aos-sandbox-host-phase0-probe"),
            nspawn: nspawn.to_owned(),
            policy: policy.to_owned(),
        });
        self.measurements = Some(Box::new(Measurements::new()));
        let body = self.observe_body_v2();
        // The before destination's own error cannot suppress its separately
        // prepaid after observation or the other entered native posts.
        self.finish_owed_v2();
        if body.is_err() && self.first.is_none() {
            self.completion = Some(Err(ComparisonFailure::Incomplete));
            self.first = Some(First::Completion);
        }
        if body.is_err() || self.first.is_some() {
            return Err(Phase0DeploymentFactsClosedV2);
        }
        self.complete_v2()?;
        Ok(self.facts)
    }

    fn observe_body_v2(&mut self) -> Result<(), Phase0DeploymentFactsClosedV2> {
        let paths = self.paths.as_ref().ok_or(Phase0DeploymentFactsClosedV2)?;
        let m = self
            .measurements
            .as_mut()
            .ok_or(Phase0DeploymentFactsClosedV2)?;
        if m.key.observe(&self.key_path, 32).is_err() {
            self.first = Some(First::Key);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        m.verifier = Some(
            m.key
                .reader
                .bytes_completed_v3()
                .and_then(|bytes| <&[u8; 32]>::try_from(bytes).ok())
                .and_then(|bytes| VerifyingKey::from_bytes(bytes).ok())
                .filter(|key| !key.is_weak())
                .ok_or(ComparisonFailure::Key),
        );
        if !matches!(m.verifier, Some(Ok(_))) {
            self.first = Some(First::KeyParse);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        m.directory = Some(
            open(
                PROBE_DIRECTORY,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map(File::from),
        );
        let Some(Ok(directory)) = m.directory.as_ref() else {
            self.first = Some(First::Directory);
            return Err(Phase0DeploymentFactsClosedV2);
        };
        m.directory_before = Some(fstat(directory));
        let Some(Ok(stat)) = m.directory_before.as_ref() else {
            self.first = Some(First::DirectoryBefore);
            return Err(Phase0DeploymentFactsClosedV2);
        };
        m.directory_policy = Some(
            if FileType::from_raw_mode(stat.st_mode) == FileType::Directory
                && stat.st_uid == 0
                && stat.st_mode & 0o077 == 0
            {
                Ok(())
            } else {
                Err(ComparisonFailure::Metadata)
            },
        );
        if !matches!(m.directory_policy, Some(Ok(()))) {
            self.first = Some(First::DirectoryPolicy);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        if m.probe
            .observe(Path::new(PROBE_PATH), PHASE0_PROBE_RECORD_BYTES)
            .is_err()
        {
            self.first = Some(First::Probe);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        m.boot_entered = true;
        m.boot_bytes[0] = m.boot[0].observe_once().ok().map(|boot| boot.into_bytes());
        if m.boot_bytes[0].is_none() {
            self.first = Some(First::Boot(0));
            return Err(Phase0DeploymentFactsClosedV2);
        }
        if m.nspawn.observe_once_v2(&paths.nspawn).is_err() {
            self.first = Some(First::Nspawn);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        m.hostd_entered = true;
        if m.hostd.observe_once_v2(&paths.hostd).is_err() {
            self.first = Some(First::Hostd);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        m.inspector_entered = true;
        if m.inspector.observe_once_v2(&paths.inspector).is_err() {
            self.first = Some(First::Inspector);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        m.policy_entered = true;
        if m.policy[0].verify_once(&paths.policy).is_err() {
            self.first = Some(First::Policy(0));
            return Err(Phase0DeploymentFactsClosedV2);
        }
        let Some(Ok(key)) = m.verifier.as_ref() else {
            return Err(Phase0DeploymentFactsClosedV2);
        };
        let bytes = m
            .probe
            .reader
            .bytes_completed_v3()
            .ok_or(Phase0DeploymentFactsClosedV2)?;
        m.signature = Some(SignedPhase0ProbeRecordV2::verify(
            bytes,
            key,
            m.boot_bytes[0].ok_or(Phase0DeploymentFactsClosedV2)?,
            m.nspawn.digest_v2().ok_or(Phase0DeploymentFactsClosedV2)?,
            m.hostd.digest_v2().ok_or(Phase0DeploymentFactsClosedV2)?,
            m.inspector
                .digest_v2()
                .ok_or(Phase0DeploymentFactsClosedV2)?,
            m.policy[0]
                .verified()
                .ok_or(Phase0DeploymentFactsClosedV2)?
                .digest(),
        ));
        if !matches!(m.signature, Some(Ok(_))) {
            self.first = Some(First::Signature);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        Ok(())
    }

    fn finish_owed_v2(&mut self) {
        let Some(paths) = self.paths.as_ref() else {
            return;
        };
        let Some(m) = self.measurements.as_mut() else {
            return;
        };
        if m.hostd_entered {
            if m.hostd.observe_after_owed_once_v2().is_err() {
                self.first.get_or_insert(First::Hostd);
            }
        }
        if m.inspector_entered {
            if m.inspector.observe_after_owed_once_v2().is_err() {
                self.first.get_or_insert(First::Inspector);
            }
        }
        if let Some(Ok(directory)) = m.directory.as_ref() {
            m.directory_after = Some(fstat(directory));
            m.directory_named_after = Some(statat(
                rustix::fs::CWD,
                PROBE_DIRECTORY,
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            if !matches!(m.directory_after, Some(Ok(_))) {
                self.first.get_or_insert(First::DirectoryAfter);
            }
            if !matches!(m.directory_named_after, Some(Ok(_))) {
                self.first.get_or_insert(First::DirectoryNamedAfter);
            }
            m.directory_comparison = Some(
                match (
                    &m.directory_before,
                    &m.directory_after,
                    &m.directory_named_after,
                ) {
                    (Some(Ok(before)), Some(Ok(after)), Some(Ok(named)))
                        if same_directory(before, after) && same_directory(before, named) =>
                    {
                        Ok(())
                    }
                    _ => Err(ComparisonFailure::DirectoryChanged),
                },
            );
            if !matches!(m.directory_comparison, Some(Ok(()))) {
                self.first.get_or_insert(First::DirectoryComparison);
            }
        }
        if m.boot_entered {
            m.boot_bytes[1] = m.boot[1].observe_once().ok().map(|boot| boot.into_bytes());
            if m.boot_bytes[1].is_none() {
                self.first.get_or_insert(First::Boot(1));
            }
            m.boot_comparison = Some(
                if m.boot_bytes[0].is_some() && m.boot_bytes[0] == m.boot_bytes[1] {
                    Ok(())
                } else {
                    Err(ComparisonFailure::BootChanged)
                },
            );
            if !matches!(m.boot_comparison, Some(Ok(()))) {
                self.first.get_or_insert(First::BootComparison);
            }
        }
        if m.policy_entered {
            if m.policy[1].verify_once(&paths.policy).is_err() {
                self.first.get_or_insert(First::Policy(1));
            }
            m.policy_comparison = Some(match (m.policy[0].verified(), m.policy[1].verified()) {
                (Some(before), Some(after)) if before == after => Ok(()),
                _ => Err(ComparisonFailure::PolicyChanged),
            });
            if !matches!(m.policy_comparison, Some(Ok(()))) {
                self.first.get_or_insert(First::PolicyComparison);
            }
        }
    }

    fn complete_v2(&mut self) -> Result<(), Phase0DeploymentFactsClosedV2> {
        let m = self
            .measurements
            .as_ref()
            .ok_or(Phase0DeploymentFactsClosedV2)?;
        let facts = (|| {
            let report = m.signature.as_ref()?.as_ref().ok()?;
            let snapshot = m.nspawn.snapshot_v2()?;
            Some(Phase0DeploymentFactsDataV2 {
                probe_digest: report.digest(),
                observation: *report.observation(),
                nspawn_device: snapshot.st_dev,
                nspawn_inode: snapshot.st_ino,
                declared_pid1_digest: m.nspawn.pid1_digest_v2()?,
                supervisor_profile_digest: m.nspawn.supervisor_profile_digest_v2()?,
                payload_filter_digest: m.nspawn.payload_filter_digest_v2()?,
            })
        })();
        self.completion = Some(if facts.is_some() {
            Ok(())
        } else {
            Err(ComparisonFailure::Incomplete)
        });
        if facts.is_none() {
            self.first.get_or_insert(First::Completion);
            return Err(Phase0DeploymentFactsClosedV2);
        }
        self.facts = facts;
        Ok(())
    }

    /// Borrows comparison DATA only after every entered nested post succeeded.
    #[must_use]
    pub fn facts_v2(&self) -> Option<&Phase0DeploymentFactsDataV2> {
        if self.first.is_some() {
            return None;
        }
        self.facts.as_ref()
    }

    /// Borrows measured executable metadata after the full collector succeeds.
    #[must_use]
    pub fn nspawn_snapshot_v2(&self) -> Option<&Stat> {
        self.facts_v2()?;
        self.measurements.as_ref()?.nspawn.snapshot_v2()
    }

    /// Borrows the original selected error without new IO or cause replacement.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Reentry => Some(&Phase0DeploymentFactsClosedV2),
            First::Paths => self.path_policy.as_ref()?.as_ref().err().map(|e| e as _),
            First::KeyPresence => self.key_presence.as_ref()?.as_ref().err().map(|e| e as _),
            First::HostdResolution => self
                .running_host_path
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as _),
            first => {
                let m = self.measurements.as_ref()?;
                match first {
                    First::Key => m.key.failure(),
                    First::KeyParse => m.verifier.as_ref()?.as_ref().err().map(|e| e as _),
                    First::Directory => m.directory.as_ref()?.as_ref().err().map(|e| e as _),
                    First::DirectoryBefore => {
                        m.directory_before.as_ref()?.as_ref().err().map(|e| e as _)
                    }
                    First::DirectoryPolicy => {
                        m.directory_policy.as_ref()?.as_ref().err().map(|e| e as _)
                    }
                    First::Probe => m.probe.failure(),
                    First::Boot(index) => m.boot[index].failure(),
                    First::Nspawn => m.nspawn.failure(),
                    First::Hostd => m.hostd.failure_v2(),
                    First::Inspector => m.inspector.failure_v2(),
                    First::Policy(index) => m.policy[index].failure(),
                    First::Signature => m.signature.as_ref()?.as_ref().err().map(|e| e as _),
                    First::DirectoryAfter => {
                        m.directory_after.as_ref()?.as_ref().err().map(|e| e as _)
                    }
                    First::DirectoryNamedAfter => m
                        .directory_named_after
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|e| e as _),
                    First::DirectoryComparison => m
                        .directory_comparison
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|e| e as _),
                    First::BootComparison => {
                        m.boot_comparison.as_ref()?.as_ref().err().map(|e| e as _)
                    }
                    First::PolicyComparison => {
                        m.policy_comparison.as_ref()?.as_ref().err().map(|e| e as _)
                    }
                    First::Completion => self.completion.as_ref()?.as_ref().err().map(|e| e as _),
                    _ => None,
                }
            }
        }
    }
}

impl Default for Phase0DeploymentFactsOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

// This wrapper adds only the existing phase-0 file policy. All positioned
// reading, actual EOF and held/named identity posts remain in the Linux engine.
struct FixedProtectedInput {
    reader: FixedProtectedReadOriginalV3,
    policy: Option<Result<(), ComparisonFailure>>,
    primary_failed: bool,
}

impl FixedProtectedInput {
    fn new() -> Self {
        Self {
            reader: FixedProtectedReadOriginalV3::new(),
            policy: None,
            primary_failed: false,
        }
    }

    fn observe(&mut self, path: &Path, bytes: usize) -> Result<(), Phase0DeploymentFactsClosedV2> {
        let body = self.observe_body(path, bytes);
        self.primary_failed = body.is_err();
        let after = self.reader.finish_once_v3(path);
        if body.is_err() || after.is_err() {
            Err(Phase0DeploymentFactsClosedV2)
        } else {
            Ok(())
        }
    }

    fn observe_body(
        &mut self,
        path: &Path,
        bytes: usize,
    ) -> Result<(), Phase0DeploymentFactsClosedV2> {
        self.reader
            .capture_once_v3(path)
            .map_err(|_| Phase0DeploymentFactsClosedV2)?;
        let metadata = self
            .reader
            .metadata_v3()
            .ok_or(Phase0DeploymentFactsClosedV2)?;
        self.policy = Some(
            if metadata.is_file()
                && metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0
                && metadata.len() == bytes as u64
            {
                Ok(())
            } else {
                Err(ComparisonFailure::Metadata)
            },
        );
        if !matches!(self.policy, Some(Ok(()))) {
            return Err(Phase0DeploymentFactsClosedV2);
        }
        self.reader
            .read_exact_bytes_and_eof_once_v3(bytes)
            .map_err(|_| Phase0DeploymentFactsClosedV2)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // A prior metadata-policy failure wins over a later named-path error.
        if self.primary_failed {
            if let Some(Err(error)) = self.policy.as_ref() {
                return Some(error);
            }
        }
        self.reader
            .failure()
            .or_else(|| self.policy.as_ref()?.as_ref().err().map(|e| e as _))
    }
}

fn packaged_role(path: &Path, suffix: &str) -> bool {
    path.to_str()
        .is_some_and(|path| path.starts_with("/nix/store/") && path.ends_with(suffix))
}

fn same_directory(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_verifier_keeps_the_observation_only_route_without_other_native_entry() {
        let directory = tempfile::tempdir().unwrap();
        let mut original = Phase0DeploymentFactsOriginalV2::new();

        let facts = original
            .observe_once_v2(directory.path(), "unused", Path::new("unused"), "unused")
            .unwrap();

        assert_eq!(facts, None);
        assert!(original.absent);
        assert!(matches!(original.key_presence, Some(Err(_))));
        assert!(original.paths.is_none());
        assert!(original.measurements.is_none());
        assert!(original.failure_v2().is_none());
    }

    #[test]
    fn late_key_creation_cannot_rearm_the_absent_observation() {
        let directory = tempfile::tempdir().unwrap();
        let mut original = Phase0DeploymentFactsOriginalV2::new();
        original
            .observe_once_v2(directory.path(), "unused", Path::new("unused"), "unused")
            .unwrap();
        std::fs::write(directory.path().join(KEY_ROLE), [1_u8; 32]).unwrap();

        assert!(
            original
                .observe_once_v2(directory.path(), "unused", Path::new("unused"), "unused")
                .is_err()
        );

        assert!(original.absent);
        assert!(matches!(original.key_presence, Some(Err(_))));
        assert!(original.measurements.is_none());
        assert!(original.facts_v2().is_none());
        assert!(original.failure_v2().is_some());
    }
}
