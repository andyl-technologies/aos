//! Shared, bounded comparison of a live enforcing SELinux policy with AOS's
//! immutable, deployment-kernel-bound canonical readback package.
//!
//! The proof is point-in-time. Callers keep their own authorization and
//! subject-label checks; matching policy bytes alone grants neither.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd};

use rustix::fs::{FileType, Mode, OFlags, fstat, fstatfs, open};
use sha2::{Digest as _, Sha256};

// selinuxfs serializes the loaded policydb, not the original compiled input.
// Only the selected kernel's canonical readback is a valid byte expectation.
const POLICY_SUFFIX: &str = "/policy.33";
const POLICY_PACKAGE: &str = "aos-selinux-kernel-policy-readback-1";
const STORE_HASH_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
const MAX_POLICY_BYTES: u64 = 64 * 1024 * 1024;
const SELINUXFS_MAGIC: u64 = 0xf97c_ff8c;

/// Reports an invalid live policy, package path, or kernel readback.
#[derive(Debug, thiserror::Error)]
#[error("SELinux policy readback rejected: {0}")]
pub struct PolicyReadbackError(&'static str);

/// Retains the digest of one exact enforcing policy comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedLiveSelinuxPolicy {
    digest: [u8; 32],
}

impl VerifiedLiveSelinuxPolicy {
    /// Compares the active policy to an immutable deployment-kernel readback.
    ///
    /// The caller supplies its image-pinned canonical readback path. Compiled
    /// policy inputs are not accepted: the loaded kernel serialization may
    /// differ even when the input was loaded without modification.
    ///
    /// # Errors
    ///
    /// Rejects a foreign path, permissive state, non-selinuxfs readback,
    /// changed or oversized package file, unequal bytes, or any read failure.
    pub fn verify(expected_path: &str) -> Result<Self, PolicyReadbackError> {
        verify_policy(expected_path, None)
    }

    /// Repeats the comparison and requires the same policy digest.
    ///
    /// # Errors
    ///
    /// Rejects any change in enforcement, package custody, or policy bytes.
    pub fn revalidate(self, expected_path: &str) -> Result<(), PolicyReadbackError> {
        self.require_same_observed_v1(Self::verify(expected_path)?)
    }

    /// Compares an actual verified readback with this original policy digest.
    ///
    /// This pure DATA comparison neither reads a policy nor authenticates a
    /// role. Retained callers keep the actual verifier original separately.
    ///
    /// # Errors
    /// Rejects a different digest from the original verified policy.
    pub fn require_same_observed_v1(self, observed: Self) -> Result<(), PolicyReadbackError> {
        if observed != self {
            return Err(PolicyReadbackError("active policy changed after verification"));
        }
        Ok(())
    }

    /// Returns the digest of the exact live policy bytes.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Reports dominant DATA costs of one complete retained policy comparison.
///
/// The caller independently admits these costs before entering the native
/// engine. Existing originals, role posts and allocator metadata are additional.
#[derive(Clone, Copy, Debug)]
pub struct LiveSelinuxPolicyReceivingDemandV1 {
    /// Bounds resident representations, buffers and simultaneous digest scratch.
    pub memory_bytes: usize,
    /// Counts the four simultaneously retained policy/enforcement descriptors.
    pub open_files: usize,
    /// Bounds the two policy streams, trailing bytes and enforcement reads.
    pub input_bytes: u64,
    /// Counts the fixed native open/stat/filesystem observations.
    pub metadata_entries: u64,
}

/// Retains the whole reached file prefix of one actual live-policy comparison.
///
/// This supplies nonauthorizing measurement custody, not selected-profile or
/// application authority. Its caller must fund entry and retain failures through
/// independent native/role posts. The original public verifier shares this same
/// engine with its ordinary short-lived disposition.
pub struct RetainedLiveSelinuxPolicyReadbackV1 {
    first_native: Option<PolicyNativeCauseV1>,
    completion: Option<Result<VerifiedLiveSelinuxPolicy, PolicyReadbackError>>,
    closed: Option<PolicyReadbackError>,
    after_enforcing: EnforcementReadbackV1,
    kernel: Option<File>,
    expected: Option<File>,
    before_enforcing: EnforcementReadbackV1,
    scratch: PolicyComparisonScratchV1,
    files_retired: bool,
    entered: bool,
}

impl RetainedLiveSelinuxPolicyReadbackV1 {
    /// Creates empty fixed storage without opening or reading a file.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            first_native: None, completion: None, closed: None,
            after_enforcing: EnforcementReadbackV1::new(), kernel: None, expected: None,
            before_enforcing: EnforcementReadbackV1::new(),
            scratch: PolicyComparisonScratchV1::new(), files_retired: false, entered: false,
        }
    }

    /// Reports the shared engine's conservative dominant pre-entry costs.
    #[must_use]
    pub const fn receiving_demand_v1() -> LiveSelinuxPolicyReceivingDemandV1 {
        LiveSelinuxPolicyReceivingDemandV1 {
            // Include the ordinary scratch even in retained mode; optimization
            // is not a resource claim. The two state Vecs each read at most 9.
            memory_bytes: std::mem::size_of::<Self>() + 2 * 16 * 1024 + 2 * 32 + 8192 + 256,
            open_files: 4,
            input_bytes: 2 * MAX_POLICY_BYTES + 2 + 2 * 9,
            // Nine existing native/namespace destinations plus the entered
            // and positive-file-retirement controls remain resident.
            metadata_entries: 11,
        }
    }

    /// Compares the actual enforcing kernel policy once with the exact package.
    ///
    /// # Errors
    /// Retains wrong paths, file/enforcement/byte/custody refusals, native first
    /// causes and all reached file owners. Reentry cannot replace any prefix.
    pub fn verify_once(&mut self, expected_path: &str) -> Result<(), PolicyReadbackError> {
        if self.entered {
            self.closed.get_or_insert(PolicyReadbackError("retained policy observation already entered"));
            return Err(PolicyReadbackError("retained policy observation already entered"));
        }
        self.entered = true;
        let result = verify_policy(expected_path, Some(&mut *self));
        self.completion = Some(result);
        match self.completion.as_ref() {
            Some(Ok(_)) => Ok(()),
            _ => Err(PolicyReadbackError("retained policy observation refused")),
        }
    }

    /// Borrows the completed point-in-time comparison DATA without moving custody.
    #[must_use]
    pub fn verified(&self) -> Option<VerifiedLiveSelinuxPolicy> {
        if self.closed.is_some() { return None; }
        self.completion.as_ref()?.as_ref().ok().copied()
    }

    /// Drops only the four Files of this completed positive comparison once.
    ///
    /// The caller first completes its own comparison against the returned
    /// policy DATA. Bytes, native outcomes, verified digest and the one-shot
    /// fence remain resident. This neither renews currentness nor refunds a
    /// financial charge; failed and incomplete observations remain untouched.
    #[must_use]
    pub fn retire_completed_files_once_v1(&mut self) -> bool {
        if self.files_retired
            || !matches!(self.completion, Some(Ok(_)))
            || self.failure().is_some()
            || self.before_enforcing.file.is_none()
            || self.expected.is_none()
            || self.kernel.is_none()
            || self.after_enforcing.file.is_none()
        {
            return false;
        }
        drop(self.after_enforcing.file.take());
        drop(self.kernel.take());
        drop(self.expected.take());
        drop(self.before_enforcing.file.take());
        self.files_retired = true;
        true
    }

    /// Borrows the first original native cause or the unchanged logical refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_native.as_ref() {
            Some(PolicyNativeCauseV1::Io(error)) => return Some(error),
            Some(PolicyNativeCauseV1::Errno(error)) => return Some(error),
            None => {}
        }
        self.completion.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &dyn std::error::Error)
            .or_else(|| self.closed.as_ref().map(|error| error as &dyn std::error::Error))
    }
}

impl Default for RetainedLiveSelinuxPolicyReadbackV1 {
    fn default() -> Self { Self::new() }
}

enum PolicyNativeCauseV1 {
    Io(std::io::Error),
    Errno(rustix::io::Errno),
}

struct EnforcementReadbackV1 {
    file: Option<File>,
    state: Vec<u8>,
}

impl EnforcementReadbackV1 {
    const fn new() -> Self { Self { file: None, state: Vec::new() } }
}

struct PolicyComparisonScratchV1 {
    expected_chunk: [u8; 16 * 1024],
    kernel_chunk: [u8; 16 * 1024],
    extra: [u8; 1],
}

impl PolicyComparisonScratchV1 {
    const fn new() -> Self {
        Self { expected_chunk: [0; 16 * 1024], kernel_chunk: [0; 16 * 1024], extra: [0] }
    }
}

// The ordinary guard owns/drops exactly this file; a selected guard ends only
// its borrow, leaving the same file in the already funded caller reservoir.
enum PolicyFileDisposition<'a> {
    Ordinary(File),
    Retained(&'a mut File),
}

impl<'a> PolicyFileDisposition<'a> {
    fn new(file: File, slot: Option<&'a mut Option<File>>) -> Self {
        match slot {
            Some(slot) => {
                *slot = Some(file);
                match slot {
                    Some(file) => Self::Retained(file),
                    None => std::process::abort(),
                }
            }
            None => Self::Ordinary(file),
        }
    }

    fn file(&mut self) -> &mut File {
        match self { Self::Ordinary(file) => file, Self::Retained(file) => file }
    }
}

impl std::os::fd::AsFd for PolicyFileDisposition<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self { Self::Ordinary(file) => file.as_fd(), Self::Retained(file) => file.as_fd() }
    }
}

fn retain_errno(
    error: rustix::io::Errno,
    first: &mut Option<&mut Option<PolicyNativeCauseV1>>,
    message: &'static str,
) -> PolicyReadbackError {
    if let Some(first) = first {
        if first.is_none() { **first = Some(PolicyNativeCauseV1::Errno(error)); }
    }
    PolicyReadbackError(message)
}

fn retain_io(
    error: std::io::Error,
    first: &mut Option<&mut Option<PolicyNativeCauseV1>>,
    message: &'static str,
) -> PolicyReadbackError {
    if let Some(first) = first {
        if first.is_none() { **first = Some(PolicyNativeCauseV1::Io(error)); }
    }
    PolicyReadbackError(message)
}

fn verify_policy(
    expected_path: &str,
    retained: Option<&mut RetainedLiveSelinuxPolicyReadbackV1>,
) -> Result<VerifiedLiveSelinuxPolicy, PolicyReadbackError> {
    let (before_enforcing, expected_slot, kernel_slot, after_enforcing, scratch, mut first) = match retained {
        Some(retained) => (
            Some(&mut retained.before_enforcing), Some(&mut retained.expected),
            Some(&mut retained.kernel), Some(&mut retained.after_enforcing),
            Some(&mut retained.scratch), Some(&mut retained.first_native),
        ),
        None => (None, None, None, None, None, None),
    };
    validate_policy_path(expected_path)?;
    require_enforcing_observed(before_enforcing, &mut first)?;

    let expected_fd = open(
        expected_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| retain_errno(error, &mut first, "cannot open deployed policy"))?;
    let mut expected = PolicyFileDisposition::new(File::from(expected_fd), expected_slot);
    let before =
        fstat(expected.as_fd()).map_err(|error| retain_errno(error, &mut first, "cannot stat deployed policy"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_size <= 0
        || u64::try_from(before.st_size).unwrap_or(u64::MAX) > MAX_POLICY_BYTES
    {
        return Err(PolicyReadbackError(
            "deployed policy is not a bounded protected file",
        ));
    }

    let kernel_fd = open(
        "/sys/fs/selinux/policy",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| retain_errno(error, &mut first, "cannot open active policy"))?;
    let mut kernel = PolicyFileDisposition::new(File::from(kernel_fd), kernel_slot);
    require_selinuxfs(kernel.as_fd(), &mut first)?;

    let digest = compare_policy_bytes(expected.file(), kernel.file(), before.st_size as u64, scratch, &mut first)?;
    let after = fstat(expected.as_fd())
        .map_err(|error| retain_errno(error, &mut first, "cannot restat deployed policy"))?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(PolicyReadbackError(
            "deployed policy changed during comparison",
        ));
    }

    require_enforcing_observed(after_enforcing, &mut first)?;
    Ok(VerifiedLiveSelinuxPolicy { digest })
}

fn validate_policy_path(path: &str) -> Result<(), PolicyReadbackError> {
    let entry = path
        .strip_prefix("/nix/store/")
        .and_then(|value| value.strip_suffix(POLICY_SUFFIX))
        .ok_or(PolicyReadbackError("production policy path is not exact"))?;
    let (hash, package) = entry.split_once('-').ok_or(PolicyReadbackError(
        "production policy derivation is malformed",
    ))?;
    if hash.len() != 32
        || !hash.bytes().all(|byte| STORE_HASH_ALPHABET.contains(&byte))
        || package != POLICY_PACKAGE
    {
        return Err(PolicyReadbackError(
            "production policy derivation is not exact",
        ));
    }
    Ok(())
}

fn require_selinuxfs(fd: BorrowedFd<'_>, first: &mut Option<&mut Option<PolicyNativeCauseV1>>) -> Result<(), PolicyReadbackError> {
    if fstatfs(fd)
        .map_err(|error| retain_errno(error, first, "cannot identify SELinux filesystem"))?
        .f_type as u64
        != SELINUXFS_MAGIC
    {
        return Err(PolicyReadbackError("readback is not from selinuxfs"));
    }
    Ok(())
}

/// Requires the actual selinuxfs enforcement state without admitting a policy.
///
/// This kernel observation is not subject, image, or effect authority.
///
/// # Errors
///
/// Rejects absent or foreign selinuxfs, unreadable state, or permissive mode.
pub fn require_enforcing() -> Result<(), PolicyReadbackError> {
    require_enforcing_observed(None, &mut None)
}

fn require_enforcing_observed(
    retained: Option<&mut EnforcementReadbackV1>,
    first: &mut Option<&mut Option<PolicyNativeCauseV1>>,
) -> Result<(), PolicyReadbackError> {
    let mut ordinary_state = Vec::new();
    let (file_slot, state) = match retained {
        Some(retained) => (Some(&mut retained.file), &mut retained.state),
        None => (None, &mut ordinary_state),
    };
    let fd = open(
        "/sys/fs/selinux/enforce",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| retain_errno(error, first, "cannot open SELinux enforcement"))?;
    let mut file = PolicyFileDisposition::new(File::from(fd), file_slot);
    require_selinuxfs(file.as_fd(), first)?;

    let read = file.file().take(9).read_to_end(state)
        .map_err(|error| retain_io(error, first, "cannot read SELinux enforcement"));
    // Ordinary File::take's temporary closed before the enforcement comparison;
    // the retained disposition ends only this borrow and keeps the same File.
    drop(file);
    read?;
    if state.as_slice() != b"1" && state.as_slice() != b"1\n" {
        return Err(PolicyReadbackError("SELinux is not enforcing"));
    }
    Ok(())
}

fn compare_policy_bytes(
    expected: &mut File,
    kernel: &mut File,
    size: u64,
    retained: Option<&mut PolicyComparisonScratchV1>,
    first: &mut Option<&mut Option<PolicyNativeCauseV1>>,
) -> Result<[u8; 32], PolicyReadbackError> {
    let mut ordinary = PolicyComparisonScratchV1::new();
    let scratch = retained.unwrap_or(&mut ordinary);
    let PolicyComparisonScratchV1 { expected_chunk, kernel_chunk, extra } = scratch;
    let mut remaining = size;
    let mut digest = Sha256::new();

    while remaining != 0 {
        let count = usize::try_from(remaining.min(expected_chunk.len() as u64))
            .map_err(|_| PolicyReadbackError("policy length is invalid"))?;
        expected
            .read_exact(&mut expected_chunk[..count])
            .map_err(|error| retain_io(error, first, "cannot read deployed policy"))?;
        kernel
            .read_exact(&mut kernel_chunk[..count])
            .map_err(|error| retain_io(error, first, "cannot read active policy"))?;
        if expected_chunk[..count] != kernel_chunk[..count] {
            return Err(PolicyReadbackError(
                "active policy differs from deployed policy",
            ));
        }
        digest.update(&expected_chunk[..count]);
        remaining -= count as u64;
    }

    if expected
        .read(extra)
        .map_err(|error| retain_io(error, first, "cannot finish deployed policy read"))?
        != 0
        || kernel
            .read(extra)
            .map_err(|error| retain_io(error, first, "cannot finish active policy read"))?
            != 0
    {
        return Err(PolicyReadbackError(
            "policy length changed during comparison",
        ));
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, Write as _};

    use super::*;

    #[test]
    fn policy_path_is_exact_kernel_readback_derivation() {
        let valid = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-selinux-kernel-policy-readback-1/policy.33";
        assert!(validate_policy_path(valid).is_ok());

        for rejected in [
            "/tmp/policy.33".to_owned(),
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-selinux-production-policy-1/etc/selinux/aos/policy/policy.33".to_owned(),
            valid.replace("kernel-policy-readback", "test-policy-readback"),
            valid.replace("readback-1/", "readback-10/"),
            valid.replace("readback-1/", "readback-1-extra/"),
            valid.replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            valid.replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            valid.replace("/policy.33", "/../policy.33"),
            format!("{valid}/extra"),
        ] {
            assert!(validate_policy_path(&rejected).is_err(), "{rejected}");
        }
    }

    #[test]
    fn canonical_policy_bytes_reject_input_or_changed_serialization() {
        let mut expected = tempfile::tempfile().unwrap();
        let mut active = tempfile::tempfile().unwrap();
        expected.write_all(b"canonical-policy").unwrap();
        active.write_all(b"compiled-policy!").unwrap();
        expected.rewind().unwrap();
        active.rewind().unwrap();

        assert!(compare_policy_bytes(&mut expected, &mut active, 16, None, &mut None).is_err());
    }

    #[test]
    fn policy_streams_require_exact_bytes_and_length() {
        let mut expected = tempfile::tempfile().unwrap();
        let mut active = tempfile::tempfile().unwrap();
        expected.write_all(b"policy-one").unwrap();
        active.write_all(b"policy-one").unwrap();
        expected.rewind().unwrap();
        active.rewind().unwrap();
        let digest: [u8; 32] = Sha256::digest(b"policy-one").into();
        assert_eq!(
            compare_policy_bytes(&mut expected, &mut active, 10, None, &mut None).unwrap(),
            digest
        );

        expected.rewind().unwrap();
        active.rewind().unwrap();
        assert!(compare_policy_bytes(&mut expected, &mut active, 9, None, &mut None).is_err());
        active.rewind().unwrap();
        active.set_len(9).unwrap();
        expected.rewind().unwrap();
        assert!(compare_policy_bytes(&mut expected, &mut active, 10, None, &mut None).is_err());
    }

    #[test]
    fn retained_comparison_keeps_actual_files_scratch_and_first_io_cause() {
        let directory = tempfile::tempdir().unwrap();
        let mut retained = RetainedLiveSelinuxPolicyReadbackV1::new();
        let mut expected = tempfile::tempfile().unwrap();
        expected.write_all(b"policy-one").unwrap();
        expected.rewind().unwrap();
        retained.expected = Some(expected);
        retained.kernel = Some(File::open(directory.path()).unwrap());

        let returned = compare_policy_bytes(
            retained.expected.as_mut().unwrap(), retained.kernel.as_mut().unwrap(), 10,
            Some(&mut retained.scratch), &mut Some(&mut retained.first_native),
        );
        assert!(returned.is_err());
        let error = retained.failure().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory);
        assert!(retained.expected.as_ref().unwrap().metadata().is_ok());
        assert!(retained.kernel.as_ref().unwrap().metadata().unwrap().is_dir());
        assert_eq!(&retained.scratch.expected_chunk[..10], b"policy-one");
        assert!(retained.verified().is_none());
    }

}
