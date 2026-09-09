//! Retained kernel cgroup-v2 directory identity and exact membership snapshots.
//!
//! The supported profile is a 64-bit Linux kernel/process. Linux 6.18.33
//! `include/linux/cgroup.h:cgroup_id` returns `cgrp->kn->id`, while
//! `include/linux/kernfs.h:kernfs_id_ino` preserves that complete ID only on
//! 64-bit kernels. Admission checks the descriptor's cgroup2 filesystem before
//! interpreting its inode number; an ordinary filesystem inode is never a
//! cgroup identifier. A retained inode pins its kernfs node against ID reuse.
//!
//! Directory link counts do not establish liveness: kernfs refreshes them even
//! for removed directories. Instead, a fresh read-only open of `cgroup.procs`
//! observes an active kernfs file (`fs/kernfs/file.c:kernfs_fop_open`). This is
//! available on the hierarchy root too, unlike `cgroup.events`. No task list is
//! read and no cgroup is modified. None of these observations fence migration,
//! removal, process exit, or a subsequent effect. The separate exact-cgroup
//! kill primitive is explicitly mutating and requires an independent retained
//! population observation before it establishes quiescence.

use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::{Component, Path};

use crate::path::{BeneathRoot, ResolveOptions};
use crate::pidfd::{PidFd, PidFdInfo};
use crate::{Error, Result, uapi};

const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const MAXIMUM_DESCENDANT_HINT_BYTES: usize = 4096;

/// Retains a kernel cgroup-v2 directory as a strict descendant-resolution root.
///
/// The caller chooses its trusted scope; this type proves neither that the
/// root is the global hierarchy root nor that a particular principal owns it.
#[derive(Debug)]
pub struct CgroupV2Root {
    anchor: RetainedCgroupAnchor,
}

impl CgroupV2Root {
    /// Adopts an owned cgroup-v2 directory after kernel identity and active-file checks.
    ///
    /// # Errors
    ///
    /// Rejects unsupported word size, non-directory or non-cgroup2 descriptors,
    /// zero identity, inaccessible/deactivated `cgroup.procs`, and kernel errors.
    pub fn from_owned(fd: OwnedFd) -> Result<Self> {
        Self::try_from(BeneathRoot::from_owned(fd)?)
    }

    /// Resolves and retains one exact cgroup beneath this root.
    ///
    /// `.` selects the root itself. Resolution rejects symlinks, magic links,
    /// mount crossings, absolute paths and parent traversal using `openat2`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, failed strict resolution, a stale
    /// root or target, unsupported filesystem identity, or kernel failures.
    pub fn resolve(&self, relative: &Path) -> Result<RetainedCgroupAnchor> {
        self.anchor.resolve_child(relative)
    }

    /// Borrows the retained resolution-root descriptor.
    ///
    /// Subsequent descriptor-relative operations retain ordinary kernel access
    /// checks; this borrow is not a read-only restriction on the subtree.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.anchor.as_fd()
    }
}

impl TryFrom<BeneathRoot> for CgroupV2Root {
    type Error = Error;

    /// Validates and consumes an existing descriptor-relative root as cgroup-v2 scope.
    ///
    /// # Errors
    ///
    /// Returns the same filesystem, active-file and platform errors as
    /// [`Self::from_owned`], without replacing the retained descriptor.
    fn try_from(root: BeneathRoot) -> Result<Self> {
        Ok(Self {
            anchor: RetainedCgroupAnchor::new(root)?,
        })
    }
}

/// Pins one exact cgroup-v2 object and its complete kernel identifier.
///
/// Exact and explicitly hinted descendant checks remain distinct. The retained
/// FD prevents reuse of this object's kernfs identity, but does not prevent
/// cgroup removal or movement of processes. Neither the ID nor a snapshot grants an
/// application principal, service provenance, or filesystem/effect authority.
#[derive(Debug)]
pub struct RetainedCgroupAnchor {
    root: BeneathRoot,
    kernel_id: u64,
}

/// Retains the kernel population file for one exact cgroup lifetime.
#[derive(Debug)]
pub struct CgroupPopulationMonitor {
    events: File,
}

/// Describes the recursive task population of one retained cgroup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CgroupPopulationState {
    /// The cgroup or at least one descendant contains a live task.
    Populated,
    /// The active cgroup and all descendants contain no live task.
    Empty,
    /// The exact retained cgroup has been removed from the active hierarchy.
    Retired,
}

impl CgroupPopulationMonitor {
    /// Reports the population or authenticated retirement of the retained cgroup.
    ///
    /// Linux permits cgroup removal only after the cgroup has no live tasks or
    /// online children. For the base `cgroup.events` file, an `ENODEV` read from
    /// its already-authenticated retained kernfs descriptor therefore proves
    /// retirement of that exact empty subtree. Callers must still pair
    /// [`CgroupPopulationState::Retired`] with any required process-liveness
    /// evidence; retirement alone says nothing about a separately retained
    /// pidfd.
    ///
    /// # Errors
    ///
    /// Returns an error for every read failure other than the kernel's exact
    /// `ENODEV` retirement signal, or when the bounded `cgroup.events` record
    /// omits its mandatory `populated` field.
    pub fn state(&self) -> Result<CgroupPopulationState> {
        let mut bytes = [0_u8; 4097];
        let length = match self.events.read_at(&mut bytes, 0) {
            Ok(length) => length,
            Err(source) if source.raw_os_error() == Some(libc::ENODEV) => {
                return Ok(CgroupPopulationState::Retired);
            }
            Err(source) => {
                return Err(Error::Syscall {
                    operation: "read cgroup.events",
                    source,
                });
            }
        };
        if length == 0 || length == bytes.len() {
            return Err(Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "population record is empty or oversized".to_owned(),
            });
        }
        let text =
            std::str::from_utf8(&bytes[..length]).map_err(|_| Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "population record is not UTF-8".to_owned(),
            })?;
        match text
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => Ok(CgroupPopulationState::Empty),
            Some("1") => Ok(CgroupPopulationState::Populated),
            _ => Err(Error::MalformedKernelResponse {
                object: "cgroup.events",
                message: "population field is absent or invalid".to_owned(),
            }),
        }
    }
}

impl RetainedCgroupAnchor {
    /// Resolves and retains one proper descendant cgroup beneath this anchor.
    ///
    /// The relative path is only a locator. Strict `openat2` resolution and
    /// the returned descriptor establish the exact cgroup identity; callers
    /// must separately authenticate any process claimed to belong to it.
    ///
    /// # Errors
    ///
    /// Rejects oversized, empty or dot-only hints, invalid/traversing paths,
    /// failed strict resolution, a stale anchor or target, and kernel errors.
    pub fn resolve_descendant(&self, relative_hint: &Path) -> Result<Self> {
        if relative_hint.as_os_str().len() > MAXIMUM_DESCENDANT_HINT_BYTES
            || !relative_hint
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
        {
            return Err(Error::invalid(
                "descendant cgroup hint",
                "must name a proper descendant within the 4096-byte limit",
            ));
        }
        self.resolve_child(relative_hint)
    }

    /// Opens a repeatable population monitor for this exact cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained cgroup is stale or its kernel events
    /// file cannot be securely opened.
    pub fn population_monitor(&self) -> Result<CgroupPopulationMonitor> {
        self.validate_active()?;
        let events = self.root.open_regular(Path::new("cgroup.events"))?;
        Ok(CgroupPopulationMonitor {
            events: File::from(events.into_owned_fd()),
        })
    }

    /// Sends `SIGKILL` to every task in this exact cgroup and its descendants.
    ///
    /// This writes the cgroup-v2 `cgroup.kill` control file relative to the
    /// retained directory. Completion of the write initiates cancellation; it
    /// does not prove process exit. Pair it with a retained population monitor
    /// and exact pidfds when quiescence is required.
    ///
    /// # Errors
    ///
    /// Returns an error if the cgroup became stale, the kill interface is not
    /// an exact regular cgroup-v2 file, permission is denied, or the complete
    /// control record cannot be written.
    pub fn kill_all(&self) -> Result<()> {
        self.validate_active()?;
        let kill = rustix::fs::openat(
            self.root.as_fd(),
            Path::new("cgroup.kill"),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|source| Error::Syscall {
            operation: "open cgroup.kill",
            source: source.into(),
        })?;
        if uapi::filesystem_type(kill.as_fd())? != CGROUP2_SUPER_MAGIC
            || uapi::fstat(kill.as_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(Error::WrongDescriptorType {
                expected: "cgroup-v2 kill control",
            });
        }
        let mut remaining: &[u8] = b"1\n";
        while !remaining.is_empty() {
            match rustix::io::write(&kill, remaining) {
                Ok(0) => {
                    return Err(Error::MalformedKernelResponse {
                        object: "cgroup.kill",
                        message: "kernel accepted an incomplete kill record".to_owned(),
                    });
                }
                Ok(written) => remaining = &remaining[written..],
                Err(rustix::io::Errno::INTR) => continue,
                Err(source) => {
                    return Err(Error::Syscall {
                        operation: "write cgroup.kill",
                        source: source.into(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Reobserves the retained cgroup's filesystem identity and active kernfs file.
    ///
    /// This does not authenticate a member or fence later removal. It allows
    /// trusted provisioning to reject a stale anchor before exposing a channel.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained identity is invalid or a fresh
    /// `cgroup.procs` open cannot obtain an active kernel reference.
    pub fn validate_current(&self) -> Result<()> {
        self.validate_active()
    }

    fn new(root: BeneathRoot) -> Result<Self> {
        if !cfg!(target_pointer_width = "64") {
            return Err(Error::invalid(
                "cgroup identity profile",
                "requires a 64-bit kernel/process",
            ));
        }
        let anchor = Self {
            kernel_id: root.identity().inode,
            root,
        };
        anchor.validate_active()?;
        Ok(anchor)
    }

    /// Returns the retained object's full kernel cgroup ID, not an authorization token.
    #[must_use]
    pub const fn kernel_id(&self) -> u64 {
        self.kernel_id
    }

    /// Borrows the descriptor that keeps the exact kernfs identity pinned.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    /// Observes exact cgroup membership of a retained live process.
    ///
    /// Checks active-file availability, reads fresh pidfd information, compares
    /// the complete cgroup ID, checks active-file availability again, and rereads
    /// pidfd information before final liveness. Both observations must agree on
    /// PID, thread group and cgroup. The freshest information is returned; it is
    /// not a migration lock, subtree proof, or authority for a later effect.
    /// Migration away and back between observations is not detected.
    ///
    /// # Errors
    ///
    /// Rejects an inaccessible/deactivated anchor, omitted cgroup information,
    /// different exact membership, process exit, or any kernel failure.
    pub fn verify_exact_membership(&self, process: &PidFd) -> Result<PidFdInfo> {
        self.validate_active()?;
        let info = process.info()?;
        if info.cgroup_id() != Some(self.kernel_id) {
            return Err(Error::invalid(
                "exact cgroup membership",
                "pidfd does not name this cgroup",
            ));
        }
        self.validate_active()?;
        recheck_process(process, info)
    }

    /// Observes membership in a strictly resolved proper descendant cgroup.
    ///
    /// The relative hint locates a candidate; it is not trusted membership
    /// evidence. Strict bounded resolution beneath this retained anchor and
    /// fresh pidfd cgroup-ID equality establish the observed relationship.
    /// Cgroup-v2 does not permit reparenting a cgroup, so retaining the resolved
    /// object preserves its ancestry. No alternate candidate is tried after a
    /// mismatch. Use [`Self::verify_exact_membership`] for the anchor itself.
    ///
    /// The process information is rechecked after the outer anchor's final
    /// active-file check. This detects observed migration, not a move away and
    /// back between observations. It neither discovers an arbitrary process's
    /// path nor fences migration or cgroup removal after its observations.
    ///
    /// # Errors
    ///
    /// Rejects oversized, empty or dot-only hints, invalid/traversing paths,
    /// failed strict resolution, inaccessible/deactivated anchors, mismatched
    /// membership, process exit, and kernel errors.
    pub fn verify_descendant_membership(
        &self,
        process: &PidFd,
        relative_hint: &Path,
    ) -> Result<PidFdInfo> {
        let child = self.resolve_descendant(relative_hint)?;
        let info = child.verify_exact_membership(process)?;
        self.validate_active()?;
        recheck_process(process, info)
    }

    fn resolve_child(&self, relative: &Path) -> Result<Self> {
        self.validate_active()?;
        let resolved = self.root.resolve(relative, ResolveOptions::directory())?;
        let child = Self::new(BeneathRoot::from_resolved(resolved)?)?;
        self.validate_active()?;
        Ok(child)
    }

    fn validate_active(&self) -> Result<()> {
        if uapi::filesystem_type(self.root.as_fd())? != CGROUP2_SUPER_MAGIC {
            return Err(Error::WrongDescriptorType {
                expected: "kernel cgroup-v2 directory",
            });
        }
        let stat = uapi::fstat(self.root.as_fd())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || self.kernel_id == 0
            || stat.st_ino != self.kernel_id
            || stat.st_dev != self.root.identity().device
        {
            return Err(Error::invalid(
                "cgroup anchor",
                "kernel directory identity changed or is unspecified",
            ));
        }
        // A retained removed directory may still report a positive nlink.
        // Opening this fixed regular kernfs file checks an active reference;
        // all lookup constraints remain enforced by BeneathRoot.
        let _active = self.root.open_regular(Path::new("cgroup.procs"))?;
        Ok(())
    }
}

fn recheck_process(process: &PidFd, before: PidFdInfo) -> Result<PidFdInfo> {
    let after = process.info()?;
    if after.pid() != before.pid()
        || after.thread_group_id() != before.thread_group_id()
        || after.cgroup_id() != before.cgroup_id()
    {
        return Err(Error::invalid(
            "cgroup membership observation",
            "process identity or membership changed during observation",
        ));
    }
    if !process.is_alive()? {
        return Err(Error::invalid(
            "cgroup membership observation",
            "pinned process exited",
        ));
    }
    Ok(after)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Read-only kernel fixture failures intentionally panic."
)]
mod tests {
    use super::*;
    use std::fs::File;
    #[cfg(feature = "kernel-tests")]
    use std::num::NonZeroU32;
    #[cfg(feature = "kernel-tests")]
    use std::process::{Child, Command};
    #[cfg(feature = "kernel-tests")]
    use std::time::{Duration, Instant};

    #[test]
    fn ordinary_directory_with_matching_file_names_is_not_a_cgroup() {
        let temporary = tempfile::tempdir().expect("test directory");
        File::create(temporary.path().join("cgroup.procs")).expect("fake cgroup file");
        let fd = File::open(temporary.path())
            .expect("open ordinary directory")
            .into();
        assert!(matches!(
            CgroupV2Root::from_owned(fd),
            Err(Error::WrongDescriptorType { .. })
        ));
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn real_readonly_hierarchy_resolves_exact_current_membership() {
        let root = CgroupV2Root::try_from(
            BeneathRoot::from_owned(
                File::open("/sys/fs/cgroup")
                    .expect("open cgroup-v2 hierarchy")
                    .into(),
            )
            .expect("pin cgroup root"),
        )
        .expect("admit real cgroup root");
        let process =
            PidFd::open(NonZeroU32::new(std::process::id()).expect("test PID")).expect("pin self");
        let membership = std::fs::read_to_string("/proc/self/cgroup").expect("read own membership");
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .expect("unified membership");
        let relative = if relative.is_empty() { "." } else { relative };
        let anchor = root
            .resolve(Path::new(relative))
            .expect("resolve current cgroup");
        let info = anchor
            .verify_exact_membership(&process)
            .expect("exact self membership");
        assert_eq!(info.cgroup_id(), Some(anchor.kernel_id()));
        let hierarchy = root.resolve(Path::new(".")).expect("pin hierarchy root");
        if hierarchy.kernel_id() != anchor.kernel_id() {
            assert!(matches!(
                hierarchy.verify_exact_membership(&process),
                Err(Error::InvalidInput {
                    field: "exact cgroup membership",
                    ..
                })
            ));
            assert_eq!(
                hierarchy
                    .verify_descendant_membership(&process, Path::new(relative))
                    .expect("hinted descendant membership")
                    .cgroup_id(),
                Some(anchor.kernel_id())
            );
        }
        for invalid in ["", ".", "./.", "../outside", "/sys/fs/cgroup"] {
            assert!(
                hierarchy
                    .verify_descendant_membership(&process, Path::new(invalid))
                    .is_err()
            );
        }
        let oversized = "./".repeat(MAXIMUM_DESCENDANT_HINT_BYTES / 2 + 1);
        assert!(matches!(
            hierarchy.verify_descendant_membership(&process, Path::new(&oversized)),
            Err(Error::InvalidInput {
                field: "descendant cgroup hint",
                ..
            })
        ));
        for invalid in ["", "/", "..", "../cgroup", "cgroup.procs"] {
            assert!(
                root.resolve(Path::new(invalid)).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn retained_population_distinguishes_empty_retired_and_recreated_cgroups() {
        let hierarchy = CgroupV2Root::from_owned(
            File::open("/sys/fs/cgroup")
                .expect("open cgroup-v2 hierarchy")
                .into(),
        )
        .expect("admit cgroup-v2 hierarchy");
        let membership =
            std::fs::read_to_string("/proc/self/cgroup").expect("read test process membership");
        let current = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .expect("unified test process membership");
        let fixture_name = format!("aos-retirement-proof-{}", std::process::id());
        let fixture_relative = Path::new(current).join(&fixture_name);
        let member_relative = fixture_relative.join("member");
        let fixture_path = Path::new("/sys/fs/cgroup").join(&fixture_relative);
        let member_path = Path::new("/sys/fs/cgroup").join(&member_relative);

        std::fs::create_dir(&fixture_path).expect("create fixture cgroup");
        std::fs::create_dir(&member_path).expect("create member cgroup");
        let fixture = hierarchy
            .resolve(&fixture_relative)
            .expect("retain fixture cgroup");
        let first_member = hierarchy
            .resolve(&member_relative)
            .expect("retain first member cgroup");
        let fixture_population = fixture
            .population_monitor()
            .expect("retain fixture population");
        let first_population = first_member
            .population_monitor()
            .expect("retain first member population");
        assert_eq!(
            fixture_population.state().expect("empty fixture"),
            CgroupPopulationState::Empty
        );
        assert_eq!(
            first_population.state().expect("empty member"),
            CgroupPopulationState::Empty
        );

        let mut first_process = spawn_fixture_process();
        let first_pid = NonZeroU32::new(first_process.id()).expect("nonzero first fixture PID");
        let first_pidfd = PidFd::open(first_pid).expect("retain first fixture process");
        move_process(&member_path, first_pid);
        assert_eq!(
            first_population.state().expect("populated member"),
            CgroupPopulationState::Populated
        );
        assert_eq!(
            fixture_population.state().expect("populated fixture"),
            CgroupPopulationState::Populated
        );
        assert_busy_removal(&member_path, "populated member cgroup");
        assert_busy_removal(&fixture_path, "fixture with a live descendant");

        stop_fixture_process(&mut first_process);
        wait_for_population(&first_population, CgroupPopulationState::Empty);
        wait_for_population(&fixture_population, CgroupPopulationState::Empty);
        assert!(
            !first_pidfd
                .is_alive()
                .expect("first fixture pidfd liveness")
        );
        std::fs::remove_dir(&member_path).expect("retire first member cgroup");
        assert_eq!(
            first_population.state().expect("retired first member"),
            CgroupPopulationState::Retired
        );
        assert!(first_member.validate_current().is_err());

        std::fs::create_dir(&member_path).expect("recreate same member path");
        let second_member = hierarchy
            .resolve(&member_relative)
            .expect("retain recreated member cgroup");
        let second_population = second_member
            .population_monitor()
            .expect("retain recreated member population");
        assert_ne!(first_member.kernel_id(), second_member.kernel_id());
        assert_eq!(
            first_population.state().expect("old member stays retired"),
            CgroupPopulationState::Retired
        );
        assert_eq!(
            second_population.state().expect("empty recreated member"),
            CgroupPopulationState::Empty
        );

        let mut second_process = spawn_fixture_process();
        let second_pid = NonZeroU32::new(second_process.id()).expect("nonzero second fixture PID");
        let second_pidfd = PidFd::open(second_pid).expect("retain second fixture process");
        move_process(&member_path, second_pid);
        assert_eq!(
            second_population
                .state()
                .expect("populated recreated member"),
            CgroupPopulationState::Populated
        );
        assert_eq!(
            first_population
                .state()
                .expect("old member remains retired"),
            CgroupPopulationState::Retired
        );
        assert_busy_removal(&fixture_path, "fixture with recreated live descendant");

        stop_fixture_process(&mut second_process);
        wait_for_population(&second_population, CgroupPopulationState::Empty);
        wait_for_population(&fixture_population, CgroupPopulationState::Empty);
        assert!(
            !second_pidfd
                .is_alive()
                .expect("second fixture pidfd liveness")
        );
        std::fs::remove_dir(&member_path).expect("retire recreated member cgroup");
        assert_eq!(
            second_population.state().expect("retired recreated member"),
            CgroupPopulationState::Retired
        );
        std::fs::remove_dir(&fixture_path).expect("retire fixture cgroup");
        assert_eq!(
            fixture_population.state().expect("retired fixture"),
            CgroupPopulationState::Retired
        );
    }

    #[cfg(feature = "kernel-tests")]
    fn spawn_fixture_process() -> Child {
        Command::new(std::env::var_os("AOS_CGROUP_TEST_SLEEP").expect("sleep fixture path"))
            .arg("30")
            .spawn()
            .expect("spawn cgroup member process")
    }

    #[cfg(feature = "kernel-tests")]
    fn move_process(cgroup: &Path, pid: NonZeroU32) {
        std::fs::write(cgroup.join("cgroup.procs"), format!("{}\n", pid.get()))
            .expect("move fixture process into cgroup");
    }

    #[cfg(feature = "kernel-tests")]
    fn stop_fixture_process(process: &mut Child) {
        process.kill().expect("kill fixture process");
        process.wait().expect("reap fixture process");
    }

    #[cfg(feature = "kernel-tests")]
    fn wait_for_population(population: &CgroupPopulationMonitor, expected: CgroupPopulationState) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = population.state().expect("observe cgroup population");
            if observed == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "expected {expected:?}, observed {observed:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(feature = "kernel-tests")]
    fn assert_busy_removal(path: &Path, context: &str) {
        let error = std::fs::remove_dir(path).expect_err(context);
        assert_eq!(
            error.raw_os_error(),
            Some(libc::EBUSY),
            "{context}: {error}"
        );
    }
}
