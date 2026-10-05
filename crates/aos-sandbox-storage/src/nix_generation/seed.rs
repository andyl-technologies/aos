//! Original readonly seed census and non-authorizing artifact publication.
//!
//! The build-platform entry reads a finalized seed, never executes target
//! bytes, and emits the SAME physical walk's complete Core object closure.
//! An external existing issuer may inspect that DATA; this code does not sign,
//! acquire a Snapshot, enroll G0 or grant runtime admission.
//!
//! ```text
//! <full-object-digest>: exact Core Content/Directory/Tree encoded bytes
//! root40: Tree digest32 | BEu64 Tree canonical encoded size
//! ```

use std::io::Write as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::protected_file::{ExactReadFailure, read_exact_positioned_census_retaining_cause};
use rustix::fs::{Mode, OFlags, Stat, StatVfs, StatVfsMountFlags};
use rustix::process::{Resource, Rlimit};

use crate::held_snapshot_tree::{HeldSnapshotTreeErrorV1, capture_seed_census, same_inode_state};
use crate::held_snapshot_tree::census::{CensusDataError, CensusDirectoryNames, CensusWalkState};

/// Owns a failed DATA operation, including its actual original descriptors.
///
/// Dropping this error releases ordinary local resources, not durable G0 debt.
/// No Snapshot, signature, enrollment or currentness can be extracted from it.
pub struct NixSeedTreeArtifactErrorV1 {
    owner: SeedTreeArtifactOriginal,
}

impl std::fmt::Debug for NixSeedTreeArtifactErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("NixSeedTreeArtifactErrorV1")
            .field("cause", &self.owner.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for NixSeedTreeArtifactErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.owner.failure() {
            Some(cause) => write!(formatter, "portable Nix seed artifact failed: {cause}"),
            None => formatter.write_str("portable Nix seed artifact is incomplete"),
        }
    }
}

impl std::error::Error for NixSeedTreeArtifactErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.owner.failure() }
}

#[derive(Clone, Copy, Default)]
enum ArtifactStage {
    #[default]
    Resources,
    Paths,
    Input,
    Output,
    RootLoan,
    Walk,
    WalkPost,
    Graph,
    GraphPost,
    Object,
    Terminal,
}

#[derive(Default)]
struct SeedTreeArtifactOriginal {
    stage: ArtifactStage,
    resources: SeedProcessResources,
    resource_post: Option<Result<(), CensusDataError>>,
    input_path: Option<Result<PathBuf, std::io::Error>>,
    output_path: Option<Result<PathBuf, std::io::Error>>,
    root: Option<Result<OwnedFd, rustix::io::Errno>>,
    output: Option<Result<OwnedFd, rustix::io::Errno>>,
    root_duplicate: Option<Result<OwnedFd, rustix::io::Errno>>,
    beneath: Option<Result<BeneathRoot, aos_sandbox_linux::Error>>,
    root_stat: [Option<Result<Stat, rustix::io::Errno>>; 5],
    root_flags: [Option<Result<StatVfs, rustix::io::Errno>>; 5],
    root_mount: [Option<Result<MountId, aos_sandbox_linux::Error>>; 5],
    output_stat: [Option<Result<Stat, rustix::io::Errno>>; 2],
    output_names: Option<CensusDirectoryNames>,
    begin: Option<Result<(), CensusDataError>>,
    walk: Option<Result<(), HeldSnapshotTreeErrorV1>>,
    root_posts: [Option<Result<(), CensusDataError>>; 4],
    publication: Option<Result<(), CensusDataError>>,
    census: CensusWalkState,
    pending_output: ArtifactOutputOriginal,
    outcome: Option<Result<(), CensusDataError>>,
}

#[derive(Default)]
struct ArtifactOutputOriginal {
    name: String,
    file: Option<Result<std::fs::File, rustix::io::Errno>>,
    write: Option<Result<(), std::io::Error>>,
    flush: Option<Result<(), std::io::Error>>,
    sync: Option<Result<(), std::io::Error>>,
    directory_sync: Option<Result<(), rustix::io::Errno>>,
    named: Option<Result<OwnedFd, rustix::io::Errno>>,
    inode: [Option<Result<Stat, rustix::io::Errno>>; 2],
    final_inode: [Option<Result<Stat, rustix::io::Errno>>; 2],
    directory_inode: [Option<Result<Stat, rustix::io::Errno>>; 2],
    bytes: Vec<u8>,
    read: Option<Result<(), ExactReadFailure>>,
    action: Option<Result<(), CensusDataError>>,
    postcheck: Option<Result<(), CensusDataError>>,
    outcome: Option<Result<(), CensusDataError>>,
}

/// Emits the finalized readonly seed's complete portable DATA graph.
///
/// The paths must already be absolute canonical locations. The output must be
/// empty, distinct from and outside the input root. Objects are created once,
/// synced and exactly read back before the root descriptor is published LAST.
/// The stronger secure Snapshot mount requirements remain unchanged elsewhere.
/// This selected build-platform entry lowers its process's descriptor and
/// address-space limits, never raising a smaller inherited limit. It observes
/// the actual baseline before admitting the bounded walk and publication.
///
/// # Errors
///
/// Retains original failures for path/mount/root changes, unsupported metadata,
/// incomplete hardlink groups, graph/resource bounds, occupied output or failed
/// writes, durability and exact named readback. Opaque lower unreturned prefixes
/// and full physical memory/I/O funding are not guaranteed by this DATA entry.
pub fn run_nix_seed_tree_artifact(input: &Path, output: &Path) -> Result<(), NixSeedTreeArtifactErrorV1> {
    let mut owner = SeedTreeArtifactOriginal::default();
    owner.outcome = Some(owner.run(input, output));
    // A failed walk/write is parked before these independent observations.
    // Neither a later error nor an unwind reopens this one-shot DATA operation.
    owner.resource_post = Some(owner.resources.observe_terminal());
    if matches!(owner.outcome, Some(Ok(())))
        && matches!(owner.resource_post, Some(Ok(())))
    {
        Ok(())
    } else {
        Err(NixSeedTreeArtifactErrorV1 { owner })
    }
}

impl SeedTreeArtifactOriginal {
    fn run(&mut self, input: &Path, output: &Path) -> Result<(), CensusDataError> {
        self.resources.admit()?;
        self.stage = ArtifactStage::Paths;
        if !input.is_absolute() || !output.is_absolute()
            || input.as_os_str().len() > 4096 || output.as_os_str().len() > 4096
        { return Err(CensusDataError::ArtifactPath); }
        self.input_path = Some(std::fs::canonicalize(input));
        self.output_path = Some(std::fs::canonicalize(output));
        let input_path = self.input_path.as_ref().ok_or(CensusDataError::Closed)?.as_ref()
            .map_err(|_| CensusDataError::ArtifactPath)?;
        let output_path = self.output_path.as_ref().ok_or(CensusDataError::Closed)?.as_ref()
            .map_err(|_| CensusDataError::ArtifactPath)?;
        if input_path != input || output_path != output || output_path.starts_with(input_path) {
            return Err(CensusDataError::ArtifactPath);
        }

        self.stage = ArtifactStage::Input;
        self.root = Some(rustix::fs::open(input, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()));
        self.observe_root(0)?;
        if !native(&self.root_flags[0])?.f_flag.contains(StatVfsMountFlags::RDONLY) {
            return Err(CensusDataError::ArtifactPath);
        }

        self.stage = ArtifactStage::Output;
        self.output_names = Some(CensusDirectoryNames::prepare()?);
        self.output = Some(rustix::fs::open(output, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()));
        let output = native(&self.output)?;
        self.output_stat[0] = Some(rustix::fs::fstat(output.as_fd()));
        let out_stat = *native(&self.output_stat[0])?;
        let input_stat = native(&self.root_stat[0])?;
        if out_stat.st_dev == input_stat.st_dev && out_stat.st_ino == input_stat.st_ino {
            return Err(CensusDataError::ArtifactPath);
        }
        self.output_names.as_mut().ok_or(CensusDataError::Closed)?
            .capture(output.as_fd(), &out_stat).map_err(|_| CensusDataError::ArtifactPath)?;
        if self.output_names.as_ref().ok_or(CensusDataError::Closed)?
            .names().map_err(|_| CensusDataError::ArtifactPath)?.len() != 0 {
            return Err(CensusDataError::ArtifactPath);
        }

        self.stage = ArtifactStage::RootLoan;
        self.root_duplicate = Some(rustix::io::dup(native(&self.root)?.as_fd()));
        native(&self.root_duplicate)?;
        let Some(Ok(duplicate)) = self.root_duplicate.take() else { return Err(CensusDataError::Closed); };
        // This ordinary consuming validator may fail before returning its
        // duplicate. The independent original remains held; no lower
        // pre-return adoption prefix is claimed as captured here.
        self.beneath = Some(BeneathRoot::from_owned(duplicate));
        let beneath = linux(&self.beneath)?;
        self.begin = Some(self.census.begin(beneath));
        if self.begin.as_ref().is_some_and(Result::is_err) { return Err(CensusDataError::Closed); }

        self.stage = ArtifactStage::Walk;
        self.walk = Some(capture_seed_census(beneath, &mut self.census));
        self.root_posts[0] = Some(self.recheck_root(1));
        if self.walk.as_ref().is_some_and(Result::is_err) { return Err(CensusDataError::Closed); }
        if self.root_posts[0].as_ref().is_some_and(Result::is_err) {
            self.stage = ArtifactStage::WalkPost;
            return Err(CensusDataError::Closed);
        }

        self.stage = ArtifactStage::Graph;
        let finalized = self.census.finalize();
        self.root_posts[1] = Some(self.recheck_root(2));
        if finalized.is_err() { return Err(CensusDataError::Closed); }
        if self.root_posts[1].as_ref().is_some_and(Result::is_err) {
            self.stage = ArtifactStage::GraphPost;
            return Err(CensusDataError::Closed);
        }

        self.stage = ArtifactStage::Object;
        self.publication = Some(self.publish_objects());
        // The physical root and output-directory observations are independent
        // of a failed write/fsync/readback. Its native cause stays first.
        self.output_stat[1] = Some(rustix::fs::fstat(native(&self.output)?.as_fd()));
        self.root_posts[3] = Some(self.recheck_root(4));
        if self.publication.as_ref().is_some_and(Result::is_err) {
            return Err(CensusDataError::ArtifactOutput);
        }
        self.stage = ArtifactStage::Terminal;
        let after = native(&self.output_stat[1])?;
        if out_stat.st_dev != after.st_dev || out_stat.st_ino != after.st_ino || out_stat.st_mode != after.st_mode {
            return Err(CensusDataError::ArtifactPath);
        }
        if self.root_posts[3].as_ref().is_some_and(Result::is_err) { return Err(CensusDataError::Closed); }
        Ok(())
    }

    fn publish_objects(&mut self) -> Result<(), CensusDataError> {
        let output = native(&self.output)?;
        for (descriptor, bytes) in self.census.arena.objects()? {
            self.pending_output = ArtifactOutputOriginal::default();
            let name = descriptor.digest().to_string();
            // Actual retained graph/name/path capacities and this temporary
            // digest string precede admission of the additional readback.
            let remaining = self.publication_capacity(name.capacity())?;
            self.pending_output.outcome = Some(capture_output_object(
                output, &mut self.pending_output, &name, bytes, remaining,
            ));
            if self.pending_output.outcome.as_ref().is_some_and(Result::is_err) {
                return Err(CensusDataError::ArtifactOutput);
            }
        }
        // Object publication cannot stand in for current input ownership.
        // This original root check immediately precedes root40 publication.
        self.root_posts[2] = Some(self.recheck_root(3));
        if self.root_posts[2].as_ref().is_some_and(Result::is_err) { return Err(CensusDataError::Closed); }
        let output = native(&self.output)?;
        let tree = self.census.tree.as_ref().ok_or(CensusDataError::Closed)?;
        let mut root_bytes = [0_u8; 40];
        root_bytes[..32].copy_from_slice(tree.digest().as_bytes());
        root_bytes[32..].copy_from_slice(&tree.encoded_size().to_be_bytes());
        self.pending_output = ArtifactOutputOriginal::default();
        let remaining = self.publication_capacity(0)?;
        // Every reachable object has complete named readback and held
        // directory durability BEFORE this one no-replace root publication.
        self.pending_output.outcome = Some(capture_output_object(output, &mut self.pending_output, "root40", &root_bytes, remaining));
        if self.pending_output.outcome.as_ref().is_some_and(Result::is_err) {
            return Err(CensusDataError::ArtifactOutput);
        }
        Ok(())
    }

    fn publication_capacity(&self, transient_name_capacity: usize) -> Result<usize, CensusDataError> {
        let names = self.output_names.as_ref().ok_or(CensusDataError::Closed)?.capacity_bytes()?;
        let input = self.input_path.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CensusDataError::Closed)?;
        let output = self.output_path.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CensusDataError::Closed)?;
        let baseline = self.census.capacity_bytes()?
            .checked_add(std::mem::size_of::<Self>())
            .and_then(|value| value.checked_add(names))
            .and_then(|value| value.checked_add(input.capacity()))
            .and_then(|value| value.checked_add(output.capacity()))
            .and_then(|value| value.checked_add(transient_name_capacity))
            .ok_or(CensusDataError::Capacity)?;
        (224_usize * 1024 * 1024).checked_sub(baseline).ok_or(CensusDataError::Capacity)
    }

    fn observe_root(&mut self, slot: usize) -> Result<(), CensusDataError> {
        let root = native(&self.root)?;
        self.root_stat[slot] = Some(rustix::fs::fstat(root.as_fd()));
        self.root_flags[slot] = Some(rustix::fs::fstatvfs(root.as_fd()));
        self.root_mount[slot] = Some(MountId::from_fd(root.as_fd()));
        native(&self.root_stat[slot])?;
        native(&self.root_flags[slot])?;
        linux(&self.root_mount[slot])?;
        Ok(())
    }

    fn recheck_root(&mut self, slot: usize) -> Result<(), CensusDataError> {
        self.observe_root(slot)?;
        let before = native(&self.root_stat[0])?;
        let after = native(&self.root_stat[slot])?;
        if !same_inode_state(before, after)
            || !native(&self.root_flags[slot])?.f_flag.contains(StatVfsMountFlags::RDONLY)
            || linux(&self.root_mount[slot])? != linux(&self.root_mount[0])?
        { return Err(CensusDataError::Changed); }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let selected: Option<&(dyn std::error::Error + 'static)> = match self.stage {
            ArtifactStage::Resources => self.resources.failure(),
            ArtifactStage::Paths => self.input_path.as_ref().and_then(|value| value.as_ref().err())
                .or_else(|| self.output_path.as_ref().and_then(|value| value.as_ref().err())).map(|error| error as _),
            ArtifactStage::Input => self.root.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
                .or_else(|| self.root_failure(0)),
            ArtifactStage::Output => self.output.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
                .or_else(|| self.output_stat[0].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
                .or_else(|| self.output_names.as_ref().and_then(|names| names.native_failure()).map(|error| error as _))
                .or_else(|| self.output_names.as_ref().and_then(|names| names.failure()).map(|error| error as _)),
            ArtifactStage::RootLoan => self.root_duplicate.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
                .or_else(|| self.beneath.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
                .or_else(|| self.begin.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)),
            ArtifactStage::Walk => self.census.failure().or_else(|| self.walk.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)),
            ArtifactStage::WalkPost => self.root_failure(1).or_else(|| self.root_posts[0].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)),
            ArtifactStage::Graph => self.census.failure(),
            ArtifactStage::GraphPost => self.root_failure(2).or_else(|| self.root_posts[1].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)),
            ArtifactStage::Object => self.pending_output.failure()
                .or_else(|| self.root_failure(3))
                .or_else(|| self.root_posts[2].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
                .or_else(|| self.publication.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)),
            ArtifactStage::Terminal => self.output_stat[1].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
                .or_else(|| self.root_failure(4)).or_else(|| self.root_posts[3].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)),
        };
        selected.or_else(|| self.outcome.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
            .or_else(|| self.resources.failure())
            .or_else(|| self.resource_post.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
    }

    fn root_failure(&self, slot: usize) -> Option<&(dyn std::error::Error + 'static)> {
        self.root_stat[slot].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
            .or_else(|| self.root_flags[slot].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
            .or_else(|| self.root_mount[slot].as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _))
    }
}

const SEED_FD_CEILING: u64 = 128;
const SEED_AS_CEILING: u64 = 256 * 1024 * 1024;
const SEED_COMPONENT_BYTES: u64 = 224 * 1024 * 1024;
// A root/output/BeneathRoot triple, at most64 active parents and a selected
// symlink plus its two checked proc-route originals. One terminal proc-FD
// directory can coexist with the still-resident failed active stack.
const SEED_ADDITIONAL_FD_PEAK: usize = 71;

/// Keeps actual selected-process limits and observations, not a funding token.
///
/// Limits are lowered after ELF startup and cannot constrain its pre-return
/// loader prefixes retroactively. The same fixed proc originals supply bounded
/// address/FD DATA; they are not the installed Storage parent's accounting.
struct SeedProcessResources {
    admitted: bool,
    limits: [Option<Rlimit>; 4],
    limit_writes: [Option<Result<(), rustix::io::Errno>>; 2],
    statm: Option<Result<OwnedFd, rustix::io::Errno>>,
    statm_filesystem: Option<Result<rustix::fs::StatFs, rustix::io::Errno>>,
    statm_reads: [Option<Result<usize, rustix::io::Errno>>; 2],
    statm_exact: [Option<Result<(), ExactReadFailure>>; 2],
    statm_bytes: [u8; 160],
    fd_directories: [Option<Result<OwnedFd, rustix::io::Errno>>; 2],
    fd_filesystems: [Option<Result<rustix::fs::StatFs, rustix::io::Errno>>; 2],
    fd_inodes: [Option<Result<Stat, rustix::io::Errno>>; 2],
    fd_names: [Option<CensusDirectoryNames>; 2],
    fd_counts: [Option<usize>; 2],
    fd_results: [Option<Result<(), CensusDataError>>; 2],
    address_bytes: [Option<u64>; 2],
    address_results: [Option<Result<(), CensusDataError>>; 2],
    terminal_limits: [Option<Rlimit>; 2],
    outcome: Option<Result<(), CensusDataError>>,
    terminal: Option<Result<(), CensusDataError>>,
}

impl Default for SeedProcessResources {
    fn default() -> Self {
        Self {
            admitted: false,
            limits: [None; 4], limit_writes: [None, None],
            statm: None, statm_filesystem: None,
            statm_reads: [None, None], statm_exact: [None, None], statm_bytes: [0; 160],
            fd_directories: [None, None], fd_filesystems: [None, None],
            fd_inodes: [None, None], fd_names: [None, None], fd_counts: [None, None],
            fd_results: [None, None], address_bytes: [None, None], address_results: [None, None],
            terminal_limits: [None, None], outcome: None, terminal: None,
        }
    }
}

impl SeedProcessResources {
    fn admit(&mut self) -> Result<(), CensusDataError> {
        if self.outcome.is_some() || self.statm.is_some() {
            return Err(CensusDataError::Closed);
        }
        self.outcome = Some(self.admit_inner());
        self.admitted = matches!(self.outcome, Some(Ok(())));
        if self.admitted { Ok(()) } else { Err(CensusDataError::Closed) }
    }

    fn admit_inner(&mut self) -> Result<(), CensusDataError> {
        // Both bounded enumeration reservoirs precede proc opens. Their
        // actual allocations are included in the subsequent address baseline.
        for slot in &mut self.fd_names {
            *slot = Some(CensusDirectoryNames::prepare()?);
        }
        for (slot, resource, ceiling) in [
            (0, Resource::Nofile, SEED_FD_CEILING),
            (1, Resource::As, SEED_AS_CEILING),
        ] {
            let original = rustix::process::getrlimit(resource);
            let selected = bounded_seed_limit(original, ceiling);
            self.limits[slot] = Some(original);
            self.limit_writes[slot] = Some(rustix::process::setrlimit(resource, selected));
            native(&self.limit_writes[slot])?;
            self.limits[slot + 2] = Some(rustix::process::getrlimit(resource));
            if self.limits[slot + 2] != Some(selected) {
                return Err(CensusDataError::Capacity);
            }
        }

        self.statm = Some(rustix::fs::open("/proc/self/statm",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()));
        self.statm_filesystem = Some(rustix::fs::fstatfs(native(&self.statm)?.as_fd()));
        require_seed_proc(native(&self.statm_filesystem)?)?;
        self.fd_results[0] = Some(self.observe_fd_count(0));
        if self.fd_results[0].as_ref().is_some_and(Result::is_err) {
            return Err(CensusDataError::Closed);
        }
        self.address_results[0] = Some(self.observe_address_space(0));
        if self.address_results[0].as_ref().is_some_and(Result::is_err) {
            return Err(CensusDataError::Closed);
        }
        let baseline = self.fd_counts[0].ok_or(CensusDataError::Closed)?;
        let ceiling = self.limits[2].and_then(|limit| limit.current).ok_or(CensusDataError::Closed)?;
        if baseline.checked_add(SEED_ADDITIONAL_FD_PEAK)
            .is_none_or(|count| u64::try_from(count).map_or(true, |count| count > ceiling))
        { return Err(CensusDataError::Capacity); }
        let address = self.address_bytes[0].ok_or(CensusDataError::Closed)?;
        let ceiling = self.limits[3].and_then(|limit| limit.current).ok_or(CensusDataError::Closed)?;
        if address.checked_add(SEED_COMPONENT_BYTES).is_none_or(|bytes| bytes > ceiling) {
            return Err(CensusDataError::Capacity);
        }
        Ok(())
    }

    fn observe_terminal(&mut self) -> Result<(), CensusDataError> {
        if self.terminal.is_some() { return Err(CensusDataError::Closed); }
        if !self.admitted {
            self.terminal = Some(Err(CensusDataError::Closed));
            return Err(CensusDataError::Closed);
        }
        // These two observations are independent, including after action Err.
        self.fd_results[1] = Some(self.observe_fd_count(1));
        self.address_results[1] = Some(self.observe_address_space(1));
        self.terminal_limits = [
            Some(rustix::process::getrlimit(Resource::Nofile)),
            Some(rustix::process::getrlimit(Resource::As)),
        ];
        self.terminal = Some(if self.fd_results[1].as_ref().is_some_and(Result::is_err)
            || self.address_results[1].as_ref().is_some_and(Result::is_err)
        {
            Err(CensusDataError::Closed)
        } else if self.terminal_limits != [self.limits[2], self.limits[3]] {
            Err(CensusDataError::Capacity)
        } else {
            Ok(())
        });
        if matches!(self.terminal, Some(Ok(()))) { Ok(()) } else { Err(CensusDataError::Closed) }
    }

    fn observe_fd_count(&mut self, slot: usize) -> Result<(), CensusDataError> {
        self.fd_directories[slot] = Some(rustix::fs::open("/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty()));
        let directory = native(&self.fd_directories[slot])?;
        self.fd_filesystems[slot] = Some(rustix::fs::fstatfs(directory.as_fd()));
        require_seed_proc(native(&self.fd_filesystems[slot])?)?;
        self.fd_inodes[slot] = Some(rustix::fs::fstat(directory.as_fd()));
        let inode = native(&self.fd_inodes[slot])?;
        let names = self.fd_names[slot].as_mut().ok_or(CensusDataError::Closed)?;
        names.capture(directory.as_fd(), inode).map_err(|_| CensusDataError::NativeObservation)?;
        let mut count = 0_usize;
        let ceiling = self.limits[2].and_then(|limit| limit.current).ok_or(CensusDataError::Closed)?;
        for name in names.names().map_err(|_| CensusDataError::Closed)? {
            let number = seed_decimal(name.as_bytes())?;
            if number >= ceiling { return Err(CensusDataError::Capacity); }
            count = count.checked_add(1).ok_or(CensusDataError::Capacity)?;
        }
        self.fd_counts[slot] = Some(count);
        if u64::try_from(count).map_or(true, |count| count > ceiling) {
            return Err(CensusDataError::Capacity);
        }
        Ok(())
    }

    fn observe_address_space(&mut self, slot: usize) -> Result<(), CensusDataError> {
        let original = native(&self.statm)?;
        self.statm_bytes.fill(0);
        self.statm_reads[slot] = Some(rustix::io::pread(original.as_fd(), &mut self.statm_bytes[..], 0));
        let count = *native(&self.statm_reads[slot])?;
        if count == 0 || count == self.statm_bytes.len() { return Err(CensusDataError::Metadata); }
        // The first bounded length observation is DATA. The shared exact
        // reader then checks the complete same original and its sole EOF probe.
        self.statm_exact[slot] = Some(read_exact_positioned_census_retaining_cause(
            original.as_fd(), &mut self.statm_bytes[..count]));
        if self.statm_exact[slot].as_ref().is_some_and(Result::is_err) {
            return Err(CensusDataError::NativeObservation);
        }
        let pages = seed_statm_pages(&self.statm_bytes[..count])?;
        let page_size = u64::try_from(rustix::param::page_size()).map_err(|_| CensusDataError::Capacity)?;
        if page_size == 0 { return Err(CensusDataError::Metadata); }
        let bytes = pages.checked_mul(page_size).ok_or(CensusDataError::Capacity)?;
        self.address_bytes[slot] = Some(bytes);
        let ceiling = self.limits[3].and_then(|limit| limit.current).ok_or(CensusDataError::Closed)?;
        if bytes > ceiling { return Err(CensusDataError::Capacity); }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for result in &self.limit_writes {
            if let Some(Err(error)) = result { return Some(error); }
        }
        if let Some(Err(error)) = &self.statm { return Some(error); }
        if let Some(Err(error)) = &self.statm_filesystem { return Some(error); }
        for slot in 0..2 {
            if let Some(Err(error)) = &self.fd_directories[slot] { return Some(error); }
            if let Some(Err(error)) = &self.fd_filesystems[slot] { return Some(error); }
            if let Some(Err(error)) = &self.fd_inodes[slot] { return Some(error); }
            if let Some(names) = &self.fd_names[slot] {
                if let Some(error) = names.failure() {
                    if matches!(error, CensusDataError::NativeObservation) {
                        if let Some(native) = names.native_failure() { return Some(native); }
                    }
                    return Some(error);
                }
            }
            if let Some(Err(error)) = &self.fd_results[slot] { return Some(error); }
            if let Some(Err(error)) = &self.statm_reads[slot] { return Some(error); }
            if let Some(Err(error)) = &self.statm_exact[slot] { return Some(error); }
            if let Some(Err(error)) = &self.address_results[slot] { return Some(error); }
            if slot == 0 {
                if let Some(Err(error)) = &self.outcome { return Some(error); }
            }
        }
        self.terminal.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
    }
}

fn bounded_seed_limit(original: Rlimit, ceiling: u64) -> Rlimit {
    let maximum = original.maximum.unwrap_or(ceiling).min(ceiling);
    let current = original.current.unwrap_or(maximum).min(maximum);
    Rlimit { current: Some(current), maximum: Some(maximum) }
}

fn require_seed_proc(filesystem: &rustix::fs::StatFs) -> Result<(), CensusDataError> {
    if filesystem.f_type as u64 != 0x9fa0 { return Err(CensusDataError::Metadata); }
    Ok(())
}

fn seed_statm_pages(bytes: &[u8]) -> Result<u64, CensusDataError> {
    let row = bytes.strip_suffix(b"\n").ok_or(CensusDataError::Metadata)?;
    let mut fields = row.split(|byte| *byte == b' ');
    let pages = seed_decimal(fields.next().ok_or(CensusDataError::Metadata)?)?;
    for _ in 0..6 {
        seed_decimal(fields.next().ok_or(CensusDataError::Metadata)?)?;
    }
    if fields.next().is_some() { return Err(CensusDataError::Metadata); }
    Ok(pages)
}

fn seed_decimal(bytes: &[u8]) -> Result<u64, CensusDataError> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return Err(CensusDataError::Metadata);
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        if !byte.is_ascii_digit() { return Err(CensusDataError::Metadata); }
        value.checked_mul(10).and_then(|value| value.checked_add(u64::from(*byte - b'0')))
            .ok_or(CensusDataError::Capacity)
    })
}

fn capture_output_object(
    directory: &OwnedFd, owner: &mut ArtifactOutputOriginal, name: &str, expected: &[u8],
    remaining_capacity: usize,
) -> Result<(), CensusDataError> {
    if expected.len().checked_add(name.len())
        .is_none_or(|bytes| bytes > remaining_capacity)
    { return Err(CensusDataError::Capacity); }
    owner.name.try_reserve_exact(name.len())?;
    owner.name.push_str(name);
    owner.bytes.try_reserve_exact(expected.len())?;
    owner.bytes.resize(expected.len(), 0);
    if owner.bytes.capacity().checked_add(owner.name.capacity())
        .is_none_or(|bytes| bytes > remaining_capacity)
    { return Err(CensusDataError::Capacity); }

    owner.directory_inode[0] = Some(rustix::fs::fstat(directory.as_fd()));
    native(&owner.directory_inode[0])?;
    owner.action = Some(capture_output_action(directory, owner, name, expected));
    // A returned action failure cannot suppress original file/directory posts.
    // Its complete Result is parked before these independent observations.
    if let Some(Ok(file)) = owner.file.as_ref() {
        owner.final_inode[0] = Some(rustix::fs::fstat(file.as_fd()));
    }
    if let Some(Ok(named)) = owner.named.as_ref() {
        owner.final_inode[1] = Some(rustix::fs::fstat(named.as_fd()));
    }
    owner.directory_inode[1] = Some(rustix::fs::fstat(directory.as_fd()));
    owner.postcheck = Some(owner.require_postcheck());
    if owner.action.as_ref().is_some_and(Result::is_err)
        || owner.postcheck.as_ref().is_some_and(Result::is_err)
    { return Err(CensusDataError::ArtifactOutput); }

    // Retirement is allowed only after the same named/original bookends.
    owner.named = None;
    owner.file = None;
    Ok(())
}

fn capture_output_action(
    directory: &OwnedFd,
    owner: &mut ArtifactOutputOriginal,
    name: &str,
    expected: &[u8],
) -> Result<(), CensusDataError> {
    owner.file = Some(rustix::fs::openat(directory.as_fd(), name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ).map(std::fs::File::from));
    let file = owner.file.as_mut().ok_or(CensusDataError::Closed)?.as_mut()
        .map_err(|_| CensusDataError::ArtifactOutput)?;
    owner.write = Some(file.write_all(expected));
    if owner.write.as_ref().is_some_and(Result::is_err) { return Err(CensusDataError::ArtifactOutput); }
    owner.flush = Some(file.flush());
    if owner.flush.as_ref().is_some_and(Result::is_err) { return Err(CensusDataError::ArtifactOutput); }
    owner.sync = Some(file.sync_all());
    if owner.sync.as_ref().is_some_and(Result::is_err) { return Err(CensusDataError::ArtifactOutput); }
    owner.inode[0] = Some(rustix::fs::fstat(file.as_fd()));
    native(&owner.inode[0])?;
    owner.directory_sync = Some(rustix::fs::fsync(directory.as_fd()));
    native(&owner.directory_sync)?;
    owner.named = Some(rustix::fs::openat(directory.as_fd(), name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()));
    let named = native(&owner.named)?;
    owner.inode[1] = Some(rustix::fs::fstat(named.as_fd()));
    let before = native(&owner.inode[0])?;
    let after = native(&owner.inode[1])?;
    if !same_inode_state(before, after) || rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || usize::try_from(before.st_size).ok() != Some(expected.len())
    { return Err(CensusDataError::ArtifactOutput); }
    owner.read = Some(read_exact_positioned_census_retaining_cause(named.as_fd(), &mut owner.bytes));
    if owner.read.as_ref().is_some_and(Result::is_err) || owner.bytes != expected {
        return Err(CensusDataError::ArtifactOutput);
    }
    Ok(())
}

impl ArtifactOutputOriginal {
    fn require_postcheck(&self) -> Result<(), CensusDataError> {
        let before = native(&self.directory_inode[0])?;
        let after = native(&self.directory_inode[1])?;
        // This publication changes the directory timestamps itself; only its
        // held identity, type and access metadata remain stable coordinates.
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid
        { return Err(CensusDataError::Changed); }

        for slot in 0..2 {
            if self.final_inode[slot].is_some() {
                let final_inode = native(&self.final_inode[slot])?;
                if let Some(Ok(before)) = &self.inode[slot] {
                    if !same_inode_state(before, final_inode) {
                        return Err(CensusDataError::Changed);
                    }
                }
            }
        }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.directory_inode[0].as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        if let Some(error) = self.file.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        for result in [&self.write, &self.flush, &self.sync] {
            if let Some(error) = result.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        }
        if let Some(error) = self.inode[0].as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        if let Some(error) = self.directory_sync.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        if let Some(error) = self.named.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        if let Some(error) = self.inode[1].as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        if let Some(error) = self.read.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        if let Some(error) = self.action.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        for result in &self.final_inode {
            if let Some(error) = result.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        }
        if let Some(error) = self.directory_inode[1].as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        if let Some(error) = self.postcheck.as_ref().and_then(|value| value.as_ref().err()) { return Some(error); }
        self.outcome.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
    }
}

fn native<T>(result: &Option<Result<T, rustix::io::Errno>>) -> Result<&T, CensusDataError> {
    result.as_ref().ok_or(CensusDataError::Closed)?.as_ref().map_err(|_| CensusDataError::NativeObservation)
}

fn linux<T>(result: &Option<Result<T, aos_sandbox_linux::Error>>) -> Result<&T, CensusDataError> {
    result.as_ref().ok_or(CensusDataError::Closed)?.as_ref().map_err(|_| CensusDataError::NativeObservation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_limit_never_raises_an_inherited_soft_or_hard_limit() {
        let inherited = Rlimit { current: Some(48), maximum: Some(96) };

        let selected = bounded_seed_limit(inherited, SEED_FD_CEILING);

        assert_eq!(selected, inherited);
        assert_eq!(bounded_seed_limit(Rlimit { current: None, maximum: None }, 128),
            Rlimit { current: Some(128), maximum: Some(128) });
        assert_eq!(bounded_seed_limit(Rlimit { current: Some(200), maximum: Some(256) }, 128),
            Rlimit { current: Some(128), maximum: Some(128) });
    }

    #[test]
    fn fixed_statm_data_requires_all_seven_complete_decimal_fields() {
        assert_eq!(seed_statm_pages(b"123 40 10 2 0 20 0\n").unwrap(), 123);
        for malformed in [
            &b"123 40 10 2 0 20 0"[..],
            &b"123 40 10 2 0 20\n"[..],
            &b"123 40 10 2 0 20 0 0\n"[..],
            &b"123  40 10 2 0 20 0\n"[..],
            &b"0123 40 10 2 0 20 0\n"[..],
            &b"18446744073709551616 0 0 0 0 0 0\n"[..],
        ] {
            assert!(seed_statm_pages(malformed).is_err());
        }
    }

    #[test]
    fn terminal_fd_bound_failure_precedes_later_address_native_debt() {
        let mut owner = SeedProcessResources::default();
        owner.outcome = Some(Ok(()));
        owner.fd_results[1] = Some(Err(CensusDataError::Capacity));
        owner.statm_reads[1] = Some(Err(rustix::io::Errno::IO));
        owner.address_results[1] = Some(Err(CensusDataError::NativeObservation));

        let failure = owner.failure().unwrap();

        assert!(matches!(failure.downcast_ref::<CensusDataError>(), Some(CensusDataError::Capacity)));
        assert_eq!(owner.statm_reads[1].as_ref().unwrap().as_ref().unwrap_err(), &rustix::io::Errno::IO);
    }

    #[test]
    fn output_native_action_failure_precedes_independent_post_debt() {
        let owner = ArtifactOutputOriginal {
            read: Some(Err(ExactReadFailure::Io(rustix::io::Errno::IO))),
            action: Some(Err(CensusDataError::ArtifactOutput)),
            final_inode: [Some(Err(rustix::io::Errno::ACCESS)), None],
            directory_inode: [None, Some(Err(rustix::io::Errno::INTR))],
            postcheck: Some(Err(CensusDataError::NativeObservation)),
            ..Default::default()
        };

        let failure = owner.failure().unwrap();

        assert!(matches!(failure.downcast_ref::<ExactReadFailure>(),
            Some(ExactReadFailure::Io(rustix::io::Errno::IO))));
        assert_eq!(owner.final_inode[0].as_ref().unwrap().as_ref().unwrap_err(),
            &rustix::io::Errno::ACCESS);
        assert!(owner.file.is_none());
    }

    #[test]
    fn output_semantic_action_failure_precedes_later_native_post_error() {
        let owner = ArtifactOutputOriginal {
            action: Some(Err(CensusDataError::ArtifactOutput)),
            final_inode: [Some(Err(rustix::io::Errno::IO)), None],
            ..Default::default()
        };

        let failure = owner.failure().unwrap();

        assert!(matches!(failure.downcast_ref::<CensusDataError>(),
            Some(CensusDataError::ArtifactOutput)));
    }
}
