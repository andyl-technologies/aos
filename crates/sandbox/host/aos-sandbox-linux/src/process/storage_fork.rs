//! Shares the native descriptor-table census of closed worker and SSH births.
//!
//! This observation is passive DATA. The actual selected worker and its parent
//! financial original remain distinct owners. A complete, signal-fenced census
//! includes the scanner, then closes only that positive scanner before the
//! shared path spawn. No child, permission or operation is created by this type.

use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};

use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;

const SCANS: usize = 2;
const STORAGE_MAXIMUM_TABLE: usize = 32;
const NETWORK_MAXIMUM_TABLE: usize = 128;
const RAW_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug)]
enum First {
    Limits,
    Open,
    Filesystem,
    Read,
    Name,
    Count,
    Rewind,
    Comparison,
    Closed,
}

/// Retains the raw native descriptor census used immediately before one clone.
///
/// Construction and returned bounds grant no payer, worker or process role.
/// Callers keep failed observations through their actual disposition.
#[derive(Debug)]
struct FixedWorkerForkObservationV4 {
    role: ForkRole,
    limits: Option<Result<rustix::process::Rlimit>>,
    limits_result: Option<Result<()>>,
    directory: Option<std::result::Result<OwnedFd, rustix::io::Errno>>,
    filesystem: Option<std::result::Result<rustix::fs::StatFs, rustix::io::Errno>>,
    filesystem_result: Option<Result<()>>,
    raw: [[MaybeUninit<u8>; RAW_BYTES]; SCANS],
    numbers: [Vec<u32>; SCANS],
    read_error: Option<rustix::io::Errno>,
    name_error: Option<Error>,
    rewind: Option<std::result::Result<u64, rustix::io::Errno>>,
    rewind_position: Option<Result<()>>,
    comparison: Option<Result<()>>,
    first: Option<First>,
    entered: bool,
    scanner_disposed: bool,
}

impl FixedWorkerForkObservationV4 {
    /// Creates fixed destinations without native observation or allocation.
    #[must_use]
    const fn new(role: ForkRole) -> Self {
        Self {
            role,
            limits: None,
            limits_result: None,
            directory: None,
            filesystem: None,
            filesystem_result: None,
            raw: [[MaybeUninit::uninit(); RAW_BYTES]; SCANS],
            numbers: [Vec::new(), Vec::new()],
            read_error: None,
            name_error: None,
            rewind: None,
            rewind_position: None,
            comparison: None,
            first: None,
            entered: false,
            scanner_disposed: false,
        }
    }

    /// Prices retained frames, bounded vectors, iterator frames and errors.
    #[must_use]
    fn requested_bytes(role: ForkRole) -> Option<usize> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(role.maximum_table().checked_add(1)?
                .checked_mul(3 * SCANS * std::mem::size_of::<u32>())?)?
            .checked_add(
                2 * std::mem::size_of::<rustix::fs::RawDir<'_, std::os::fd::BorrowedFd<'_>>>(),
            )?
            .checked_add(2 * std::mem::size_of::<rustix::fs::RawDirEntry<'_>>())?;
        if matches!(role, ForkRole::GuestSsh { .. }) {
            return bytes.checked_add(4 * 256);
        }
        bytes
            // The shared fence holds the exact previous mask and two native
            // construction masks. Its outer result holds the real spawn owner.
            .checked_add(3 * std::mem::size_of::<libc::sigset_t>())?
            .checked_add(2 * std::mem::size_of::<Result<super::SpawnedProcess>>())?
            .checked_add(4 * 256)
    }

    /// Borrows the original first native or semantic refusal.
    #[must_use]
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(
            value: &Option<std::result::Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|error| error as _)
        }
        match self.first? {
            First::Limits => cause(&self.limits).or_else(|| cause(&self.limits_result)),
            First::Open => cause(&self.directory),
            First::Filesystem => cause(&self.filesystem).or_else(|| cause(&self.filesystem_result)),
            First::Read => self.read_error.as_ref().map(|error| error as _),
            First::Name => self.name_error.as_ref().map(|error| error as _),
            First::Rewind => cause(&self.rewind).or_else(|| cause(&self.rewind_position)),
            First::Comparison => cause(&self.comparison),
            First::Count | First::Closed => Some(self.role.refused()),
        }
    }

    fn capture_before_path_spawn(&mut self) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(First::Closed);
            return Err(census_refused(self.role));
        }
        self.entered = true;
        self.limits = Some(super::observe_nofile_limit_v1());
        self.limits_result = Some(match (self.role, self.limits.as_ref()) {
            (ForkRole::NetworkProgramme { native_nofile, .. }, Some(Ok(limit)))
                if limit.current == Some(native_nofile) && limit.maximum == Some(native_nofile) => Ok(()),
            (ForkRole::GuestSsh { .. }, Some(Ok(limit))) if
                limit.current.is_none_or(|current| current != 0)
                    && limit.maximum.is_none_or(|maximum| maximum != 0)
                    && match (limit.current, limit.maximum) {
                        (Some(current), Some(maximum)) => current <= maximum,
                        (None, Some(_)) => false,
                        _ => true,
                    } => Ok(()),
            (ForkRole::Storage | ForkRole::Network, Some(Ok(rustix::process::Rlimit {
                current: Some(128),
                maximum: Some(128),
            }))) => Ok(()),
            _ => Err(Error::invalid(
                self.role.limit_field(),
                self.role.limit_expectation(),
            )),
        });
        if !matches!(self.limits_result, Some(Ok(()))) {
            self.first = Some(First::Limits);
            return Err(census_refused(self.role));
        }
        self.directory = Some(rustix::fs::open(
            "/proc/self/fd",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ));
        if !matches!(self.directory, Some(Ok(_))) {
            self.first = Some(First::Open);
            return Err(census_refused(self.role));
        }
        if matches!(self.role, ForkRole::GuestSsh { .. }) {
            let Some(Ok(directory)) = self.directory.as_ref() else {
                std::process::abort();
            };
            self.filesystem = Some(rustix::fs::fstatfs(directory));
            self.filesystem_result = Some(if matches!(self.filesystem,
                Some(Ok(ref stat)) if stat.f_type as u64 == 0x9fa0)
            { Ok(()) } else { Err(census_refused(self.role)) });
            if !matches!(self.filesystem_result, Some(Ok(()))) {
                self.first = Some(First::Filesystem);
                return Err(census_refused(self.role));
            }
        }
        self.scan(0)?;
        let Some(Ok(directory)) = self.directory.as_ref() else {
            std::process::abort();
        };
        self.rewind = Some(rustix::fs::seek(
            directory.as_fd(),
            rustix::fs::SeekFrom::Start(0),
        ));
        self.rewind_position = Some(if matches!(self.rewind, Some(Ok(0))) {
            Ok(())
        } else {
            Err(Error::invalid(
                self.role.census_field(),
                "native directory rewind refused",
            ))
        });
        if !matches!(self.rewind_position, Some(Ok(()))) {
            self.first = Some(First::Rewind);
            return Err(census_refused(self.role));
        }
        self.scan(1)?;
        let Some(Ok(directory)) = self.directory.as_ref() else {
            std::process::abort();
        };
        self.comparison = Some(
            if if matches!(self.role, ForkRole::GuestSsh { .. }) {
                u32::try_from(directory.as_raw_fd()).is_ok_and(|scanner|
                    self.numbers.iter().all(|numbers| numbers.binary_search(&scanner).is_ok()))
            } else { self.numbers[0] == self.numbers[1]
                && directory.as_raw_fd() >= 3
                && (0..3).all(|number| self.numbers[0].binary_search(&number).is_ok())
            }
            {
                Ok(())
            } else {
                Err(Error::invalid(
                    self.role.census_field(),
                    "table changed or original stdio is absent",
                ))
            },
        );
        if !matches!(self.comparison, Some(Ok(()))) {
            self.first = Some(First::Comparison);
            return Err(census_refused(self.role));
        }

        // This native inspection is complete independently of a future child.
        // The scanner is counted in its fixed role ceiling, then closed before clone; the
        // shared parent later opens at most one pidfd in that reclaimed slot.
        drop(self.directory.take());
        self.scanner_disposed = true;
        Ok(())
    }

    fn scan(&mut self, index: usize) -> Result<()> {
        let Some(Ok(directory)) = self.directory.as_ref() else {
            std::process::abort();
        };
        let mut iterator = rustix::fs::RawDir::new(directory.as_fd(), &mut self.raw[index]);
        while let Some(entry) = iterator.next() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.read_error = Some(error);
                    self.first = Some(First::Read);
                    return Err(census_refused(self.role));
                }
            };
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            let number = std::str::from_utf8(name)
                .ok()
                .filter(|name| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|name| name.parse::<u32>().ok());
            let Some(number) = number else {
                self.name_error = Some(Error::invalid(
                    self.role.census_field(),
                    "invalid native descriptor number",
                ));
                self.first = Some(First::Name);
                return Err(census_refused(self.role));
            };
            self.numbers[index].push(number);
            if self.numbers[index].len() > self.role.maximum_table() {
                self.first = Some(First::Count);
                return Err(census_refused(self.role));
            }
        }
        self.numbers[index].sort_unstable();
        Ok(())
    }
}

static CENSUS_REFUSED: CensusRefused = CensusRefused;

#[derive(Debug, thiserror::Error)]
#[error("Storage worker descriptor census is incomplete or refused")]
struct CensusRefused;

fn census_refused(role: ForkRole) -> Error {
    Error::invalid(role.census_field(), "native original retained")
}

#[derive(Clone, Copy, Debug)]
enum ForkRole {
    Storage,
    Network,
    NetworkProgramme { native_nofile: u64, maximum_table: usize },
    GuestSsh { maximum_table: usize },
}

impl ForkRole {
    const fn maximum_table(self) -> usize {
        match self {
            Self::Storage => STORAGE_MAXIMUM_TABLE,
            Self::Network => NETWORK_MAXIMUM_TABLE,
            Self::NetworkProgramme { maximum_table, .. } => maximum_table,
            Self::GuestSsh { maximum_table } => maximum_table,
        }
    }
    const fn limit_field(self) -> &'static str {
        match self {
            Self::Storage => "Storage worker descriptor limit",
            Self::Network | Self::NetworkProgramme { .. } => "Network worker descriptor limit",
            Self::GuestSsh { .. } => "Guest SSH source descriptor limit",
        }
    }
    const fn limit_expectation(self) -> &'static str {
        match self {
            Self::Storage | Self::Network => "requires exact soft/hard 128",
            Self::NetworkProgramme { .. } => "requires the actual selected finite soft/hard NOFILE",
            Self::GuestSsh { .. } => "invalid actual source nofile record",
        }
    }
    const fn census_field(self) -> &'static str {
        match self {
            Self::Storage => "Storage worker descriptor census",
            Self::Network | Self::NetworkProgramme { .. } => "Network worker descriptor census",
            Self::GuestSsh { .. } => "Guest SSH source descriptor census",
        }
    }
    fn refused(self) -> &'static (dyn std::error::Error + 'static) {
        match self {
            Self::Storage => &CENSUS_REFUSED,
            Self::Network | Self::NetworkProgramme { .. } => &NETWORK_CENSUS_REFUSED,
            Self::GuestSsh { .. } => &GUEST_SSH_CENSUS_REFUSED,
        }
    }
}

static NETWORK_CENSUS_REFUSED: NetworkCensusRefused = NetworkCensusRefused;
#[derive(Debug, thiserror::Error)]
#[error("Network worker descriptor census is incomplete or refused")]
struct NetworkCensusRefused;

static GUEST_SSH_CENSUS_REFUSED: GuestSshCensusRefused = GuestSshCensusRefused;

#[derive(Debug, thiserror::Error)]
#[error("Guest SSH source descriptor census is incomplete or refused")]
struct GuestSshCensusRefused;

/// Keeps SSH's finite source observation on the same descriptor scan engine.
///
/// Its closed constructor accepts no path, PID or role. The actual selected
/// Guest caller supplies only already-prepaid denial bounds and source-audited
/// concurrent growth; those scalars grant neither a worker nor an FD allowance.
#[derive(Debug, Default)]
pub(crate) struct GuestSshForkObservationV1 {
    native: Option<Box<FixedWorkerForkObservationV4>>,
    bound: Option<Result<()>>,
    closed: Option<Error>,
}

impl GuestSshForkObservationV1 {
    pub(crate) fn new() -> Self { Self::default() }

    pub(crate) fn capture_once_v1(&mut self, copied_files: u32, highest_fd: u32,
        future_files: u64) -> Result<()>
    {
        if self.native.is_some() || self.closed.is_some() || copied_files == 0 {
            self.closed.get_or_insert_with(|| census_refused(ForkRole::GuestSsh { maximum_table: 0 }));
            return Err(census_refused(ForkRole::GuestSsh { maximum_table: 0 }));
        }
        let role = ForkRole::GuestSsh { maximum_table: usize::try_from(copied_files)
            .map_err(|_| census_refused(ForkRole::GuestSsh { maximum_table: 0 }))? };
        self.native = Some(Box::new(FixedWorkerForkObservationV4::new(role)));
        let original = self.native.as_mut().ok_or_else(|| census_refused(role))?;
        original.capture_before_path_spawn()?;
        let count = original.numbers.iter().map(Vec::len).max()
            .and_then(|count| u64::try_from(count).ok()).ok_or_else(|| census_refused(role))?;
        let highest = original.numbers.iter().filter_map(|numbers| numbers.last()).copied().max()
            .ok_or_else(|| census_refused(role))?;
        // The completed scanner closes before clone. The loader's one finite
        // alias replaces that position in this conservative bound. Other
        // thread growth is separately supplied from the stable actual registry.
        let copied = count.checked_add(future_files);
        let highest = u64::from(highest).max(super::DUPLICATE_FD_MINIMUM as u64)
            .checked_add(future_files);
        self.bound = Some(if copied.is_some_and(|count| count <= u64::from(copied_files))
            && highest.is_some_and(|number| number <= u64::from(highest_fd))
            && original.scanner_disposed
        { Ok(()) } else { Err(census_refused(role)) });
        if matches!(self.bound, Some(Ok(()))) { Ok(()) } else { Err(census_refused(role)) }
    }

    pub(crate) fn receiving_bytes_v1(copied_files: u32) -> Option<usize> {
        let maximum_table = usize::try_from(copied_files).ok()?;
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(FixedWorkerForkObservationV4::requested_bytes(
                ForkRole::GuestSsh { maximum_table })?)
    }

    pub(crate) fn receiving_metadata_entries_v1(copied_files: u32) -> Option<usize> {
        usize::try_from(copied_files).ok()?.checked_add(1)?
            .checked_mul(SCANS)?.checked_add(1)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.as_ref().and_then(|original| original.failure())
            .or_else(|| self.bound.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

/// Retains the existing closed Storage fork census and exact original cause.
#[derive(Debug)]
pub struct StorageWorkerForkObservationV1(FixedWorkerForkObservationV4);

impl StorageWorkerForkObservationV1 {
    /// Creates inert custody for the exact Storage worker recipe.
    #[must_use]
    pub const fn new() -> Self {
        Self(FixedWorkerForkObservationV4::new(ForkRole::Storage))
    }
    /// Bounds the complete parent table including the temporary scanner.
    pub const MAXIMUM_PARENT_FILES_V1: usize = STORAGE_MAXIMUM_TABLE;
    /// Bounds both retained name indexes, including each rejected next entry.
    pub const MAXIMUM_DESCRIPTOR_INDEX_ENTRIES_V1: usize = SCANS * (STORAGE_MAXIMUM_TABLE + 1);
    /// Counts the actual procfs lookup and both descriptor-name indexes.
    pub const METADATA_ENTRIES_V1: usize = 1 + Self::MAXIMUM_DESCRIPTOR_INDEX_ENTRIES_V1;
    /// Prices this actual original, native iterator/fence and bounded indexes.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        FixedWorkerForkObservationV4::requested_bytes(ForkRole::Storage)
    }
    /// Borrows the original first native or semantic refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.failure()
    }
    pub(super) fn capture_before_path_spawn(&mut self) -> Result<()> {
        self.0.capture_before_path_spawn()
    }
}

impl Default for StorageWorkerForkObservationV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct NetworkForkIdentity;
#[derive(Debug)]
struct NetworkForkReturnedMarker(std::sync::Arc<NetworkForkIdentity>);
impl std::fmt::Display for NetworkForkReturnedMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Network fork census original retained")
    }
}
impl std::error::Error for NetworkForkReturnedMarker {}

/// Retains the fixed Network worker's signal-fenced complete fork table.
///
/// The exact canonical worker NOFILE recipe is 128. The parent must prepay its
/// child/fork receiving source under SAME F before issue; this census supplies
/// no role, reservation or guarantee that an arbitrary table fits a profile.
#[derive(Debug)]
pub struct NetworkWorkerForkObservationV4 {
    native: FixedWorkerForkObservationV4,
    identity: std::sync::Arc<NetworkForkIdentity>,
}

impl NetworkWorkerForkObservationV4 {
    /// Creates a census for the actual selected native limit and paid table frontier.
    ///
    /// Both values are comparison DATA from the protected finite programme.
    /// The native reader checks the real soft/hard limit and complete table;
    /// neither argument creates a Source, account, clone or budget permission.
    /// The frontier includes the scanner and all prospective concurrent growth.
    #[must_use]
    pub fn new_for_programme_data_v2(native_nofile: u64, maximum_table: usize) -> Option<Self> {
        let role = network_programme_role(native_nofile, maximum_table)?;
        Some(Self { native: FixedWorkerForkObservationV4::new(role),
            identity: std::sync::Arc::new(NetworkForkIdentity) })
    }

    /// Prices that same bounded census without changing any native limit.
    #[must_use]
    pub fn requested_programme_bytes_data_v2(native_nofile: u64, maximum_table: usize) -> Option<usize> {
        let role = network_programme_role(native_nofile, maximum_table)?;
        FixedWorkerForkObservationV4::requested_bytes(role)?
            .checked_add(2 * std::mem::size_of::<std::sync::Arc<NetworkForkIdentity>>())?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::size_of::<NetworkForkReturnedMarker>())?
            .checked_add(2 * std::mem::size_of::<std::io::Error>())
    }

    /// Returns the two real tables and attached PIDFD ceiling for that programme.
    ///
    /// The completed scanner closes before clone. Its native table charge is
    /// replaced by the actually attached parent PIDFD, with no bank refund.
    #[must_use]
    pub fn programme_fork_files_data_v2(native_nofile: u64, maximum_table: usize) -> Option<usize> {
        network_programme_role(native_nofile, maximum_table)?;
        maximum_table.checked_sub(1)?.checked_mul(2)?.checked_add(1)
    }

    /// Counts the exact two-walk metadata indexes for this configured census.
    ///
    /// The same role validator enforces the actual native limit and finite
    /// frontier. This DATA changes no table, scan, native cap or permission.
    #[must_use]
    pub fn programme_metadata_entries_data_v2(
        native_nofile: u64,
        maximum_table: usize,
    ) -> Option<usize> {
        network_programme_role(native_nofile, maximum_table)?;
        1usize.checked_add(SCANS.checked_mul(maximum_table.checked_add(1)?)?)
    }

    /// Creates native destinations and their same-original diagnostic identity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            native: FixedWorkerForkObservationV4::new(ForkRole::Network),
            identity: std::sync::Arc::new(NetworkForkIdentity),
        }
    }
    /// Bounds parent descriptors including the scanner before actual clone.
    pub const MAXIMUM_PARENT_FILES_V4: usize = NETWORK_MAXIMUM_TABLE;
    /// Bounds both process tables at clone and the newly attached parent pidfd.
    pub const MAXIMUM_FORK_FILES_V4: usize = 2 * (NETWORK_MAXIMUM_TABLE - 1) + 1;
    /// Counts the procfs lookup and both actual descriptor-number indexes.
    pub const METADATA_ENTRIES_V4: usize = 1 + SCANS * (NETWORK_MAXIMUM_TABLE + 1);
    /// Prices the actual native owner, indexes and same-source returned marker.
    #[must_use]
    pub fn requested_bytes_v4() -> Option<usize> {
        FixedWorkerForkObservationV4::requested_bytes(ForkRole::Network)?
            .checked_add(2 * std::mem::size_of::<std::sync::Arc<NetworkForkIdentity>>())?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::size_of::<NetworkForkReturnedMarker>())?
            .checked_add(2 * std::mem::size_of::<std::io::Error>())
    }
    /// Borrows the exact first entered native or semantic failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure()
    }
    /// Selects a source only for its actual same-original returned marker.
    #[must_use]
    pub fn failure_for_returned_v4(
        &self,
        returned: &Error,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        let Error::Syscall { source, .. } = returned else {
            return None;
        };
        let marker = source
            .get_ref()?
            .downcast_ref::<NetworkForkReturnedMarker>()?;
        if !std::sync::Arc::ptr_eq(&marker.0, &self.identity) {
            return None;
        }
        self.native.failure()
    }
    fn capture_before_path_spawn(&mut self) -> Result<()> {
        if self.native.capture_before_path_spawn().is_err() {
            return Err(Error::Syscall {
                operation: "Network worker complete fork census",
                source: std::io::Error::other(NetworkForkReturnedMarker(std::sync::Arc::clone(
                    &self.identity,
                ))),
            });
        }
        Ok(())
    }
}

fn network_programme_role(native_nofile: u64, maximum_table: usize) -> Option<ForkRole> {
    // Three standard descriptors plus the actual scanner form the smallest
    // observable table. The amount is never a substituted NOFILE declaration.
    if maximum_table < 3 + 1 || u64::try_from(maximum_table).ok()? > native_nofile {
        return None;
    }
    Some(ForkRole::NetworkProgramme { native_nofile, maximum_table })
}
impl Default for NetworkWorkerForkObservationV4 {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) enum WorkerForkObservationBorrowV4<'held> {
    Storage(&'held mut StorageWorkerForkObservationV1),
    Network(&'held mut NetworkWorkerForkObservationV4),
}
impl WorkerForkObservationBorrowV4<'_> {
    pub(super) fn capture_before_path_spawn(&mut self) -> Result<()> {
        match self {
            Self::Storage(original) => original.capture_before_path_spawn(),
            Self::Network(original) => original.capture_before_path_spawn(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const CASE: &str = "AOS_STORAGE_FORK_CENSUS_KERNEL_CASE_V1";

    #[test]
    fn guest_ssh_census_includes_high_cloexec_positions_before_source_admission() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let high = rustix::io::fcntl_dupfd_cloexec(&file, super::super::DUPLICATE_FD_MINIMUM).unwrap();
        let number = u32::try_from(high.as_raw_fd()).unwrap();
        assert!(rustix::io::fcntl_getfd(&high).unwrap().contains(rustix::io::FdFlags::CLOEXEC));
        let mut original = GuestSshForkObservationV1::new();

        assert!(original.capture_once_v1(4096, number - 1, 0).is_err());

        let native = original.native.as_ref().unwrap();
        assert!(native.numbers.iter().all(|numbers| numbers.binary_search(&number).is_ok()));
        assert!(native.scanner_disposed);
        assert!(native.directory.is_none());
        assert!(matches!(original.bound, Some(Err(_))));
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(original.capture_once_v1(4096, number + 4096, 0).is_err());
        assert_eq!(original.failure().unwrap() as *const dyn std::error::Error as *const (), first);
    }

    #[test]
    fn guest_ssh_positive_source_prices_finite_concurrent_growth() {
        let mut original = GuestSshForkObservationV1::new();

        original.capture_once_v1(4096, 4096, 7).unwrap();

        assert!(matches!(original.bound, Some(Ok(()))));
        assert!(original.native.as_ref().unwrap().scanner_disposed);
        assert!(original.native.as_ref().unwrap().directory.is_none());
        assert!(original.failure().is_none());
    }

    #[test]
    fn network_census_uses_its_actual_table_and_exact_returned_marker() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::storage_fork::tests::network_kernel_case",
                "--nocapture",
            ])
            .env("AOS_NETWORK_FORK_CENSUS_CASE_V4", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn network_kernel_case() {
        if std::env::var_os("AOS_NETWORK_FORK_CENSUS_CASE_V4").is_none() {
            return;
        }
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(128),
                maximum: Some(128),
            },
        )
        .unwrap();
        let files = (0..40)
            .map(|_| std::fs::File::open("/dev/null").unwrap())
            .collect::<Vec<_>>();
        let mut original = NetworkWorkerForkObservationV4::new();
        original.capture_before_path_spawn().unwrap();
        assert!(original.native.numbers[0].len() > STORAGE_MAXIMUM_TABLE);
        assert_eq!(original.native.numbers[0], original.native.numbers[1]);
        assert!(original.native.directory.is_none());
        assert!(original.native.scanner_disposed);
        drop(files);

        let returned = original.capture_before_path_spawn().unwrap_err();
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert_eq!(
            original.failure_for_returned_v4(&returned).unwrap() as *const dyn std::error::Error
                as *const (),
            first
        );
        let foreign = NetworkWorkerForkObservationV4::new();
        assert!(foreign.failure_for_returned_v4(&returned).is_none());
        assert!(
            original
                .failure_for_returned_v4(&Error::invalid("other", "pure error"))
                .is_none()
        );

        let mut refused = NetworkWorkerForkObservationV4::new();
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(127),
                maximum: Some(128),
            },
        )
        .unwrap();
        let returned = refused.capture_before_path_spawn().unwrap_err();
        assert!(matches!(refused.native.first, Some(First::Limits)));
        assert!(refused.native.directory.is_none());
        assert!(refused.failure_for_returned_v4(&returned).is_some());
        let saved = refused.failure().unwrap() as *const dyn std::error::Error as *const ();
        let returned = refused.capture_before_path_spawn().unwrap_err();
        assert_eq!(
            refused.failure_for_returned_v4(&returned).unwrap() as *const dyn std::error::Error
                as *const (),
            saved
        );
    }

    #[test]
    fn actual_native_count_refusal_keeps_directory_and_partial_census() {
        let executable = std::env::current_exe().unwrap();
        let result = std::process::Command::new(executable)
            .args([
                "--exact",
                "process::storage_fork::tests::kernel_case",
                "--nocapture",
            ])
            .env(CASE, "overfull")
            .output()
            .unwrap();

        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn actual_native_positive_census_closes_its_scanner_before_returning() {
        let executable = std::env::current_exe().unwrap();
        let result = std::process::Command::new(executable)
            .args([
                "--exact",
                "process::storage_fork::tests::kernel_case",
                "--nocapture",
            ])
            .env(CASE, "positive")
            .output()
            .unwrap();

        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn actual_inherited_limit_difference_refuses_without_mutating_the_limit() {
        let executable = std::env::current_exe().unwrap();
        let result = std::process::Command::new(executable)
            .args([
                "--exact",
                "process::storage_fork::tests::kernel_case",
                "--nocapture",
            ])
            .env(CASE, "limits")
            .output()
            .unwrap();

        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn no_work_child() {}

    #[test]
    fn kernel_case() {
        let Some(case) = std::env::var_os(CASE) else {
            return;
        };
        // This runs only in a separate current-test executable. The parent's
        // process-wide native limits and concurrent tests are untouched.
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(if case == "limits" { 127 } else { 128 }),
                maximum: Some(128),
            },
        )
        .unwrap();
        let mut files = Vec::new();
        if case == "overfull" {
            for _ in 0..40 {
                files.push(std::fs::File::open("/dev/null").unwrap());
            }
        }
        let executable = std::env::current_exe().unwrap();
        let arguments = [
            "--exact".into(),
            "process::storage_fork::tests::no_work_child".into(),
            "--nocapture".into(),
        ];
        let request = crate::process::FixedProcessRequest {
            executable: &executable,
            arguments: &arguments,
            timeout: std::time::Duration::from_secs(2),
            maximum_stdout_bytes: 4096,
            maximum_stderr_bytes: 4096,
        };
        let invocation = crate::process::PreparedInvocation::new(request).unwrap();
        let mut observation = StorageWorkerForkObservationV1::new();
        // Like the existing native process fixtures, this enters the private
        // shared spawn body directly. Libtest itself has a waiting harness
        // thread; this fixture does not claim public single-thread admission.
        let result = invocation
            .spawn_internal(
                None,
                &[],
                crate::process::SpawnExecution::Path,
                Some(&mut observation),
            )
            .and_then(|spawned| crate::process::supervise(spawned, request));

        if case == "limits" {
            assert!(result.is_err());
            assert!(matches!(observation.0.first, Some(First::Limits)));
            assert!(matches!(
                observation.0.limits.as_ref(),
                Some(Ok(rustix::process::Rlimit {
                    current: Some(127),
                    maximum: Some(128)
                },))
            ));
            assert!(observation.0.directory.is_none());
            assert_eq!(
                crate::process::observe_nofile_limit_v1().unwrap().current,
                Some(127)
            );
        } else if case == "overfull" {
            assert!(result.is_err());
            assert!(matches!(observation.0.first, Some(First::Count)));
            assert_eq!(observation.0.numbers[0].len(), STORAGE_MAXIMUM_TABLE + 1);
            assert!(!observation.0.scanner_disposed);
            let directory = observation.0.directory.as_ref().unwrap().as_ref().unwrap();
            assert!(rustix::fs::fstat(directory.as_fd()).is_ok());
            let first = observation.failure().unwrap() as *const dyn std::error::Error as *const ();
            drop(files);
            assert!(observation.capture_before_path_spawn().is_err());
            assert_eq!(
                observation.failure().unwrap() as *const dyn std::error::Error as *const (),
                first
            );
        } else {
            let crate::process::FixedProcessOutcome::Completed(output) = result.unwrap() else {
                panic!("native fixed child did not complete");
            };
            assert_eq!(output.exit_code, Some(0), "{:?}", output.stderr);
            assert!(observation.0.directory.is_none());
            assert!(observation.0.scanner_disposed);
            assert_eq!(observation.0.numbers[0], observation.0.numbers[1]);
            assert!(observation.0.numbers[0].len() <= STORAGE_MAXIMUM_TABLE);
            assert!(observation.failure().is_none());
            assert!(observation.capture_before_path_spawn().is_err());
        }
    }
}
