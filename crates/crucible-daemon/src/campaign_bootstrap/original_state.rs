//! Opens the fixed campaign state under the actor's existing original budget.
//!
//! Every path and identity allocation is admitted before construction. Kernel
//! results are stored before the original postcut; a late refusal retains the
//! actual root, lock, files and their external credit. This owns only the state
//! stage of the genuine campaign service, before graph and repository creation.

use std::ffi::OsString;

use crucible::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeDescriptorLoan, DecodeScratch,
};

use super::*;

const STATE_ROOT: &str = "/var/lib/crucible/measurement";

/// Holds a prepared or uncertain state stage outside the funded repository.
pub(crate) struct OriginalCampaignStateBootstrap {
    physical_closed: bool,
    shared: Option<Arc<OriginalStatePins>>,
    shared_control: Option<DecodeScratch>,
    transfer_identity: Option<String>,
    root: Option<File>,
    lock: Option<File>,
    identity: Option<File>,
    staging: Option<File>,
    paths: Option<StatePaths>,
    descriptors: Option<DecodeDescriptorLoan>,
    temporary_descriptors: Option<DecodeDescriptorLoan>,
    budget: Option<DecodeBudget>,
    custody: Option<DecodeCustody>,
}

struct StatePaths {
    root: PathBuf,
    lock: PathBuf,
    identity: PathBuf,
    staging: PathBuf,
}

/// Keeps actual state work and its separate original postcut intact.
#[derive(Debug, thiserror::Error)]
#[error("original campaign state {operation} refused: {source}; original: {original_after:?}")]
pub struct OriginalCampaignStateError {
    operation: StateBoundary,
    #[source]
    source: StateCause,
    original_after: Option<DecodeAdmissionError>,
}

#[derive(Clone, Copy, Debug)]
enum StateBoundary {
    Prepare,
    Close,
    Unlock,
}

impl std::fmt::Display for StateBoundary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Prepare => "prepare-state",
            Self::Close => "close-state",
            Self::Unlock => "unlock-state",
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum StateCause {
    #[error("original state credit refused: {0}")]
    Original(#[from] DecodeAdmissionError),
    #[error("original actor state custody refused: {0}")]
    Actor(#[source] crucible_qemu::OriginalActorAccountError),
    #[error("state kernel operation refused: {0}")]
    Io(#[from] io::Error),
    #[error("state kernel operation refused: {source}; immediate original: {original_after:?}")]
    Kernel {
        #[source]
        source: io::Error,
        original_after: Option<DecodeAdmissionError>,
    },
    #[error("state allocation refused: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("state ownership, mode or identity is invalid")]
    Identity,
    #[error("the genuine service or registry still retains state aliases")]
    Aliases,
    #[error("another campaign service holds the state lock; original: {original_after:?}")]
    InUse {
        original_after: Option<DecodeAdmissionError>,
    },
}

impl OriginalCampaignStateBootstrap {
    pub(crate) fn prepare(
        owner: &crucible_qemu::OriginalActorDecodeOwner,
    ) -> Result<Self, OriginalCampaignStateError> {
        let budget = owner
            .budget()
            .map_err(|source| OriginalCampaignStateError {
                operation: StateBoundary::Prepare,
                source: StateCause::Actor(source),
                original_after: None,
            })?;
        Self::prepare_at(Path::new(STATE_ROOT), 0, 0, budget)
    }

    #[cfg(test)]
    pub(super) fn fixture_at(
        root: &Path,
        budget: &DecodeBudget,
    ) -> Result<Self, OriginalCampaignStateError> {
        use rustix::process::{getgid, getuid};
        Self::prepare_at(root, getuid().as_raw(), getgid().as_raw(), budget)
    }

    fn prepare_at(
        root_path: &Path,
        user_id: u32,
        group_id: u32,
        budget: &DecodeBudget,
    ) -> Result<Self, OriginalCampaignStateError> {
        original(budget, StateBoundary::Prepare)?;
        let mut owner = Self {
            physical_closed: false,
            shared: None,
            shared_control: None,
            transfer_identity: None,
            root: None,
            lock: None,
            identity: None,
            staging: None,
            paths: None,
            descriptors: None,
            temporary_descriptors: None,
            budget: Some(budget.clone()),
            custody: Some(budget.custody()),
        };
        let work = (|| {
            // These are the actual four separately live path buffers. The
            // error carrier stores static operations and raw io::Error, so
            // failures create no additional formatted or cloned path buffer.
            owner.paths = Some(StatePaths {
                root: admitted_path(root_path, None, budget)?,
                lock: admitted_path(root_path, Some(STATE_LOCK_FILE), budget)?,
                identity: admitted_path(root_path, Some(STATE_IDENTITY_FILE), budget)?,
                staging: admitted_path(root_path, Some(STATE_IDENTITY_STAGING_FILE), budget)?,
            });
            owner.descriptors = Some(budget.reserve_descriptors(2)?);
            // Identity/staging plus directory sync can overlap while the
            // retained root and lock remain open. Randomness closes before
            // staging birth; all transient opens share these two paid slots.
            owner.temporary_descriptors = Some(budget.reserve_descriptors(2)?);
            owner.open_state(user_id, group_id, budget)
        })();
        reconcile(budget, StateBoundary::Prepare, work)?;
        Ok(owner)
    }

    fn open_state(
        &mut self,
        user_id: u32,
        group_id: u32,
        budget: &DecodeBudget,
    ) -> Result<(), StateCause> {
        let paths = self.paths.as_ref().ok_or(StateCause::Identity)?;
        let metadata = effect(budget, || fs::symlink_metadata(&paths.root))?;
        validate_state_root(&metadata, user_id, group_id).map_err(|()| StateCause::Identity)?;

        budget.verify_live()?;
        self.root = Some(open_file(
            &paths.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        budget.verify_live()?;
        let root = self.root.as_ref().ok_or(StateCause::Identity)?;
        require_identity(root, &metadata, budget)?;

        budget.verify_live()?;
        self.lock = Some(open_file(
            &paths.lock,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?);
        budget.verify_live()?;
        let lock = self.lock.as_ref().ok_or(StateCause::Identity)?;
        let lock_metadata = effect(budget, || lock.metadata())?;
        if !lock_metadata.is_file()
            || lock_metadata.uid() != user_id
            || lock_metadata.gid() != group_id
        {
            return Err(StateCause::Identity);
        }
        effect(budget, || {
            rustix::fs::fchmod(lock, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)
        })?;
        if effect(budget, || lock.metadata())?.mode() & 0o777 != 0o600 {
            return Err(StateCause::Identity);
        }
        budget.verify_live()?;
        let locked = flock(lock, FlockOperation::NonBlockingLockExclusive);
        let after = budget.verify_live();
        match locked {
            Ok(()) => after?,
            Err(source) => {
                return Err(if source == rustix::io::Errno::WOULDBLOCK {
                    StateCause::InUse {
                        original_after: after.err(),
                    }
                } else {
                    StateCause::Kernel {
                        source: io::Error::from(source),
                        original_after: after.err(),
                    }
                });
            }
        }
        require_path(root, &metadata, &paths.root, user_id, group_id, budget)?;

        let transfer_identity = self.load_identity(user_id, group_id, budget)?;
        let paths = self.paths.as_ref().ok_or(StateCause::Identity)?;
        let root = self.root.as_ref().ok_or(StateCause::Identity)?;
        require_path(root, &metadata, &paths.root, user_id, group_id, budget)?;
        effect(budget, || root.sync_all())?;

        self.transfer_identity = Some(transfer_identity);
        Ok(())
    }

    fn load_identity(
        &mut self,
        user_id: u32,
        group_id: u32,
        budget: &DecodeBudget,
    ) -> Result<String, StateCause> {
        let paths = self.paths.as_ref().ok_or(StateCause::Identity)?;
        budget.verify_live()?;
        let opened = open_file(
            &paths.identity,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        );
        match opened {
            Ok(file) => {
                self.identity = Some(file);
                budget.verify_live()?;
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                budget.verify_live()?;
                self.create_identity(user_id, group_id, budget)?;
            }
            Err(source) => return Err(source.into()),
        }
        let file = self.identity.as_mut().ok_or(StateCause::Identity)?;
        let metadata = effect(budget, || file.metadata())?;
        if !metadata.is_file()
            || metadata.uid() != user_id
            || metadata.gid() != group_id
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != STATE_IDENTITY_BYTES as u64
        {
            return Err(StateCause::Identity);
        }
        let mut bytes = [0_u8; STATE_IDENTITY_BYTES];
        effect(budget, || file.read_exact(&mut bytes))?;
        if &bytes[..STATE_IDENTITY_MAGIC.len()] != STATE_IDENTITY_MAGIC {
            return Err(StateCause::Identity);
        }
        let payload_end = STATE_IDENTITY_MAGIC.len() + 32;
        let expected =
            CampaignHash::derive("crucible.campaign.state-identity.v1", &bytes[..payload_end]);
        if bytes[payload_end..] != expected.as_bytes()[..] {
            return Err(StateCause::Identity);
        }
        budget.charge_bytes(64)?;
        Ok(CampaignHash::derive(
            "crucible.campaign.transfer-endpoint.v1",
            &bytes[STATE_IDENTITY_MAGIC.len()..payload_end],
        )
        .to_hex())
    }

    fn create_identity(
        &mut self,
        user_id: u32,
        group_id: u32,
        budget: &DecodeBudget,
    ) -> Result<(), StateCause> {
        let paths = self.paths.as_ref().ok_or(StateCause::Identity)?;
        match effect(budget, || fs::symlink_metadata(&paths.staging)) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.uid() != user_id
                    || metadata.gid() != group_id
                    || metadata.mode() & 0o777 != 0o600
                {
                    return Err(StateCause::Identity);
                }
                effect(budget, || fs::remove_file(&paths.staging))?;
            }
            Err(StateCause::Kernel {
                source,
                original_after: None,
            }) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(source),
        }
        let mut instance = [0_u8; 32];
        effect(budget, || {
            File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut instance))
        })?;
        let mut bytes = [0_u8; STATE_IDENTITY_BYTES];
        bytes[..STATE_IDENTITY_MAGIC.len()].copy_from_slice(STATE_IDENTITY_MAGIC);
        let payload_end = STATE_IDENTITY_MAGIC.len() + 32;
        bytes[STATE_IDENTITY_MAGIC.len()..payload_end].copy_from_slice(&instance);
        let checksum =
            CampaignHash::derive("crucible.campaign.state-identity.v1", &bytes[..payload_end]);
        bytes[payload_end..].copy_from_slice(&checksum.as_bytes());

        budget.verify_live()?;
        self.staging = Some(open_file(
            &paths.staging,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?);
        budget.verify_live()?;
        let file = self.staging.as_mut().ok_or(StateCause::Identity)?;
        effect(budget, || file.write_all(&bytes))?;
        effect(budget, || file.sync_all())?;
        effect(budget, || {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &paths.staging,
                rustix::fs::CWD,
                &paths.identity,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(io::Error::from)
        })?;
        let root = self.root.as_ref().ok_or(StateCause::Identity)?;
        effect(budget, || root.sync_all())?;
        effect(budget, || file.rewind())?;
        self.identity = self.staging.take();
        Ok(())
    }

    /// Shares the same physical state with service owners without moving credit.
    pub(crate) fn share_for_service(
        &mut self,
    ) -> Result<OriginalCampaignStateHandle, OriginalCampaignStateError> {
        let budget = self.budget.as_ref().ok_or_else(state_identity_error)?;
        original(budget, StateBoundary::Prepare)?;
        if self.shared.is_none() {
            if self.root.is_none()
                || self.lock.is_none()
                || self.paths.is_none()
                || self.transfer_identity.is_none()
            {
                return Err(state_identity_error());
            }
            let (layout, _) = std::alloc::Layout::new::<(usize, usize)>()
                .extend(std::alloc::Layout::new::<OriginalStatePins>())
                .map_err(|_| state_identity_error())?;
            self.shared_control = Some(
                budget
                    .reserve_scratch_bytes(layout.pad_to_align().size() as u64)
                    .map_err(|source| OriginalCampaignStateError {
                        operation: StateBoundary::Prepare,
                        source: StateCause::Original(source),
                        original_after: None,
                    })?,
            );
            // All validation and payment precede the move. No fallible work
            // separates taking actual files from publication in this owner.
            self.shared = Some(Arc::new(OriginalStatePins {
                root: self.root.take(),
                lock: self.lock.take(),
                identity: self.identity.take(),
                staging: self.staging.take(),
                paths: self.paths.take(),
                transfer_identity: self.transfer_identity.take(),
            }));
        }
        original(budget, StateBoundary::Prepare)?;
        let pins = self.shared.as_ref().ok_or_else(state_identity_error)?;
        let handle = OriginalCampaignStateHandle {
            pins: Arc::clone(pins),
            budget: budget.clone(),
        };
        handle.transfer_identity()?;
        Ok(handle)
    }

    /// Borrows the same validated namespace retained by this state owner.
    ///
    /// The enclosing artifact owner copies this path under its original account;
    /// the state pins and lock remain external through runtime retirement.
    ///
    /// # Errors
    /// Refuses a closed state owner, missing namespace pins or lock, or the
    /// retained original account at either boundary.
    pub(crate) fn run_state_root(&self) -> Result<&Path, OriginalCampaignStateError> {
        let budget = self.budget.as_ref().ok_or_else(state_identity_error)?;
        original(budget, StateBoundary::Prepare)?;
        if self.physical_closed {
            return Err(state_identity_error());
        }
        let (root, lock, paths) = match self.shared.as_ref() {
            Some(pins) => (&pins.root, &pins.lock, &pins.paths),
            None => (&self.root, &self.lock, &self.paths),
        };
        if root.is_none() || lock.is_none() {
            return Err(state_identity_error());
        }
        let paths = paths.as_ref().ok_or_else(state_identity_error)?;
        original(budget, StateBoundary::Prepare)?;
        Ok(&paths.root)
    }

    /// Closes only this genuine state stage after its users have gone.
    /// A refused original or uncertain unlock retains all still-live custody.
    pub(crate) fn try_close(mut self) -> Result<(), OriginalCampaignStateError> {
        let budget = self
            .budget
            .as_ref()
            .ok_or_else(|| OriginalCampaignStateError {
                operation: StateBoundary::Close,
                source: StateCause::Identity,
                original_after: None,
            })?;
        budget
            .check()
            .map_err(|source| OriginalCampaignStateError {
                operation: StateBoundary::Close,
                source: StateCause::Original(source),
                original_after: None,
            })?;
        original(budget, StateBoundary::Close)?;
        if let Some(shared) = self.shared.as_mut() {
            let pins = Arc::get_mut(shared).ok_or_else(|| OriginalCampaignStateError {
                operation: StateBoundary::Close,
                source: StateCause::Aliases,
                original_after: None,
            })?;
            if let Some(lock) = pins.lock.as_ref() {
                reconcile(
                    budget,
                    StateBoundary::Unlock,
                    flock(lock, FlockOperation::Unlock)
                        .map_err(|source| StateCause::Io(io::Error::from(source))),
                )?;
            }
            drop(pins.identity.take());
            drop(pins.staging.take());
            drop(pins.lock.take());
            drop(pins.root.take());
            // get_mut proved both strong and Weak exclusivity. No handle
            // escapes between that gate and freeing this same Arc control.
            drop(self.shared.take());
        }
        if let Some(lock) = self.lock.as_ref() {
            reconcile(
                budget,
                StateBoundary::Unlock,
                flock(lock, FlockOperation::Unlock)
                    .map_err(|source| StateCause::Io(io::Error::from(source))),
            )?;
        }
        drop(self.identity.take());
        drop(self.staging.take());
        drop(self.lock.take());
        drop(self.root.take());
        self.physical_closed = true;
        original(budget, StateBoundary::Close)?;
        drop(self.shared_control.take());
        drop(self.transfer_identity.take());
        drop(self.paths.take());
        drop(self.temporary_descriptors.take());
        drop(self.descriptors.take());
        drop(self.custody.take());
        drop(self.budget.take());
        Ok(())
    }
}

impl Drop for OriginalCampaignStateBootstrap {
    fn drop(&mut self) {
        if self.physical_closed
            || self.shared.is_some()
            || self.root.is_some()
            || self.lock.is_some()
            || self.identity.is_some()
            || self.staging.is_some()
        {
            // An error or unwind cannot unlock a namespace and refund its
            // loans while the genuine service's physical closure is unknown.
            std::mem::forget(self.shared.take());
            std::mem::forget(self.shared_control.take());
            std::mem::forget(self.transfer_identity.take());
            std::mem::forget(self.root.take());
            std::mem::forget(self.lock.take());
            std::mem::forget(self.identity.take());
            std::mem::forget(self.staging.take());
            std::mem::forget(self.paths.take());
            std::mem::forget(self.descriptors.take());
            std::mem::forget(self.temporary_descriptors.take());
            std::mem::forget(self.custody.take());
            std::mem::forget(self.budget.take());
        }
    }
}

fn admitted_path(
    root: &Path,
    child: Option<&str>,
    budget: &DecodeBudget,
) -> Result<PathBuf, StateCause> {
    let length = root
        .as_os_str()
        .len()
        .checked_add(child.map_or(0, |child| 1 + child.len()))
        .ok_or(StateCause::Identity)?;
    budget.charge_bytes(length as u64)?;
    let mut path = OsString::new();
    path.try_reserve_exact(length)?;
    path.push(root.as_os_str());
    if let Some(child) = child {
        path.push("/");
        path.push(child);
    }
    Ok(path.into())
}

fn open_file(path: &Path, flags: OFlags, mode: Mode) -> Result<File, io::Error> {
    rustix::fs::open(path, flags, mode)
        .map(File::from)
        .map_err(io::Error::from)
}

fn effect<T>(budget: &DecodeBudget, work: impl FnOnce() -> io::Result<T>) -> Result<T, StateCause> {
    budget.verify_live()?;
    let result = work();
    let after = budget.verify_live();
    match result {
        Ok(value) => {
            after?;
            Ok(value)
        }
        Err(source) => Err(StateCause::Kernel {
            source,
            original_after: after.err(),
        }),
    }
}

fn validate_state_root(metadata: &fs::Metadata, user: u32, group: u32) -> Result<(), ()> {
    validate_secure_directory(metadata, user, group)?;
    if metadata.mode() & 0o777 != 0o700 {
        return Err(());
    }
    Ok(())
}

fn require_identity(
    file: &File,
    expected: &fs::Metadata,
    budget: &DecodeBudget,
) -> Result<(), StateCause> {
    let observed = effect(budget, || file.metadata())?;
    if observed.dev() != expected.dev() || observed.ino() != expected.ino() {
        return Err(StateCause::Identity);
    }
    Ok(())
}

fn require_path(
    file: &File,
    expected: &fs::Metadata,
    path: &Path,
    user: u32,
    group: u32,
    budget: &DecodeBudget,
) -> Result<(), StateCause> {
    require_identity(file, expected, budget)?;
    let observed = effect(budget, || fs::symlink_metadata(path))?;
    validate_state_root(&observed, user, group).map_err(|()| StateCause::Identity)?;
    if observed.dev() != expected.dev() || observed.ino() != expected.ino() {
        return Err(StateCause::Identity);
    }
    Ok(())
}

fn original(
    budget: &DecodeBudget,
    operation: StateBoundary,
) -> Result<(), OriginalCampaignStateError> {
    budget
        .verify_live()
        .map_err(|source| OriginalCampaignStateError {
            operation,
            source: source.into(),
            original_after: None,
        })
}

fn reconcile<T>(
    budget: &DecodeBudget,
    operation: StateBoundary,
    work: Result<T, StateCause>,
) -> Result<T, OriginalCampaignStateError> {
    let after = budget.verify_live();
    match (work, after) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(source), after) => Err(OriginalCampaignStateError {
            operation,
            source,
            original_after: after.err(),
        }),
        (Ok(_), Err(source)) => Err(OriginalCampaignStateError {
            operation,
            source: source.into(),
            original_after: None,
        }),
    }
}

#[cfg(test)]
mod tests;

/// Moves the genuine state pins, while all original loans remain external.
struct OriginalStatePins {
    root: Option<File>,
    lock: Option<File>,
    identity: Option<File>,
    staging: Option<File>,
    paths: Option<StatePaths>,
    transfer_identity: Option<String>,
}

/// Keeps the same namespace locked for a prepared service or runtime registry.
///
/// This handle contains no loan. Its external bootstrap must survive every
/// service/registry handle and Weak control, including uncertain shutdown.
pub(crate) struct OriginalCampaignStateHandle {
    pins: Arc<OriginalStatePins>,
    budget: DecodeBudget,
}

impl OriginalCampaignStateHandle {
    fn transfer_identity(&self) -> Result<&str, OriginalCampaignStateError> {
        original(&self.budget, StateBoundary::Prepare)?;
        self.pins
            .transfer_identity
            .as_deref()
            .ok_or_else(state_identity_error)
    }

    fn debug_session_inventory_path(&self) -> Result<PathBuf, OriginalCampaignStateError> {
        let paths = self.pins.paths.as_ref().ok_or_else(state_identity_error)?;
        original(&self.budget, StateBoundary::Prepare)?;
        let result = admitted_path(&paths.root, Some("debug-sessions.v1"), &self.budget);
        reconcile(&self.budget, StateBoundary::Prepare, result)
    }
}

/// Retains either ordinary state or the same externally funded original pins.
/// This enum exists only in the private feature; the default field is unchanged.
pub(crate) struct PreparedCampaignStateOwner(StateOwnerKind);

enum StateOwnerKind {
    Ordinary(CampaignStateOwner),
    Original(OriginalCampaignStateHandle),
}

impl From<CampaignStateOwner> for PreparedCampaignStateOwner {
    fn from(state: CampaignStateOwner) -> Self {
        Self(StateOwnerKind::Ordinary(state))
    }
}

impl From<OriginalCampaignStateHandle> for PreparedCampaignStateOwner {
    fn from(state: OriginalCampaignStateHandle) -> Self {
        Self(StateOwnerKind::Original(state))
    }
}

impl PreparedCampaignStateOwner {
    pub(super) fn transfer_identity(&self) -> Result<&str, CampaignLocalServiceError> {
        match &self.0 {
            StateOwnerKind::Ordinary(state) => Ok(state.transfer_identity()),
            StateOwnerKind::Original(state) => state
                .transfer_identity()
                .map_err(CampaignLocalServiceError::OriginalState),
        }
    }

    pub(super) fn debug_session_inventory_path(
        &self,
    ) -> Result<PathBuf, CampaignLocalServiceError> {
        match &self.0 {
            StateOwnerKind::Ordinary(state) => Ok(state.debug_session_inventory_path()),
            StateOwnerKind::Original(state) => state
                .debug_session_inventory_path()
                .map_err(CampaignLocalServiceError::OriginalState),
        }
    }
}

fn state_identity_error() -> OriginalCampaignStateError {
    OriginalCampaignStateError {
        operation: StateBoundary::Prepare,
        source: StateCause::Identity,
        original_after: None,
    }
}
