//! Shares the same fixed readonly Cache object-view native sampler for F and R.
//!
//! The role fixes every pathname and reuses the existing native root/name
//! observations and exact positional byte reader. Preparation stops at actual
//! metadata; the actual role owner must debit that exact byte/model peak before
//! entering the byte reader. No public path, descriptor, budget or proof can
//! establish role authority from this mechanical native observation.

use std::error::Error;
use std::fs::File;
use std::os::fd::AsFd as _;
use std::path::Path;

mod metadata;
pub use metadata::{RootCacheMetadataReadOriginalV2, RootCacheMetadataReadClosedV2};

use super::{
    CacheLockObservationDataV1, CacheManifestObservationDataV1, CacheRootObservationDataV1,
    PhysicalCacheObservationFailureV1, inspect_lock_v1, inspect_manifest_identity_v1,
    inspect_root_v1, open_readonly_root_v1, reject_legacy_object_root_at_v1,
};
use aos_sandbox_core::{ObjectDigest, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::{
    ProtectedFailure, open_read_only_protected_file_original,
};
use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
use aos_sandbox_linux::signer_mount::{RootReadonlyViewV1, SignerMountReadbackAttemptV1, SignerMountReadbackClosedV1};
use aos_sandbox_protocol::cache_state::physical_manifest::CACHE_PHYSICAL_MANIFEST_MAXIMUM_BYTES_V1;

use aos_sandbox_protocol::cache_state::physical_manifest::view_data::{
    PhysicalManifestDataErrorV1, PhysicalManifestLimitsDataV1, PhysicalManifestSnapshotDataV1,
    decode_actual_manifest_v1,
};
/// Marks only an unavailable or incomplete native object-view comparison.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
#[error("physical Cache object view is incomplete")]
pub struct CacheObjectViewClosedV1;
use CacheObjectViewClosedV1 as Closed;

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

const SIGNER_VIEW: &str = "/run/aos/sandbox-cache-signer-objects";
/// Selects the compiled Root readonly object mount; the unit/profile must provide it.
pub const ROOT_CURRENT_OBJECT_VIEW_V1: &str = "/run/aos/sandbox-root-cache-objects";

#[derive(Clone, Copy)]
enum ViewRecipeV1 { CacheSigner, RootCurrent }

impl ViewRecipeV1 {
    const fn path(self) -> &'static str {
        match self { Self::CacheSigner => SIGNER_VIEW, Self::RootCurrent => ROOT_CURRENT_OBJECT_VIEW_V1 }
    }
}
const SOURCE: &str = "/var/lib/aos/sandbox/cache-residency-objects";
const LEGACY: &str = "/var/lib/aos/sandbox/cache-residency";
const PARENTS: [&str; 6] = [
    "/var",
    "/var/lib",
    "/var/lib/aos",
    "/var/lib/aos/sandbox",
    "/run",
    "/run/aos",
];

/// Preserves the reached native or physical Cache comparison refusal.
#[derive(Debug, thiserror::Error)]
pub enum CacheObjectViewErrorV1 {
    /// Retains the original filesystem I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Retains the original Linux syscall error.
    #[error(transparent)]
    Native(#[from] rustix::io::Errno),
    /// Rejects an unsafe fixed object-view boundary.
    #[error("physical Cache view boundary differs")]
    Boundary,
    /// Rejects changed physical names or identities.
    #[error("physical Cache view changed")]
    Changed,
    /// Rejects an unsupported protected opening.
    #[error("physical Cache readonly opening is unsupported")]
    Unsupported,
    /// Rejects malformed physical manifest metadata.
    #[error("physical Cache manifest metadata is invalid")]
    Manifest,
}

impl ProtectedFailure for CacheObjectViewErrorV1 {
    const BOUNDARY: Self = Self::Boundary;
    const UNSUPPORTED_OPEN: Self = Self::Unsupported;
    const STALE_NAME: Self = Self::Changed;
}

impl PhysicalCacheObservationFailureV1 for CacheObjectViewErrorV1 {
    const ROOT_CHANGED: Self = Self::Changed;
    const INVALID_MANIFEST: Self = Self::Manifest;
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    MetadataRoot,
    LegacyBefore,
    MountBefore,
    Root,
    RootCheck,
    SourceOwner,
    Lock,
    LockCheck,
    ManifestName,
    ManifestOpen,
    ManifestMetadata,
    Extent,
    Read,
    Decode,
    RootAfter,
    LockAfter,
    ManifestAfter,
    Names,
    LegacyAfter,
    MountAfter,
    MountBinding,
}

/// Keeps real native originals; compact DATA alone cannot construct this owner.
pub struct CacheObjectViewOriginalV1 {
    recipe: ViewRecipeV1,
    entered: bool,
    signer_uid: u32,
    source_uid: u32,
    legacy_before: Option<Result<(), CacheObjectViewErrorV1>>,
    mount_before: SignerMountReadbackAttemptV1,
    mount_before_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    root: Option<rustix::io::Result<File>>,
    root_check: Option<Result<CacheRootObservationDataV1, CacheObjectViewErrorV1>>,
    source_owner: Option<Result<(), CacheObjectViewErrorV1>>,
    lock: Option<rustix::io::Result<File>>,
    lock_open: Option<Result<(), CacheObjectViewErrorV1>>,
    lock_check: Option<Result<CacheLockObservationDataV1, CacheObjectViewErrorV1>>,
    manifest_name: Option<Result<Option<CacheManifestObservationDataV1>, CacheObjectViewErrorV1>>,
    manifest: Option<rustix::io::Result<File>>,
    manifest_open: Option<Result<(), CacheObjectViewErrorV1>>,
    manifest_metadata: Option<rustix::io::Result<rustix::fs::Stat>>,
    extent: Option<Result<usize, CacheObjectViewErrorV1>>,
    bytes: FixedRoleCredentialReadV1,
    byte_result: Option<Result<(), Closed>>,
    decoded: Option<Result<PhysicalManifestSnapshotDataV1, PhysicalManifestDataErrorV1>>,
    metadata_catalog: Option<Result<aos_sandbox_protocol::cache_state::physical_manifest::view_data::PhysicalManifestInventoryDataV2, PhysicalManifestDataErrorV1>>,
    metadata_root: aos_sandbox_linux::path::BeneathRootOpenOriginalV2,
    metadata_root_result: Option<Result<(), aos_sandbox_linux::Error>>,
    root_after: Option<Result<CacheRootObservationDataV1, CacheObjectViewErrorV1>>,
    lock_after: Option<Result<CacheLockObservationDataV1, CacheObjectViewErrorV1>>,
    manifest_after: Option<Result<Option<CacheManifestObservationDataV1>, CacheObjectViewErrorV1>>,
    names: Option<Result<(), CacheObjectViewErrorV1>>,
    legacy_after: Option<Result<(), CacheObjectViewErrorV1>>,
    mount_after: SignerMountReadbackAttemptV1,
    mount_after_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    mount_binding: Option<Result<(), CacheObjectViewErrorV1>>,
    prepared: bool,
    posts_entered: bool,
    first: Option<First>,
}

impl CacheObjectViewOriginalV1 {
    /// Creates inert native destinations for the unchanged fixed Cache F view.
    pub fn cache_signer_v1() -> Self { Self::new(ViewRecipeV1::CacheSigner) }

    /// Creates inert native destinations for the separate fixed Root R view.
    pub fn root_current_v1() -> Self { Self::new(ViewRecipeV1::RootCurrent) }

    fn new(recipe: ViewRecipeV1) -> Self {
        Self {
            recipe,
            entered: false,
            signer_uid: 0,
            source_uid: 0,
            legacy_before: None,
            mount_before: SignerMountReadbackAttemptV1::new(),
            mount_before_result: None,
            root: None,
            root_check: None,
            source_owner: None,
            lock: None,
            lock_open: None,
            lock_check: None,
            manifest_name: None,
            manifest: None,
            manifest_open: None,
            manifest_metadata: None,
            extent: None,
            bytes: FixedRoleCredentialReadV1::prearmed(),
            byte_result: None,
            decoded: None,
            metadata_catalog: None,
            metadata_root: aos_sandbox_linux::path::BeneathRootOpenOriginalV2::new(),
            metadata_root_result: None,
            root_after: None,
            lock_after: None,
            manifest_after: None,
            names: None,
            legacy_after: None,
            mount_after: SignerMountReadbackAttemptV1::new(),
            mount_after_result: None,
            mount_binding: None,
            prepared: false,
            posts_entered: false,
            first: None,
        }
    }

    /// Prices one actual prefix, including independently owed local mount posts.
    pub fn fixed_receiving_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                SignerMountReadbackAttemptV1::receiving_memory_bound_v1()?.checked_mul(2)?,
            )?
            .checked_add(4 * (SIGNER_VIEW.len().max(ROOT_CURRENT_OBJECT_VIEW_V1.len()) + 1))?;
        // Root+lock+manifest, one failed positional duplicate and two actual
        // mountinfo originals. Successful duplicate disposal takes no credit.
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, 6),
        )
    }

    /// Captures the fixed mapped root, lock and manifest metadata once.
    ///
    /// The Controller UID is comparison DATA from the actual role profile.
    /// The fixed constructor selects the only path and mapping recipe.
    ///
    /// # Errors
    /// Retains reentry, native errors, unsafe mounts or changed physical names.
    pub fn prepare_once(&mut self, controller_uid: u32) -> Result<(), Closed> {
        if self.entered {
            return self.refuse(First::Entry);
        }
        self.entered = true;
        self.signer_uid = rustix::process::geteuid().as_raw();
        self.source_uid = controller_uid;
        self.legacy_before = Some(reject_legacy_object_root_at_v1(Path::new(LEGACY)));
        if !matches!(self.legacy_before, Some(Ok(()))) {
            return self.refuse(First::LegacyBefore);
        }
        self.mount_before_result = Some(match self.recipe {
            ViewRecipeV1::CacheSigner => self.mount_before.observe_once(
                self.recipe.path(), SOURCE, self.signer_uid, "/run/aos", &PARENTS),
            ViewRecipeV1::RootCurrent => self.mount_before.observe_root_readonly_once(
                RootReadonlyViewV1::CacheObjects, controller_uid,
                rustix::process::getegid().as_raw(), None),
        });
        if !matches!(self.mount_before_result, Some(Ok(()))) {
            return self.refuse(First::MountBefore);
        }
        self.root = Some(open_readonly_root_v1(self.recipe.path()).map(File::from));
        let root = match self.root.as_ref() {
            Some(Ok(root)) => root,
            _ => return self.refuse(First::Root),
        };
        self.root_check = Some(inspect_root_v1(root));
        let root_data = match self.root_check.as_ref() {
            Some(Ok(data)) => *data,
            _ => return self.refuse(First::RootCheck),
        };
        self.source_owner = Some(match self.mount_before.witness() {
            Some(mount)
                if controller_uid != 0
                    && mount.source_uid() == controller_uid
                    && mount.matches_opened_root(root_data.device, root_data.inode) =>
            {
                Ok(())
            }
            _ => Err(CacheObjectViewErrorV1::Changed),
        });
        if !matches!(self.source_owner, Some(Ok(()))) {
            return self.refuse(First::SourceOwner);
        }
        self.lock_open = Some(open_read_only_protected_file_original(
            root,
            ".owner.lock",
            self.signer_uid,
            &mut self.lock,
        ));
        if !matches!(self.lock_open, Some(Ok(()))) {
            return self.refuse(First::Lock);
        }
        let lock = match self.lock.as_ref() {
            Some(Ok(lock)) => lock,
            _ => return self.refuse(First::Lock),
        };
        self.lock_check = Some(inspect_lock_v1(root, lock));
        if !matches!(self.lock_check, Some(Ok(_))) {
            return self.refuse(First::LockCheck);
        }
        self.manifest_name = Some(inspect_manifest_identity_v1(root));
        let named = match self.manifest_name.as_ref() {
            Some(Ok(named)) => *named,
            _ => return self.refuse(First::ManifestName),
        };
        self.manifest_open = Some(open_read_only_protected_file_original(
            root,
            "owner-state",
            self.signer_uid,
            &mut self.manifest,
        ));
        if named.is_none() && matches!(self.manifest, Some(Err(rustix::io::Errno::NOENT))) {
            // Expected absence is an observed native branch, not copied from
            // Held DATA. The raw NOENT and independent name result stay owned.
            self.extent = Some(Ok(0));
            self.prepared = true;
            return Ok(());
        }
        if !matches!(self.manifest_open, Some(Ok(()))) {
            return self.refuse(First::ManifestOpen);
        }
        let file = match self.manifest.as_ref() {
            Some(Ok(file)) => file,
            _ => return self.refuse(First::ManifestOpen),
        };
        self.manifest_metadata = Some(rustix::fs::fstat(file));
        self.extent = Some((|| {
            let stat = self
                .manifest_metadata
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheObjectViewErrorV1::Manifest)?;
            let named = named.ok_or(CacheObjectViewErrorV1::Changed)?;
            if (stat.st_dev, stat.st_ino) != (named.device, named.inode) {
                return Err(CacheObjectViewErrorV1::Changed);
            }
            let bytes =
                usize::try_from(stat.st_size).map_err(|_| CacheObjectViewErrorV1::Manifest)?;
            if bytes > CACHE_PHYSICAL_MANIFEST_MAXIMUM_BYTES_V1 {
                return Err(CacheObjectViewErrorV1::Manifest);
            }
            Ok(bytes)
        })());
        if self.manifest_metadata.as_ref().is_some_and(Result::is_err) {
            return self.refuse(First::ManifestMetadata);
        }
        if !matches!(self.extent, Some(Ok(_))) {
            return self.refuse(First::Extent);
        }
        self.prepared = true;
        Ok(())
    }

    /// Returns the actual prepared manifest extent before byte admission.
    ///
    /// # Errors
    /// Refuses a failed or unentered fixed preparation.
    pub fn prepared_length_v1(&self) -> Result<usize, Closed> {
        if !self.prepared || self.first.is_some() {
            return Err(Closed);
        }
        self.extent
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(Closed)
    }

    /// Enters only after the actual role funds this same prepared extent.
    /// Reads the same prepared extent after the role admits its byte/model peak.
    ///
    /// # Errors
    /// Retains reentry, incomplete preparation, native errors or invalid manifests.
    pub fn read_once(&mut self, limits: PhysicalManifestLimitsDataV1) -> Result<(), Closed> {
        self.read_with_metadata_catalog_once_v2(limits, false)
    }

    /// Retains the actual Root manifest catalog for closed D metadata reads.
    ///
    /// The real enclosing R owner prepays the additional retained map/name peak
    /// and root duplicate before this entry. The same parser reads the same
    /// original bytes once; no descriptor or supplied tuple constructs a catalog.
    ///
    /// # Errors
    /// Retains the original full-view error, catalog rejection or root duplication.
    pub fn read_delete_metadata_catalog_once_v2(&mut self, limits: PhysicalManifestLimitsDataV1)
        -> Result<(), Closed>
    {
        if !matches!(self.recipe, ViewRecipeV1::RootCurrent) {
            return self.refuse(First::Entry);
        }
        self.read_with_metadata_catalog_once_v2(limits, true)?;
        let root = self.root.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Closed)?;
        self.metadata_root_result = Some(self.metadata_root.capture_root_once_v1(root.as_fd()));
        if !matches!(self.metadata_root_result, Some(Ok(()))) {
            return self.refuse(First::MetadataRoot);
        }
        Ok(())
    }

    fn read_with_metadata_catalog_once_v2(&mut self, limits: PhysicalManifestLimitsDataV1,
        retain_catalog: bool,
    ) -> Result<(), Closed> {
        if self.byte_result.is_some() || self.decoded.is_some() || self.posts_entered {
            return self.refuse(First::Entry);
        }
        let length = self.prepared_length_v1()?;
        if matches!(self.manifest_name, Some(Ok(None))) {
            self.decoded = Some(Ok(PhysicalManifestSnapshotDataV1 {
                generation: 0,
                digest: ObjectDigest::from_bytes([0; 32]),
                disk_count: 0,
                negative_count: 0,
                pin_count: 0,
            }));
            return Ok(());
        }
        let file = self
            .manifest
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(Closed)?;
        self.bytes.read_exact_at_once(file.as_fd(), length);
        self.byte_result = Some(match self.bytes.outcome() {
            Some(Ok(Some(_))) => Ok(()),
            _ => Err(Closed),
        });
        if !matches!(self.byte_result, Some(Ok(()))) {
            return self.refuse(First::Read);
        }
        let bytes = self.bytes.outcome().and_then(Result::ok).flatten().ok_or(Closed)?;
        if retain_catalog {
            self.metadata_catalog = Some(aos_sandbox_protocol::cache_state::physical_manifest::view_data::
                decode_actual_manifest_inventory_v2(bytes, limits));
            self.decoded = Some(match self.metadata_catalog.as_ref() {
                Some(Ok(inventory)) => Ok(inventory.snapshot_v2()),
                Some(Err(cause)) => Err(*cause),
                None => return self.refuse(First::Entry),
            });
        } else {
            self.decoded = Some(decode_actual_manifest_v1(bytes, limits));
        }
        if self.decoded.as_ref().is_some_and(Result::is_err) {
            return self.refuse(First::Decode);
        }
        Ok(())
    }

    /// Runs every reached independently owed name/mount post without a body flag.
    /// Performs every independently owed physical name and mount post.
    ///
    /// # Errors
    /// Retains changed names, unsafe mounts, native errors or incomplete reads.
    pub fn finish_native_once(&mut self) -> Result<(), Closed> {
        if !self.entered || self.posts_entered {
            return self.refuse(First::Entry);
        }
        self.posts_entered = true;
        if let Some(Ok(root)) = self.root.as_ref() {
            self.root_after = Some(inspect_root_v1(root));
            if !matches!(self.root_after, Some(Ok(_))) {
                self.first.get_or_insert(First::RootAfter);
            }
            if let Some(Ok(lock)) = self.lock.as_ref() {
                self.lock_after = Some(inspect_lock_v1(root, lock));
                if !matches!(self.lock_after, Some(Ok(_))) {
                    self.first.get_or_insert(First::LockAfter);
                }
            }
            self.manifest_after = Some(inspect_manifest_identity_v1(root));
            if !matches!(self.manifest_after, Some(Ok(_))) {
                self.first.get_or_insert(First::ManifestAfter);
            }
            self.names = Some(
                if matches!((&self.root_check, &self.root_after), (Some(Ok(before)), Some(Ok(after))) if before == after)
                    && matches!((&self.lock_check, &self.lock_after), (Some(Ok(before)), Some(Ok(after))) if before == after)
                    && matches!((&self.manifest_name, &self.manifest_after), (Some(Ok(before)), Some(Ok(after))) if before == after)
                {
                    Ok(())
                } else {
                    Err(CacheObjectViewErrorV1::Changed)
                },
            );
            if !matches!(self.names, Some(Ok(()))) {
                self.first.get_or_insert(First::Names);
            }
        }
        self.legacy_after = Some(reject_legacy_object_root_at_v1(Path::new(LEGACY)));
        if !matches!(self.legacy_after, Some(Ok(()))) {
            self.first.get_or_insert(First::LegacyAfter);
        }
        self.mount_after_result = Some(match self.recipe {
            ViewRecipeV1::CacheSigner => self.mount_after.observe_once(
                self.recipe.path(), SOURCE, self.signer_uid, "/run/aos", &PARENTS),
            ViewRecipeV1::RootCurrent => self.mount_after.observe_root_readonly_once(
                RootReadonlyViewV1::CacheObjects, self.source_uid,
                rustix::process::getegid().as_raw(), None),
        });
        if !matches!(self.mount_after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::MountAfter);
        }
        self.mount_binding = Some(
            match (self.mount_before.witness(), self.mount_after.witness()) {
                (Some(before), Some(after))
                    if before == after && before.source_uid() == self.source_uid =>
                {
                    Ok(())
                }
                _ => Err(CacheObjectViewErrorV1::Changed),
            },
        );
        if !matches!(self.mount_binding, Some(Ok(()))) {
            self.first.get_or_insert(First::MountBinding);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    /// Returns only the completed actual physical snapshot as comparison DATA.
    ///
    /// # Errors
    /// Refuses any uncompleted native read, post or physical comparison.
    pub fn completed_data_v1(&self) -> Result<PhysicalManifestSnapshotDataV1, Closed> {
        if self.first.is_some()
            || !self.posts_entered
            || !matches!(self.names, Some(Ok(())))
            || !matches!(self.mount_binding, Some(Ok(())))
        {
            return Err(Closed);
        }
        self.decoded
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(Closed)
    }

    /// Compares only two fully completed actual native object observations.
    ///
    /// # Errors
    /// Rejects an incomplete/error observation or changed complete native cut.
    /// Projects the complete physical comparison from this same finished view.
    ///
    /// The enclosing role supplies its already-derived limits digest. This is
    /// DATA only and cannot construct physical custody or a read capability.
    ///
    /// # Errors
    /// Refuses an incomplete native view or missing retained original identity.
    pub fn completed_comparison_data_v2(&self, limits: ObjectDigest) -> Result<
        aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1,
        Closed,
    > {
        let snapshot = self.completed_data_v1()?;
        let (root, lock, manifest) = self.observed_identities_v1()?;
        Ok(Self::comparison_from_observations_data_v2(root, lock, manifest,
            self.observed_source_uid_v1()?, snapshot, limits))
    }

    /// Assembles canonical physical comparison DATA from observed parts.
    ///
    /// Calling this pure projection authenticates none of its input fields and
    /// cannot create a native owner, role, physical read or lifecycle grant.
    pub fn comparison_from_observations_data_v2(root: CacheRootObservationDataV1,
        lock: CacheLockObservationDataV1, manifest: Option<CacheManifestObservationDataV1>,
        source_uid: u32, snapshot: PhysicalManifestSnapshotDataV1, limits: ObjectDigest,
    ) -> aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1 {
        aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1 {
            root: (root.device, root.inode), uid: source_uid, mode: root.mode,
            lock: (lock.device, lock.inode),
            manifest: manifest.map_or((0, 0), |value| (value.device, value.inode)),
            generation: snapshot.generation, digest: *snapshot.digest.as_bytes(), limits: *limits.as_bytes(),
        }
    }

    /// Compares two complete physical snapshots and original inode bindings.
    ///
    /// # Errors
    /// Refuses incomplete owners or different snapshot, root, lock or manifest identities.
    pub fn require_same_completed_v1(&self, other: &Self) -> Result<(), Closed> {
        if self.completed_data_v1()? != other.completed_data_v1()?
            || self.observed_identities_v1()? != other.observed_identities_v1()? { return Err(Closed); }
        Ok(())
    }

    /// Returns the completed root, lock and optional manifest identities.
    ///
    /// # Errors
    /// Refuses incomplete physical observation or missing original identities.
    pub fn observed_identities_v1(
        &self,
    ) -> Result<
        (
            CacheRootObservationDataV1,
            CacheLockObservationDataV1,
            Option<CacheManifestObservationDataV1>,
        ),
        Closed,
    > {
        self.completed_data_v1()?;
        Ok((
            *self
                .root_check
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(Closed)?,
            *self
                .lock_check
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(Closed)?,
            *self
                .manifest_name
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(Closed)?,
        ))
    }

    /// Returns the completed original writer UID comparison.
    ///
    /// # Errors
    /// Refuses an incomplete or failed original mount observation.
    pub fn observed_source_uid_v1(&self) -> Result<u32, Closed> {
        self.completed_data_v1()?;
        self.mount_before
            .witness()
            .map(|witness| witness.source_uid())
            .ok_or(Closed)
    }

    /// Borrows the same earliest retained native or physical refusal.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Entry => Some(&Closed),
            First::MetadataRoot => cause(&self.metadata_root_result),
            First::LegacyBefore => cause(&self.legacy_before),
            First::MountBefore => self
                .mount_before
                .failure()
                .or_else(|| cause(&self.mount_before_result)),
            First::Root => cause(&self.root),
            First::RootCheck => cause(&self.root_check),
            First::SourceOwner => cause(&self.source_owner),
            First::Lock => cause(&self.lock).or_else(|| cause(&self.lock_open)),
            First::LockCheck => cause(&self.lock_check),
            First::ManifestName => cause(&self.manifest_name),
            First::ManifestOpen => cause(&self.manifest).or_else(|| cause(&self.manifest_open)),
            First::ManifestMetadata => cause(&self.manifest_metadata),
            First::Extent => cause(&self.extent),
            First::Read => self.bytes.failure().or_else(|| cause(&self.byte_result)),
            First::Decode => cause(&self.decoded),
            First::RootAfter => cause(&self.root_after),
            First::LockAfter => cause(&self.lock_after),
            First::ManifestAfter => cause(&self.manifest_after),
            First::Names => cause(&self.names),
            First::LegacyAfter => cause(&self.legacy_after),
            First::MountAfter => self
                .mount_after
                .failure()
                .or_else(|| cause(&self.mount_after_result)),
            First::MountBinding => cause(&self.mount_binding),
        }
    }

    fn refuse(&mut self, stage: First) -> Result<(), Closed> {
        self.first.get_or_insert(stage);
        Err(Closed)
    }
}
