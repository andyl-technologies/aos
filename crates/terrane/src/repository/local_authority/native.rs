//! Translates protected administrative records into checked native guard contexts.
//!
//! Raw records supply candidate fields only. Each guard factory independently
//! rereads protected bytes under backend then configuration exclusion before
//! installing a context. Historical baselines are never recreated on reopen.

use std::collections::BTreeMap;

use crate::{
    bucket::{BucketBinding, FileBucket},
    domain::DomainNamespace,
    guard::{AssociationView, BootstrapView, Guard, OriginalAuthority, RegistrationView},
    ref_advance::{Coordinator, PreparedAdvance, WriterSession},
    repository::Repository,
    store::{
        CapabilityReport, Clock, ContentValidator, LocalFs, RefCapability, Store, StoreErrorKind,
        StoreFailure,
    },
};

use super::{
    Error,
    retention::{self, BootstrapRecord, CommitAssociation, Record, RegistrationRecord},
    validate_ancestors, validate_private_directory,
};

/// Keeps the factory-checked physical association and trusted new-epoch configuration.
pub(crate) struct NativeRetention {
    /// Opaque association independently checked against the actual backend.
    pub(crate) authority: OriginalAuthority,
    /// Operator-configured owner already validated by the local factory.
    pub(crate) owner_uid: u32,
    /// Trusted administrative bootstrap ACL for genuinely new authoring epochs.
    pub(crate) authoring_acl: Vec<(String, u8)>,
}

impl<F, B, V, C> Repository<FileBucket<F, B, V>, C, F>
where
    F: LocalFs + BucketBinding + Sync + 'static,
    B: Clock + BucketBinding + Sync + 'static,
    V: ContentValidator + BucketBinding + Sync + 'static,
    C: Clock + Sync,
{
    /// Initializes protected retention for an explicitly configured native authority.
    ///
    /// The caller supplies the actual opened coordinator and a private sibling
    /// control directory. Existing registrations are refused; no history or
    /// signing authority is inferred from bucket contents or configuration labels.
    ///
    /// # Errors
    /// Rejects read-only capabilities before effects, another namespace or storage
    /// domain, insecure physical state, existing registration, failed durability
    /// and unavailable native verification.
    pub(crate) async fn initialize_native_retention(
        coordinator: Coordinator<FileBucket<F, B, V>, C, F>,
        namespace: &DomainNamespace,
        control: &std::path::Path,
        owner_uid: u32,
    ) -> Result<Self, Error> {
        let guard = coordinator.guard();
        if guard.store().capabilities().refs != RefCapability::Cas {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly).into());
        }
        if namespace.root != guard.store().root()
            || namespace.domain != guard.config().storage_domain
        {
            return Err(Error::Denied);
        }
        let registration = retention::initialize_registration(
            guard.store().fs(),
            guard.store().root(),
            &namespace.domain,
            control,
            owner_uid,
        )
        .await?;
        let authority = guard
            .bind_original_authority(namespace, control, registration.view())
            .await?;
        Self::from_native_authority(coordinator, authority, owner_uid).await
    }

    /// Reopens existing protected retention without constructing missing history.
    ///
    /// # Errors
    /// Rejects absent or unsafe registration, inconsistent namespace bindings,
    /// missing or conflicting historical evidence and unavailable native verification.
    pub(crate) async fn reopen_native_retention(
        coordinator: Coordinator<FileBucket<F, B, V>, C, F>,
        namespace: &DomainNamespace,
        control: &std::path::Path,
        owner_uid: u32,
    ) -> Result<Self, Error> {
        let guard = coordinator.guard();
        let registration: RegistrationRecord =
            retention::read(guard.store().fs(), control, owner_uid, "registration.cbor").await?;
        let authority = guard
            .bind_original_authority(namespace, control, registration.view())
            .await?;
        Self::from_native_authority(coordinator, authority, owner_uid).await
    }

    /// Binds checked physical authority to the coordinator's exact native backend.
    ///
    /// The sealed verifier freshly checks the opaque association. Only trusted
    /// new-epoch configuration supplies authoring policy; existing retained
    /// historical baselines and commit associations are loaded without repair.
    ///
    /// # Errors
    /// Rejects changed physical bindings, unsafe protected files, inconsistent or
    /// unsupported retained evidence and unavailable native verification.
    pub(crate) async fn from_native_authority(
        coordinator: Coordinator<FileBucket<F, B, V>, C, F>,
        authority: OriginalAuthority,
        owner_uid: u32,
    ) -> Result<Self, Error> {
        let guard = coordinator.guard();
        guard.install_original_verifier(&authority).await?;
        let retention = NativeRetention {
            authority,
            owner_uid,
            authoring_acl: guard.config().initial_acl.clone(),
        };
        retention.load(guard).await?;
        let root = guard.store().root().to_path_buf();

        let mut repository = Self::new(coordinator);
        repository.local_retention = Some(retention);
        repository.local_backend_root = Some(root);
        Ok(repository)
    }
}

impl RegistrationRecord {
    /// Borrows untrusted primitives for independent native physical validation.
    pub(crate) fn view(&self) -> RegistrationView<'_> {
        RegistrationView {
            id: &self.id,
            root: &self.root,
            domain: &self.domain,
            root_identity: (self.root_device, self.root_inode),
            coordination_identity: (self.coordination_device, self.coordination_inode),
            control: &self.control,
        }
    }
}

impl BootstrapRecord {
    /// Borrows untrusted policy fields for exact protected-byte validation.
    pub(crate) fn view(&self) -> BootstrapView<'_> {
        BootstrapView {
            id: &self.id,
            reference: &self.reference,
            epoch: self.epoch,
            acl: &self.acl,
        }
    }
}

impl CommitAssociation {
    /// Borrows untrusted association fields without establishing original authority.
    pub(crate) fn view(&self) -> AssociationView<'_> {
        AssociationView {
            commit: &self.commit,
            id: &self.id,
            reference: &self.reference,
            epoch: self.epoch,
        }
    }
}

impl NativeRetention {
    /// Retains the configured baseline for the session's exact allocated epoch.
    ///
    /// # Errors
    /// Rejects changed physical authority, conflicting protected policy, unsafe
    /// control state and failed durable retention or independent native checks.
    pub(crate) async fn retain_baseline<S: Store, C, F: LocalFs + Sync>(
        &self,
        guard: &Guard<S, C>,
        fs: &F,
        session: &WriterSession,
    ) -> Result<(), Error> {
        let record = BootstrapRecord {
            id: *self.authority.id(),
            reference: session.reference().to_owned(),
            epoch: session.epoch(),
            acl: self.authoring_acl.clone(),
        };
        self.retain(fs, &record).await?;
        guard.check_original_bootstrap(record.view()).await?;
        Ok(())
    }

    /// Retains the exact signed candidate and independently checks its association.
    ///
    /// # Errors
    /// Rejects another physical authority, inconsistent baseline fields,
    /// conflicting retained bytes, failed durability and changed protected state.
    pub(crate) async fn retain_candidate<S: Store, C, F: LocalFs + Sync>(
        &self,
        guard: &Guard<S, C>,
        fs: &F,
        prepared: &PreparedAdvance,
    ) -> Result<crate::guard::OriginalCommitContext, Error> {
        let baseline = prepared.baseline();
        if baseline.authority() != &self.authority {
            return Err(Error::Denied);
        }
        let record = CommitAssociation {
            commit: prepared.commit(),
            id: *self.authority.id(),
            reference: baseline.reference().to_owned(),
            epoch: baseline.epoch(),
        };
        self.retain(fs, &record).await?;
        Ok(guard.check_original_commit(baseline, record.view()).await?)
    }

    async fn retain<F: LocalFs + Sync, R: Record>(&self, fs: &F, record: &R) -> Result<(), Error> {
        let key =
            terrane_core::bucket::BucketKey::parse("CAPABILITIES").map_err(|_| Error::Denied)?;
        let coordination = self.authority.root().join(key.lock_name());
        self.check_physical(fs, &coordination).await?;

        let backend = fs.lock_exclusive(&coordination).await?;
        self.check_physical(fs, &coordination).await?;
        let configuration =
            retention::configuration_lock(fs, self.authority.control(), self.owner_uid, false)
                .await?;
        self.check_physical(fs, &coordination).await?;
        retention::retain(
            fs,
            self.authority.control(),
            self.owner_uid,
            &record.selector()?,
            record,
            false,
        )
        .await?;

        // Independent guard checks acquire the same locks after these are released.
        drop(configuration);
        drop(backend);
        Ok(())
    }

    async fn check_physical<F: LocalFs + Sync>(
        &self,
        fs: &F,
        coordination: &std::path::Path,
    ) -> Result<(), Error> {
        use std::os::unix::fs::MetadataExt;

        validate_ancestors(fs, self.authority.root()).await?;
        validate_private_directory(fs, self.authority.root(), self.owner_uid).await?;
        validate_ancestors(fs, coordination).await?;
        let root = fs.symlink_metadata(self.authority.root()).await?;
        let lock = fs.symlink_metadata(coordination).await?;
        if ((root.dev(), root.ino()), (lock.dev(), lock.ino()))
            != self.authority.physical_identity()
            || !lock.is_file()
            || lock.file_type().is_symlink()
            || lock.uid() != self.owner_uid
            || lock.nlink() != 1
        {
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// Loads exact retained local baselines and immutable commit associations.
    ///
    /// Enumeration reads private administrative configuration, never backend
    /// content inventory. Every selected record is decoded and independently
    /// checked; its filename supplies neither policy nor physical authority.
    ///
    /// # Errors
    /// Rejects missing or inconsistent historical evidence, unsafe files,
    /// unsupported imported evidence, changed physical registration and failed I/O.
    pub(crate) async fn load<F, B, V, C>(
        &self,
        guard: &Guard<FileBucket<F, B, V>, C>,
    ) -> Result<(), Error>
    where
        F: LocalFs + BucketBinding + Sync,
        B: Clock + BucketBinding + Sync,
        V: ContentValidator + BucketBinding + Sync,
        C: Clock + Sync,
    {
        let fs = guard.store().fs();
        let directory = self.authority.control();
        let mut baselines = BTreeMap::new();
        let mut associations = Vec::new();
        for path in fs.read_dir(directory).await? {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(Error::Denied)?;
            if name.starts_with("bootstrap-") {
                let record: BootstrapRecord =
                    retention::read(fs, directory, self.owner_uid, name).await?;
                let checked = guard
                    .bind_original_bootstrap(&self.authority, record.view())
                    .await?;
                guard.install_original_bootstrap(checked.clone()).await?;
                baselines.insert((record.reference, record.epoch), checked);
            } else if name.starts_with("commit-") {
                associations.push(
                    retention::read::<_, CommitAssociation>(fs, directory, self.owner_uid, name)
                        .await?,
                );
            } else if name.ends_with(".cbor") && name != "registration.cbor" && name != "token.cbor"
            {
                // Source retention requires the separate checked import factory.
                return Err(Error::UnavailableOperation("original authority import"));
            }
        }

        for association in associations {
            let key = (association.reference.clone(), association.epoch);
            let baseline = baselines.get(&key).ok_or(Error::Denied)?;
            let checked = guard
                .bind_original_commit(baseline, association.view())
                .await?;
            guard.install_original_commit(checked).await?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "tokio"))]
#[path = "native_tests.rs"]
mod tests;
