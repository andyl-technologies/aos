//! Binds retained original authority to protected physical bucket registration.
//!
//! Raw registration fields are untrusted. Binding independently checks their
//! canonical protected bytes while holding backend exclusion before control
//! exclusion. Imported historical associations cannot mint this local binding.
//!
//! The private canonical CBOR records retain their ordered fields:
//!
//! ```text
//! registration = [1, id32, root-bytes, domain, root-dev, root-ino,
//!                 coordination-dev, coordination-ino, control-bytes]
//! bootstrap = [1, id32, original-ref, writer-epoch, [[subject, verbs], ...]]
//! association = [1, commit32, id32, original-ref, writer-epoch]
//! ```

#[cfg(unix)]
mod control;
#[cfg(unix)]
pub(crate) use control::{ControlExclusion, RetainedControls};
mod verifier;
pub(super) use verifier::OriginalVerifier;

use std::path::{Component, Path, PathBuf};

use crate::bucket::held::HeldIdentity;
use crate::bucket::{BucketBinding, FileBucket};
use crate::domain::{DomainNamespace, DomainNamespaces};
use crate::store::{
    CapabilityReport, Clock, ContentValidator, LocalFs, RefCapability, StoreErrorKind, StoreFailure,
};
use terrane_core::{bucket::BucketKey, cbor};

use super::{Guard, invalid};

/// Supplies untrusted decoded registration fields for independent checking.
pub(crate) struct RegistrationView<'a> {
    /// Protected administrative association identifier.
    pub id: &'a [u8; 32],
    /// Registered complete bucket path.
    pub root: &'a Path,
    /// Registered canonical domain.
    pub domain: &'a str,
    /// Actual root device and inode.
    pub root_identity: (u64, u64),
    /// Persistent coordination device and inode.
    pub coordination_identity: (u64, u64),
    /// Protected sibling control directory.
    pub control: &'a Path,
}

/// Retains a checked local physical registration without granting operation rights.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalAuthority {
    id: [u8; 32],
    root: PathBuf,
    domain: String,
    root_identity: (u64, u64),
    coordination_identity: (u64, u64),
    control: PathBuf,
}

impl OriginalAuthority {
    /// Returns the protected association identifier.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Returns the configured physical namespace path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the registered canonical physical domain.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the actual root and coordination identities checked at binding.
    pub fn physical_identity(&self) -> ((u64, u64), (u64, u64)) {
        (self.root_identity, self.coordination_identity)
    }

    /// Returns the protected configuration directory.
    pub fn control(&self) -> &Path {
        &self.control
    }
}

fn io_failure(error: std::io::Error) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
}

fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && !path.as_os_str().as_encoded_bytes().contains(&0)
}

#[cfg(unix)]
fn registration_bytes(view: &RegistrationView<'_>) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 9);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, view.id);
    cbor::write_bytes(&mut bytes, view.root.as_os_str().as_bytes());
    cbor::write_text(&mut bytes, view.domain);
    for value in [
        view.root_identity.0,
        view.root_identity.1,
        view.coordination_identity.0,
        view.coordination_identity.1,
    ] {
        cbor::write_uint(&mut bytes, value);
    }
    cbor::write_bytes(&mut bytes, view.control.as_os_str().as_bytes());
    bytes
}

#[cfg(unix)]
async fn protected_file<F: LocalFs>(
    fs: &F,
    path: &Path,
    owner: u32,
) -> Result<(u64, u64), StoreFailure> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs.symlink_metadata(path).await.map_err(io_failure)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(invalid());
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
impl<F: LocalFs + BucketBinding, B: Clock + BucketBinding, V: ContentValidator + BucketBinding, C>
    Guard<FileBucket<F, B, V>, C>
{
    /// Revalidates a protected registration against this opened physical backend.
    ///
    /// Trusted setup supplies the namespace and sibling control directory. This
    /// snapshot does not authorize a request or attach an original policy resolver.
    /// Protected ancestors and mount configuration remain operator-controlled.
    ///
    /// # Errors
    /// Rejects missing, aliased, replaced, unsafe, or mismatched registration;
    /// preserves filesystem failures without repairing protected configuration.
    pub(crate) async fn bind_original_authority(
        &self,
        namespace: &DomainNamespace,
        control: &Path,
        registration: RegistrationView<'_>,
    ) -> Result<OriginalAuthority, StoreFailure> {
        self.bind_original_records(namespace, control, registration, &[], None, None)
            .await
    }

    /// Retains freshly checked original registration exclusion beneath a held backend.
    ///
    /// # Errors
    /// Refuses a mismatched opened profile, physical registration, protected
    /// control record or namespace, and propagates unavailable existing-state reads.
    pub(crate) async fn hold_original_registration<'a>(
        &'a self,
        authority: &OriginalAuthority,
        held: &HeldIdentity<'_>,
    ) -> Result<ControlExclusion<'a, F>, StoreFailure> {
        let (name, profile) = self.store.publication_profile();
        if name != self.config.chunk_profile_name || profile != self.config.chunk_profile.as_ref() {
            return Err(invalid());
        }
        let namespace = DomainNamespace {
            root: authority.root.clone(),
            domain: authority.domain.clone(),
        };
        let view = RegistrationView {
            id: &authority.id,
            root: &authority.root,
            domain: &authority.domain,
            root_identity: authority.root_identity,
            coordination_identity: authority.coordination_identity,
            control: &authority.control,
        };
        let expected = registration_bytes(&view);
        self.bind_original_records(&namespace, &authority.control, view, &[], Some(held), None)
            .await?;

        let owner = self
            .store
            .publication_operator_uid()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
        let mut control =
            ControlExclusion::acquire(self.store.fs(), &authority.control, owner).await?;
        if control.read_record("registration.cbor").await? != expected {
            return Err(invalid());
        }
        Ok(control)
    }

    async fn bind_original_records(
        &self,
        namespace: &DomainNamespace,
        control: &Path,
        registration: RegistrationView<'_>,
        records: &[(String, Vec<u8>)],
        held: Option<&HeldIdentity<'_>>,
        retained: Option<&RetainedControls>,
    ) -> Result<OriginalAuthority, StoreFailure> {
        use std::os::unix::fs::MetadataExt;

        if self.store.capabilities().refs != RefCapability::Cas {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        if !normalized(control)
            || !normalized(&namespace.root)
            || control.starts_with(&namespace.root)
            || namespace.root.starts_with(control)
            || namespace.root != self.store.root()
            || namespace.domain != self.config.storage_domain
            || registration.root != namespace.root
            || registration.domain != namespace.domain
            || registration.control != control
        {
            return Err(invalid());
        }

        let fs = self.store.fs();
        DomainNamespaces::new(vec![namespace.clone()])?
            .verify_paths(fs)
            .await?;
        let root = fs
            .symlink_metadata(self.store.root())
            .await
            .map_err(io_failure)?;
        let owner = self
            .store
            .publication_operator_uid()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
        if root.uid() != owner {
            return Err(invalid());
        }
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| invalid())?;
        let lock_path = self.store.root().join(key.lock_name());
        let lock = fs.symlink_metadata(&lock_path).await.map_err(io_failure)?;
        if !lock.is_file()
            || lock.file_type().is_symlink()
            || lock.uid() != owner
            || lock.nlink() != 1
            || root.mode() & 0o022 != 0
            || (root.dev(), root.ino()) != registration.root_identity
            || (lock.dev(), lock.ino()) != registration.coordination_identity
        {
            return Err(invalid());
        }
        let _backend = if let Some(proof) = held {
            if proof.root() != self.store.root()
                || proof.physical_identity()
                    != (
                        registration.root_identity,
                        registration.coordination_identity,
                    )
            {
                return Err(invalid());
            }
            None
        } else {
            Some(
                fs.lock_existing_exclusive(&lock_path)
                    .await
                    .map_err(io_failure)?,
            )
        };

        let mut current = PathBuf::new();
        for part in control.components() {
            current.push(part);
            let metadata = fs.symlink_metadata(&current).await.map_err(io_failure)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid());
            }
        }
        let directory = fs.symlink_metadata(control).await.map_err(io_failure)?;
        if directory.uid() != owner || directory.mode() & 0o777 != 0o700 {
            return Err(invalid());
        }
        let mut configuration = match retained {
            Some(retained) => {
                // Retained exclusion never replaces actual backend qualification.
                if held.is_none() {
                    return Err(invalid());
                }
                control::OriginalControls::retained(fs, control, owner, retained).await?
            }
            None => control::OriginalControls::acquire(fs, control, owner).await?,
        };
        if configuration.read_record("registration.cbor").await?
            != registration_bytes(&registration)
        {
            return Err(invalid());
        }

        for (selector, expected) in records {
            if configuration.read_record(selector).await? != *expected {
                return Err(invalid());
            }
        }

        let root_after = fs
            .symlink_metadata(self.store.root())
            .await
            .map_err(io_failure)?;
        let lock_after = fs.symlink_metadata(&lock_path).await.map_err(io_failure)?;
        let directory_after = fs.symlink_metadata(control).await.map_err(io_failure)?;
        DomainNamespaces::new(vec![namespace.clone()])?
            .verify_paths(fs)
            .await?;
        if !directory_after.is_dir()
            || directory_after.file_type().is_symlink()
            || directory_after.uid() != owner
            || directory_after.mode() & 0o777 != 0o700
            || (directory_after.dev(), directory_after.ino()) != (directory.dev(), directory.ino())
            || !root_after.is_dir()
            || root_after.file_type().is_symlink()
            || root_after.uid() != owner
            || root_after.mode() != root.mode()
            || !lock_after.is_file()
            || lock_after.file_type().is_symlink()
            || lock_after.uid() != owner
            || lock_after.nlink() != 1
            || lock_after.mode() != lock.mode()
            || (root_after.dev(), root_after.ino()) != registration.root_identity
            || (lock_after.dev(), lock_after.ino()) != registration.coordination_identity
        {
            return Err(invalid());
        }
        configuration.revalidate().await?;
        Ok(OriginalAuthority {
            id: *registration.id,
            root: namespace.root.clone(),
            domain: namespace.domain.clone(),
            root_identity: registration.root_identity,
            coordination_identity: registration.coordination_identity,
            control: control.to_path_buf(),
        })
    }
}

/// Supplies an untrusted original bootstrap record decoded by protected storage.
pub(crate) struct BootstrapView<'a> {
    /// Registered association identifier.
    pub id: &'a [u8; 32],
    /// Exact original canonical reference.
    pub reference: &'a str,
    /// Original allocated writer epoch.
    pub epoch: u64,
    /// Original ordered baseline ACL.
    pub acl: &'a [(String, u8)],
}

/// Supplies an untrusted immutable commit association decoded by protected storage.
#[derive(Clone, Copy)]
pub(crate) struct AssociationView<'a> {
    /// Exact immutable authored commit identity.
    pub commit: &'a terrane_core::identity::Digest,
    /// Registered original authority identifier.
    pub id: &'a [u8; 32],
    /// Exact original reference.
    pub reference: &'a str,
    /// Exact original writer epoch.
    pub epoch: u64,
}

/// Retains an original baseline checked against protected physical registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedBootstrap {
    authority: OriginalAuthority,
    reference: String,
    epoch: u64,
    acl: Vec<(String, u8)>,
}

impl RetainedBootstrap {
    /// Returns the checked original physical authority.
    pub fn authority(&self) -> &OriginalAuthority {
        &self.authority
    }

    /// Returns the original reference retained before publication.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the original allocated writer epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the protected original ACL without substituting current policy.
    pub fn acl(&self) -> &[(String, u8)] {
        &self.acl
    }
}

/// Associates one exact immutable commit with its checked retained original baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalCommitContext {
    commit: terrane_core::identity::Digest,
    baseline: RetainedBootstrap,
    retention_owner: OriginalAuthority,
}

impl OriginalCommitContext {
    /// Returns the exact immutable commit named by protected association.
    pub fn commit(&self) -> &terrane_core::identity::Digest {
        &self.commit
    }

    /// Returns the independently retained original baseline.
    pub fn baseline(&self) -> &RetainedBootstrap {
        &self.baseline
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Encodes an untrusted bootstrap row and its registered protected key.
///
/// Canonical bytes alone establish no physical registration or operation rights.
///
/// # Errors
/// Rejects invalid ref names, empty ACL subjects and unregistered verb bits.
pub(super) fn bootstrap_record(
    view: &BootstrapView<'_>,
) -> Result<(String, Vec<u8>), StoreFailure> {
    terrane_core::refs::RefName::parse(view.reference).map_err(|_| invalid())?;
    if view
        .acl
        .iter()
        .any(|(subject, verbs)| subject.is_empty() || *verbs > 31)
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 5);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, view.id);
    cbor::write_text(&mut bytes, view.reference);
    cbor::write_uint(&mut bytes, view.epoch);
    cbor::write_array(&mut bytes, view.acl.len());
    for (subject, verbs) in view.acl {
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, subject);
        cbor::write_uint(&mut bytes, u64::from(*verbs));
    }
    let selector = format!(
        "bootstrap-{}-{}-{}.cbor",
        hex(view.id),
        hex(blake3::hash(view.reference.as_bytes()).as_bytes()),
        view.epoch
    );
    Ok((selector, bytes))
}

#[cfg(unix)]
impl<F: LocalFs + BucketBinding, B: Clock + BucketBinding, V: ContentValidator + BucketBinding, C>
    Guard<FileBucket<F, B, V>, C>
{
    /// Checks an existing original baseline under physical and protected exclusion.
    ///
    /// # Errors
    /// Rejects a conflicting authority, malformed baseline, changed physical
    /// registration, missing retention, or unavailable protected storage.
    pub(crate) async fn bind_original_bootstrap(
        &self,
        authority: &OriginalAuthority,
        view: BootstrapView<'_>,
    ) -> Result<RetainedBootstrap, StoreFailure> {
        if view.id != authority.id() {
            return Err(invalid());
        }
        let record = bootstrap_record(&view)?;
        let namespace = DomainNamespace {
            root: authority.root.clone(),
            domain: authority.domain.clone(),
        };
        let checked = self
            .bind_original_records(
                &namespace,
                &authority.control,
                RegistrationView {
                    id: &authority.id,
                    root: &authority.root,
                    domain: &authority.domain,
                    root_identity: authority.root_identity,
                    coordination_identity: authority.coordination_identity,
                    control: &authority.control,
                },
                &[record],
                None,
                None,
            )
            .await?;
        Ok(RetainedBootstrap {
            authority: checked,
            reference: view.reference.into(),
            epoch: view.epoch,
            acl: view.acl.to_vec(),
        })
    }

    /// Checks an exact immutable commit association and its retained baseline together.
    ///
    /// This checks protected administrative association, not the commit's
    /// signature, original claims, current token, or current ACL.
    ///
    /// # Errors
    /// Rejects mismatched baseline fields, missing or conflicting protected
    /// bytes, changed physical binding, or unavailable protected storage.
    pub(crate) async fn bind_original_commit(
        &self,
        baseline: &RetainedBootstrap,
        view: AssociationView<'_>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        self.bind_original_commit_at(baseline, view, None, None)
            .await
    }

    async fn bind_original_commit_at(
        &self,
        baseline: &RetainedBootstrap,
        view: AssociationView<'_>,
        held: Option<&HeldIdentity<'_>>,
        retained: Option<&RetainedControls>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        let authority = &baseline.authority;
        if view.id != authority.id()
            || view.reference != baseline.reference
            || view.epoch != baseline.epoch
        {
            return Err(invalid());
        }
        let baseline_record = bootstrap_record(&BootstrapView {
            id: &authority.id,
            reference: &baseline.reference,
            epoch: baseline.epoch,
            acl: &baseline.acl,
        })?;
        let mut bytes = Vec::new();
        cbor::write_array(&mut bytes, 5);
        cbor::write_uint(&mut bytes, 1);
        cbor::write_bytes(&mut bytes, view.commit);
        cbor::write_bytes(&mut bytes, view.id);
        cbor::write_text(&mut bytes, view.reference);
        cbor::write_uint(&mut bytes, view.epoch);
        let namespace = DomainNamespace {
            root: authority.root.clone(),
            domain: authority.domain.clone(),
        };
        self.bind_original_records(
            &namespace,
            &authority.control,
            RegistrationView {
                id: &authority.id,
                root: &authority.root,
                domain: &authority.domain,
                root_identity: authority.root_identity,
                coordination_identity: authority.coordination_identity,
                control: &authority.control,
            },
            &[
                baseline_record,
                (format!("commit-{}.cbor", hex(view.commit)), bytes),
            ],
            held,
            retained,
        )
        .await?;
        Ok(OriginalCommitContext {
            commit: *view.commit,
            baseline: baseline.clone(),
            retention_owner: authority.clone(),
        })
    }
}

#[cfg(unix)]
impl<F: LocalFs + BucketBinding, B: Clock + BucketBinding, V: ContentValidator + BucketBinding, C>
    Guard<FileBucket<F, B, V>, C>
{
    /// Installs a freshly rechecked protected baseline for exact local authoring.
    ///
    /// # Errors
    /// Rejects stale physical binding, unavailable protected records, or an
    /// already installed conflicting original authority/ref/epoch baseline.
    pub(crate) async fn install_original_bootstrap(
        &self,
        baseline: RetainedBootstrap,
    ) -> Result<(), StoreFailure> {
        let checked = self
            .bind_original_bootstrap(
                &baseline.authority,
                BootstrapView {
                    id: baseline.authority.id(),
                    reference: &baseline.reference,
                    epoch: baseline.epoch,
                    acl: &baseline.acl,
                },
            )
            .await?;
        let mut baselines = self.original_baselines.write().map_err(|_| unavailable())?;
        let key = (checked.reference.clone(), checked.epoch);
        if baselines
            .get(&key)
            .is_some_and(|existing| existing != &checked)
        {
            return Err(invalid());
        }
        baselines.insert(key, checked);
        Ok(())
    }

    /// Installs a freshly rechecked protected immutable local commit association.
    ///
    /// # Errors
    /// Rejects unavailable or conflicting protected retention, another physical
    /// destination, or a conflicting association already installed for this commit.
    pub(crate) async fn install_original_commit(
        &self,
        context: OriginalCommitContext,
    ) -> Result<(), StoreFailure> {
        if context.retention_owner.root != self.store.root()
            || context.retention_owner.domain != self.config.storage_domain
        {
            return Err(invalid());
        }
        let checked = self
            .bind_original_commit(
                &context.baseline,
                AssociationView {
                    commit: &context.commit,
                    id: context.baseline.authority.id(),
                    reference: &context.baseline.reference,
                    epoch: context.baseline.epoch,
                },
            )
            .await?;
        let mut contexts = self.original_commits.write().map_err(|_| unavailable())?;
        if contexts
            .get(&checked.commit)
            .is_some_and(|existing| existing != &checked)
        {
            return Err(invalid());
        }
        contexts.insert(checked.commit, checked);
        Ok(())
    }
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}

impl<S, C> Guard<S, C> {
    pub(crate) fn original_bootstrap(
        &self,
        reference: &str,
        epoch: u64,
    ) -> Result<RetainedBootstrap, StoreFailure> {
        self.original_baselines
            .read()
            .map_err(|_| unavailable())?
            .get(&(reference.to_owned(), epoch))
            .cloned()
            .ok_or_else(invalid)
    }

    pub(crate) fn original_commit(
        &self,
        commit: &terrane_core::identity::Digest,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        self.original_commits
            .read()
            .map_err(|_| unavailable())?
            .get(commit)
            .cloned()
            .ok_or_else(invalid)
    }
}

/// Derives exact canonical control pins from a freshly checked original context.
///
/// # Errors
/// Rejects an unsupported retained owner or malformed canonical administrative rows.
pub(crate) fn consumed_pins(
    context: &OriginalCommitContext,
) -> Result<Vec<terrane_core::gc::publication::evidence::RequiredControlPin>, StoreFailure> {
    use terrane_core::gc::publication::evidence::{ControlKind, RequiredControlPin};

    let baseline = context.baseline();
    let authority = baseline.authority();
    if &context.retention_owner != authority {
        return Err(invalid());
    }
    let registration = registration_bytes(&RegistrationView {
        id: authority.id(),
        root: authority.root(),
        domain: authority.domain(),
        root_identity: authority.root_identity,
        coordination_identity: authority.coordination_identity,
        control: authority.control(),
    });
    let (bootstrap_key, bootstrap) = bootstrap_record(&BootstrapView {
        id: authority.id(),
        reference: baseline.reference(),
        epoch: baseline.epoch(),
        acl: baseline.acl(),
    })?;
    let mut association = Vec::new();
    cbor::write_array(&mut association, 5);
    cbor::write_uint(&mut association, 1);
    cbor::write_bytes(&mut association, context.commit());
    cbor::write_bytes(&mut association, authority.id());
    cbor::write_text(&mut association, baseline.reference());
    cbor::write_uint(&mut association, baseline.epoch());
    let owner = super::consumed::registration(authority);
    [
        (
            ControlKind::Registration,
            "registration.cbor".into(),
            registration,
        ),
        (ControlKind::Bootstrap, bootstrap_key, bootstrap),
        (
            ControlKind::Association,
            format!("commit-{}.cbor", hex(context.commit())),
            association,
        ),
    ]
    .into_iter()
    .map(|(kind, key, bytes)| {
        let pin = RequiredControlPin {
            kind,
            owner: owner.clone(),
            key,
            digest: *blake3::hash(&bytes).as_bytes(),
        };
        pin.check_record(&bytes).map_err(|_| invalid())?;
        Ok(pin)
    })
    .collect()
}
