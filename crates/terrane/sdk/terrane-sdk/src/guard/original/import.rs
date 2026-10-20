//! Resolves original authority from exact imports retained by a checked destination.
//!
//! Imported records are administrative evidence, never private source ancestry.
//! Every resolution rereads the import, destination binding and historical public
//! trust under the destination's physical and protected configuration exclusions.

use super::{
    AssociationView, OriginalAuthority, OriginalCommitContext, RegistrationView, RetainedBootstrap,
    invalid,
};
use crate::bucket::held::HeldIdentity;
use crate::bucket::{BucketBinding, FileBucket};
use crate::domain::DomainNamespace;
use crate::guard::Guard;
use crate::repository::local_authority::{
    import_binding::ImportBindingRecord,
    public_trust::PublicTrustRecord,
    retention::{ImportRecord, Record},
};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::gc::publication::evidence::{ControlKind, RequiredControlPin};

/// Keeps the exact canonical bytes whose destination retention was checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ImportedEvidence {
    import: Vec<u8>,
    binding: Vec<u8>,
    trust: Vec<u8>,
    // A same-original round trip supplements independently checked local
    // originals; its imported controls never replace their dependencies.
    /// Reports a same-original import that supplements local Original dependencies.
    pub(super) supplements_local: bool,
}

impl ImportedEvidence {
    /// Derives pins for all imported controls owned by the actual destination.
    ///
    /// # Errors
    /// Rejects malformed records, contradictory coordinates or noncanonical bytes.
    pub(super) fn pins(
        &self,
        owner: &OriginalAuthority,
    ) -> Result<Vec<RequiredControlPin>, StoreFailure> {
        let import = ImportRecord::decode(&self.import).map_err(|_| invalid())?;
        let binding = ImportBindingRecord::decode(&self.binding).map_err(|_| invalid())?;
        let trust = PublicTrustRecord::decode(&self.trust).map_err(|_| invalid())?;
        binding
            .validate_pair(&import, owner.id())
            .map_err(|_| invalid())?;
        trust.validate_binding(&binding).map_err(|_| invalid())?;
        let owner = crate::guard::consumed_registration(owner);
        [
            (ControlKind::Import, Ok(import.selector()), &self.import),
            (
                ControlKind::ImportBinding,
                binding.selector(),
                &self.binding,
            ),
            (ControlKind::ImportTrust, trust.selector(), &self.trust),
        ]
        .into_iter()
        .map(|(kind, key, bytes)| {
            let pin = RequiredControlPin {
                kind,
                owner: owner.clone(),
                key: key.map_err(|_| invalid())?,
                digest: *blake3::hash(bytes).as_bytes(),
            };
            pin.check_record(bytes).map_err(|_| invalid())?;
            Ok(pin)
        })
        .collect()
    }

    /// Decodes the public mappings without exposing or requiring a signing seed.
    ///
    /// # Errors
    /// Rejects malformed retained canonical public mappings.
    pub(super) fn trust(&self) -> Result<PublicTrustRecord, StoreFailure> {
        PublicTrustRecord::decode(&self.trust).map_err(|_| invalid())
    }
}

impl OriginalCommitContext {
    /// Serializes checked original context as untrusted data for a paired import.
    ///
    /// The native producer freshly rechecks this context under its actual source
    /// retention owner before copying it. An already imported context preserves
    /// its original registration instead of substituting the current discloser.
    ///
    /// # Errors
    /// Rejects malformed retained import bytes or inconsistent original fields.
    pub(crate) fn retained_import_record(&self) -> Result<ImportRecord, StoreFailure> {
        if let Some(evidence) = &self.imported {
            return ImportRecord::decode(&evidence.import).map_err(|_| invalid());
        }
        use crate::repository::local_authority::retention::{
            BootstrapRecord, CommitAssociation, RegistrationRecord,
        };
        let baseline = self.baseline();
        let authority = baseline.authority();
        let (root, coordination) = authority.physical_identity();
        let import = ImportRecord {
            registration: RegistrationRecord {
                id: *authority.id(),
                root: authority.root().to_owned(),
                domain: authority.domain().to_owned(),
                root_device: root.0,
                root_inode: root.1,
                coordination_device: coordination.0,
                coordination_inode: coordination.1,
                control: authority.control().to_owned(),
            },
            baseline: BootstrapRecord {
                id: *authority.id(),
                reference: baseline.reference().to_owned(),
                epoch: baseline.epoch(),
                acl: baseline.acl().to_vec(),
            },
            association: CommitAssociation {
                commit: *self.commit(),
                id: *authority.id(),
                reference: baseline.reference().to_owned(),
                epoch: baseline.epoch(),
            },
        };
        import.validate().map_err(|_| invalid())?;
        Ok(import)
    }

    /// Returns exact independently retained verification keys for an import.
    ///
    /// Current operation authorization still uses the local configured keys.
    ///
    /// # Errors
    /// Rejects malformed protected historical mappings.
    pub(crate) fn historical_keys(
        &self,
    ) -> Result<Option<Vec<terrane_format::auth::IssuerKey>>, StoreFailure> {
        self.imported
            .as_ref()
            .map(|evidence| evidence.trust().map(|trust| trust.issuer_keys))
            .transpose()
    }

    /// Returns independently retained disclosure-role mappings for an import.
    ///
    /// # Errors
    /// Rejects malformed retained public trust bytes.
    pub(crate) fn historical_disclosure_roles(
        &self,
    ) -> Result<
        Option<Vec<crate::repository::local_authority::public_trust::DisclosureRoleRecord>>,
        StoreFailure,
    > {
        self.imported
            .as_ref()
            .map(|evidence| evidence.trust().map(|trust| trust.disclosure_roles))
            .transpose()
    }
}

impl<F: LocalFs + BucketBinding, B: Clock + BucketBinding, V: ContentValidator + BucketBinding, C>
    Guard<FileBucket<F, B, V>, C>
{
    /// Checks the complete configured dedicated role set under existing exclusion.
    ///
    /// Role configuration changes cannot remain hidden behind a cached snapshot.
    /// Imported mappings are separately rechecked when their original contexts
    /// are consumed; this check owns only this physical owner's role records.
    ///
    /// # Errors
    /// Rejects malformed names and added, removed, replaced or changed role rows.
    pub(crate) async fn check_retained_trust_controls(
        &self,
        owner: &OriginalAuthority,
        controls: &mut super::ControlExclusion<'_, F>,
        snapshot: &terrane_format::gc::publication::evidence::GuardSnapshot,
    ) -> Result<(), StoreFailure> {
        let mut expected_roles = std::collections::BTreeSet::new();
        for row in snapshot
            .disclosures
            .iter()
            .filter(|row| row.repository == super::hex(owner.id()))
        {
            let role = crate::repository::local_authority::public_trust::DisclosureRoleRecord {
                repository: row.repository.clone(),
                domain: row.domain.clone(),
                public_key: row.public_key,
                not_before: row.not_before,
                not_after: row.not_after,
            };
            let key = role.selector().map_err(retention_failure)?;
            if !expected_roles.insert(key.clone())
                || controls.read_record(&key).await? != role.encode().map_err(retention_failure)?
            {
                return Err(invalid());
            }
        }
        let mut actual_roles = std::collections::BTreeSet::new();
        for path in self
            .store()
            .fs()
            .read_dir(owner.control())
            .await
            .map_err(super::io_failure)?
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(invalid)?;
            if name.starts_with("disclosure-role-") {
                actual_roles.insert(name.to_owned());
            }
        }
        if actual_roles != expected_roles {
            return Err(invalid());
        }
        controls.revalidate().await?;
        Ok(())
    }

    /// Checks one additive local role against the complete protected role inventory.
    ///
    /// Only the pending native rotation Guard calls this before selection. Old
    /// rows remain byte-identical, and the new seed must authenticate the exact
    /// new public key. This operation grants no actor rights or selected state.
    ///
    /// # Errors
    /// Rejects a foreign registration, nonmonotonic role, unknown or changed
    /// protected rows, unsafe seeds, key substitution or unavailable state.
    pub(crate) async fn install_checked_disclosure_rotation(
        &self,
        owner: &OriginalAuthority,
        role: &crate::repository::local_authority::public_trust::DisclosureRoleRecord,
        seed_name: &str,
        controls: &mut super::ControlExclusion<'_, F>,
    ) -> Result<(), StoreFailure> {
        if self.configured_original_authority()? != *owner
            || role.repository != super::hex(owner.id())
            || role.domain != owner.domain()
            || role.not_after.is_some()
        {
            return Err(invalid());
        }
        let previous = self.configured_disclosure_roles()?;
        if previous.is_empty()
            || previous.iter().any(|old| {
                old.repository != role.repository
                    || old.domain != role.domain
                    || old.not_before >= role.not_before
                    || old.public_key == role.public_key
            })
        {
            return Err(invalid());
        }
        let seed: [u8; 32] = controls
            .read_record(seed_name)
            .await?
            .try_into()
            .map_err(|_| invalid())?;
        let expected_seed = format!("disclosure-{}.seed", super::hex(&role.public_key));
        if seed_name != expected_seed
            || terrane_format::auth::public_key_from_secret(&seed) != role.public_key
        {
            return Err(invalid());
        }
        let mut roles = previous.clone();
        roles.push(role.clone());
        let mut expected = std::collections::BTreeSet::new();
        for row in &roles {
            let name = row.selector().map_err(retention_failure)?;
            if !expected.insert(name.clone())
                || controls.read_record(&name).await? != row.encode().map_err(retention_failure)?
            {
                return Err(invalid());
            }
        }
        let mut actual = std::collections::BTreeSet::new();
        for path in self
            .store()
            .fs()
            .read_dir(owner.control())
            .await
            .map_err(super::io_failure)?
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(invalid)?;
            if name.starts_with("disclosure-role-") {
                actual.insert(name.to_owned());
            }
        }
        if actual != expected {
            return Err(invalid());
        }
        controls.revalidate().await?;
        roles.sort_by(|left, right| {
            (
                &left.repository,
                &left.domain,
                left.public_key,
                left.not_before,
            )
                .cmp(&(
                    &right.repository,
                    &right.domain,
                    right.public_key,
                    right.not_before,
                ))
        });
        let mut verifier = self
            .original_verifier
            .write()
            .map_err(|_| super::unavailable())?;
        let verifier = verifier.as_mut().ok_or_else(invalid)?;
        if verifier.roles != previous {
            return Err(invalid());
        }
        verifier.roles = roles;
        Ok(())
    }

    /// Adopts a selected same-backend role delta after the native durable acknowledgment.
    ///
    /// # Errors
    /// Rejects a foreign native authority, a changed serving role set or an
    /// invalid additive delta, preserving the existing serving configuration.
    pub(crate) fn adopt_disclosure_rotation<D>(
        &self,
        selected: &Guard<FileBucket<F, B, V>, D>,
        previous: &[crate::repository::local_authority::public_trust::DisclosureRoleRecord],
    ) -> Result<(), StoreFailure> {
        if self.configured_original_authority()? != selected.configured_original_authority()? {
            return Err(invalid());
        }
        let roles = selected.configured_disclosure_roles()?;
        if roles.len() != previous.len().checked_add(1).ok_or_else(invalid)?
            || previous.iter().any(|role| !roles.contains(role))
        {
            return Err(invalid());
        }
        let mut verifier = self
            .original_verifier
            .write()
            .map_err(|_| super::unavailable())?;
        let verifier = verifier.as_mut().ok_or_else(invalid)?;
        if verifier.roles != previous {
            return Err(invalid());
        }
        verifier.roles = roles;
        Ok(())
    }
}

impl<
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C,
> Guard<FileBucket<F, B, V>, C>
{
    /// Rechecks a retained original association against its actual destination.
    ///
    /// A copied source registration is not checked as this backend's physical
    /// identity. The independently protected destination binding determines the
    /// retention owner; source registration supplies only the original context.
    ///
    /// # Errors
    /// Rejects missing or conflicting controls, altered canonical bytes, another
    /// physical destination, mismatched original policy and unavailable storage.
    pub(in crate::guard::original) async fn bind_imported_commit_at(
        &self,
        owner: &OriginalAuthority,
        baseline: &RetainedBootstrap,
        view: AssociationView<'_>,
        held: Option<&HeldIdentity<'_>>,
        retained: Option<&super::RetainedControls>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        if view.id != baseline.authority().id()
            || view.reference != baseline.reference()
            || view.epoch != baseline.epoch()
        {
            return Err(invalid());
        }
        let fs = self.store().fs();
        let uid = self
            .store()
            .publication_operator_uid()
            .ok_or_else(invalid)?;
        let commit = super::hex(view.commit);
        let import: ImportRecord = crate::repository::local_authority::retention::read(
            fs,
            owner.control(),
            uid,
            &format!("import-{commit}.cbor"),
        )
        .await
        .map_err(retention_failure)?;
        let binding: ImportBindingRecord = crate::repository::local_authority::retention::read(
            fs,
            owner.control(),
            uid,
            &format!("import-binding-{commit}.cbor"),
        )
        .await
        .map_err(retention_failure)?;
        binding
            .validate_pair(&import, owner.id())
            .map_err(|_| invalid())?;
        let trust_key = format!("import-trust-{}.cbor", super::hex(&binding.import_digest));
        let trust: PublicTrustRecord = crate::repository::local_authority::retention::read(
            fs,
            owner.control(),
            uid,
            &trust_key,
        )
        .await
        .map_err(retention_failure)?;
        trust.validate_binding(&binding).map_err(|_| invalid())?;
        if import.association.commit != *view.commit
            || import.baseline.id != *view.id
            || import.baseline.reference != view.reference
            || import.baseline.epoch != view.epoch
            || import.baseline.acl != baseline.acl()
            || original_authority(&import) != *baseline.authority()
        {
            return Err(invalid());
        }
        let imported = ImportedEvidence {
            import: import.encode().map_err(|_| invalid())?,
            binding: binding.encode().map_err(|_| invalid())?,
            trust: trust.encode().map_err(|_| invalid())?,
            supplements_local: baseline.authority() == owner,
        };
        let mut records = vec![
            (import.selector(), imported.import.clone()),
            (
                binding.selector().map_err(|_| invalid())?,
                imported.binding.clone(),
            ),
            (trust_key, imported.trust.clone()),
        ];
        if imported.supplements_local {
            // Even an exact protected import cannot repair missing local
            // authoring authority. Check it independently, then include both
            // local originals in the final single held control observation.
            self.bind_original_commit_at(baseline, view, held, retained)
                .await?;
            use crate::repository::local_authority::retention::{
                BootstrapRecord, CommitAssociation,
            };
            let bootstrap = BootstrapRecord {
                id: *owner.id(),
                reference: baseline.reference().to_owned(),
                epoch: baseline.epoch(),
                acl: baseline.acl().to_vec(),
            };
            let association = CommitAssociation {
                commit: *view.commit,
                id: *owner.id(),
                reference: view.reference.to_owned(),
                epoch: view.epoch,
            };
            records.push((
                bootstrap.selector().map_err(|_| invalid())?,
                bootstrap.encode().map_err(|_| invalid())?,
            ));
            records.push((
                association.selector(),
                association.encode().map_err(|_| invalid())?,
            ));
        }
        let namespace = DomainNamespace {
            root: owner.root().to_path_buf(),
            domain: owner.domain().to_owned(),
        };
        let checked_owner = self
            .bind_original_records(
                &namespace,
                owner.control(),
                RegistrationView {
                    id: owner.id(),
                    root: owner.root(),
                    domain: owner.domain(),
                    root_identity: owner.root_identity,
                    coordination_identity: owner.coordination_identity,
                    control: owner.control(),
                },
                &records,
                held,
                retained,
            )
            .await?;
        Ok(OriginalCommitContext {
            commit: *view.commit,
            baseline: baseline.clone(),
            retention_owner: checked_owner,
            imported: Some(imported),
        })
    }

    /// Loads an imported baseline without substituting current local authoring ACLs.
    ///
    /// # Errors
    /// Rejects missing or malformed protected imports, mismatched destinations,
    /// altered public mappings and changed physical registration.
    pub(crate) async fn load_original_import(
        &self,
        owner: &OriginalAuthority,
        import: &ImportRecord,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        let baseline = RetainedBootstrap {
            authority: original_authority(import),
            reference: import.baseline.reference.clone(),
            epoch: import.baseline.epoch,
            acl: import.baseline.acl.clone(),
        };
        self.bind_imported_commit_at(owner, &baseline, import.association.view(), None, None)
            .await?;
        self.check_original_commit(&baseline, import.association.view())
            .await
    }

    /// Preserves local originals before considering supplemental protected trust.
    ///
    /// Missing supplemental data keeps an ordinary local context. Present data
    /// must pass the complete native import check; it never supplies a fallback
    /// for missing or conflicting original local bootstrap or association bytes.
    ///
    /// # Errors
    /// Rejects missing local originals, invalid present supplements, changed
    /// protected records or namespaces and unavailable filesystem observations.
    pub(in crate::guard::original) async fn bind_local_or_import_at(
        &self,
        owner: &OriginalAuthority,
        baseline: &RetainedBootstrap,
        view: AssociationView<'_>,
        held: Option<&HeldIdentity<'_>>,
        retained: Option<&super::RetainedControls>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        let local = self
            .bind_original_commit_at(baseline, view, held, retained)
            .await?;
        let selector = format!("import-{}.cbor", super::hex(view.commit));
        match self
            .store()
            .fs()
            .symlink_metadata(&owner.control().join(selector))
            .await
        {
            Ok(_) => {
                self.bind_imported_commit_at(owner, baseline, view, held, retained)
                    .await
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(local),
            Err(error) => Err(super::io_failure(error)),
        }
    }
}

fn original_authority(import: &ImportRecord) -> OriginalAuthority {
    let record = &import.registration;
    OriginalAuthority {
        id: record.id,
        root: record.root.clone(),
        domain: record.domain.clone(),
        root_identity: (record.root_device, record.root_inode),
        coordination_identity: (record.coordination_device, record.coordination_inode),
        control: record.control.clone(),
    }
}

/// Preserves protected storage failures while rejecting invalid administrative data.
pub(crate) fn retention_failure(error: crate::repository::Error) -> StoreFailure {
    match error {
        crate::repository::Error::Store(failure) => failure,
        crate::repository::Error::Io(error) => super::io_failure(error),
        error => StoreFailure::with_source(
            StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest),
            error,
        ),
    }
}

impl<S, C> Guard<S, C> {
    /// Installs exact import context under the caller's actual held destination.
    ///
    /// This acquires only protected configuration exclusion and returns the
    /// checked context actually installed by the native verifier.
    ///
    /// # Errors
    /// Rejects an unrelated or read-only holder, unavailable originals, changed
    /// import controls, conflicting installed context and physical mismatches.
    pub(crate) async fn load_original_import_held(
        &self,
        owner: &OriginalAuthority,
        import: &ImportRecord,
        held: &HeldIdentity<'_>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        let baseline = RetainedBootstrap {
            authority: original_authority(import),
            reference: import.baseline.reference.clone(),
            epoch: import.baseline.epoch,
            acl: import.baseline.acl.clone(),
        };
        if self.configured_original_authority()? != *owner
            || owner.root() != held.root()
            || owner.physical_identity() != held.physical_identity()
        {
            return Err(invalid());
        }
        self.check_original_import_held(&baseline, import.association.view(), held)
            .await
    }

    /// Returns roles loaded by the concrete factory from protected source configuration.
    ///
    /// A guard without native dispatch has no configured disclosure roles.
    ///
    /// # Errors
    /// Rejects unavailable synchronized state.
    pub(crate) fn configured_disclosure_roles(
        &self,
    ) -> Result<
        Vec<crate::repository::local_authority::public_trust::DisclosureRoleRecord>,
        StoreFailure,
    > {
        Ok(self
            .original_verifier
            .read()
            .map_err(|_| super::unavailable())?
            .as_ref()
            .map(|verifier| verifier.roles.clone())
            .unwrap_or_default())
    }

    /// Enumerates only mappings carried by independently checked retained contexts.
    ///
    /// # Errors
    /// Rejects malformed retained public trust or unavailable resolver state.
    pub(crate) fn retained_public_trust(&self) -> Result<Vec<PublicTrustRecord>, StoreFailure> {
        self.original_commits
            .read()
            .map_err(|_| super::unavailable())?
            .values()
            .filter_map(|context| context.imported.as_ref())
            .map(ImportedEvidence::trust)
            .collect()
    }
}
