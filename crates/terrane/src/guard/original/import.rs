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
use terrane_core::gc::publication::evidence::{ControlKind, RequiredControlPin};

/// Keeps the exact canonical bytes whose destination retention was checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ImportedEvidence {
    import: Vec<u8>,
    binding: Vec<u8>,
    trust: Vec<u8>,
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
        binding.validate_pair(&import, owner.id()).map_err(|_| invalid())?;
        trust.validate_binding(&binding).map_err(|_| invalid())?;
        let owner = crate::guard::consumed_registration(owner);
        [
            (ControlKind::Import, import.selector(), &self.import),
            (ControlKind::ImportBinding, binding.selector(), &self.binding),
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
    /// Returns exact independently retained verification keys for an import.
    ///
    /// Current operation authorization still uses the local configured keys.
    ///
    /// # Errors
    /// Rejects malformed protected historical mappings.
    pub(crate) fn historical_keys(
        &self,
    ) -> Result<Option<Vec<terrane_core::auth::IssuerKey>>, StoreFailure> {
        self.imported
            .as_ref()
            .map(|evidence| evidence.trust().map(|trust| trust.issuer_keys))
            .transpose()
    }
}

impl<
    F: LocalFs + BucketBinding,
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
    ) -> Result<OriginalCommitContext, StoreFailure> {
        if view.id != baseline.authority().id()
            || view.reference != baseline.reference()
            || view.epoch != baseline.epoch()
        {
            return Err(invalid());
        }
        let fs = self.store().fs();
        let uid = self.store().publication_operator_uid().ok_or_else(invalid)?;
        let commit = super::hex(view.commit);
        let import: ImportRecord = crate::repository::local_authority::retention::read(
            fs, owner.control(), uid, &format!("import-{commit}.cbor"),
        ).await.map_err(retention_failure)?;
        let binding: ImportBindingRecord = crate::repository::local_authority::retention::read(
            fs, owner.control(), uid, &format!("import-binding-{commit}.cbor"),
        ).await.map_err(retention_failure)?;
        binding.validate_pair(&import, owner.id()).map_err(|_| invalid())?;
        let trust_key = format!("import-trust-{}.cbor", super::hex(&binding.import_digest));
        let trust: PublicTrustRecord = crate::repository::local_authority::retention::read(
            fs, owner.control(), uid, &trust_key,
        ).await.map_err(retention_failure)?;
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
        };
        let records = vec![
            (import.selector().map_err(|_| invalid())?, imported.import.clone()),
            (binding.selector().map_err(|_| invalid())?, imported.binding.clone()),
            (trust_key, imported.trust.clone()),
        ];
        let namespace = DomainNamespace {
            root: owner.root().to_path_buf(),
            domain: owner.domain().to_owned(),
        };
        let checked_owner = self.bind_original_records(
            &namespace,
            owner.control(),
            RegistrationView {
                id: owner.id(), root: owner.root(), domain: owner.domain(),
                root_identity: owner.root_identity,
                coordination_identity: owner.coordination_identity,
                control: owner.control(),
            },
            &records,
            held,
        ).await?;
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
        self.bind_imported_commit_at(
            owner, &baseline, import.association.view(), None,
        ).await?;
        self.check_original_commit(&baseline, import.association.view()).await
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

fn retention_failure(error: crate::repository::Error) -> StoreFailure {
    match error {
        crate::repository::Error::Store(failure) => failure,
        crate::repository::Error::Io(error) => super::io_failure(error),
        error => StoreFailure::with_source(
            StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest), error,
        ),
    }
}

impl<S, C> Guard<S, C> {
    /// Enumerates only mappings carried by independently checked retained contexts.
    ///
    /// # Errors
    /// Rejects malformed retained public trust or unavailable resolver state.
    pub(crate) fn retained_public_trust(&self) -> Result<Vec<PublicTrustRecord>, StoreFailure> {
        self.original_commits.read().map_err(|_| super::unavailable())?
            .values()
            .filter_map(|context| context.imported.as_ref())
            .map(ImportedEvidence::trust)
            .collect()
    }
}
