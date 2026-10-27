//! Explicit ordinary and checked I/O for complete campaign-closure walks.

use std::collections::BTreeSet;

use crucible_store::content_store::{ContentId, OwnedBlobBytes, StoreError};
use crucible_store::owned_decode::DecodeBudget;

use super::*;

#[cfg(test)]
mod tests;

pub(in crate::repository) enum ClosureRead<'a> {
    Compatibility(&'a CampaignRepository),
    Checked {
        repository: &'a CampaignRepository,
        saved: &'a DecodeBudget,
        operation: ClosureOperation<'a>,
    },
}

pub(in crate::repository) enum ClosureOperation<'a> {
    Owned(DecodeBudget),
    Borrowed(&'a DecodeBudget),
}

pub(super) enum ClosureBytes {
    Compatibility(Vec<u8>),
    Checked(OwnedBlobBytes),
}

pub(in crate::repository) struct ClosureSemanticRead<'a, 'repository> {
    reader: &'a ClosureRead<'repository>,
    boundary: &'a mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
}

pub(in crate::repository) fn with_compatibility_semantic<T>(
    repository: &CampaignRepository,
    action: impl FnOnce(&mut ClosureSemanticRead<'_, '_>) -> Result<T, CampaignRepositoryError>,
) -> Result<T, CampaignRepositoryError> {
    let reader = ClosureRead::Compatibility(repository);
    let mut boundary = || Ok(());
    action(&mut reader.semantic(&mut boundary))
}

impl AsRef<[u8]> for ClosureBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Compatibility(bytes) => bytes,
            Self::Checked(bytes) => bytes,
        }
    }
}

impl<'a> ClosureRead<'a> {
    pub(super) fn new(
        repository: &'a CampaignRepository,
        original: Option<&'a DecodeBudget>,
    ) -> Result<Self, CampaignRepositoryError> {
        let Some(original) = original else {
            return Ok(Self::Compatibility(repository));
        };
        let operation = original.child().map_err(|source| {
            CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                original, source,
            ))
        })?;
        Ok(Self::Checked {
            repository,
            saved: original,
            operation: ClosureOperation::Owned(operation),
        })
    }

    pub(in crate::repository) fn from_operation(
        repository: &'a CampaignRepository,
        saved: &'a DecodeBudget,
        operation: &'a DecodeBudget,
    ) -> Self {
        Self::Checked {
            repository,
            saved,
            operation: ClosureOperation::Borrowed(operation),
        }
    }

    pub(in crate::repository) fn poll(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        let Self::Checked {
            saved, operation, ..
        } = self
        else {
            return boundary().map_err(CampaignRepositoryError::Ram);
        };
        let operation = operation.as_ref();
        let mut supervised = || poll_saved(saved, boundary);
        crucible_store::ram::with_store_operation_boundary(operation, &mut supervised, |checked| {
            checked()
        })
        .map_err(map_checked_error)
    }

    pub(super) fn authenticate_opaque(
        &self,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        let Self::Checked {
            repository,
            saved,
            operation,
        } = self
        else {
            let handle = self.repository().blobs.read(id, None)?;
            handle.copy_to(&mut std::io::sink())?;
            return Ok(());
        };
        let operation = operation.as_ref();
        let mut supervised = || poll_saved(saved, boundary);
        crucible_store::ram::with_store_operation_boundary(operation, &mut supervised, |checked| {
            let source = repository
                .blobs
                .read_with_boundary(operation, id, None, checked)?;
            source.authenticate_with_boundary(operation, id, checked)?;
            drop(source);
            checked()
        })
        .map_err(map_checked_error)
    }

    pub(super) fn authenticate_exact_leaf(
        &self,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        if matches!(self, Self::Checked { .. }) {
            self.authenticate_opaque(id, boundary)?;
            if id.kind() != crucible_store::content_store::ObjectKind::Observation
                || id.schema_version() != 1
            {
                return Err(integrity("campaign-exact-leaf-identity-mismatch"));
            }
            return Ok(());
        }

        // Compatibility opened the leaf before checking the parent-granted
        // role, so retain its missing-object versus invalid-role precedence.
        let handle = self.repository().blobs.read(id, None)?;
        if id.kind() != crucible_store::content_store::ObjectKind::Observation
            || id.schema_version() != 1
            || ContentId::for_source(id.kind(), id.schema_version(), &handle)? != id
        {
            return Err(integrity("campaign-exact-leaf-identity-mismatch"));
        }
        Ok(())
    }

    pub(super) fn read_envelope_bytes(
        &self,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<ClosureBytes, CampaignRepositoryError> {
        let Self::Checked {
            repository,
            saved,
            operation,
        } = self
        else {
            return Ok(ClosureBytes::Compatibility(
                self.repository()
                    .blobs
                    .read(id, None)?
                    .read_all(MAX_ENVELOPE_BYTES)?,
            ));
        };
        let operation = operation.as_ref();
        let mut supervised = || poll_saved(saved, boundary);
        crucible_store::ram::with_store_operation_boundary(operation, &mut supervised, |checked| {
            let source = repository
                .blobs
                .read_with_boundary(operation, id, None, checked)?;
            let bytes = source.read_all_with_boundary(operation, MAX_ENVELOPE_BYTES, checked)?;
            drop(source);
            checked()?;
            Ok(ClosureBytes::Checked(bytes))
        })
        .map_err(map_checked_error)
    }

    pub(super) fn authenticate_ram_root(
        &self,
        id: ContentId,
        verify_contents: bool,
        explicit_original: Option<Option<&DecodeBudget>>,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        let Self::Checked {
            repository,
            saved,
            operation,
        } = self
        else {
            return match explicit_original {
                None => self
                    .repository()
                    .authenticate_ram_root(id, verify_contents, boundary),
                Some(Some(original)) => self.repository().authenticate_ram_root_under(
                    id,
                    verify_contents,
                    original,
                    boundary,
                ),
                Some(None) => Err(StoreError::Unsupported {
                    capability: "campaign-archive-ram-admission",
                }
                .into()),
            };
        };
        if explicit_original.is_some_and(|original| original.is_none()) {
            return Err(StoreError::Unsupported {
                capability: "campaign-archive-ram-admission",
            }
            .into());
        }

        let operation = operation.as_ref();
        let mut supervised = || poll_saved(saved, boundary);
        repository.authenticate_ram_root_under(id, verify_contents, operation, &mut supervised)?;
        self.poll(boundary)
    }

    pub(super) fn verify_merkle_closure(
        &self,
        root: ContentId,
        verified_positions: &mut BTreeSet<(ContentId, Vec<u8>)>,
        authenticate_leaves: bool,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<crate::merkle::VerifiedMerkleClosure, CampaignRepositoryError> {
        let Self::Checked {
            repository,
            saved,
            operation,
        } = self
        else {
            return if authenticate_leaves {
                self.repository()
                    .merkle
                    .verify_closure_objects_cached(root, verified_positions)
                    .map_err(CampaignRepositoryError::from)
            } else {
                self.repository()
                    .merkle
                    .verify_closure_structure_cached(root, verified_positions)
                    .map_err(CampaignRepositoryError::from)
            };
        };

        let operation = operation.as_ref();
        let mut semantic = None;
        let mut supervised = || poll_saved(saved, boundary);
        let result = crucible_store::ram::with_store_operation_boundary(
            operation,
            &mut supervised,
            |checked| {
                let result = if authenticate_leaves {
                    repository
                        .merkle
                        .verify_closure_objects_cached_with_boundary(
                            root,
                            verified_positions,
                            operation,
                            checked,
                        )
                } else {
                    repository
                        .merkle
                        .verify_closure_structure_cached_with_boundary(
                            root,
                            verified_positions,
                            operation,
                            checked,
                        )
                };
                match result {
                    Ok(closure) => Ok(closure),
                    Err(crate::CampaignStoreError::Store(source)) => Err(source),
                    Err(source) => {
                        semantic = Some(source);
                        Err(StoreError::Corrupt { id: root })
                    }
                }
            },
        );
        match (semantic, result) {
            (
                Some(source),
                Err(crucible_store::ram::RamStoreError::Store(StoreError::Corrupt { id })),
            ) if id == root => Err(source.into()),
            (_, result) => result.map_err(map_checked_error),
        }
    }

    fn checked_merkle<T>(
        &self,
        failure_id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
        action: impl FnOnce(
            &CampaignRepository,
            &DecodeBudget,
            &mut dyn FnMut() -> Result<(), StoreError>,
        ) -> Result<T, crate::CampaignStoreError>,
    ) -> Result<T, CampaignRepositoryError> {
        let Self::Checked {
            repository,
            saved,
            operation,
        } = self
        else {
            return Err(StoreError::Unsupported {
                capability: "campaign-closure-checked-merkle-read",
            }
            .into());
        };
        let operation = operation.as_ref();
        let mut semantic = None;
        let mut supervised = || poll_saved(saved, boundary);
        let result = crucible_store::ram::with_store_operation_boundary(
            operation,
            &mut supervised,
            |checked| match action(repository, operation, checked) {
                Ok(value) => Ok(value),
                Err(crate::CampaignStoreError::Store(source)) => Err(source),
                Err(source) => {
                    semantic = Some(source);
                    Err(StoreError::Corrupt { id: failure_id })
                }
            },
        );
        match (semantic, result) {
            (
                Some(source),
                Err(crucible_store::ram::RamStoreError::Store(StoreError::Corrupt { id })),
            ) if id == failure_id => Err(source.into()),
            (_, result) => result.map_err(map_checked_error),
        }
    }

    pub(super) fn charge_btree_entry<K, V>(&self) -> Result<(), CampaignRepositoryError> {
        let Some(operation) = self.operation() else {
            return Ok(());
        };
        operation
            .charge_btree_entry::<K, V>()
            .map_err(CampaignCodecError::from)
            .map_err(CampaignRepositoryError::from)
    }

    pub(super) fn push<T>(
        &self,
        values: &mut Vec<T>,
        value: T,
    ) -> Result<(), CampaignRepositoryError> {
        if let Some(operation) = self.operation()
            && std::mem::size_of::<T>() != 0
            && values.len() == values.capacity()
        {
            // Eight slots cover RawVec's largest small-element minimum. Later
            // growth doubles, so repeated traversal pushes remain logarithmic.
            // The monotone operation retains every prior growth charge.
            let target = values
                .capacity()
                .checked_mul(2)
                .ok_or(StoreError::Quota)?
                .max(8)
                .max(values.len().checked_add(1).ok_or(StoreError::Quota)?);
            let additional = target.checked_sub(values.len()).ok_or(StoreError::Quota)?;
            let _scope = operation.enter();
            crucible_store::owned_decode::reserve_vec(values, additional)
                .map_err(CampaignCodecError::from)?;
        }
        values.push(value);
        Ok(())
    }

    pub(super) fn operation(&self) -> Option<&DecodeBudget> {
        match self {
            Self::Compatibility(_) => None,
            Self::Checked { operation, .. } => Some(operation.as_ref()),
        }
    }

    pub(super) const fn is_checked(&self) -> bool {
        matches!(self, Self::Checked { .. })
    }

    pub(super) fn enter_operation(&self) -> Option<crucible_store::owned_decode::DecodeScope> {
        self.operation().map(DecodeBudget::enter)
    }

    pub(super) fn retained_operation(&self) -> Option<DecodeBudget> {
        match self {
            Self::Checked { operation, .. } => Some(operation.as_ref().clone()),
            Self::Compatibility(_) => None,
        }
    }

    pub(in crate::repository) fn semantic<'context>(
        &'context self,
        boundary: &'context mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> ClosureSemanticRead<'context, 'a> {
        ClosureSemanticRead {
            reader: self,
            boundary,
        }
    }

    fn repository(&self) -> &CampaignRepository {
        match self {
            Self::Compatibility(repository) | Self::Checked { repository, .. } => repository,
        }
    }
}

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn repository(&self) -> &CampaignRepository {
        self.reader.repository()
    }

    pub(in crate::repository) fn poll(&mut self) -> Result<(), CampaignRepositoryError> {
        self.reader.poll(self.boundary)
    }

    pub(in crate::repository) fn enter_operation(
        &self,
    ) -> Option<crucible_store::owned_decode::DecodeScope> {
        self.reader.enter_operation()
    }

    pub(in crate::repository) fn read_envelope(
        &mut self,
        id: ContentId,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        if !self.reader.is_checked() {
            return self.repository().read_envelope(id);
        }
        let bytes = self.reader.read_envelope_bytes(id, self.boundary)?;
        let envelope = ObjectEnvelope::from_canonical_bytes(bytes.as_ref())?;
        if envelope.content_id() != id {
            return Err(integrity("envelope-content-id-mismatch"));
        }
        Ok(envelope)
    }

    pub(in crate::repository) fn read_content_envelope(
        &mut self,
        id: ContentId,
    ) -> Result<(ContentEnvelope, u64), CampaignRepositoryError> {
        let bytes = self.reader.read_envelope_bytes(id, self.boundary)?;
        let logical_length = u64::try_from(bytes.as_ref().len()).map_err(|_| StoreError::Quota)?;
        let envelope = ContentEnvelope::from_canonical_bytes(bytes.as_ref())
            .map_err(CampaignCodecError::from)?;
        if envelope.content_id(id.kind()) != id {
            return Err(integrity("campaign-closure-envelope-id-mismatch"));
        }
        Ok((envelope, logical_length))
    }

    pub(in crate::repository) fn require_record_kind(
        &mut self,
        id: ContentId,
        expected: crate::CampaignRecordKind,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != expected {
            return Err(integrity("campaign-child-record-kind-mismatch"));
        }
        Ok(envelope)
    }

    pub(in crate::repository) fn authenticate_opaque(
        &mut self,
        id: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        self.reader.authenticate_opaque(id, self.boundary)
    }

    pub(in crate::repository) fn verify_merkle_closure(
        &mut self,
        root: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        self.reader
            .verify_merkle_closure(root, &mut BTreeSet::new(), true, self.boundary)
            .map(|_| ())
    }

    pub(in crate::repository) fn validate_complete_head(
        &mut self,
        head: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        if !self.reader.is_checked() {
            return self.reader.repository().validate_complete_head(head);
        }

        let mut choice_cache = ChoiceValidationCache::default();
        self.validate_snapshot_ancestry(head, &mut choice_cache, MAX_SNAPSHOT_ANCESTRY)?;

        let ClosureRead::Checked {
            repository,
            saved,
            operation,
        } = self.reader
        else {
            return Err(integrity("campaign-closure-checked-reader-is-missing"));
        };
        repository.verify_campaign_closures_anchored_cached_collect(
            [head],
            &BTreeSet::new(),
            &mut choice_cache,
            super::incremental::ClosureCollection {
                checked_original: Some(saved),
                checked_operation: Some(operation.as_ref()),
                ..super::incremental::ClosureCollection::default()
            },
            self.boundary,
        )?;
        Ok(())
    }

    pub(in crate::repository) fn charge_btree_entry<K, V>(
        &self,
    ) -> Result<(), CampaignRepositoryError> {
        self.reader.charge_btree_entry::<K, V>()
    }

    pub(in crate::repository) fn insert_set<T: Ord>(
        &self,
        values: &mut std::collections::BTreeSet<T>,
        value: T,
    ) -> Result<bool, CampaignRepositoryError> {
        if values.contains(&value) {
            return Ok(false);
        }
        self.charge_btree_entry::<T, ()>()?;
        Ok(values.insert(value))
    }

    pub(in crate::repository) fn insert_map<K: Ord, V>(
        &self,
        values: &mut std::collections::BTreeMap<K, V>,
        key: K,
        value: V,
    ) -> Result<Option<V>, CampaignRepositoryError> {
        if !values.contains_key(&key) {
            self.charge_btree_entry::<K, V>()?;
        }
        Ok(values.insert(key, value))
    }

    pub(in crate::repository) fn push<T>(
        &self,
        values: &mut Vec<T>,
        value: T,
    ) -> Result<(), CampaignRepositoryError> {
        self.reader.push(values, value)
    }

    pub(in crate::repository) fn merkle_get(
        &mut self,
        root: ContentId,
        key: crate::CampaignHash,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        if !self.reader.is_checked() {
            return self
                .repository()
                .merkle
                .get(root, key)
                .map_err(CampaignRepositoryError::from);
        }
        self.reader
            .checked_merkle(root, self.boundary, |repository, operation, checked| {
                repository
                    .merkle
                    .get_with_boundary(root, key, operation, checked)
            })
    }

    pub(in crate::repository) fn merkle_inspect_shallow(
        &mut self,
        root: ContentId,
    ) -> Result<crate::merkle::MerkleMapRoot, CampaignRepositoryError> {
        if !self.reader.is_checked() {
            return self
                .repository()
                .merkle
                .inspect_shallow(root)
                .map_err(CampaignRepositoryError::from);
        }
        self.reader
            .checked_merkle(root, self.boundary, |repository, operation, checked| {
                repository
                    .merkle
                    .inspect_shallow_with_boundary(root, operation, checked)
            })
    }

    pub(in crate::repository) fn merkle_scan(
        &mut self,
        root: ContentId,
        after: Option<crate::CampaignHash>,
        limit: usize,
    ) -> Result<crate::merkle::MerkleMapPage, CampaignRepositoryError> {
        if !self.reader.is_checked() {
            return self
                .repository()
                .merkle
                .scan(root, after, limit)
                .map_err(CampaignRepositoryError::from);
        }
        self.reader
            .checked_merkle(root, self.boundary, |repository, operation, checked| {
                repository
                    .merkle
                    .scan_with_boundary(root, after, limit, operation, checked)
            })
    }

    pub(in crate::repository) fn merkle_equals_after_upserts(
        &mut self,
        prior: ContentId,
        next: ContentId,
        upserts: &std::collections::BTreeMap<crate::CampaignHash, ContentId>,
    ) -> Result<bool, CampaignRepositoryError> {
        if !self.reader.is_checked() {
            return self
                .repository()
                .merkle
                .equals_after_upserts(prior, next, upserts)
                .map_err(CampaignRepositoryError::from);
        }
        self.reader
            .checked_merkle(next, self.boundary, |repository, operation, checked| {
                repository
                    .merkle
                    .root_after_upserts_with_boundary(prior, upserts, operation, checked)
            })
            .map(|expected| expected == next)
    }

    pub(in crate::repository) fn merkle_root_after_edits(
        &mut self,
        prior: ContentId,
        edits: &std::collections::BTreeMap<crate::CampaignHash, Option<ContentId>>,
    ) -> Result<ContentId, CampaignRepositoryError> {
        if !self.reader.is_checked() {
            return self
                .repository()
                .merkle
                .root_after_edits(prior, edits)
                .map_err(CampaignRepositoryError::from);
        }
        self.reader
            .checked_merkle(prior, self.boundary, |repository, operation, checked| {
                repository
                    .merkle
                    .root_after_edits_with_boundary(prior, edits, operation, checked)
            })
    }

    pub(in crate::repository) fn merkle_root_after_upserts(
        &mut self,
        prior: ContentId,
        upserts: &std::collections::BTreeMap<crate::CampaignHash, ContentId>,
    ) -> Result<ContentId, CampaignRepositoryError> {
        if !self.reader.is_checked() {
            return self
                .repository()
                .merkle
                .root_after_upserts(prior, upserts)
                .map_err(CampaignRepositoryError::from);
        }
        self.reader
            .checked_merkle(prior, self.boundary, |repository, operation, checked| {
                repository
                    .merkle
                    .root_after_upserts_with_boundary(prior, upserts, operation, checked)
            })
    }
}

impl ClosureOperation<'_> {
    fn as_ref(&self) -> &DecodeBudget {
        match self {
            Self::Owned(operation) => operation,
            Self::Borrowed(operation) => operation,
        }
    }
}

fn poll_saved(
    saved: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
) -> Result<(), crucible_store::ram::RamStoreError> {
    saved
        .verify_live()
        .map_err(|source| crucible_store::ram::RamStoreError::from_admission(saved, source))?;
    boundary()?;
    saved
        .verify_live()
        .map_err(|source| crucible_store::ram::RamStoreError::from_admission(saved, source))
}

fn map_checked_error(source: crucible_store::ram::RamStoreError) -> CampaignRepositoryError {
    match source {
        source @ crucible_store::ram::RamStoreError::Store(
            StoreError::RamReadBoundary { .. }
            | StoreError::RamReadValidation { .. }
            | StoreError::RamReadContinuation { .. },
        ) => CampaignRepositoryError::Ram(source),
        crucible_store::ram::RamStoreError::Store(source) => CampaignRepositoryError::Store(source),
        source => CampaignRepositoryError::Ram(source),
    }
}
