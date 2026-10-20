//! Resolves portable copy data without importing protected source authority.
//!
//! Exact snapshot predecessors reconstruct the current projection. Existing
//! catalog, container, content and selected-log validators check its closure;
//! repository graph interpretation remains above the opaque store boundary.

use super::{corrupt, projection, receipts::RecordRead};
use crate::bucket::content::VerifiedBody;
use crate::bucket::{BucketBinding, FileBucket, catalog::Catalog};
use crate::pack::{MergedEntry, MergedShard, PackId, PackReader, RecordState};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use std::collections::{BTreeMap, BTreeSet};
use terrane_format::bucket::{BucketKey, GenerationManifest};
use terrane_format::gc::publication::{
    BackendBinding, CommittedSelection, PermanentBurnOwner, PermanentOwnerSelection,
    PortableCurrent, PortableSnapshot, PublicationState, SelectedHistory,
};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::refs::{RefClass, RefName, RefRecord};

/// Carries complete verified ordinary data, never a registration capability.
pub(crate) struct CopyPayload {
    /// Complete ordinary projection, including explicit ref and lease absence.
    pub(crate) logical: BTreeMap<String, Option<Vec<u8>>>,
    /// Source data stamp, without physical or original-authority capability.
    pub(crate) origin: BackendBinding,
    /// Every exact input whose bytes were validated under the destination lock.
    pub(crate) reads: Vec<RecordRead>,
}

/// Builds visibility-only destination state from a complete portable catalog.
///
/// # Errors
/// Rejects missing history or malformed catalog data. Unknown legacy burn
/// completeness remains unknown and grants no destructive or readmission rights.
pub(crate) fn state(
    logical: &projection::Values,
    binding: BackendBinding,
) -> Result<PublicationState, StoreFailure> {
    let cap = projection::capabilities(logical)?;
    let history =
        SelectedHistory::decode(projection::value(logical, "publication/SELECTED-HISTORY")?)
            .map_err(|_| corrupt())?;
    let manifest = GenerationManifest::decode(projection::value(
        logical,
        &format!(
            "objects/index/{}/MANIFEST",
            cap.generation.ok_or_else(corrupt)?
        ),
    )?)
    .map_err(|_| corrupt())?;
    let owners = manifest.burns.map(|burns| {
        burns
            .into_iter()
            .map(|pack| PermanentBurnOwner {
                pack,
                selection: PermanentOwnerSelection::CopiedVisibility,
            })
            .collect()
    });
    Ok(PublicationState {
        revision: 0,
        loss_generation: 0,
        binding,
        sources: Vec::new(),
        branches: history.branches,
        guard: None,
        burn_owners: owners,
    })
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Reads one exact pointer and its acyclic complete checkpoint ancestry.
    ///
    /// # Errors
    /// Rejects missing, malformed or contradictory snapshots and incomplete
    /// payload or selected-log closure. Individual mutable caches are ignored.
    pub(in crate::bucket) async fn portable_copy_payload(
        &self,
    ) -> Result<CopyPayload, StoreFailure> {
        let mut reads = Vec::new();
        let bytes = self.copy_read("publication/PORTABLE", &mut reads).await?;
        let mut pointer = PortableCurrent::decode(&bytes).map_err(|_| corrupt())?;
        let mut snapshots = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(pointer.key.clone()) {
                return Err(corrupt());
            }
            let bytes = self.copy_read(&pointer.key, &mut reads).await?;
            pointer.check_snapshot(&bytes).map_err(|_| corrupt())?;
            let snapshot = PortableSnapshot::decode(&bytes).map_err(|_| corrupt())?;
            if let Some(next) = snapshots.last() {
                let next: &PortableSnapshot = next;
                next.check_predecessor(&pointer, &bytes)
                    .map_err(|_| corrupt())?;
            }
            let previous = snapshot.predecessor.clone();
            snapshots.push(snapshot);
            match previous {
                Some(previous) => pointer = previous,
                None => break,
            }
        }
        let origin = snapshots.first().ok_or_else(corrupt)?.origin.clone();
        let mut logical = None;
        for snapshot in snapshots.iter().rev() {
            let next = projection::apply(snapshot, logical.as_ref())?;
            if let Some(previous) = &logical {
                projection::validate_successor(previous, &next)?;
            }
            logical = Some(next);
        }
        self.validate_copy_payload(logical.ok_or_else(corrupt)?, origin, reads)
            .await
    }

    /// Checks the complete ordinary closure of one already resolved checkpoint.
    ///
    /// # Errors
    /// Rejects incompatible or incomplete catalogs, unavailable eligible bodies,
    /// container disagreements and missing or contradictory selected history.
    pub(in crate::bucket) async fn validate_copy_payload(
        &self,
        logical: projection::Values,
        origin: BackendBinding,
        mut reads: Vec<RecordRead>,
    ) -> Result<CopyPayload, StoreFailure> {
        if logical.get("gc/lease") != Some(&None) {
            return Err(corrupt());
        }
        let state = state(&logical, origin.clone())?;
        projection::validate(self, &state, &logical)?;
        let capabilities = projection::capabilities(&logical)?;
        let generation = capabilities.generation.ok_or_else(corrupt)?;
        let manifest_key = format!("objects/index/{generation}/MANIFEST");
        let manifest = GenerationManifest::decode(projection::value(&logical, &manifest_key)?)
            .map_err(|_| corrupt())?;
        let mut shards = Vec::new();
        for row in &manifest.shards {
            let key = format!("objects/index/{generation}/{}.idx", row.shard);
            let bytes = self.copy_read(&key, &mut reads).await?;
            if bytes != projection::value(&logical, &key)? {
                return Err(corrupt());
            }
            shards.push(
                MergedShard::decode(
                    &bytes,
                    generation,
                    u8::try_from(row.shard).map_err(|_| corrupt())?,
                )
                .map_err(|_| corrupt())?,
            );
            if row.filter.is_some() {
                let key = format!("objects/index/{generation}/{}.flt", row.shard);
                if self.copy_read(&key, &mut reads).await? != projection::value(&logical, &key)? {
                    return Err(corrupt());
                }
            }
        }
        if self.copy_read(&manifest_key, &mut reads).await?
            != projection::value(&logical, &manifest_key)?
        {
            return Err(corrupt());
        }
        let catalog = Catalog {
            capability_bytes: projection::value(&logical, "CAPABILITIES")?.to_vec(),
            capabilities,
            shards,
            inventory: manifest.inventory,
            exclusions: manifest.exclusions,
            burns: manifest.burns,
        };
        let mut containers = BTreeSet::new();
        for row in catalog.inventory.as_ref().ok_or_else(corrupt)? {
            if self.physically_excluded(&catalog, &row.pack_id) {
                continue;
            }
            containers.insert(row.pack_id);
        }
        // Older admitted metadata may have authoritative Live rows without an
        // inventory row. Their exact pack/index preimages still bind validation.
        for row in catalog.shards.iter().flat_map(MergedShard::entries) {
            if row.state() == RecordState::Live
                && !self.physically_excluded(&catalog, row.pack().as_bytes())
            {
                containers.insert(*row.pack().as_bytes());
            }
        }
        let mut retained = BTreeMap::new();
        for id in containers {
            let id = PackId::from_random_bytes(id);
            let pack = self.copy_read(&id.pack_key(), &mut reads).await?;
            let index = self.copy_read(&id.index_key(), &mut reads).await?;
            crate::bucket::containers::admitted_artifacts(id, &pack, &index)?;
            retained.insert(id, (pack, index));
        }
        for row in catalog.inventory.as_ref().ok_or_else(corrupt)? {
            if self.physically_excluded(&catalog, &row.pack_id) {
                continue;
            }
            let id = PackId::from_random_bytes(row.pack_id);
            if retained.get(&id) != Some(&self.verified_container(row).await?) {
                return Err(corrupt());
            }
        }
        for row in catalog.shards.iter().flat_map(MergedShard::entries) {
            if row.state() != RecordState::Live
                || self.physically_excluded(&catalog, row.pack().as_bytes())
            {
                continue;
            }
            let identity = TERRANE_V1
                .from_digest(row.entry().kind().identity_kind(), row.entry().hash())
                .map_err(|_| corrupt())?;
            // A retained old inventory can exclude a detached alias carried in
            // a fresh Live row. The selected serving policy still forbids it.
            if self.is_excluded(&catalog, &identity)? {
                continue;
            }
            let expected = retained_body(&retained, row)?;
            match self.verified_body_outcome(&catalog, &identity).await? {
                VerifiedBody::Bytes(actual) if actual == expected => {}
                VerifiedBody::ExcludedDetachedIndex => {
                    // This independently admitted alias is valid data but never
                    // visible. Its typed hash binds the exact validator input.
                    TERRANE_V1
                        .verify(&identity, expected)
                        .map_err(|_| corrupt())?;
                }
                VerifiedBody::Bytes(_) => return Err(corrupt()),
            }
        }
        // Ref targets independently require an admitted opaque Commit body.
        // Merely resolving other Live rows cannot establish this closure.
        for name in catalog
            .capabilities
            .ref_names
            .as_ref()
            .ok_or_else(corrupt)?
        {
            if RefName::parse(name).map_err(|_| corrupt())?.class() == RefClass::Notes {
                continue;
            }
            if let Some(bytes) = logical
                .get(&format!("{name}:record"))
                .and_then(Option::as_deref)
            {
                let head = RefRecord::decode(bytes).map_err(|_| corrupt())?;
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Commit, &head.commit)
                    .map_err(|_| corrupt())?;
                let actual = self.verified_body(&catalog, &identity).await?;
                let row = catalog
                    .shards
                    .iter()
                    .flat_map(MergedShard::entries)
                    .find(|row| {
                        row.entry().kind().identity_kind() == IdentityKind::Commit
                            && row.entry().hash() == &head.commit
                    })
                    .ok_or_else(corrupt)?;
                if actual != retained_body(&retained, row)? {
                    return Err(corrupt());
                }
            }
        }
        for branch in &state.branches {
            match &branch.selection {
                CommittedSelection::Selected(record) => {
                    self.committed_logs_observed(&branch.name, *record.clone(), &mut reads)
                        .await?;
                }
                CommittedSelection::Never => {}
                CommittedSelection::Unknown => return Err(super::unsupported()),
            }
        }
        Ok(CopyPayload {
            logical,
            origin,
            reads,
        })
    }

    async fn copy_read(
        &self,
        key: &str,
        reads: &mut Vec<RecordRead>,
    ) -> Result<Vec<u8>, StoreFailure> {
        let key = BucketKey::parse(key).map_err(|_| corrupt())?;
        let read = self.read_optional_observed(&key).await?;
        let bytes = read.bytes().ok_or_else(corrupt)?.to_vec();
        reads.push(read);
        Ok(bytes)
    }
}

/// Binds an existing verifier's returned body to its retained whole-container read.
fn retained_body<'a>(
    retained: &'a BTreeMap<PackId, (Vec<u8>, Vec<u8>)>,
    row: &MergedEntry,
) -> Result<&'a [u8], StoreFailure> {
    let (pack, _) = retained.get(&row.pack()).ok_or_else(corrupt)?;
    let reader = PackReader::open(pack).map_err(|_| corrupt())?;
    let entry = reader
        .entries()
        .iter()
        .find(|entry| entry.hash() == row.entry().hash())
        .ok_or_else(corrupt)?;
    if entry != row.entry() {
        return Err(corrupt());
    }
    let start = usize::try_from(entry.offset()).map_err(|_| corrupt())?;
    let end = start
        .checked_add(entry.body_len() as usize)
        .ok_or_else(corrupt)?;
    pack.get(start..end).ok_or_else(corrupt)
}
