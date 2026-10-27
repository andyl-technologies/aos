//! Checks exact native probe and fresh Commit catalog publication boundaries.
//!
//! All values are observations from actual held selection or the forwarded native
//! executor. These comparisons neither create lineage nor grant publication rights.

use super::{BucketBinding, Clock, Fixture, RecordRead, TestResult, assert_read_unchanged};
use std::collections::BTreeMap;
use terrane_format::{
    bucket::BucketCapabilities,
    gc::publication::{
        PortableCurrent, PortableSnapshot, PredecessorSlot, PublicationCommit, PublicationProof,
        PublicationState,
    },
    identity::Digest,
};

/// Retains a complete independently held selection for a calibration boundary.
pub(super) struct Selection {
    state: PublicationState,
    logical: BTreeMap<String, Option<Vec<u8>>>,
    stamp: (u64, Digest),
    snapshot: PortableCurrent,
    control_identity: (u64, u64),
    reads: Vec<RecordRead>,
}

impl Selection {
    /// Captures actual backend selection and completes its unchanged-read check.
    ///
    /// # Errors
    /// Propagates unavailable or contradictory held publication observations.
    pub(super) async fn capture<C: Clock + BucketBinding + Clone + Sync + 'static>(
        fixture: &Fixture<C>,
    ) -> TestResult<Self> {
        let holder = crate::bucket::held::SingleHeld::acquire(fixture.bucket()).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        let selection = Self {
            state: observed.state().clone(),
            logical: observed.logical().clone(),
            stamp: observed.stamp(),
            snapshot: observed.snapshot().clone(),
            control_identity: observed.control_identity(),
            reads: observed.physical_reads().to_vec(),
        };
        observed.revalidate().await?;
        Ok(selection)
    }

    /// Checks zero publication or exactly one bound Raw probe timestamp update.
    ///
    /// # Errors
    /// Propagates malformed canonical records or unavailable exact retained reads.
    ///
    /// # Panics
    /// Panics on any additional publication, changed non-probe state or broken
    /// native slot, transaction, snapshot, predecessor or ACK association.
    pub(super) async fn assert_probe_successor<
        C: Clock + BucketBinding + Clone + Sync + 'static,
    >(
        &self,
        fixture: &Fixture<C>,
        after: &Self,
        mutation_start: usize,
    ) -> TestResult {
        assert_eq!(self.control_identity, after.control_identity);
        assert_eq!(self.stamp.0, self.state.revision);
        assert_eq!(after.stamp.0, after.state.revision);
        // Selected slots, transactions, snapshots, registration and ref logs are
        // immutable. The previous observed absent next slot may become present.
        for read in self.reads.iter().filter(|read| read.bytes().is_some()) {
            assert_read_unchanged(&fixture.fs, read).await?;
        }

        let mutations = fixture.fs.mutations();
        let observed = mutations
            .get(mutation_start..)
            .ok_or("calibration mutation observer was reset")?;
        let old_cap = self.capabilities()?;
        let new_cap = after.capabilities()?;
        if old_cap == new_cap {
            assert!(
                observed.is_empty(),
                "unchanged probe published a transaction"
            );
            assert_eq!(after.state, self.state);
            assert_eq!(after.logical, self.logical);
            assert_eq!(after.stamp, self.stamp);
            assert_eq!(after.snapshot, self.snapshot);
            return Ok(());
        }

        let [row] = observed else {
            panic!("changed probe requires exactly one observed native publication");
        };
        assert!(row.acknowledged, "probe successor lacks actual native ACK");
        let transaction = &row.transaction;
        assert_eq!(transaction.encode()?, row.transaction_bytes);
        assert!(matches!(transaction.proof, PublicationProof::Raw));
        assert_eq!(transaction.old.as_ref(), Some(&self.state));
        assert_eq!(transaction.new, after.state);
        assert_eq!(
            transaction.predecessor,
            Some(PredecessorSlot {
                revision: self.stamp.0,
                digest: self.stamp.1,
            })
        );

        let mut expected_state = self.state.clone();
        expected_state.revision = expected_state
            .revision
            .checked_add(1)
            .ok_or("probe revision overflow")?;
        assert_eq!(after.state, expected_state);
        let mut expected_cap = BucketCapabilities::decode(old_cap)?;
        let next_cap = BucketCapabilities::decode(new_cap)?;
        assert_eq!(expected_cap.encode()?.as_slice(), old_cap);
        assert_eq!(next_cap.encode()?.as_slice(), new_cap);
        assert_ne!(expected_cap.probed_at, next_cap.probed_at);
        expected_cap.probed_at = next_cap.probed_at;
        assert_eq!(next_cap, expected_cap);
        let [change] = transaction.changes.as_slice() else {
            panic!("probe successor requires exactly one logical change");
        };
        assert_eq!(change.key, "CAPABILITIES");
        assert_eq!(change.expected.as_deref(), Some(old_cap));
        assert_eq!(change.new.as_deref(), Some(new_cap));
        let mut expected_logical = self.logical.clone();
        expected_logical.insert("CAPABILITIES".into(), Some(new_cap.to_vec()));
        assert_eq!(after.logical, expected_logical);

        let slot = PublicationCommit::decode(&row.slot_bytes)?;
        assert_eq!(slot.encode()?, row.slot_bytes);
        assert_eq!(slot.revision, after.stamp.0);
        assert_eq!(slot.predecessor, Some(self.stamp.1));
        assert_eq!(*blake3::hash(&row.slot_bytes).as_bytes(), after.stamp.1);
        slot.check_transaction(
            &format!("publication/commits/{}", slot.revision),
            &row.transaction_bytes,
        )?;
        transaction.check_key(&slot.transaction_key)?;
        let control = row
            .path
            .ancestors()
            .nth(3)
            .ok_or("actual native slot control")?;
        assert_eq!(
            row.path,
            control.join(format!("publication/commits/{}", after.stamp.0))
        );
        for (path, expected_bytes) in [
            (row.path.clone(), row.slot_bytes.as_slice()),
            (
                control.join(&slot.transaction_key),
                row.transaction_bytes.as_slice(),
            ),
        ] {
            let read = after
                .reads
                .iter()
                .find(|read| read.path() == path)
                .ok_or("actual selected native slot or transaction read")?;
            assert_eq!(read.bytes(), Some(expected_bytes));
            assert_read_unchanged(&fixture.fs, read).await?;
        }
        let old_slot = self
            .reads
            .iter()
            .find(|read| {
                read.path() == control.join(format!("publication/commits/{}", self.stamp.0))
            })
            .and_then(RecordRead::bytes)
            .ok_or("actual prior selected native slot")?;
        assert_eq!(*blake3::hash(old_slot).as_bytes(), self.stamp.1);
        assert_eq!(transaction.snapshot, after.snapshot);
        let snapshot_read = after
            .reads
            .iter()
            .find(|read| read.path() == fixture.bucket().root().join(&after.snapshot.key))
            .ok_or("actual selected portable snapshot read")?;
        let snapshot_bytes = snapshot_read.bytes().ok_or("selected snapshot bytes")?;
        transaction.check_snapshot(snapshot_bytes)?;
        let snapshot = PortableSnapshot::decode(snapshot_bytes)?;
        assert_eq!(snapshot.encode()?.as_slice(), snapshot_bytes);
        if let Some(predecessor) = snapshot.predecessor {
            assert_eq!(predecessor, self.snapshot);
        }
        assert_read_unchanged(&fixture.fs, snapshot_read).await?;
        Ok(())
    }

    /// Borrows the complete independently selected publication state.
    pub(super) fn state(&self) -> &PublicationState {
        &self.state
    }

    /// Checks the sole fresh Commit catalog publication and its Candidate successor.
    ///
    /// # Errors
    /// Propagates unavailable physical records and malformed canonical bindings.
    ///
    /// # Panics
    /// Panics on another publication, descriptor, state change or missing native ACK.
    pub(super) async fn assert_commit_catalog_chain<
        C: Clock + BucketBinding + Clone + Sync + 'static,
    >(
        &self,
        fixture: &Fixture<C>,
        target: &str,
        record: &terrane_format::refs::RefRecord,
    ) -> TestResult {
        let commit = &record.commit;
        use crate::{
            pack::{EntryKind, MergedShard, PackId, PackReader, RawBodyDecoder, RecordState},
            store::LocalFs,
        };
        use terrane_format::{
            bucket::{BucketCapabilities, GenerationManifest},
            identity::{IdentityKind, TERRANE_V1},
        };

        let rows = fixture.fs.mutations();
        let [catalog, candidate] = rows.as_slice() else {
            panic!(
                "cold fork requires exactly one fresh Commit catalog and one Candidate publication"
            );
        };
        assert!(matches!(catalog.transaction.proof, PublicationProof::Raw));
        assert!(matches!(
            candidate.transaction.proof,
            PublicationProof::Candidate(_)
        ));
        let final_selection = Self::capture(fixture).await?;
        assert_eq!(final_selection.control_identity, self.control_identity);
        for read in self.reads.iter().filter(|read| read.bytes().is_some()) {
            assert_read_unchanged(&fixture.fs, read).await?;
        }

        let mut state = self.state.clone();
        let mut logical = self.logical.clone();
        let mut stamp = self.stamp;
        let mut snapshot = self.snapshot.clone();
        for row in &rows {
            assert!(
                row.acknowledged,
                "publication lacks actual native executor ACK"
            );
            assert!(fixture.fs.effects().contains(&(
                if matches!(row.transaction.proof, PublicationProof::Raw) {
                    "SealRawPublication".into()
                } else {
                    "SealMutationPublication".into()
                },
                Some(row.path.clone())
            )));
            let transaction = &row.transaction;
            assert_eq!(transaction.encode()?, row.transaction_bytes);
            assert_eq!(transaction.old.as_ref(), Some(&state));
            assert_eq!(
                transaction.predecessor,
                Some(PredecessorSlot {
                    revision: stamp.0,
                    digest: stamp.1
                })
            );
            assert_eq!(
                transaction.new.revision,
                state.revision.checked_add(1).ok_or("revision overflow")?
            );
            let slot = PublicationCommit::decode(&row.slot_bytes)?;
            assert_eq!(slot.encode()?, row.slot_bytes);
            assert_eq!(slot.revision, transaction.new.revision);
            assert_eq!(slot.predecessor, Some(stamp.1));
            slot.check_transaction(
                &format!("publication/commits/{}", slot.revision),
                &row.transaction_bytes,
            )?;
            transaction.check_key(&slot.transaction_key)?;
            let control = row.path.ancestors().nth(3).ok_or("native slot control")?;
            assert_eq!(
                row.path,
                control.join(format!("publication/commits/{}", slot.revision))
            );
            assert_eq!(fixture.fs.read_nofollow(&row.path).await?, row.slot_bytes);
            assert_eq!(
                fixture
                    .fs
                    .read_nofollow(&control.join(&slot.transaction_key))
                    .await?,
                row.transaction_bytes
            );
            let portable_bytes = fixture
                .fs
                .read_nofollow(&fixture.bucket().root().join(&transaction.snapshot.key))
                .await?;
            transaction.check_snapshot(&portable_bytes)?;
            let portable = PortableSnapshot::decode(&portable_bytes)?;
            assert_eq!(portable.encode()?, portable_bytes);
            assert_eq!(portable.revision, transaction.new.revision);
            assert_eq!(portable.origin, transaction.new.binding);
            for change in &transaction.changes {
                assert_eq!(logical.get(&change.key).cloned().flatten(), change.expected);
                logical.insert(change.key.clone(), change.new.clone());
            }
            let expected_projection = if portable.predecessor.is_some() {
                assert_eq!(portable.predecessor.as_ref(), Some(&snapshot));
                transaction
                    .changes
                    .iter()
                    .map(|change| (change.key.clone(), change.new.clone()))
                    .collect::<BTreeMap<_, _>>()
            } else {
                logical.clone()
            };
            assert_eq!(
                portable
                    .projection
                    .iter()
                    .map(|row| (row.key.clone(), row.value.clone()))
                    .collect::<BTreeMap<_, _>>(),
                expected_projection
            );
            state = transaction.new.clone();
            stamp = (slot.revision, *blake3::hash(&row.slot_bytes).as_bytes());
            snapshot = transaction.snapshot.clone();
        }
        assert_eq!(state, final_selection.state);
        assert_eq!(logical, final_selection.logical);
        assert_eq!(stamp, final_selection.stamp);
        assert_eq!(snapshot, final_selection.snapshot);

        let mut expected_state = self.state.clone();
        expected_state.revision = expected_state
            .revision
            .checked_add(1)
            .ok_or("catalog revision overflow")?;
        assert_eq!(catalog.transaction.new, expected_state);
        let cap_change = catalog
            .transaction
            .changes
            .iter()
            .find(|row| row.key == "CAPABILITIES")
            .ok_or("catalog CAPABILITIES change")?;
        assert_eq!(cap_change.expected.as_deref(), Some(self.capabilities()?));
        let mut old_cap = BucketCapabilities::decode(self.capabilities()?)?;
        let new_cap = BucketCapabilities::decode(
            cap_change
                .new
                .as_deref()
                .ok_or("catalog successor capabilities")?,
        )?;
        assert_eq!(
            new_cap.generation,
            Some(
                old_cap
                    .generation
                    .ok_or("prior generation")?
                    .checked_add(1)
                    .ok_or("generation overflow")?
            )
        );
        let old_generation = old_cap.generation.ok_or("prior generation")?;
        let new_generation = new_cap.generation.ok_or("successor generation")?;
        old_cap.generation = new_cap.generation;
        assert_eq!(
            new_cap, old_cap,
            "catalog changes no other capability field"
        );
        assert_eq!(
            new_cap.encode()?,
            cap_change.new.clone().ok_or("new capabilities")?
        );
        let old_manifest_key = format!("objects/index/{old_generation}/MANIFEST");
        let old_manifest = GenerationManifest::decode(
            self.logical
                .get(&old_manifest_key)
                .and_then(Option::as_deref)
                .ok_or("prior manifest")?,
        )?;
        let new_manifest_key = format!("objects/index/{new_generation}/MANIFEST");
        let manifest_change = catalog
            .transaction
            .changes
            .iter()
            .find(|row| row.key == new_manifest_key)
            .ok_or("successor manifest")?;
        assert_eq!(manifest_change.expected, None);
        let new_manifest_bytes = manifest_change
            .new
            .as_deref()
            .ok_or("successor manifest bytes")?;
        let new_manifest = GenerationManifest::decode(new_manifest_bytes)?;
        assert_eq!(new_manifest.encode()?.as_slice(), new_manifest_bytes);
        assert_eq!(new_manifest.generation, new_generation);
        assert_eq!(new_manifest.cycle, old_manifest.cycle);
        assert_eq!(new_manifest.exclusions, old_manifest.exclusions);
        assert_eq!(new_manifest.burns, old_manifest.burns);
        let old_inventory = old_manifest
            .inventory
            .as_ref()
            .ok_or("complete prior inventory")?;
        let new_inventory = new_manifest
            .inventory
            .as_ref()
            .ok_or("complete successor inventory")?;
        assert!(old_inventory.iter().all(|row| new_inventory.contains(row)));
        let additions = new_inventory
            .iter()
            .filter(|row| !old_inventory.contains(row))
            .collect::<Vec<_>>();
        let [addition] = additions.as_slice() else {
            panic!("fresh Commit adds exactly one pack");
        };
        assert_eq!(new_inventory.len(), old_inventory.len() + 1);
        let pack_id = PackId::from_random_bytes(addition.pack_id);
        let pack_bytes = fixture
            .fs
            .read_nofollow(&fixture.bucket().root().join(pack_id.pack_key()))
            .await?;
        let index_bytes = fixture
            .fs
            .read_nofollow(&fixture.bucket().root().join(pack_id.index_key()))
            .await?;
        assert_eq!(pack_bytes.len() as u64, addition.pack_size);
        assert_eq!(index_bytes.len() as u64, addition.index_size);
        TERRANE_V1.verify(
            &TERRANE_V1.from_digest(IdentityKind::Pack, &addition.pack_hash)?,
            &pack_bytes,
        )?;
        TERRANE_V1.verify(
            &TERRANE_V1.from_digest(IdentityKind::Index, &addition.index_hash)?,
            &index_bytes,
        )?;
        let pack = PackReader::open(&pack_bytes)?;
        pack.check_index_object(&index_bytes)?;
        let [entry] = pack.entries() else {
            panic!("fresh pack contains only the signed Commit");
        };
        assert_eq!(entry.kind(), EntryKind::Commit);
        assert_eq!(entry.hash(), commit);
        let actual_commit = pack.read(EntryKind::Commit, commit, &RawBodyDecoder)?;
        assert_eq!(
            terrane_format::refs::Commit::decode(&actual_commit)?.identity()?,
            *commit
        );

        let mut expected_candidate_keys = vec![
            "CAPABILITIES".to_owned(),
            "publication/SELECTED-HISTORY".to_owned(),
            format!("{target}:record"),
        ];
        expected_candidate_keys.sort();
        assert_eq!(
            candidate
                .transaction
                .changes
                .iter()
                .map(|row| row.key.clone())
                .collect::<Vec<_>>(),
            expected_candidate_keys
        );
        let candidate_cap = candidate
            .transaction
            .changes
            .iter()
            .find(|row| row.key == "CAPABILITIES")
            .ok_or("Candidate capability change")?;
        assert_eq!(candidate_cap.expected.as_ref(), cap_change.new.as_ref());
        let mut expected_cap = new_cap.clone();
        let names = expected_cap
            .ref_names
            .as_mut()
            .ok_or("complete ref names")?;
        let position = names
            .binary_search_by(|name| name.as_bytes().cmp(target.as_bytes()))
            .err()
            .ok_or("fresh target absent from old names")?;
        names.insert(position, target.to_owned());
        assert_eq!(
            candidate_cap.new.as_deref(),
            Some(expected_cap.encode()?.as_slice())
        );
        let target_change = candidate
            .transaction
            .changes
            .iter()
            .find(|row| row.key == format!("{target}:record"))
            .ok_or("Candidate target record")?;
        assert_eq!(target_change.expected, None);
        assert_eq!(
            target_change.new.as_deref(),
            Some(record.encode()?.as_slice())
        );

        let mut old_entries = Vec::new();
        for shard in &old_manifest.shards {
            let key = format!("objects/index/{old_generation}/{}.idx", shard.shard);
            let bytes = self
                .logical
                .get(&key)
                .and_then(Option::as_deref)
                .ok_or("prior shard")?;
            old_entries.extend_from_slice(
                MergedShard::decode(bytes, old_generation, u8::try_from(shard.shard)?)?.entries(),
            );
        }
        let mut new_entries = Vec::new();
        let mut allowed_keys = vec!["CAPABILITIES".to_owned(), new_manifest_key];
        for shard in &new_manifest.shards {
            let key = format!("objects/index/{new_generation}/{}.idx", shard.shard);
            allowed_keys.push(key.clone());
            let change = catalog
                .transaction
                .changes
                .iter()
                .find(|row| row.key == key)
                .ok_or("successor shard change")?;
            assert_eq!(change.expected, None);
            let bytes = change.new.as_deref().ok_or("successor shard bytes")?;
            assert_eq!(bytes.len() as u64, shard.index_size);
            TERRANE_V1.verify(
                &TERRANE_V1.from_digest(IdentityKind::Index, &shard.index_hash)?,
                bytes,
            )?;
            let decoded = MergedShard::decode(bytes, new_generation, u8::try_from(shard.shard)?)?;
            assert_eq!(decoded.encode().as_slice(), bytes);
            new_entries.extend_from_slice(decoded.entries());
            if let Some((hash, size)) = shard.filter {
                let filter_key = format!("objects/index/{new_generation}/{}.flt", shard.shard);
                allowed_keys.push(filter_key.clone());
                let filter = catalog
                    .transaction
                    .changes
                    .iter()
                    .find(|row| row.key == filter_key)
                    .ok_or("unchanged copied filter")?;
                assert_eq!(filter.expected, None);
                let bytes = filter.new.as_deref().ok_or("filter bytes")?;
                assert_eq!(bytes.len() as u64, size);
                TERRANE_V1.verify(&TERRANE_V1.from_digest(IdentityKind::Filter, &hash)?, bytes)?;
                assert_eq!(
                    self.logical
                        .get(&format!(
                            "objects/index/{old_generation}/{}.flt",
                            shard.shard
                        ))
                        .and_then(Option::as_deref),
                    Some(bytes)
                );
            }
        }
        assert!(old_entries.iter().all(|entry| new_entries.contains(entry)));
        let additions = new_entries
            .iter()
            .filter(|entry| !old_entries.contains(entry))
            .collect::<Vec<_>>();
        let [added] = additions.as_slice() else {
            panic!("catalog adds only one fresh Commit descriptor");
        };
        assert_eq!(new_entries.len(), old_entries.len() + 1);
        assert_eq!(added.pack(), pack_id);
        assert_eq!(added.entry(), entry);
        assert_eq!(added.state(), RecordState::Live);
        allowed_keys.sort();
        assert_eq!(
            catalog
                .transaction
                .changes
                .iter()
                .map(|row| row.key.clone())
                .collect::<Vec<_>>(),
            allowed_keys
        );
        Ok(())
    }

    fn capabilities(&self) -> TestResult<&[u8]> {
        self.logical
            .get("CAPABILITIES")
            .and_then(Option::as_deref)
            .ok_or_else(|| "actual selected capabilities".into())
    }
}
