//! Rebuilds immutable merged-index shards and applies generation deltas.
//!
//! ```text
//! TRIX | count:u64le | (hash:32, pack-id:16, offset:8, stored:4,
//!                       plain:4, codec:1, kind:1, state:1, reserved:5)*
//! ```

use super::binary::{core_record, native_header, native_record};
use super::{EntryKind, IndexEntry, PackError, PackHeader, PackId};
use std::collections::{BTreeMap, BTreeSet};
use terrane_core::identity::Digest;

/// An immutable per-pack index validated without consulting pack bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackIndexSnapshot {
    header: PackHeader,
    generation: u64,
    entries: Vec<IndexEntry>,
}

impl PackIndexSnapshot {
    /// Parses a header-prefixed index object associated with a publication generation.
    ///
    /// The generation comes from durable publication state; it is not inferred
    /// from pack IDs or listing order. Pack bodies remain authoritative if a
    /// reader later discovers a detached-index disagreement.
    ///
    /// # Errors
    /// Rejects malformed headers, index count, reserved fields, kinds, codecs,
    /// duplicate hashes, overlapping offsets, or unsorted index records.
    pub fn decode(bytes: &[u8], generation: u64) -> Result<Self, PackError> {
        let (wire_header, records) = terrane_core::pack_format::decode_detached_index(bytes)?;
        let header = native_header(wire_header);
        let entries = records
            .iter()
            .map(native_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            header,
            generation,
            entries,
        })
    }

    /// Returns the immutable pack header.
    pub const fn header(&self) -> PackHeader {
        self.header
    }

    /// Returns the generation at which this pack was published.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrows validated hash-sorted per-pack records.
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }
}

/// Whether a merged record resolves content or prevents stale resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordState {
    /// Content can be read from the recorded pack.
    Live = 0,
    /// Content must not be served from this tombstoned pack.
    Tombstone = 1,
    /// The identity must not be served until explicit verified repair.
    Quarantine = 2,
}

/// One validated 72-byte merged index entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergedEntry {
    pack: PackId,
    entry: IndexEntry,
    state: RecordState,
}

impl MergedEntry {
    /// Returns the pack holding the body.
    pub const fn pack(&self) -> PackId {
        self.pack
    }

    /// Returns the content location and kind.
    ///
    /// Dictionary registry IDs are absent from merged records and are zero;
    /// a codec-two body's full dictionary digest remains authoritative.
    pub const fn entry(&self) -> &IndexEntry {
        &self.entry
    }

    /// Returns whether this location is live, GC-retired, or quarantined.
    pub const fn state(&self) -> RecordState {
        self.state
    }
}

/// An immutable hash-sorted shard belonging to exactly one publication generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergedShard {
    generation: u64,
    shard: u8,
    entries: Vec<MergedEntry>,
}

impl MergedShard {
    /// Rebuilds one shard from detached per-pack indexes and verified GC state.
    ///
    /// Input indexes are processed in publication order, with pack ID as a
    /// deterministic tie-breaker. A live replacement is preferred to an older
    /// tombstoned location. Previous tombstones persist unless a later generation
    /// explicitly confirms that pack's bytes were deleted.
    /// Identity quarantine persists independently of recorded-pack deletion;
    /// inventory and fresh placements are not evidence of verified repair.
    ///
    /// # Errors
    /// Rejects stale generations, conflicting copies of the same immutable pack,
    /// or indexes published after the requested compaction generation.
    pub fn rebuild(
        shard: u8,
        generation: u64,
        packs: &[PackIndexSnapshot],
        tombstoned: &BTreeSet<PackId>,
        previous: Option<&Self>,
        deleted: &BTreeSet<PackId>,
    ) -> Result<Self, PackError> {
        if previous.is_some_and(|prior| prior.shard != shard || prior.generation >= generation) {
            return Err(PackError::Generation);
        }

        let mut retired = tombstoned.clone();
        if let Some(prior) = previous {
            retired.extend(
                prior
                    .entries
                    .iter()
                    .filter(|record| record.state == RecordState::Tombstone)
                    .map(|record| record.pack),
            );
        }

        let mut seen = BTreeMap::new();
        let mut records: BTreeMap<Digest, MergedEntry> = BTreeMap::new();
        if let Some(prior) = previous {
            for record in &prior.entries {
                if record.state == RecordState::Quarantine
                    || (record.state == RecordState::Tombstone && !deleted.contains(&record.pack))
                {
                    records.insert(record.entry.hash, record.clone());
                }
            }
        }

        let mut ordered: Vec<_> = packs.iter().collect();
        ordered.sort_by_key(|pack| (pack.generation, pack.header.id));
        for pack in ordered {
            if pack.generation > generation {
                return Err(PackError::Generation);
            }
            if let Some(prior) = seen.insert(pack.header.id, pack)
                && (prior.header != pack.header || prior.entries != pack.entries)
            {
                return Err(PackError::Generation);
            }
            if deleted.contains(&pack.header.id) {
                continue;
            }

            let state = if retired.contains(&pack.header.id) {
                RecordState::Tombstone
            } else {
                RecordState::Live
            };
            for entry in pack.entries.iter().filter(|entry| entry.hash[0] == shard) {
                // Quarantine fences the identity, while GC retires only a placement.
                if records.get(&entry.hash).is_some_and(|existing| {
                    existing.state == RecordState::Quarantine
                        || (state == RecordState::Tombstone && existing.state == RecordState::Live)
                }) {
                    continue;
                }

                let mut entry = entry.clone();
                entry.dictionary_id = 0;
                records.insert(
                    entry.hash,
                    MergedEntry {
                        pack: pack.header.id,
                        entry,
                        state,
                    },
                );
            }
        }

        Ok(Self {
            generation,
            shard,
            entries: records.into_values().collect(),
        })
    }

    /// Returns the publication generation supplied by the verified manifest.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the first digest byte shared by every record.
    pub const fn shard(&self) -> u8 {
        self.shard
    }

    /// Borrows the immutable hash-sorted merged records.
    pub fn entries(&self) -> &[MergedEntry] {
        &self.entries
    }

    /// Encodes the exact registered 72-byte record format.
    pub fn encode(&self) -> Vec<u8> {
        let records = self
            .entries
            .iter()
            .map(|entry| terrane_core::pack_format::MergedRecord {
                pack: *entry.pack.as_bytes(),
                record: core_record(&entry.entry),
                state: entry.state as u8,
            })
            .collect::<Vec<_>>();
        terrane_core::pack_format::encode_shard(&records)
    }

    /// Parses a shard fetched under its manifest generation and shard key.
    ///
    /// # Errors
    /// Rejects count or reserved-byte disagreement, unknown fields, invalid
    /// offsets or lengths, another hash prefix, unsorted or duplicate hashes.
    pub fn decode(bytes: &[u8], generation: u64, shard: u8) -> Result<Self, PackError> {
        let records = terrane_core::pack_format::decode_shard(bytes, shard)?;
        let entries = records
            .iter()
            .map(|record| {
                Ok(MergedEntry {
                    pack: PackId::from_random_bytes(record.pack),
                    entry: native_record(&record.record)?,
                    state: match record.state {
                        0 => RecordState::Live,
                        1 => RecordState::Tombstone,
                        2 => RecordState::Quarantine,
                        _ => return Err(PackError::Reserved),
                    },
                })
            })
            .collect::<Result<Vec<_>, PackError>>()?;
        Ok(Self {
            generation,
            shard,
            entries,
        })
    }
}

/// A catalog lookup that distinguishes absence, GC retirement, and quarantine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Lookup {
    /// A checked live content location.
    Live(MergedEntry),
    /// A current tombstone that forbids falling back to an older index.
    Tombstone(PackId),
    /// An identity quarantine that blocks every ordinary content placement.
    Quarantine(PackId),
    /// No loaded shard or newer per-pack index contains this content.
    Missing,
}

/// A reader's independently refreshed shards plus newer per-pack fallback indexes.
#[derive(Default)]
pub struct IndexCatalog {
    shards: BTreeMap<u8, MergedShard>,
    newer_packs: BTreeMap<PackId, PackIndexSnapshot>,
}

impl IndexCatalog {
    /// Creates an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically installs a delta whose manifest and artifacts were verified.
    ///
    /// The bucket adapter must verify BKT-4 before calling this method. This
    /// layer has no key-fetch capability and never treats an absent manifest as
    /// publication. Conflicting equal generations are rejected; identical
    /// retries are idempotent.
    ///
    /// # Errors
    /// Rejects repeated shard IDs, older generations, or conflicting immutable
    /// records, leaving all existing shards unchanged.
    pub fn refresh(&mut self, delta: Vec<MergedShard>) -> Result<(), PackError> {
        let mut seen = BTreeSet::new();
        for shard in &delta {
            if !seen.insert(shard.shard) {
                return Err(PackError::Generation);
            }
            if let Some(current) = self.shards.get(&shard.shard)
                && (shard.generation < current.generation
                    || (shard.generation == current.generation && shard != current))
            {
                return Err(PackError::Generation);
            }
        }
        for shard in delta {
            self.shards.insert(shard.shard, shard);
        }
        Ok(())
    }

    /// Retains an index for fallback while merged shards catch up with publication.
    ///
    /// # Errors
    /// Rejects a conflicting index copy or generation for the same pack ID.
    pub fn add_pack(&mut self, pack: PackIndexSnapshot) -> Result<(), PackError> {
        if self
            .newer_packs
            .get(&pack.header.id)
            .is_some_and(|current| current != &pack)
        {
            return Err(PackError::Generation);
        }
        self.newer_packs.insert(pack.header.id, pack);
        Ok(())
    }

    /// Resolves through the newest shard, then packs published after that shard.
    ///
    /// A tombstone never falls back to a stale per-pack index; an independently
    /// published replacement after the shard generation can supersede it. The caller
    /// must still verify the returned body and its kind before serving it.
    /// Quarantine is checked before fallback and applies to the identity regardless
    /// of the requested kind; only explicit verified repair can clear it.
    pub fn lookup(&self, kind: EntryKind, hash: &Digest) -> Lookup {
        let shard = self.shards.get(&hash[0]);
        let generation = shard.map_or(0, |shard| shard.generation);
        let merged = shard.and_then(|shard| {
            shard
                .entries
                .binary_search_by_key(hash, |entry| entry.entry.hash)
                .ok()
                .map(|position| &shard.entries[position])
        });

        if let Some(record) = merged
            && record.state == RecordState::Quarantine
        {
            return Lookup::Quarantine(record.pack);
        }

        let fallback = self
            .newer_packs
            .values()
            .filter(|pack| shard.is_none() || pack.generation > generation)
            .filter(|pack| {
                merged.is_none_or(|record| {
                    record.state != RecordState::Tombstone || record.pack != pack.header.id
                })
            })
            .filter_map(|pack| {
                pack.entries
                    .binary_search_by_key(hash, |entry| entry.hash)
                    .ok()
                    .map(|position| (pack, &pack.entries[position]))
            })
            .max_by_key(|(pack, _)| (pack.generation, pack.header.id));
        if let Some((pack, entry)) = fallback {
            return if entry.kind == kind {
                Lookup::Live(MergedEntry {
                    pack: pack.header.id,
                    entry: entry.clone(),
                    state: RecordState::Live,
                })
            } else {
                Lookup::Missing
            };
        }
        if let Some(record) = merged
            && record.state == RecordState::Tombstone
        {
            return Lookup::Tombstone(record.pack);
        }
        match merged {
            Some(record) if record.entry.kind == kind => Lookup::Live(record.clone()),
            _ => Lookup::Missing,
        }
    }

    /// Returns precisely the published shards newer than this reader's versions.
    pub fn delta_needed(&self, published: &BTreeMap<u8, u64>) -> Vec<(u8, u64)> {
        published
            .iter()
            .filter(|(shard, generation)| {
                self.shards
                    .get(shard)
                    .is_none_or(|current| current.generation < **generation)
            })
            .map(|(shard, generation)| (*shard, *generation))
            .collect()
    }
}
