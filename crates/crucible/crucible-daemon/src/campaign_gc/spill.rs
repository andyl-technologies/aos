//! GC record encodings and scratch storage over the shared external sorter.
//!
//! Closure, root, and inventory sets can each hold up to the manifest entry
//! bound, so GC keeps them as sorted runs on disk instead of in memory. The
//! run, sort, and scratch-directory machinery is
//! [`crucible_campaign::spill`]; this module owns the GC record encodings,
//! whose byte order is the manifests' canonical order:
//!
//! ```text
//! id record (37 bytes):
//!   kind rank:u8              # rank of the kind's wire tag in byte order
//!   schema version:u32be
//!   digest[32]
//! ```
//!
//! so comparing records with `memcmp` matches the manifests' (kind tag,
//! schema version, digest) order. This differs from the campaign archive's
//! [`crucible_campaign::spill::ordered_id_record`], which follows
//! `ContentId`'s declaration-order `Ord`. Larger records append fields after
//! the id. Records never leave the process and are not a published format.
//!
//! ```text
//! placement record (45 bytes): id record || logical_length:u64be
//! ```
//!
//! [`sort_inventory`] spills one fenced physical inventory as sorted
//! placement records. It keeps repeats, so a consumer can reject an
//! inventory that lists one object twice. Every GC file lives in one
//! [`GcWorkDirectory`], created owner-only beside the caller's durable state
//! and removed with its contents when the last handle drops.

use std::io;
use std::path::Path;
use std::sync::Arc;

pub(super) use crucible_campaign::spill::{
    ExternalSorter, ID_RECORD_BYTES, IdRecord, RUN_RECORDS, RecordReader, SpillFile, SpillWriter,
};
use crucible_campaign::spill::{SortedRecords, SpillDirectory};
use crucible_store::content_store::{
    BlobInventoryFence, BlobInventorySummary, ContentId, ObjectKind, StoreError,
};

/// Owner-only GC scratch directory removed with its contents on drop.
pub(super) type GcWorkDirectory = SpillDirectory;

/// Forward-only membership test over one sorted, deduplicated id file.
pub(super) type SortedIds = SortedRecords<ID_RECORD_BYTES>;

/// Creates a new private GC work directory inside the existing `parent`.
pub(super) fn create_work_directory(parent: &Path) -> io::Result<Arc<GcWorkDirectory>> {
    SpillDirectory::create(parent, ".crucible-gc-spill")
}

/// Width of one spilled physical placement record.
pub(super) const PLACEMENT_RECORD_BYTES: usize = ID_RECORD_BYTES + 8;

/// One spilled physical placement: identity and logical length.
pub(super) type PlacementRecord = [u8; PLACEMENT_RECORD_BYTES];

/// Object kinds ordered by their wire tag, which is the manifest order.
const KINDS_BY_TAG: [ObjectKind; 14] = [
    ObjectKind::CampaignFact,
    ObjectKind::CampaignSnapshot,
    ObjectKind::Configuration,
    ObjectKind::DeviceState,
    ObjectKind::DiskExtent,
    ObjectKind::ExactManifest,
    ObjectKind::Finding,
    ObjectKind::MerkleNode,
    ObjectKind::Observation,
    ObjectKind::Policy,
    ObjectKind::Projection,
    ObjectKind::RamExtent,
    ObjectKind::Scenario,
    ObjectKind::Trace,
];

const fn kind_rank(kind: ObjectKind) -> u8 {
    // An exhaustive match makes a new kind a compile error here rather than
    // a silent ordering hole; the table above must gain the same entry.
    match kind {
        ObjectKind::CampaignFact => 0,
        ObjectKind::CampaignSnapshot => 1,
        ObjectKind::Configuration => 2,
        ObjectKind::DeviceState => 3,
        ObjectKind::DiskExtent => 4,
        ObjectKind::ExactManifest => 5,
        ObjectKind::Finding => 6,
        ObjectKind::MerkleNode => 7,
        ObjectKind::Observation => 8,
        ObjectKind::Policy => 9,
        ObjectKind::Projection => 10,
        ObjectKind::RamExtent => 11,
        ObjectKind::Scenario => 12,
        ObjectKind::Trace => 13,
    }
}

/// Encodes one identity as an order-preserving fixed-width record.
pub(super) fn encode_id(id: ContentId) -> IdRecord {
    let mut record = [0_u8; ID_RECORD_BYTES];
    record[0] = kind_rank(id.kind());
    record[1..5].copy_from_slice(&id.schema_version().to_be_bytes());
    record[5..].copy_from_slice(&id.digest());
    record
}

/// Decodes one identity record written by [`encode_id`].
pub(super) fn decode_id(record: &[u8]) -> io::Result<ContentId> {
    let kind = record
        .first()
        .and_then(|rank| KINDS_BY_TAG.get(usize::from(*rank)))
        .copied()
        .ok_or_else(|| corrupt("GC spill record has an unknown object kind"))?;
    let schema = record
        .get(1..5)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or_else(|| corrupt("GC spill record is truncated"))?;
    let digest = record
        .get(5..ID_RECORD_BYTES)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| corrupt("GC spill record is truncated"))?;
    Ok(ContentId::from_parts(
        kind,
        u32::from_be_bytes(schema),
        digest,
    ))
}

/// Encodes one physical placement as an order-preserving record.
pub(super) fn placement_record(id: ContentId, logical_length: u64) -> PlacementRecord {
    let mut record = [0_u8; PLACEMENT_RECORD_BYTES];
    record[..ID_RECORD_BYTES].copy_from_slice(&encode_id(id));
    record[ID_RECORD_BYTES..].copy_from_slice(&logical_length.to_be_bytes());
    record
}

/// Returns a placement record's identity prefix.
pub(super) fn placement_id(record: &PlacementRecord) -> IdRecord {
    field(record, 0)
}

/// Returns a placement record's logical length.
pub(super) fn placement_length(record: &PlacementRecord) -> u64 {
    u64::from_be_bytes(field(record, ID_RECORD_BYTES))
}

/// Copies a fixed-width field out of a record whose layout fixes its bounds.
pub(super) fn field<const N: usize>(record: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0_u8; N];
    value.copy_from_slice(&record[offset..offset + N]);
    value
}

/// Failure to spill one fenced physical inventory.
pub(super) enum InventorySortError {
    /// The fenced backend failed or reported an incomplete inventory.
    Store(StoreError),
    /// Scratch storage failed.
    Spill(io::Error),
}

/// Visits one fenced inventory into a sorted placement run.
///
/// Repeated placements stay adjacent in the output. A spill failure aborts
/// the visit and takes precedence over the store error that abort produces.
pub(super) fn sort_inventory(
    fence: &mut dyn BlobInventoryFence,
    directory: &Arc<GcWorkDirectory>,
) -> Result<(BlobInventorySummary, SpillFile), InventorySortError> {
    let mut sorter = ExternalSorter::<PLACEMENT_RECORD_BYTES>::new_retaining_duplicates(
        directory,
        "placements",
        RUN_RECORDS,
    );
    let mut spill_error = None;
    let visited = fence.visit_inventory(&mut |record| {
        sorter
            .push(placement_record(record.id(), record.logical_length()))
            .map_err(|source| {
                spill_error = Some(source);
                StoreError::InvalidComposition {
                    reason: "campaign GC inventory spill failed",
                }
            })
    });
    if let Some(source) = spill_error {
        return Err(InventorySortError::Spill(source));
    }
    let summary = visited.map_err(InventorySortError::Store)?;
    let placements = sorter.finish().map_err(InventorySortError::Spill)?;
    Ok((summary, placements))
}

fn corrupt(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture failures localize exact spill behavior.
    #![allow(clippy::expect_used)]

    use super::*;

    fn id(kind: ObjectKind, schema: u32, seed: u8) -> ContentId {
        ContentId::for_bytes(kind, schema, &[seed])
    }

    fn read_ids(file: &SpillFile) -> Vec<ContentId> {
        let mut reader = file.reader::<ID_RECORD_BYTES>().expect("open spill file");
        let mut ids = Vec::new();
        while let Some(record) = reader.next_record().expect("read spill record") {
            ids.push(decode_id(&record).expect("decode spill record"));
        }
        ids
    }

    #[test]
    fn kind_ranks_follow_wire_tag_order_and_round_trip() {
        for (rank, kind) in KINDS_BY_TAG.iter().enumerate() {
            assert_eq!(usize::from(kind_rank(*kind)), rank);
        }
        for pair in KINDS_BY_TAG.windows(2) {
            assert!(pair[0].as_str() < pair[1].as_str());
        }
        for kind in KINDS_BY_TAG {
            let original = id(kind, 7, 3);
            assert_eq!(decode_id(&encode_id(original)).expect("decode"), original);
        }
    }

    #[test]
    fn record_order_matches_manifest_identity_order() {
        let ids = [
            id(ObjectKind::Trace, 1, 1),
            id(ObjectKind::MerkleNode, 2, 1),
            id(ObjectKind::MerkleNode, 1, 2),
            id(ObjectKind::CampaignFact, 9, 3),
            id(ObjectKind::Scenario, 1, 4),
        ];
        let mut by_record = ids.to_vec();
        by_record.sort_by_key(|id| encode_id(*id));
        let mut by_manifest = ids.to_vec();
        by_manifest.sort_by(|left, right| {
            left.kind()
                .as_str()
                .cmp(right.kind().as_str())
                .then_with(|| left.schema_version().cmp(&right.schema_version()))
                .then_with(|| left.digest().cmp(&right.digest()))
        });
        assert_eq!(by_record, by_manifest);
    }

    #[test]
    fn shared_sorter_yields_gc_records_in_manifest_order_inside_the_work_directory() {
        let parent = tempfile::tempdir().expect("spill parent");
        let directory = create_work_directory(parent.path()).expect("work directory");
        let ids = [
            id(ObjectKind::Trace, 1, 1),
            id(ObjectKind::MerkleNode, 1, 2),
            id(ObjectKind::CampaignFact, 9, 3),
            id(ObjectKind::Trace, 1, 1),
        ];
        // Two-record runs force a merge of several spilled runs.
        let mut sorter = ExternalSorter::<ID_RECORD_BYTES>::new(&directory, "ids", 2);
        for content in ids {
            sorter.push(encode_id(content)).expect("push id");
        }

        let sorted = sorter.finish().expect("finish sort");
        drop(directory);

        let mut expected = ids.to_vec();
        expected.sort_by_key(|id| encode_id(*id));
        expected.dedup();
        assert_eq!(read_ids(&sorted), expected);
        assert_eq!(
            std::fs::read_dir(parent.path()).expect("parent").count(),
            1,
            "a live spill file keeps its work directory"
        );
        drop(sorted);
        assert_eq!(std::fs::read_dir(parent.path()).expect("parent").count(), 0);
    }
}
