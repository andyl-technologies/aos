//! Immutable model backing for real Unix-socket page-source component tests.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::ram_source::{QemuRamBacking, QemuRamSourceError};
use crucible_ram::{
    Limits, MetadataBudget, PageDigest, RamError, RamSnapshot, RegionClass, RegionDescriptor,
    RegionTree, RootRecord, Scope, Topology,
};

// The model tree and its copied response use the same finite original budget.
// This grants no physical storage or native namespace authority.
pub(crate) fn fixture_page_response(
    tree: &RegionTree,
    region: &str,
    index: u64,
    original: &MetadataBudget,
    bytes: &[u8],
    boundary: &mut crate::ram_source::QemuRamReadBoundary<'_>,
    consumer: &mut crate::ram_source::QemuRamResponseConsumer<'_>,
) -> Result<(), QemuRamSourceError> {
    let siblings = usize::try_from(tree.geometry().height())
        .map_err(|_| QemuRamSourceError::Ownership)?
        .checked_mul(std::mem::size_of::<crucible_ram::NodeDigest>())
        .ok_or(QemuRamSourceError::Ownership)?;
    let encoding = 64_usize
        .checked_add(region.len())
        .and_then(|value| value.checked_add(siblings))
        .ok_or(QemuRamSourceError::Ownership)?;
    let extent = bytes
        .len()
        .checked_add(region.len())
        .and_then(|value| value.checked_add(siblings))
        .and_then(|value| value.checked_add(encoding))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(QemuRamSourceError::Ownership)?;
    // Declaration order keeps every copied allocation ahead of its refund.
    let _credit = original
        .reserve_bytes(extent)
        .map_err(|error| QemuRamSourceError::Proof(error.to_string()))?;
    let proof = tree
        .proof(region, index)
        .map_err(|error| QemuRamSourceError::Proof(error.to_string()))?;
    if bytes.len() != proof.valid_length() as usize
        || PageDigest::hash(bytes).map_err(|error| QemuRamSourceError::Proof(error.to_string()))?
            != proof.page_digest()
    {
        return Err(QemuRamSourceError::Proof(
            "modeled page identity".to_owned(),
        ));
    }
    let mut page = bytes.to_vec();
    let proof = crucible_ram::EncodedPageProof::new(proof);
    consumer(
        crucible_ram::BorrowedPageResponse::new(&mut page, &proof),
        boundary,
    );
    Ok(())
}

pub(crate) struct ImmutableBacking {
    root: RootRecord,
    snapshot: RamSnapshot,
    pages: Vec<Vec<u8>>,
    identity: String,
    pub(crate) corrupt_reads: AtomicBool,
    original: MetadataBudget,
}

impl ImmutableBacking {
    pub(crate) fn new(changed: u8) -> Result<Self, RamError> {
        let budget = MetadataBudget::new(1024 * 1024);
        let original = budget.clone();
        let topology = Topology::new(
            vec![RegionDescriptor::new(
                "machine.ram",
                RegionClass::MutableMain,
                8192 + 19,
            )?],
            Limits::default(),
        )?;
        let pages = vec![vec![1; 4096], vec![changed; 4096], vec![3; 19]];
        let digests = pages
            .iter()
            .map(|bytes| PageDigest::hash(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let tree = RegionTree::from_page_digests(8192 + 19, &digests, &budget)?;
        let snapshot = RamSnapshot::new(topology, vec![tree], &budget)?;
        let root = snapshot.root_record(Scope::Exact)?;
        let identity = format!("immutable-test-backing:{}", root.digest());
        Ok(Self {
            root,
            snapshot,
            pages,
            identity,
            corrupt_reads: AtomicBool::new(false),
            original,
        })
    }
}

impl QemuRamBacking for ImmutableBacking {
    fn root_object_id(&self) -> &str {
        &self.identity
    }

    fn root_record(&self) -> &RootRecord {
        &self.root
    }

    fn with_page_response(
        &self,
        region_id: &str,
        page_index: u64,
        boundary: &mut dyn FnMut() -> Result<(), crate::ram_source::QemuRamReadBoundaryError>,
        consumer: &mut crate::ram_source::QemuRamResponseConsumer<'_>,
    ) -> Result<(), QemuRamSourceError> {
        boundary()?;
        let tree = self
            .snapshot
            .region_tree(region_id)
            .ok_or(QemuRamSourceError::Ownership)?;
        let index = usize::try_from(page_index).map_err(|_| QemuRamSourceError::Ownership)?;
        let bytes = self.pages.get(index).ok_or(QemuRamSourceError::Ownership)?;
        if self.corrupt_reads.load(Ordering::Acquire) {
            let _credit = self
                .original
                .reserve_bytes(bytes.len() as u64)
                .map_err(|error| QemuRamSourceError::Proof(error.to_string()))?;
            let mut corrupted = bytes.clone();
            corrupted[0] ^= 1;
            boundary()?;
            return fixture_page_response(
                tree,
                region_id,
                page_index,
                &self.original,
                &corrupted,
                boundary,
                consumer,
            );
        }
        boundary()?;
        fixture_page_response(
            tree,
            region_id,
            page_index,
            &self.original,
            bytes,
            boundary,
            consumer,
        )
    }
}
