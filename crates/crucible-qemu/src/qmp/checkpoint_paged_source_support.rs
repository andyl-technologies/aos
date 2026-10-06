//! Immutable model backing for real Unix-socket page-source component tests.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::ram_source::{QemuRamBacking, QemuRamSourceError};
use crucible_ram::{
    Limits, MetadataBudget, PageDigest, PageProof, RamError, RamSnapshot, RegionClass,
    RegionDescriptor, RegionTree, RootRecord, Scope, Topology,
};

pub(super) struct ImmutableBacking {
    root: RootRecord,
    snapshot: RamSnapshot,
    pages: Vec<Vec<u8>>,
    identity: String,
    pub(super) corrupt_reads: AtomicBool,
}

impl ImmutableBacking {
    pub(super) fn new(changed: u8) -> Result<Self, RamError> {
        let budget = MetadataBudget::new(1024 * 1024);
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

    fn read_page_with_proof(
        &self,
        region_id: &str,
        page_index: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamSourceError>,
    ) -> Result<(Vec<u8>, PageProof), QemuRamSourceError> {
        boundary()?;
        let tree = self
            .snapshot
            .region_tree(region_id)
            .ok_or(QemuRamSourceError::Ownership)?;
        let index = usize::try_from(page_index).map_err(|_| QemuRamSourceError::Ownership)?;
        let mut bytes = self
            .pages
            .get(index)
            .ok_or(QemuRamSourceError::Ownership)?
            .clone();
        let proof = tree
            .proof(region_id, page_index)
            .map_err(|error| QemuRamSourceError::Proof(error.to_string()))?;
        if self.corrupt_reads.load(Ordering::Acquire) {
            bytes[0] ^= 1;
        }
        boundary()?;
        Ok((bytes, proof))
    }
}
