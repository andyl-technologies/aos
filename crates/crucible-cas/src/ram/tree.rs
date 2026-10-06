//! Streaming initial capture, persistent path replacement, and lazy page lookup.

use std::sync::Arc;

use crucible_ram::{PageDigest, PageProof, RegionDescriptor, RootRecord, Scope, Topology};

use crate::content_store::ObjectKind;

use super::codec::{TreeNode, TreeRef};
use super::{
    LeasedRamRoot, RamRetention, RamRootLease, RamStore, RamStoreError, Work, height, logical,
    page_count, valid_length,
};

/// Supplies coherent logical page bytes while the capture owner holds its fence.
pub type RamPageReader<'a> =
    dyn FnMut(&RegionDescriptor, u64, &mut [u8]) -> Result<(), RamStoreError> + 'a;

/// One changed logical page supplied to persistent checkpoint publication.
#[derive(Clone, Debug)]
pub struct RamPageChange {
    /// Stable logical region identity.
    pub region_id: String,
    /// Zero-based logical page index within the region.
    pub page_index: u64,
    /// Current canonical valid bytes, without host padding.
    pub bytes: Vec<u8>,
}

/// Counters for a completed bounded full-closure verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RamVerificationReport {
    /// Number of real logical pages authenticated, including repeated content.
    pub pages: u64,
    /// Number of canonical valid page bytes authenticated.
    pub logical_bytes: u64,
    /// Number of bounded metadata/page object reads performed.
    pub object_visits: u64,
}

impl RamStore {
    /// Inspects authenticated bounded root metadata without granting retention.
    ///
    /// This is a discovery operation only. The record may be used for identity
    /// and cost admission, but a live lease is still required before page reads.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable or corrupt metadata, invalid catalog
    /// geometry, cancellation, or configured bounds.
    pub fn inspect_root(
        &self,
        id: crate::content_store::ContentId,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RootRecord, RamStoreError> {
        let mut work = Work::new(self.limits, boundary);
        let (record, regions) = self.read_root(id, &mut work)?;
        self.admit_topology(record.topology())?;
        self.validate_root_catalogs(&record, &regions)?;
        Ok(record)
    }

    /// Captures a coherent RAM image into immutable catalogs with bounded memory.
    ///
    /// The caller must hold the semantic write fence and pager disposition
    /// barrier throughout `read_page`. Objects become durable before the root;
    /// cancellation can leave retained children, never a partial root. The page
    /// callback reads into a single reusable-sized logical buffer, including the
    /// exact valid length of the final page.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable bytes, cancellation, invalid geometry,
    /// resource limits, retention failure, or unsatisfied durable publication.
    pub fn capture(
        &self,
        topology: Topology,
        scope: Scope,
        read_page: &mut RamPageReader<'_>,
        retention: &dyn RamRetention,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<LeasedRamRoot, RamStoreError> {
        self.admit_ram_publication(&topology, scope)?;
        let mut work = Work::new(self.limits, boundary);
        work.pending = Some(Vec::with_capacity(64));
        let mut regions = Vec::new();
        let mut roots = Vec::new();

        for region in topology
            .regions()
            .iter()
            .filter(|region| scope.includes(region.class()))
        {
            let count = page_count(region.logical_length());
            let catalog = self.capture_region(
                region,
                0,
                height(count),
                count,
                read_page,
                retention,
                &mut work,
            )?;
            roots.push(crucible_ram::region_tree_digest(
                region.geometry(),
                catalog.digest,
            ));
            regions.push(catalog);
        }

        self.flush_capture_batch(&mut work)?;
        work.pending = None;
        let record = RootRecord::new(topology, scope, roots).map_err(logical)?;
        let id = self.put_root(&record, &regions, retention, &mut work)?;
        let lease = retention.retain_root(id)?;
        if lease.root() != id {
            return Err(RamStoreError::Invalid("retention root receipt"));
        }
        Ok(LeasedRamRoot {
            record,
            regions,
            lease,
        })
    }

    /// Opens bounded root metadata under an existing GC-safe retention lease.
    ///
    /// This validates the root/catalog associations, not every descendant's
    /// possession. Call `verify` before granting complete local restore readiness.
    /// Individual `read_page` calls always authenticate their accessed path.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible, corrupt, excessive, or missing metadata.
    pub fn open(
        &self,
        lease: Arc<dyn RamRootLease>,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<LeasedRamRoot, RamStoreError> {
        let mut work = Work::new(self.limits, boundary);
        let (record, regions) = self.read_root(lease.root(), &mut work)?;
        self.admit_topology(record.topology())?;
        self.validate_root_catalogs(&record, &regions)?;
        Ok(LeasedRamRoot {
            record,
            regions,
            lease,
        })
    }

    /// Reads and authenticates one page without populating the live guest mapping.
    ///
    /// # Errors
    ///
    /// Returns an error for an excluded region, invalid coordinate, corrupt path,
    /// wrong valid length, lost storage, cancellation, or a resource ceiling.
    pub fn read_page(
        &self,
        root: &LeasedRamRoot,
        region_id: &str,
        page_index: u64,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<Vec<u8>, RamStoreError> {
        self.read_page_with_proof(root, region_id, page_index, boundary)
            .map(|(bytes, _)| bytes)
    }

    /// Reads a page and supplies its bounded portable proof to the trusted root.
    ///
    /// The proof contains logical digests and coordinates only. Its storage
    /// references and live source lease remain in the host process.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or corrupt content, invalid coordinates,
    /// cancellation, or exhausted operation limits.
    pub fn read_page_with_proof(
        &self,
        root: &LeasedRamRoot,
        region_id: &str,
        page_index: u64,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<(Vec<u8>, PageProof), RamStoreError> {
        self.admit_topology(root.record.topology())?;
        let (index, region) = selected_region(&root.record, region_id)?;
        let expected_length = valid_length(region, page_index)?;
        let mut reference = root.regions[index];
        let mut page = page_index;
        let mut work = Work::new(self.limits, boundary);
        let mut siblings = Vec::with_capacity(reference.height as usize);

        loop {
            match self.read_tree(reference, &mut work)? {
                TreeNode::Padding => {
                    return Err(RamStoreError::Invalid("real page resolves to padding"));
                }
                TreeNode::Leaf {
                    page: object,
                    digest,
                } => {
                    let bytes = self.read_page_object(object, digest, &mut work)?;
                    if bytes.len() != expected_length {
                        return Err(RamStoreError::Invalid("logical page valid length"));
                    }
                    siblings.reverse();
                    let proof = PageProof::new(
                        region_id,
                        page_index,
                        expected_length as u32,
                        digest,
                        siblings,
                    )
                    .map_err(logical)?;
                    proof
                        .verify(&bytes, &root.record, root.logical_digest())
                        .map_err(logical)?;
                    return Ok((bytes, proof));
                }
                TreeNode::Branch { left, right } => {
                    let width = 1_u64 << (reference.height - 1);
                    if page < width {
                        siblings.push(right.digest);
                        reference = left;
                    } else {
                        siblings.push(left.digest);
                        page -= width;
                        reference = right;
                    }
                }
            }
        }
    }

    /// Publishes changed pages by replacing only their immutable binary paths.
    ///
    /// Changes must be strictly sorted by region ID and page index, so duplicate
    /// updates cannot silently overwrite earlier input. The source root remains
    /// leased until the new root and successor retention receipt are complete.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate/unsorted changes, invalid bytes or paths,
    /// cancellation, limits, retention failure, or durable storage errors.
    pub fn update(
        &self,
        root: &LeasedRamRoot,
        changes: impl IntoIterator<Item = RamPageChange>,
        retention: &dyn RamRetention,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<LeasedRamRoot, RamStoreError> {
        let mut changes = changes.into_iter();
        self.update_with_reader(root, &mut || Ok(changes.next()), retention, boundary)
    }

    /// Publishes an ordered fallible page stream without concealing source errors.
    ///
    /// The source returns `None` only after its authenticated stream completes.
    /// An error leaves the predecessor current and prevents root publication.
    ///
    /// # Errors
    ///
    /// Returns source errors, ordering/length failures, cancellation, exhausted
    /// limits, or unsatisfied durable successor publication.
    pub fn update_with_reader(
        &self,
        root: &LeasedRamRoot,
        next: &mut dyn FnMut() -> Result<Option<RamPageChange>, RamStoreError>,
        retention: &dyn RamRetention,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<LeasedRamRoot, RamStoreError> {
        self.admit_ram_publication(root.record.topology(), root.record.scope())?;
        let mut regions = root.regions.clone();
        let mut roots = root.record.region_roots().to_vec();
        let mut previous: Option<(String, u64)> = None;
        let mut work = Work::new(self.limits, boundary);

        loop {
            (work.boundary)()?;
            let Some(change) = next()? else {
                break;
            };
            let coordinate = (change.region_id.clone(), change.page_index);
            if previous
                .as_ref()
                .is_some_and(|previous| previous >= &coordinate)
            {
                return Err(RamStoreError::Invalid("nonascending page changes"));
            }
            let (index, region) = selected_region(&root.record, &change.region_id)?;
            if change.bytes.len() != valid_length(region, change.page_index)? {
                return Err(RamStoreError::Invalid("changed page valid length"));
            }
            regions[index] = self.replace_page(
                regions[index],
                change.page_index,
                &change.bytes,
                retention,
                &mut work,
            )?;
            roots[index] =
                crucible_ram::region_tree_digest(region.geometry(), regions[index].digest);
            previous = Some(coordinate);
        }

        let record = RootRecord::new(root.record.topology().clone(), root.record.scope(), roots)
            .map_err(logical)?;
        let id = self.put_root(&record, &regions, retention, &mut work)?;
        let lease = retention.retain_root(id)?;
        if lease.root() != id {
            return Err(RamStoreError::Invalid("retention root receipt"));
        }
        Ok(LeasedRamRoot {
            record,
            regions,
            lease,
        })
    }

    /// Verifies complete local page availability through bounded depth-first reads.
    ///
    /// Repeated content may be read more than once to avoid a flat visited set.
    /// The work bound counts those visits explicitly. No live guest mapping is
    /// touched, and every required page's actual bytes are checked.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/corrupt content, invalid geometry, cancellation,
    /// or insufficient declared traversal/I/O capacity.
    pub fn verify(
        &self,
        root: &LeasedRamRoot,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RamVerificationReport, RamStoreError> {
        self.admit_topology(root.record.topology())?;
        self.validate_root_catalogs(&root.record, &root.regions)?;
        let mut report = RamVerificationReport::default();
        let mut work = Work::new(self.limits, boundary);
        for (region, reference) in root
            .record
            .topology()
            .regions()
            .iter()
            .filter(|region| root.record.scope().includes(region.class()))
            .zip(&root.regions)
        {
            self.verify_region(region, *reference, 0, &mut report, &mut work)?;
        }
        report.object_visits = work.visits;
        Ok(report)
    }

    /// Checks destination index headroom for a complete immutable RAM image.
    ///
    /// The count assumes unique pages and every node of each padded binary
    /// catalog. It is intentionally conservative and bounded by the admitted
    /// topology. This check does not reserve capacity against concurrent writers
    /// or replace per-put quota and durability validation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid topology bounds, count overflow, insufficient
    /// writable-leaf headroom, or an unadmitted backend capacity contract.
    pub fn admit_ram_publication(
        &self,
        topology: &Topology,
        scope: Scope,
    ) -> Result<(), RamStoreError> {
        self.admit_topology(topology)?;
        let mut pages = 0_u64;
        let mut nodes = 0_u64;
        for region in topology
            .regions()
            .iter()
            .filter(|region| scope.includes(region.class()))
        {
            let count = page_count(region.logical_length());
            let padded = count
                .checked_next_power_of_two()
                .ok_or(RamStoreError::Limit("RAM catalog node count"))?;
            let region_nodes = padded
                .checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .ok_or(RamStoreError::Limit("RAM catalog node count"))?;
            pages = pages
                .checked_add(count)
                .ok_or(RamStoreError::Limit("RAM page object count"))?;
            nodes = nodes
                .checked_add(region_nodes)
                .ok_or(RamStoreError::Limit("RAM catalog node count"))?;
        }
        self.backend.admit_object_graph(&[
            (ObjectKind::RamExtent, pages),
            (ObjectKind::RamTree, nodes),
            (ObjectKind::ExactManifest, 1),
        ])?;
        Ok(())
    }

    pub(super) fn admit_topology(&self, topology: &Topology) -> Result<(), RamStoreError> {
        let mut pages = 0_u64;
        for region in topology.regions() {
            pages = pages
                .checked_add(page_count(region.logical_length()))
                .ok_or(RamStoreError::Limit("logical page count"))?;
        }
        if topology.total_logical_bytes() > self.limits.maximum_logical_bytes {
            return Err(RamStoreError::Limit("logical RAM bytes"));
        }
        if pages > self.limits.maximum_pages {
            return Err(RamStoreError::Limit("logical page count"));
        }
        Ok(())
    }

    pub(super) fn validate_root_catalogs(
        &self,
        record: &RootRecord,
        regions: &[TreeRef],
    ) -> Result<(), RamStoreError> {
        let selected = record
            .topology()
            .regions()
            .iter()
            .filter(|region| record.scope().includes(region.class()));
        if selected.clone().count() != regions.len() || regions.len() != record.region_roots().len()
        {
            return Err(RamStoreError::Invalid("selected region catalogs"));
        }
        for ((region, catalog), digest) in selected.zip(regions).zip(record.region_roots()) {
            let count = page_count(region.logical_length());
            if catalog.height != height(count)
                || catalog.pages != count
                || crucible_ram::region_tree_digest(region.geometry(), catalog.digest) != *digest
            {
                return Err(RamStoreError::Invalid("region catalog root"));
            }
        }
        Ok(())
    }

    // crucible-lint: allow rust-allow -- recursive capture keeps logical geometry, source reader, retention, and shared work budget explicit.
    #[allow(clippy::too_many_arguments)]
    fn capture_region(
        &self,
        region: &RegionDescriptor,
        first: u64,
        height: u32,
        count: u64,
        read_page: &mut RamPageReader<'_>,
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<TreeRef, RamStoreError> {
        (work.boundary)()?;
        if count == 0 {
            return self.put_tree(&TreeNode::Padding, height, 0, retention, work);
        }
        if height == 0 {
            let mut bytes = vec![0_u8; valid_length(region, first)?];
            read_page(region, first, &mut bytes)?;
            let (page, digest) = self.put_page(&bytes, retention, work)?;
            return self.put_tree(&TreeNode::Leaf { page, digest }, 0, 1, retention, work);
        }

        let width = 1_u64 << (height - 1);
        let left = self.capture_region(
            region,
            first,
            height - 1,
            count.min(width),
            read_page,
            retention,
            work,
        )?;
        let right = self.capture_region(
            region,
            first + width,
            height - 1,
            count.saturating_sub(width),
            read_page,
            retention,
            work,
        )?;
        self.put_tree(
            &TreeNode::Branch { left, right },
            height,
            count,
            retention,
            work,
        )
    }

    fn replace_page(
        &self,
        reference: TreeRef,
        page_index: u64,
        bytes: &[u8],
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<TreeRef, RamStoreError> {
        match self.read_tree(reference, work)? {
            TreeNode::Padding => Err(RamStoreError::Invalid("update targets padding")),
            TreeNode::Leaf { page, digest } => {
                let current = self.read_page_object(page, digest, work)?;
                if PageDigest::hash(bytes).map_err(logical)? == digest && current == bytes {
                    retention.retain_object(reference.id)?;
                    return Ok(reference);
                }
                let (page, digest) = self.put_page(bytes, retention, work)?;
                self.put_tree(&TreeNode::Leaf { page, digest }, 0, 1, retention, work)
            }
            TreeNode::Branch {
                mut left,
                mut right,
            } => {
                let width = 1_u64 << (reference.height - 1);
                if page_index < width {
                    left = self.replace_page(left, page_index, bytes, retention, work)?;
                } else {
                    right = self.replace_page(right, page_index - width, bytes, retention, work)?;
                }
                // Retention of the old root protects untouched subtrees until
                // the successor root's transitive lease is installed.
                self.put_tree(
                    &TreeNode::Branch { left, right },
                    reference.height,
                    reference.pages,
                    retention,
                    work,
                )
            }
        }
    }

    fn verify_region(
        &self,
        region: &RegionDescriptor,
        reference: TreeRef,
        first: u64,
        report: &mut RamVerificationReport,
        work: &mut Work<'_>,
    ) -> Result<(), RamStoreError> {
        match self.read_tree(reference, work)? {
            TreeNode::Padding => Ok(()),
            TreeNode::Leaf { page, digest } => {
                let bytes = self.read_page_object(page, digest, work)?;
                if bytes.len() != valid_length(region, first)? {
                    return Err(RamStoreError::Invalid("verified page valid length"));
                }
                report.pages = report
                    .pages
                    .checked_add(1)
                    .ok_or(RamStoreError::Limit("verified pages"))?;
                report.logical_bytes = report
                    .logical_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or(RamStoreError::Limit("verified bytes"))?;
                Ok(())
            }
            TreeNode::Branch { left, right } => {
                self.verify_region(region, left, first, report, work)?;
                self.verify_region(
                    region,
                    right,
                    first + (1_u64 << (reference.height - 1)),
                    report,
                    work,
                )
            }
        }
    }
}

pub(super) fn selected_region<'a>(
    record: &'a RootRecord,
    id: &str,
) -> Result<(usize, &'a RegionDescriptor), RamStoreError> {
    record
        .topology()
        .regions()
        .iter()
        .filter(|region| record.scope().includes(region.class()))
        .enumerate()
        .find(|(_, region)| region.id() == id)
        .ok_or(RamStoreError::Invalid("region outside selected scope"))
}
