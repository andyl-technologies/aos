//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Implements complete portable root records and bounded logical page proofs.
//!
//! Record editions are explicit and all integers are big-endian. Wire wrappers
//! are distinct from hash preimages; their complete inventories permit receivers
//! to derive scope membership without trusting a supplied topology digest.
//!
//! ```text
//! root  = "CRUCRR01" || U32(1) || U32(4096) || S(scope) || Inventory
//!         || U32(selected_count) || (RegionDescriptor || RegionTreeDigest)*
//! proof = "CRUCRP01" || S(region_id) || U64(page_index) || U32(valid_length)
//!         || PageDigest || U32(depth) || NodeDigest[depth]
//! ```

use crate::digest::tagged;
use crate::topology::validate_id;
use crate::{
    Geometry, LOGICAL_ENCODING_EDITION, LOGICAL_PAGE_SIZE, Limits, NodeDigest, PageDigest,
    RamError, RamRootDigest, RegionClass, RegionDescriptor, RegionTreeDigest, Scope, Topology,
    empty_leaf_digest, inner_digest, leaf_digest, region_tree_digest,
};

const ROOT_MAGIC: &[u8; 8] = b"CRUCRR01";
const PROOF_MAGIC: &[u8; 8] = b"CRUCRP01";

/// A complete canonical inventory and all roots selected by a named scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootRecord {
    topology: Topology,
    scope: Scope,
    roots: Vec<RegionTreeDigest>,
    digest: RamRootDigest,
}

impl RootRecord {
    /// Binds selected roots, in inventory order, to a complete topology and scope.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::InvalidLength`] unless exactly one root is supplied
    /// for each selected region. It does not establish storage or execution
    /// authority for those roots.
    pub fn new(
        topology: Topology,
        scope: Scope,
        roots: Vec<RegionTreeDigest>,
    ) -> Result<Self, RamError> {
        let selected_count = topology
            .regions()
            .iter()
            .filter(|region| scope.includes(region.class()))
            .count();
        if roots.len() != selected_count {
            return Err(RamError::InvalidLength);
        }

        let mut hasher = tagged("root");
        hasher.update(&LOGICAL_ENCODING_EDITION.to_be_bytes());
        hasher.update(&LOGICAL_PAGE_SIZE.to_be_bytes());
        hasher.update(&(scope.as_str().len() as u32).to_be_bytes());
        hasher.update(scope.as_str().as_bytes());
        hasher.update(topology.digest().as_bytes());
        hasher.update(&(roots.len() as u32).to_be_bytes());
        for (region, root) in topology
            .regions()
            .iter()
            .filter(|region| scope.includes(region.class()))
            .zip(&roots)
        {
            let mut encoded = Vec::with_capacity(269);
            region.encode_into(&mut encoded);
            hasher.update(&encoded);
            hasher.update(root.as_bytes());
        }
        Ok(Self {
            topology,
            scope,
            roots,
            digest: RamRootDigest::from_bytes(*hasher.finalize().as_bytes()),
        })
    }

    /// Returns the complete inventory, including regions omitted by the scope.
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// Returns the declared coverage scope.
    pub const fn scope(&self) -> Scope {
        self.scope
    }

    /// Returns selected region roots in canonical inventory order.
    pub fn region_roots(&self) -> &[RegionTreeDigest] {
        &self.roots
    }

    /// Returns the scoped logical RAM commitment.
    pub const fn digest(&self) -> RamRootDigest {
        self.digest
    }

    /// Looks up a selected region's root without accepting an omitted region.
    pub fn region_root(&self, id: &str) -> Option<RegionTreeDigest> {
        self.topology
            .regions()
            .iter()
            .filter(|region| self.scope.includes(region.class()))
            .zip(&self.roots)
            .find_map(|(region, root)| (region.id() == id).then_some(*root))
    }

    /// Encodes the complete versioned root record, not merely its hash preimage.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut output);
        output
    }

    /// Returns the exact bounded wire size before reserving an observer buffer.
    pub fn encoded_len(&self) -> usize {
        16 + 4
            + self.scope.as_str().len()
            + self.topology.inventory_encoded_len()
            + 4
            + self
                .topology
                .regions()
                .iter()
                .filter(|region| self.scope.includes(region.class()))
                .map(|region| 46 + region.id().len())
                .sum::<usize>()
    }

    /// Encodes a complete record using a fallible bounded allocation.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::Allocation`] if the exact record buffer cannot be
    /// allocated. Callers separately reserve and retain its metadata charge.
    pub fn try_encode(&self) -> Result<Vec<u8>, RamError> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(self.encoded_len())
            .map_err(|_| RamError::Allocation)?;
        self.encode_into(&mut output);
        Ok(output)
    }

    fn encode_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(ROOT_MAGIC);
        output.extend_from_slice(&LOGICAL_ENCODING_EDITION.to_be_bytes());
        output.extend_from_slice(&LOGICAL_PAGE_SIZE.to_be_bytes());
        put_string(output, self.scope.as_str());
        output.extend_from_slice(&(self.topology.regions().len() as u32).to_be_bytes());
        for region in self.topology.regions() {
            region.encode_into(output);
        }
        output.extend_from_slice(&(self.roots.len() as u32).to_be_bytes());
        for (region, root) in self
            .topology
            .regions()
            .iter()
            .filter(|region| self.scope.includes(region.class()))
            .zip(&self.roots)
        {
            region.encode_into(output);
            output.extend_from_slice(root.as_bytes());
        }
    }

    /// Decodes a complete record with count, ordering, scope, and resource checks.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for malformed or incompatible bytes, invalid
    /// descriptors, incomplete selections, exceeded bounds, or trailing data.
    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self, RamError> {
        let mut reader = Reader::new(bytes, limits)?;
        if reader.take(8)? != ROOT_MAGIC
            || reader.u32()? != LOGICAL_ENCODING_EDITION
            || reader.u32()? != LOGICAL_PAGE_SIZE
        {
            return Err(RamError::InvalidEncoding);
        }
        let scope = Scope::decode(reader.string(9)?)?;
        let topology = read_inventory(&mut reader, limits)?;
        let expected = topology
            .regions()
            .iter()
            .filter(|region| scope.includes(region.class()))
            .count();
        let count = reader.u32()? as usize;
        if count != expected {
            return Err(RamError::InvalidLength);
        }
        reader.check_count(count, 47)?;
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(count)
            .map_err(|_| RamError::Allocation)?;
        for region in topology
            .regions()
            .iter()
            .filter(|region| scope.includes(region.class()))
        {
            if read_descriptor(&mut reader)? != *region {
                return Err(RamError::InvalidEncoding);
            }
            roots.push(RegionTreeDigest::from_bytes(reader.digest()?));
        }
        reader.finish()?;
        Self::new(topology, scope, roots)
    }
}

impl Topology {
    /// Decodes the exact inventory format without sorting untrusted records.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for noncanonical descriptors or ordering, exceeded
    /// limits, malformed UTF-8, truncation, overflow, or trailing data.
    pub fn decode_inventory(bytes: &[u8], limits: Limits) -> Result<Self, RamError> {
        let mut reader = Reader::new(bytes, limits)?;
        let topology = read_inventory(&mut reader, limits)?;
        reader.finish()?;
        Ok(topology)
    }
}

fn read_inventory(reader: &mut Reader<'_>, limits: Limits) -> Result<Topology, RamError> {
    let count = reader.u32()? as usize;
    if count > limits.max_regions.min(4096) {
        return Err(RamError::ResourceLimit);
    }
    reader.check_count(count, 15)?;
    let mut regions = Vec::new();
    regions
        .try_reserve_exact(count)
        .map_err(|_| RamError::Allocation)?;
    for _ in 0..count {
        let region = read_descriptor(reader)?;
        if regions.last().is_some_and(|previous: &RegionDescriptor| {
            previous.id().as_bytes() >= region.id().as_bytes()
        }) {
            return Err(RamError::InvalidOrder);
        }
        regions.push(region);
    }
    Topology::new(regions, limits)
}

fn read_descriptor(reader: &mut Reader<'_>) -> Result<RegionDescriptor, RamError> {
    let id = reader.string(255)?.to_owned();
    let class = RegionClass::decode(reader.u8()?)?;
    if reader.u8()? != class.coverage_mask() {
        return Err(RamError::InvalidEncoding);
    }
    RegionDescriptor::new(id, class, reader.u64()?)
}

/// A bounded region-local sibling path that additionally requires a complete root record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageProof {
    region_id: String,
    page_index: u64,
    valid_length: u32,
    page_digest: PageDigest,
    siblings: Vec<NodeDigest>,
}

impl PageProof {
    /// Validates structural proof bounds before topology-specific verification.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for invalid identifiers, lengths, or depth. Position,
    /// canonical geometry, and digest membership are checked by [`Self::verify`].
    pub fn new(
        region_id: impl Into<String>,
        page_index: u64,
        valid_length: u32,
        page_digest: PageDigest,
        siblings: Vec<NodeDigest>,
    ) -> Result<Self, RamError> {
        let region_id = region_id.into();
        validate_id(&region_id)?;
        if !(1..=LOGICAL_PAGE_SIZE).contains(&valid_length) {
            return Err(RamError::InvalidLength);
        }
        if siblings.len() > 52 || page_index >= 1_u64 << 52 {
            return Err(RamError::OutOfRange);
        }
        Ok(Self {
            region_id,
            page_index,
            valid_length,
            page_digest,
            siblings,
        })
    }

    /// Returns the canonical owner identifier.
    pub fn region_id(&self) -> &str {
        &self.region_id
    }

    /// Returns the logical page index.
    pub const fn page_index(&self) -> u64 {
        self.page_index
    }

    /// Returns the committed valid length.
    pub const fn valid_length(&self) -> u32 {
        self.valid_length
    }

    /// Returns the claimed content digest, which must still be verified.
    pub const fn page_digest(&self) -> PageDigest {
        self.page_digest
    }

    /// Returns sibling digests from leaf level to tree root.
    pub fn siblings(&self) -> &[NodeDigest] {
        &self.siblings
    }

    /// Verifies actual page bytes against a separately authenticated scoped root.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for a mismatched expected root, omitted region,
    /// padding position, wrong valid length/depth, or invalid content/path.
    pub fn verify(
        &self,
        bytes: &[u8],
        record: &RootRecord,
        expected_root: RamRootDigest,
    ) -> Result<PageDigest, RamError> {
        if record.digest() != expected_root {
            return Err(RamError::DigestMismatch);
        }
        let region = record
            .topology()
            .region(&self.region_id)
            .ok_or(RamError::OutOfRange)?;
        let expected_region = record
            .region_root(&self.region_id)
            .ok_or(RamError::OutOfRange)?;
        let geometry = region.geometry();
        if geometry.valid_length(self.page_index)? != self.valid_length
            || bytes.len() != self.valid_length as usize
            || self.siblings.len() != geometry.height() as usize
        {
            return Err(RamError::InvalidLength);
        }
        if PageDigest::hash(bytes)? != self.page_digest {
            return Err(RamError::DigestMismatch);
        }
        let reduced = self.verify_path(geometry)?;
        if region_tree_digest(geometry, reduced) != expected_region {
            return Err(RamError::DigestMismatch);
        }
        Ok(self.page_digest)
    }

    fn verify_path(&self, geometry: Geometry) -> Result<NodeDigest, RamError> {
        let mut node = leaf_digest(self.page_digest);
        let mut empty = empty_leaf_digest();
        for (level, sibling) in self.siblings.iter().enumerate() {
            let sibling_start = ((self.page_index >> level) ^ 1) << level;
            if sibling_start >= geometry.page_count() && *sibling != empty {
                return Err(RamError::DigestMismatch);
            }
            node = if (self.page_index >> level) & 1 == 0 {
                inner_digest(level as u32 + 1, node, *sibling)?
            } else {
                inner_digest(level as u32 + 1, *sibling, node)?
            };
            empty = inner_digest(level as u32 + 1, empty, empty)?;
        }
        Ok(node)
    }

    /// Encodes a bounded path without page bytes or native storage references.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(64 + self.region_id.len() + self.siblings.len() * 32);
        output.extend_from_slice(PROOF_MAGIC);
        put_string(&mut output, &self.region_id);
        output.extend_from_slice(&self.page_index.to_be_bytes());
        output.extend_from_slice(&self.valid_length.to_be_bytes());
        output.extend_from_slice(self.page_digest.as_bytes());
        output.extend_from_slice(&(self.siblings.len() as u32).to_be_bytes());
        for sibling in &self.siblings {
            output.extend_from_slice(sibling.as_bytes());
        }
        output
    }

    /// Decodes a structural proof within receiver-controlled record limits.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for incompatible tags, invalid lengths/depth,
    /// resource excess, truncation, or trailing bytes. Membership still requires
    /// [`Self::verify`] with actual page bytes and a trusted expected root.
    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self, RamError> {
        let mut reader = Reader::new(bytes, limits)?;
        if reader.take(8)? != PROOF_MAGIC {
            return Err(RamError::InvalidEncoding);
        }
        let id = reader.string(255)?.to_owned();
        let index = reader.u64()?;
        let length = reader.u32()?;
        let page = PageDigest::from_bytes(reader.digest()?);
        let depth = reader.u32()? as usize;
        if depth > 52 {
            return Err(RamError::ResourceLimit);
        }
        reader.check_count(depth, 32)?;
        let mut siblings = Vec::new();
        siblings
            .try_reserve_exact(depth)
            .map_err(|_| RamError::Allocation)?;
        for _ in 0..depth {
            siblings.push(NodeDigest::from_bytes(reader.digest()?));
        }
        reader.finish()?;
        Self::new(id, index, length, page, siblings)
    }
}

fn put_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: Limits) -> Result<Self, RamError> {
        if bytes.len() > limits.max_record_bytes {
            return Err(RamError::ResourceLimit);
        }
        Ok(Self { bytes, position: 0 })
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RamError> {
        let end = self.position.checked_add(count).ok_or(RamError::Overflow)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(RamError::Malformed)?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, RamError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, RamError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| RamError::Malformed)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, RamError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| RamError::Malformed)?,
        ))
    }

    fn digest(&mut self) -> Result<[u8; 32], RamError> {
        self.take(32)?.try_into().map_err(|_| RamError::Malformed)
    }

    fn string(&mut self, maximum: usize) -> Result<&'a str, RamError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(RamError::ResourceLimit);
        }
        std::str::from_utf8(self.take(length)?).map_err(|_| RamError::InvalidEncoding)
    }

    fn check_count(&self, count: usize, minimum: usize) -> Result<(), RamError> {
        if count.checked_mul(minimum).ok_or(RamError::Overflow)? > self.bytes.len() - self.position
        {
            return Err(RamError::Malformed);
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), RamError> {
        if self.position != self.bytes.len() {
            return Err(RamError::Malformed);
        }
        Ok(())
    }
}
