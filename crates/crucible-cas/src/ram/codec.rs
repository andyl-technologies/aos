//! Strict bounded CAS envelopes for pages, binary catalog nodes, and roots.
//!
//! ```text
//! page body: PageDigest:32 | valid-length:u32be | bytes
//! node body: kind:u8 | NodeDigest:32 | height:u32be | real-pages:u64be | kind-fields
//! root body: logical-record-length:u32be | RootRecord | region-TreeRefs
//! TreeRef: NodeDigest:32 | height:u32be | real-pages:u64be
//! ```
//!
//! Storage references occur only in the envelope's generic child table, so
//! ordinary closure walkers and GC see every required realization. All fixed
//! body fields authenticate against the separately computed logical digests.

use std::collections::BTreeSet;

use crucible_ram::{Limits, NodeDigest, PageDigest, RootRecord};

use crate::content_envelope::{ContentChild, ContentEnvelope};
use crate::content_store::{ContentId, ObjectKind, StoreError};

use super::codec_ownership::{OwnedEnvelope, admission, encoded_source};

use super::{
    MAX_RAM_OBJECT_BYTES, PendingPublication, RamRetention, RamStore, RamStoreError, Work,
    empty_node, logical,
};

pub(super) const PAGE_SCHEMA: &str = "crucible.ram.page";
pub(super) const TREE_SCHEMA: &str = "crucible.ram.tree";
pub(super) const ROOT_SCHEMA: &str = "crucible.ram.root";
pub(super) const SCHEMA_VERSION: u32 = 1;
const MAX_CAPTURE_BATCH_OBJECTS: usize = 64;
const MAX_CAPTURE_BATCH_BYTES: u64 = 4 * 1024 * 1024;

pub(super) fn object_limits(id: ContentId) -> Result<(u64, usize), RamStoreError> {
    match id.kind() {
        ObjectKind::ExactManifest => Ok((MAX_RAM_OBJECT_BYTES, Limits::default().max_regions)),
        ObjectKind::RamTree => Ok((4096, 2)),
        ObjectKind::RamExtent => Ok((8192, 0)),
        _ => Err(RamStoreError::Invalid("RAM object kind")),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TreeRef {
    pub id: ContentId,
    pub digest: NodeDigest,
    pub height: u32,
    pub pages: u64,
}

pub(super) enum TreeNode {
    Padding,
    Leaf { page: ContentId, digest: PageDigest },
    Branch { left: TreeRef, right: TreeRef },
}

impl RamStore {
    pub(super) fn put_envelope(
        &self,
        envelope: &ContentEnvelope,
        kind: ObjectKind,
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<ContentId, RamStoreError> {
        let account = self.object_account()?;
        let _scope = account.enter();
        let bytes = envelope.canonical_bytes();
        account.check().map_err(admission)?;
        let id = envelope.content_id(kind);
        work.visit(bytes.len() as u64)?;

        // The operation's GC fence must precede publication. Registering this
        // exact expected ID also protects crash recovery before a put completes.
        retention.retain_object(id)?;
        let source = encoded_source(bytes, &account)?;
        if let Some(pending) = &work.pending {
            if let Some(existing) = pending.iter().find(|existing| existing.id == id) {
                if existing.envelope != *envelope {
                    return Err(StoreError::Corrupt { id }.into());
                }
                return Ok(id);
            }
            let buffered_bytes = pending.iter().try_fold(0_u64, |total, object| {
                total
                    .checked_add(object.source.logical_length())
                    .ok_or(RamStoreError::Limit("capture batch bytes"))
            })?;
            if buffered_bytes
                .checked_add(source.logical_length())
                .is_none_or(|total| total > MAX_CAPTURE_BATCH_BYTES)
                || pending.len() == MAX_CAPTURE_BATCH_OBJECTS
            {
                self.flush_capture_batch(work)?;
            }
            if let Some(pending) = &mut work.pending {
                // A pending canonical envelope is a distinct owned copy. Its
                // conservative closed-schema loan precedes that copy and stays
                // with it until batch publication and authentication finish.
                let clone_bytes = ContentEnvelope::decoding_memory_bound(
                    source.logical_length() as usize,
                    envelope.children().len(),
                )?;
                crate::owned_decode::charge_bytes(clone_bytes).map_err(admission)?;
                pending.push(PendingPublication {
                    id,
                    source,
                    envelope: OwnedEnvelope::new(envelope.clone(), &account),
                });
                return Ok(id);
            }
        }
        let receipt = self.backend.put_if_absent(id, &source)?;
        self.validate_receipt(&receipt, id, source.logical_length())?;

        let persisted = self.read_envelope(id, work)?;
        if persisted != *envelope {
            return Err(StoreError::Corrupt { id }.into());
        }
        Ok(id)
    }

    pub(super) fn flush_capture_batch(&self, work: &mut Work<'_>) -> Result<(), RamStoreError> {
        let Some(pending) = work.pending.take() else {
            return Ok(());
        };
        if !pending.is_empty() {
            (work.boundary)()?;
            let account = self.object_account()?;
            let _scope = account.enter();
            crate::owned_decode::charge_array::<(ContentId, crate::content_store::BlobHandle)>(
                pending.len(),
            )
            .map_err(admission)?;
            let objects = pending
                .iter()
                .map(|object| (object.id, object.source.clone()))
                .collect::<Vec<_>>();
            let receipts = self.backend.put_many_if_absent(&objects)?;
            if receipts.len() != pending.len() {
                return Err(RamStoreError::Invalid("capture batch receipt count"));
            }
            for (object, receipt) in pending.iter().zip(&receipts) {
                self.validate_receipt(receipt, object.id, object.source.logical_length())?;
                if self.read_envelope(object.id, work)? != object.envelope {
                    return Err(StoreError::Corrupt { id: object.id }.into());
                }
            }
        }
        work.pending = Some(Vec::with_capacity(MAX_CAPTURE_BATCH_OBJECTS));
        Ok(())
    }

    fn validate_receipt(
        &self,
        receipt: &crate::content_store::PutReceipt,
        id: ContentId,
        logical_length: u64,
    ) -> Result<(), RamStoreError> {
        let durable = receipt.durable_placements();
        if receipt.id != id
            || receipt
                .placements
                .iter()
                .any(|placement| placement.logical_length != logical_length)
        {
            return Err(StoreError::Corrupt { id }.into());
        }
        if durable < usize::from(self.durability.minimum_durable_placements()) {
            return Err(StoreError::DurabilityUnsatisfied {
                id,
                minimum_durable_placements: self.durability.minimum_durable_placements(),
                observed_durable_placements: u16::try_from(durable)
                    .map_err(|_| RamStoreError::Limit("durable placement count"))?,
            }
            .into());
        }

        Ok(())
    }

    pub(super) fn read_envelope(
        &self,
        id: ContentId,
        work: &mut Work<'_>,
    ) -> Result<OwnedEnvelope, RamStoreError> {
        let account = self.object_account()?;
        let _scope = account.enter();
        if id.schema_version() != SCHEMA_VERSION {
            return Err(RamStoreError::Invalid("RAM storage schema"));
        }
        // Page and binary-tree lookups run under bounded page-in scratch. A
        // malformed small-object identity must not borrow the root decoder's
        // larger catalog allocation merely by declaring a large body/table.
        let (maximum_bytes, maximum_children) = object_limits(id)?;
        (work.boundary)()?;
        let source = self.backend.read(id, None)?;
        if source.logical_length() > maximum_bytes {
            return Err(RamStoreError::Limit("single canonical object"));
        }
        work.visit(source.logical_length())?;
        let bytes = source.read_all(maximum_bytes)?;
        if !id.authenticates(&bytes) {
            return Err(StoreError::Corrupt { id }.into());
        }
        let envelope =
            ContentEnvelope::from_canonical_bytes_with_child_limit(&bytes, maximum_children)?;
        if envelope.schema_version() != SCHEMA_VERSION {
            return Err(RamStoreError::Invalid("RAM envelope schema"));
        }
        Ok(OwnedEnvelope::new(envelope, &account))
    }

    pub(super) fn put_page(
        &self,
        bytes: &[u8],
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<(ContentId, PageDigest), RamStoreError> {
        let digest = PageDigest::hash(bytes).map_err(logical)?;
        let mut body = Vec::with_capacity(36 + bytes.len());
        body.extend_from_slice(digest.as_bytes());
        body.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(bytes);
        let envelope = ContentEnvelope::new(PAGE_SCHEMA, SCHEMA_VERSION, BTreeSet::new(), body)?;
        let id = self.put_envelope(&envelope, ObjectKind::RamExtent, retention, work)?;
        Ok((id, digest))
    }

    pub(super) fn read_page_object(
        &self,
        id: ContentId,
        expected: PageDigest,
        work: &mut Work<'_>,
    ) -> Result<Vec<u8>, RamStoreError> {
        if id.kind() != ObjectKind::RamExtent {
            return Err(RamStoreError::Invalid("page object kind"));
        }
        let envelope = self.read_envelope(id, work)?;
        if envelope.schema_name() != PAGE_SCHEMA || !envelope.children().is_empty() {
            return Err(RamStoreError::Invalid("page envelope"));
        }
        let mut decoder = Decoder::new(envelope.body());
        let recorded = PageDigest::from_bytes(decoder.digest()?);
        let length = decoder.u32()? as usize;
        if length == 0 || length > 4096 || length != decoder.remaining().len() {
            return Err(RamStoreError::Invalid("page object length"));
        }
        let bytes = decoder.remaining();
        if recorded != expected || PageDigest::hash(bytes).map_err(logical)? != expected {
            return Err(RamStoreError::Invalid("logical page digest"));
        }
        Ok(bytes.to_vec())
    }

    pub(super) fn put_tree(
        &self,
        node: &TreeNode,
        height: u32,
        pages: u64,
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<TreeRef, RamStoreError> {
        let mut children = BTreeSet::new();
        let (kind, digest) = match node {
            TreeNode::Padding => (0, empty_node(height)?),
            TreeNode::Leaf { page, digest } => {
                children.insert(ContentChild::new("page", *page)?);
                (1, crucible_ram::leaf_digest(*digest))
            }
            TreeNode::Branch { left, right } => {
                children.insert(ContentChild::new("left", left.id)?);
                children.insert(ContentChild::new("right", right.id)?);
                (
                    2,
                    crucible_ram::inner_digest(height, left.digest, right.digest)
                        .map_err(logical)?,
                )
            }
        };

        let mut body = Vec::with_capacity(133);
        body.push(kind);
        body.extend_from_slice(digest.as_bytes());
        body.extend_from_slice(&height.to_be_bytes());
        body.extend_from_slice(&pages.to_be_bytes());
        match node {
            TreeNode::Padding => {}
            TreeNode::Leaf { digest, .. } => body.extend_from_slice(digest.as_bytes()),
            TreeNode::Branch { left, right } => {
                encode_ref(&mut body, *left);
                encode_ref(&mut body, *right);
            }
        }
        let envelope = ContentEnvelope::new(TREE_SCHEMA, SCHEMA_VERSION, children, body)?;
        let id = self.put_envelope(&envelope, ObjectKind::RamTree, retention, work)?;
        let reference = TreeRef {
            id,
            digest,
            height,
            pages,
        };
        validate_tree(&envelope, reference)?;
        Ok(reference)
    }

    pub(super) fn read_tree(
        &self,
        reference: TreeRef,
        work: &mut Work<'_>,
    ) -> Result<TreeNode, RamStoreError> {
        if reference.id.kind() != ObjectKind::RamTree {
            return Err(RamStoreError::Invalid("tree object kind"));
        }
        let envelope = self.read_envelope(reference.id, work)?;
        validate_tree(&envelope, reference)
    }

    pub(super) fn put_root(
        &self,
        record: &RootRecord,
        regions: &[TreeRef],
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<ContentId, RamStoreError> {
        let canonical = record.encode();
        let length = u32::try_from(canonical.len())
            .map_err(|_| RamStoreError::Limit("logical root record"))?;
        let mut body = Vec::with_capacity(4 + canonical.len() + 44 * regions.len());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&canonical);
        let mut children = BTreeSet::new();
        for (index, reference) in regions.iter().enumerate() {
            encode_ref(&mut body, *reference);
            children.insert(ContentChild::new(
                format!("region-{index:08x}"),
                reference.id,
            )?);
        }
        let envelope = ContentEnvelope::new(ROOT_SCHEMA, SCHEMA_VERSION, children, body)?;
        self.put_envelope(&envelope, ObjectKind::ExactManifest, retention, work)
    }

    pub(super) fn read_root(
        &self,
        id: ContentId,
        work: &mut Work<'_>,
    ) -> Result<(RootRecord, Vec<TreeRef>), RamStoreError> {
        if id.kind() != ObjectKind::ExactManifest {
            return Err(RamStoreError::Invalid("root object kind"));
        }
        let envelope = self.read_envelope(id, work)?;
        decode_root_envelope(&envelope)
    }
}

pub(super) fn decode_root_envelope(
    envelope: &ContentEnvelope,
) -> Result<(RootRecord, Vec<TreeRef>), RamStoreError> {
    if envelope.schema_name() != ROOT_SCHEMA {
        return Err(RamStoreError::Invalid("root envelope"));
    }
    let mut decoder = Decoder::new(envelope.body());
    let length = decoder.u32()? as usize;
    let canonical = decoder.take(length)?;
    let record = RootRecord::decode(canonical, Limits::default()).map_err(logical)?;
    if envelope.children().len() != record.region_roots().len() {
        return Err(RamStoreError::Invalid("root child count"));
    }
    let mut regions = Vec::with_capacity(record.region_roots().len());
    for (index, child) in envelope.children().iter().enumerate() {
        if child.role() != format!("region-{index:08x}") || child.id().kind() != ObjectKind::RamTree
        {
            return Err(RamStoreError::Invalid("root child role or kind"));
        }
        regions.push(decode_ref(&mut decoder, child.id())?);
    }
    decoder.finish()?;
    Ok((record, regions))
}

pub(super) fn validate_tree(
    envelope: &ContentEnvelope,
    expected: TreeRef,
) -> Result<TreeNode, RamStoreError> {
    if envelope.schema_name() != TREE_SCHEMA || expected.height > 52 {
        return Err(RamStoreError::Invalid("tree schema or height"));
    }
    let mut decoder = Decoder::new(envelope.body());
    let kind = decoder.byte()?;
    let digest = NodeDigest::from_bytes(decoder.digest()?);
    let height = decoder.u32()?;
    let pages = decoder.u64()?;
    if (digest, height, pages) != (expected.digest, expected.height, expected.pages)
        || pages > (1_u64 << height)
    {
        return Err(RamStoreError::Invalid("tree reference geometry"));
    }
    let children = envelope.children();
    let node = match kind {
        0 if pages == 0 && children.is_empty() => {
            if digest != empty_node(height)? {
                return Err(RamStoreError::Invalid("padding digest"));
            }
            TreeNode::Padding
        }
        1 if height == 0 && pages == 1 && children.len() == 1 => {
            let child = children
                .iter()
                .next()
                .ok_or(RamStoreError::Invalid("leaf child"))?;
            if child.role() != "page" || child.id().kind() != ObjectKind::RamExtent {
                return Err(RamStoreError::Invalid("leaf child role"));
            }
            let page_digest = PageDigest::from_bytes(decoder.digest()?);
            if digest != crucible_ram::leaf_digest(page_digest) {
                return Err(RamStoreError::Invalid("leaf digest"));
            }
            TreeNode::Leaf {
                page: child.id(),
                digest: page_digest,
            }
        }
        2 if height != 0 && pages != 0 && children.len() == 2 => {
            let mut children = children.iter();
            let left_child = children
                .next()
                .ok_or(RamStoreError::Invalid("left child"))?;
            let right_child = children
                .next()
                .ok_or(RamStoreError::Invalid("right child"))?;
            if left_child.role() != "left" || right_child.role() != "right" {
                return Err(RamStoreError::Invalid("branch child roles"));
            }
            let left = decode_ref(&mut decoder, left_child.id())?;
            let right = decode_ref(&mut decoder, right_child.id())?;
            let width = 1_u64 << (height - 1);
            if left.height != height - 1
                || right.height != height - 1
                || left.pages != pages.min(width)
                || right.pages != pages.saturating_sub(width)
                || left.id.kind() != ObjectKind::RamTree
                || right.id.kind() != ObjectKind::RamTree
                || digest
                    != crucible_ram::inner_digest(height, left.digest, right.digest)
                        .map_err(logical)?
            {
                return Err(RamStoreError::Invalid("branch geometry or digest"));
            }
            TreeNode::Branch { left, right }
        }
        _ => return Err(RamStoreError::Invalid("tree node kind")),
    };
    decoder.finish()?;
    Ok(node)
}

fn encode_ref(bytes: &mut Vec<u8>, reference: TreeRef) {
    bytes.extend_from_slice(reference.digest.as_bytes());
    bytes.extend_from_slice(&reference.height.to_be_bytes());
    bytes.extend_from_slice(&reference.pages.to_be_bytes());
}

fn decode_ref(decoder: &mut Decoder<'_>, id: ContentId) -> Result<TreeRef, RamStoreError> {
    Ok(TreeRef {
        id,
        digest: NodeDigest::from_bytes(decoder.digest()?),
        height: decoder.u32()?,
        pages: decoder.u64()?,
    })
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RamStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RamStoreError::Invalid("record offset"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RamStoreError::Invalid("truncated RAM record"))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, RamStoreError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(RamStoreError::Invalid("byte field"))
    }

    fn digest(&mut self) -> Result<[u8; 32], RamStoreError> {
        self.take(32)?
            .try_into()
            .map_err(|_| RamStoreError::Invalid("digest field"))
    }

    fn u32(&mut self) -> Result<u32, RamStoreError> {
        self.take(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| RamStoreError::Invalid("u32 field"))
    }

    fn u64(&mut self) -> Result<u64, RamStoreError> {
        self.take(8)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| RamStoreError::Invalid("u64 field"))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn finish(self) -> Result<(), RamStoreError> {
        if self.offset != self.bytes.len() {
            return Err(RamStoreError::Invalid("trailing RAM record bytes"));
        }
        Ok(())
    }
}
