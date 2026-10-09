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
use std::sync::Arc;

use crucible_ram::{Limits, NodeDigest, PageDigest, RootRecord};

use crate::content_envelope::{ContentChild, ContentEnvelope};
use crate::content_store::{ContentId, ObjectKind, StoreError};

use super::codec_ownership::{OwnedEnvelope, PublicationInput, admission, encoded_source};
use super::record_account::{RecordAccount, RecordAllocationPlan, child_node_bytes, shared_extent};
use crate::owned_decode::DecodeBudget;

use super::{
    MAX_RAM_OBJECT_BYTES, PendingBatch, PendingPublication, RamRetention, RamStore, RamStoreError,
    Work, empty_node, logical,
};

pub(super) const PAGE_SCHEMA: &str = "crucible.ram.page";
pub(super) const TREE_SCHEMA: &str = "crucible.ram.tree";
pub(super) const ROOT_SCHEMA: &str = "crucible.ram.root";
pub(super) const SCHEMA_VERSION: u32 = 1;
const MAX_PUBLICATION_BATCH_OBJECTS: usize = 64;
const MAX_PUBLICATION_BATCH_BYTES: u64 = 4 * 1024 * 1024;

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

#[derive(Clone, Copy)]
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
        let account = work.original().child().map_err(admission)?;
        self.put_envelope_with_account(
            PublicationInput::Borrowed(envelope),
            kind,
            retention,
            work,
            &RecordAccount {
                codec: account.clone(),
                original: account,
            },
        )
    }

    fn put_envelope_with_account(
        &self,
        input: PublicationInput<'_>,
        kind: ObjectKind,
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
        accounts: &RecordAccount,
    ) -> Result<ContentId, RamStoreError> {
        let envelope = input.envelope();
        let account = &accounts.codec;
        let original = &accounts.original;
        let (id, bytes) = {
            let _scope = account.enter();
            let bytes = envelope.canonical_bytes();
            account.check().map_err(admission)?;
            // The admitted image is already canonical. Hash that exact image
            // without emitting the framing and child identities a second time.
            let id = ContentId::for_bytes(kind, envelope.schema_version(), &bytes);
            (id, bytes)
        };
        // Operation, retention and all backend callbacks use original authority.
        // Only concrete codec allocations enter the prepaid partition.
        let _original_scope = original.enter();
        work.visit(bytes.len() as u64)?;
        retention.retain_object(id)?;
        let source = {
            let _scope = account.enter();
            encoded_source(bytes, account, original)?
        };
        if let Some(pending) = &work.pending {
            if let Some(existing) = pending.iter().find(|existing| existing.id == id) {
                if *existing.envelope != *envelope {
                    return Err(StoreError::Corrupt { id }.into());
                }
                (work.boundary)()?;
                return Ok(id);
            }
            let buffered_bytes = pending.iter().try_fold(0_u64, |total, object| {
                total
                    .checked_add(object.source.logical_length())
                    .ok_or(RamStoreError::Limit("RAM publication batch bytes"))
            })?;
            if buffered_bytes
                .checked_add(source.logical_length())
                .is_none_or(|total| total > MAX_PUBLICATION_BATCH_BYTES)
                || pending.len() == MAX_PUBLICATION_BATCH_OBJECTS
            {
                self.flush_publication_batch(work)?;
            }
            if let Some(pending) = &mut work.pending {
                let envelope = input.into_pending(account, source.logical_length() as usize)?;
                (work.boundary)()?;
                pending.push(PendingPublication {
                    id,
                    source,
                    envelope,
                });
                return Ok(id);
            }
        }
        let objects = [(id, source)];
        let receipt = work.checked(|original, boundary| {
            self.backend
                .put_many_if_absent_with_boundary(original, &objects, boundary)
        })?;
        let receipt = receipt
            .check(|receipts| {
                let result = (|| {
                    if receipts.len() != 1 {
                        return Err(RamStoreError::Invalid("singleton RAM receipt count"));
                    }
                    self.validate_receipt(&receipts[0], id, objects[0].1.logical_length())?;
                    if self.read_envelope(id, work)? != *envelope {
                        return Err(StoreError::Corrupt { id }.into());
                    }
                    Ok(())
                })();
                result.map_err(|error| work.validation_error(error))
            })
            .map_err(RamStoreError::from)?;
        work.checked(|_, boundary| receipt.accept_with_boundary(boundary))?;
        Ok(id)
    }

    pub(super) fn flush_publication_batch(&self, work: &mut Work<'_>) -> Result<(), RamStoreError> {
        let Some(pending) = work.pending.take() else {
            return Ok(());
        };
        if !pending.is_empty() {
            if pending.len() > MAX_PUBLICATION_BATCH_OBJECTS {
                return Err(RamStoreError::Limit("RAM publication batch object count"));
            }
            let mut expected = [None; MAX_PUBLICATION_BATCH_OBJECTS];
            for (slot, object) in expected.iter_mut().zip(pending.iter()) {
                *slot = Some((object.id, object.source.logical_length()));
            }
            (work.boundary)()?;
            let original = work.original();
            let _scope = original.enter();
            let _objects_credit = original
                .reserve_scratch_array::<(ContentId, crate::content_store::BlobHandle)>(
                    pending.len(),
                )
                .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
            let objects = pending
                .iter()
                .map(|object| (object.id, object.source.clone()))
                .collect::<Vec<_>>();
            let receipts = work.checked(|original, boundary| {
                self.backend
                    .put_many_if_absent_with_boundary(original, &objects, boundary)
            })?;
            // The input ID commits to its complete canonical bytes, including
            // schema and children. The owning receipt now retains the actual
            // publication outcome; authenticated readback needs only that ID
            // and length, not all original codec bodies and encoded vectors.
            drop(objects);
            drop(_objects_credit);
            drop(pending);
            let receipts = receipts
                .check(|receipts| {
                    let result = (|| {
                        let count = expected.iter().flatten().count();
                        if receipts.len() != count {
                            return Err(RamStoreError::Invalid(
                                "RAM publication batch receipt count",
                            ));
                        }
                        for ((id, length), receipt) in
                            expected.iter().flatten().zip(receipts.iter())
                        {
                            self.validate_receipt(receipt, *id, *length)?;
                            // This authenticates the exact committed input and
                            // still applies the canonical schema/child limits.
                            self.read_envelope(*id, work)?;
                        }
                        Ok(())
                    })();
                    result.map_err(|error| work.validation_error(error))
                })
                .map_err(RamStoreError::from)?;
            work.checked(|_, boundary| receipts.accept_with_boundary(boundary))?;
        } else {
            drop(pending);
        }
        self.begin_publication_batch(work)?;
        Ok(())
    }

    pub(super) fn begin_publication_batch(&self, work: &mut Work<'_>) -> Result<(), RamStoreError> {
        if work.pending.is_some() {
            return Err(RamStoreError::Invalid(
                "RAM publication batch already present",
            ));
        }
        let account = work.original();
        let extent = (std::mem::size_of::<PendingPublication>() as u64)
            .checked_mul(MAX_PUBLICATION_BATCH_OBJECTS as u64)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PendingBatch>() as u64))
            .ok_or(RamStoreError::Limit("RAM publication batch allocation"))?;
        let credit = account.reserve_scratch_bytes(extent).map_err(admission)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(MAX_PUBLICATION_BATCH_OBJECTS)
            .map_err(|source| StoreError::StreamIo {
                operation: "allocate RAM publication batch",
                source: std::io::Error::other(source),
            })?;
        work.pending = Some(PendingBatch {
            objects,
            _credit: credit,
        });
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
        self.read_envelope_with_partition(id, work, true)
    }

    #[cfg(test)]
    pub(super) fn read_envelope_without_prepayment(
        &self,
        id: ContentId,
        work: &mut Work<'_>,
    ) -> Result<OwnedEnvelope, RamStoreError> {
        self.read_envelope_with_partition(id, work, false)
    }

    pub(super) fn read_envelope_with_partition(
        &self,
        id: ContentId,
        work: &mut Work<'_>,
        prepaid: bool,
    ) -> Result<OwnedEnvelope, RamStoreError> {
        read_envelope_from(self.backend.as_ref(), id, work, prepaid)
    }

    pub(super) fn put_page(
        &self,
        bytes: &[u8],
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<(ContentId, PageDigest), RamStoreError> {
        let digest = PageDigest::hash(bytes).map_err(logical)?;
        let original = work.original();
        let body_length = 36 + bytes.len();
        let original = original.child().map_err(admission)?;
        let record = RecordAccount::phase(
            &original,
            RecordAllocationPlan::input(body_length, PAGE_SCHEMA, &[])?,
        )?;
        let canonical_length = 30 + PAGE_SCHEMA.len() + body_length;
        let scope = record.codec.enter();
        record
            .codec
            .charge_array::<u8>(body_length)
            .map_err(admission)?;
        record
            .codec
            .charge_array::<u8>(PAGE_SCHEMA.len())
            .map_err(admission)?;
        let mut body = Vec::with_capacity(body_length);
        body.extend_from_slice(digest.as_bytes());
        body.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(bytes);
        let envelope = ContentEnvelope::new(PAGE_SCHEMA, SCHEMA_VERSION, BTreeSet::new(), body)?;
        record
            .codec
            .charge_bytes(shared_extent::<OwnedEnvelope>()?)
            .map_err(admission)?;
        let envelope = Arc::new(OwnedEnvelope::new(envelope, &record.codec));
        drop(scope);
        let canonical = RecordAccount::phase(
            &original,
            RecordAllocationPlan::canonical(canonical_length)?,
        )?;
        let id = self.put_envelope_with_account(
            PublicationInput::OwnedSmall(envelope),
            ObjectKind::RamExtent,
            retention,
            work,
            &canonical,
        )?;
        Ok((id, digest))
    }

    pub(super) fn read_page_object(
        &self,
        id: ContentId,
        expected: PageDigest,
        work: &mut Work<'_>,
    ) -> Result<super::RamPageBytes, RamStoreError> {
        if id.kind() != ObjectKind::RamExtent {
            return Err(RamStoreError::Invalid("page object kind"));
        }
        let envelope = self.read_envelope_with_partition(id, work, false)?;
        validate_page_envelope(&envelope, expected)?;
        Ok(super::RamPageBytes::new(envelope))
    }

    pub(super) fn put_tree(
        &self,
        node: &TreeNode,
        height: u32,
        pages: u64,
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<TreeRef, RamStoreError> {
        let original = work.original();
        let (roles, body_length, child_length): (&[&str], usize, usize) = match node {
            TreeNode::Padding => (&[], 45, 0),
            TreeNode::Leaf { page, .. } => (&["page"], 77, 4 + "page".len() + page.encoded_len()),
            TreeNode::Branch { left, right } => (
                &["left", "right"],
                133,
                8 + "left".len() + "right".len() + left.id.encoded_len() + right.id.encoded_len(),
            ),
        };
        let original = original.child().map_err(admission)?;
        let record = RecordAccount::phase(
            &original,
            RecordAllocationPlan::input(133, TREE_SCHEMA, roles)?,
        )?;
        let canonical_length = 30 + TREE_SCHEMA.len() + body_length + child_length;
        let scope = record.codec.enter();
        record.codec.charge_array::<u8>(133).map_err(admission)?;
        record
            .codec
            .charge_array::<u8>(TREE_SCHEMA.len())
            .map_err(admission)?;
        for role in roles {
            record
                .codec
                .charge_bytes(child_node_bytes())
                .map_err(admission)?;
            record
                .codec
                .charge_array::<u8>(role.len())
                .map_err(admission)?;
        }
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
        record
            .codec
            .charge_bytes(shared_extent::<OwnedEnvelope>()?)
            .map_err(admission)?;
        let envelope = Arc::new(OwnedEnvelope::new(envelope, &record.codec));
        drop(scope);
        let canonical = RecordAccount::phase(
            &original,
            RecordAllocationPlan::canonical(canonical_length)?,
        )?;
        let id = self.put_envelope_with_account(
            PublicationInput::OwnedSmall(Arc::clone(&envelope)),
            ObjectKind::RamTree,
            retention,
            work,
            &canonical,
        )?;
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
        super::bounded_read::read_tree(self.backend.as_ref(), reference, work)
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

// Emits only the closed canonical binary-node format from an actual validated
// record. The full storage ID check seals framing and child-role correspondence
// before the response can expose any generated bytes.
#[cfg(test)]
pub(super) fn encode_validated_tree(
    reference: TreeRef,
    node: &TreeNode,
    original: &DecodeBudget,
) -> Result<Vec<u8>, RamStoreError> {
    let (kind, children, body_length, child_length) = match node {
        TreeNode::Padding => (0_u8, 0_u32, 45, 0),
        TreeNode::Leaf { page, .. } => (1, 1, 77, 4 + "page".len() + page.encoded_len()),
        TreeNode::Branch { left, right } => (
            2,
            2,
            133,
            8 + "left".len() + "right".len() + left.id.encoded_len() + right.id.encoded_len(),
        ),
    };
    let length = 30 + TREE_SCHEMA.len() + child_length + body_length;
    original.charge_array::<u8>(length).map_err(admission)?;
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(b"CRUCOBJE");
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&(TREE_SCHEMA.len() as u16).to_be_bytes());
    bytes.extend_from_slice(TREE_SCHEMA.as_bytes());
    bytes.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
    bytes.extend_from_slice(&children.to_be_bytes());
    {
        let mut child = |role: &str, id: ContentId| {
            bytes.extend_from_slice(&(role.len() as u16).to_be_bytes());
            bytes.extend_from_slice(role.as_bytes());
            id.with_encoded_text(|id| {
                bytes.extend_from_slice(&(id.len() as u16).to_be_bytes());
                bytes.extend_from_slice(id);
            });
        };
        match node {
            TreeNode::Padding => {}
            TreeNode::Leaf { page, .. } => child("page", *page),
            TreeNode::Branch { left, right } => {
                child("left", left.id);
                child("right", right.id);
            }
        }
    }
    bytes.extend_from_slice(&(body_length as u64).to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(reference.digest.as_bytes());
    bytes.extend_from_slice(&reference.height.to_be_bytes());
    bytes.extend_from_slice(&reference.pages.to_be_bytes());
    match node {
        TreeNode::Padding => {}
        TreeNode::Leaf { digest, .. } => bytes.extend_from_slice(digest.as_bytes()),
        TreeNode::Branch { left, right } => {
            encode_ref(&mut bytes, *left);
            encode_ref(&mut bytes, *right);
        }
    }
    if bytes.len() != length
        || ContentId::for_bytes(ObjectKind::RamTree, SCHEMA_VERSION, &bytes) != reference.id
    {
        return Err(StoreError::Corrupt { id: reference.id }.into());
    }
    Ok(bytes)
}

pub(super) fn validate_page_envelope(
    envelope: &ContentEnvelope,
    expected: PageDigest,
) -> Result<usize, RamStoreError> {
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
    Ok(length)
}

pub(super) fn decode_envelope(
    id: ContentId,
    bytes: &[u8],
    maximum_children: usize,
    account: &DecodeBudget,
) -> Result<OwnedEnvelope, RamStoreError> {
    if !id.authenticates(bytes) {
        return Err(StoreError::Corrupt { id }.into());
    }
    let envelope = ContentEnvelope::from_canonical_bytes_with_child_limit(bytes, maximum_children)?;
    if envelope.schema_version() != SCHEMA_VERSION {
        return Err(RamStoreError::Invalid("RAM envelope schema"));
    }
    Ok(OwnedEnvelope::new(envelope, account))
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

#[derive(Clone, Copy)]
pub(super) struct TreeChild<'a> {
    pub(super) role: &'a str,
    pub(super) id: ContentId,
}

pub(super) fn validate_tree(
    envelope: &ContentEnvelope,
    expected: TreeRef,
) -> Result<TreeNode, RamStoreError> {
    let mut children = envelope.children().iter();
    validate_tree_parts(
        envelope.schema_name(),
        envelope.body(),
        envelope.children().len(),
        |_| {
            children.next().map(|child| TreeChild {
                role: child.role(),
                id: child.id(),
            })
        },
        expected,
    )
}

pub(super) fn validate_tree_parts<'a>(
    schema: &str,
    body: &[u8],
    child_count: usize,
    mut child_at: impl FnMut(usize) -> Option<TreeChild<'a>>,
    expected: TreeRef,
) -> Result<TreeNode, RamStoreError> {
    if schema != TREE_SCHEMA || expected.height > 52 {
        return Err(RamStoreError::Invalid("tree schema or height"));
    }
    let mut decoder = Decoder::new(body);
    let kind = decoder.byte()?;
    let digest = NodeDigest::from_bytes(decoder.digest()?);
    let height = decoder.u32()?;
    let pages = decoder.u64()?;
    if (digest, height, pages) != (expected.digest, expected.height, expected.pages)
        || pages > (1_u64 << height)
    {
        return Err(RamStoreError::Invalid("tree reference geometry"));
    }
    let node = match kind {
        0 if pages == 0 && child_count == 0 => {
            if digest != empty_node(height)? {
                return Err(RamStoreError::Invalid("padding digest"));
            }
            TreeNode::Padding
        }
        1 if height == 0 && pages == 1 && child_count == 1 => {
            let child = child_at(0).ok_or(RamStoreError::Invalid("leaf child"))?;
            if child.role != "page" || child.id.kind() != ObjectKind::RamExtent {
                return Err(RamStoreError::Invalid("leaf child role"));
            }
            let page_digest = PageDigest::from_bytes(decoder.digest()?);
            if digest != crucible_ram::leaf_digest(page_digest) {
                return Err(RamStoreError::Invalid("leaf digest"));
            }
            TreeNode::Leaf {
                page: child.id,
                digest: page_digest,
            }
        }
        2 if height != 0 && pages != 0 && child_count == 2 => {
            let left_child = child_at(0).ok_or(RamStoreError::Invalid("left child"))?;
            let right_child = child_at(1).ok_or(RamStoreError::Invalid("right child"))?;
            if left_child.role != "left" || right_child.role != "right" {
                return Err(RamStoreError::Invalid("branch child roles"));
            }
            let left = decode_ref(&mut decoder, left_child.id)?;
            let right = decode_ref(&mut decoder, right_child.id)?;
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

/// Executes the single existing checked envelope route under its owning Work.
pub(super) fn read_envelope_from<B: crate::content_store::ImmutableBlobBackend + ?Sized>(
    backend: &B,
    id: ContentId,
    work: &mut Work<'_>,
    prepaid: bool,
) -> Result<OwnedEnvelope, RamStoreError> {
    read_envelope_using(
        id,
        work,
        prepaid,
        &mut |original, id, boundary| backend.read_with_boundary(original, id, None, boundary),
        &mut |_| Ok(()),
    )
}

/// Reads one canonical envelope through the selected private inventory view.
/// The ordinary entry supplies its unchanged checked backend lookup.
pub(super) fn read_envelope_using(
    id: ContentId,
    work: &mut Work<'_>,
    prepaid: bool,
    source: &mut impl FnMut(
        &crate::owned_decode::DecodeBudget,
        ContentId,
        &mut dyn FnMut() -> Result<(), crate::content_store::StoreError>,
    ) -> Result<
        crate::content_store::BlobHandle,
        crate::content_store::StoreError,
    >,
    verify: &mut impl FnMut(
        &crate::owned_decode::DecodeBudget,
    ) -> Result<(), crate::content_store::StoreError>,
) -> Result<OwnedEnvelope, RamStoreError> {
    if id.schema_version() == SCHEMA_VERSION
        && matches!(
            id.kind(),
            ObjectKind::RamExtent | ObjectKind::RamTree | ObjectKind::ExactManifest
        )
    {
        work.reject_exhausted_nonempty_visit()?;
    }
    let account = work.original().child().map_err(admission)?;
    let _scope = account.enter();
    if id.schema_version() != SCHEMA_VERSION {
        return Err(RamStoreError::Invalid("RAM storage schema"));
    }
    // Page and binary-tree lookups run under bounded page-in scratch. A
    // malformed small-object identity must not borrow the root decoder's
    // larger catalog allocation merely by declaring a large body/table.
    let (maximum_bytes, maximum_children) = object_limits(id)?;
    (work.boundary)()?;
    let source = work.checked(|original, boundary| {
        let mut checked = || {
            boundary()?;
            verify(original)
        };
        source(original, id, &mut checked)
    })?;
    if source.logical_length() > maximum_bytes {
        return Err(RamStoreError::Limit("single canonical object"));
    }
    if prepaid && matches!(id.kind(), ObjectKind::RamTree | ObjectKind::RamExtent) {
        let previous_counts = (work.visits, work.io_bytes);
        if let Err(error) = work.visit_accounting(source.logical_length()) {
            let refused_counts = (work.visits, work.io_bytes);
            (work.visits, work.io_bytes) = previous_counts;
            // Preserve the original second-poll cancellation precedence and
            // partial scalar state. No codec allocation follows refusal.
            (work.boundary)()?;
            (work.visits, work.io_bytes) = refused_counts;
            return Err(error);
        }
        let length = usize::try_from(source.logical_length())
            .map_err(|_| RamStoreError::Limit("single canonical object"))?;
        let record = RecordAccount::new(
            &account,
            RecordAllocationPlan::read(length, maximum_children)?,
        )?;
        let bytes = work.checked(|original, boundary| {
            let mut checked = || {
                boundary()?;
                verify(original)
            };
            source.read_all_with_boundary(original, maximum_bytes, &mut checked)
        })?;
        let envelope = {
            let _codec_scope = record.codec.enter();
            decode_envelope(id, &bytes, maximum_children, &record.codec)?
        };
        // Local partition charges validate monotone accounting, not host
        // liveness. Recheck the SAME original operation after decoding and
        // before accepting an owning result; EOF may have expired it.
        {
            let _terminal_scope = record.original.enter();
            if let Err(error) = work.checked(|original, boundary| {
                let mut checked = || {
                    boundary()?;
                    verify(original)
                };
                crate::content_store::checked_reader::check(original, &mut checked)
            }) {
                (work.visits, work.io_bytes) = previous_counts;
                return Err(error);
            }
        }
        return Ok(envelope);
    }
    work.visit(source.logical_length())?;
    let bytes = work.checked(|original, boundary| {
        let mut checked = || {
            boundary()?;
            verify(original)
        };
        source.read_all_with_boundary(original, maximum_bytes, &mut checked)
    })?;
    decode_envelope(id, &bytes, maximum_children, &account)
}
