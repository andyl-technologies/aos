//! Private authenticated projection pages for sorted GC runs.
//!
//! ```text
//! GCMRUN01 | version:u8 | tag:u8 | count:u64be | height:u8 | first[32] | last[32]
//! leaf:   (key[32] | id_length:u8 | canonical_id)*
//! branch: (id_length:u8 | canonical_id | count:u64be | height:u8 | first[32] | last[32])*2
//! ```
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crucible_cas::content_store::{ObjectKind, OwnedBlobBytes};

const MAGIC: &[u8; 8] = b"GCMRUN01";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 83;
const ID_BYTES: usize = 93;
pub(super) const MAX_PAGE_BYTES: u64 = (HEADER_BYTES + PAGE * (32 + 1 + ID_BYTES)) as u64;
pub(super) const LEVELS: usize = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NodeRef {
    pub(super) id: ContentId,
    pub(super) count: u64,
    pub(super) height: u8,
    pub(super) first: CampaignHash,
    pub(super) last: CampaignHash,
}

pub(super) enum Record<'a> {
    Leaf {
        node: NodeRef,
        entries: Reader<'a>,
    },
    Branch {
        node: NodeRef,
        children: [NodeRef; 2],
    },
}

pub(super) fn decode(id: ContentId, bytes: &[u8]) -> Result<Record<'_>, StoreError> {
    if id.kind() != ObjectKind::Projection || id.schema_version() != 1 || !id.authenticates(bytes) {
        return Err(StoreError::Corrupt { id });
    }
    let mut input = Reader {
        bytes,
        position: 0,
        id,
    };
    if input.take(8)? != MAGIC || input.byte()? != VERSION {
        return Err(input.corrupt());
    }
    let tag = input.byte()?;
    let node = input.node_fields(id)?;
    if node.count == 0
        || node.count > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64
        || usize::from(node.height) >= LEVELS
        || node.first > node.last
    {
        return Err(input.corrupt());
    }
    match tag {
        0 if node.height == 0 && node.count <= PAGE as u64 => {
            let mut validation = input.clone();
            let mut previous = None;
            for index in 0..node.count {
                let entry = validation.entry()?;
                if previous.is_some_and(|prior| prior >= entry.0)
                    || (index == 0 && entry.0 != node.first)
                    || (index + 1 == node.count && entry.0 != node.last)
                {
                    return Err(validation.corrupt());
                }
                previous = Some(entry.0);
            }
            validation.finish()?;
            Ok(Record::Leaf {
                node,
                entries: input,
            })
        }
        1 if node.height > 0 => {
            let left = input.child()?;
            let right = input.child()?;
            input.finish()?;
            if left.count == 0
                || right.count == 0
                || left.count.checked_add(right.count) != Some(node.count)
                || left.height.max(right.height).checked_add(1) != Some(node.height)
                || left.first > left.last
                || right.first > right.last
                || left.last >= right.first
                || left.first != node.first
                || right.last != node.last
            {
                return Err(StoreError::Corrupt { id });
            }
            Ok(Record::Branch {
                node,
                children: [left, right],
            })
        }
        _ => Err(input.corrupt()),
    }
}

pub(super) fn leaf(
    entries: &[MarkEntry],
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(NodeRef, OwnedBlobBytes), StoreError> {
    let Some(first) = entries.first() else {
        return Err(StoreError::Quota);
    };
    if entries.len() > PAGE
        || entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || entries.iter().any(|entry| entry.0 != mark_key(entry.1))
    {
        return Err(StoreError::InvalidComposition {
            reason: "GC run leaf is not bounded and typed",
        });
    }
    let last = entries.last().ok_or(StoreError::Quota)?;
    let length = entries.iter().try_fold(HEADER_BYTES, |length, (_, id)| {
        length
            .checked_add(33 + id.encoded_len())
            .ok_or(StoreError::Quota)
    })?;
    let bytes = OwnedBlobBytes::write_with_boundary(original, length, boundary, |bytes| {
        let mut output = Writer { bytes, position: 0 };
        output.header(0, entries.len() as u64, 0, first.0, last.0)?;
        for (key, id) in entries {
            output.write(&key.as_bytes())?;
            output.id(*id)?;
        }
        Ok(output.position)
    })?;
    let id = ContentId::for_bytes(ObjectKind::Projection, 1, &bytes);
    Ok((
        NodeRef {
            id,
            count: entries.len() as u64,
            height: 0,
            first: first.0,
            last: last.0,
        },
        bytes,
    ))
}

pub(super) fn branch(
    left: NodeRef,
    right: NodeRef,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(NodeRef, OwnedBlobBytes), StoreError> {
    let count = left
        .count
        .checked_add(right.count)
        .ok_or(StoreError::Quota)?;
    let height = left
        .height
        .max(right.height)
        .checked_add(1)
        .ok_or(StoreError::Quota)?;
    if count > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64
        || usize::from(height) >= LEVELS
        || left.last >= right.first
    {
        return Err(StoreError::Quota);
    }
    let length = HEADER_BYTES
        .checked_add(2 * 74)
        .and_then(|length| length.checked_add(left.id.encoded_len()))
        .and_then(|length| length.checked_add(right.id.encoded_len()))
        .ok_or(StoreError::Quota)?;
    let bytes = OwnedBlobBytes::write_with_boundary(original, length, boundary, |bytes| {
        let mut output = Writer { bytes, position: 0 };
        output.header(1, count, height, left.first, right.last)?;
        for child in [left, right] {
            output.id(child.id)?;
            output.fields(child.count, child.height, child.first, child.last)?;
        }
        Ok(output.position)
    })?;
    let id = ContentId::for_bytes(ObjectKind::Projection, 1, &bytes);
    Ok((
        NodeRef {
            id,
            count,
            height,
            first: left.first,
            last: right.last,
        },
        bytes,
    ))
}

#[derive(Clone)]
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pub(super) position: usize,
    id: ContentId,
}

impl<'a> Reader<'a> {
    pub(super) fn at(bytes: &'a [u8], id: ContentId, position: usize) -> Self {
        Self {
            bytes,
            position,
            id,
        }
    }

    fn corrupt(&self) -> StoreError {
        StoreError::Corrupt { id: self.id }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| self.corrupt())?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| self.corrupt())?;
        self.position = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn number(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| self.corrupt())?,
        ))
    }

    fn key(&mut self) -> Result<CampaignHash, StoreError> {
        Ok(CampaignHash::from_bytes(
            self.take(32)?.try_into().map_err(|_| self.corrupt())?,
        ))
    }

    fn id(&mut self) -> Result<ContentId, StoreError> {
        let length = usize::from(self.byte()?);
        if length > ID_BYTES {
            return Err(self.corrupt());
        }
        let text = std::str::from_utf8(self.take(length)?).map_err(|_| self.corrupt())?;
        ContentId::parse(text).map_err(|_| self.corrupt())
    }

    fn node_fields(&mut self, id: ContentId) -> Result<NodeRef, StoreError> {
        Ok(NodeRef {
            id,
            count: self.number()?,
            height: self.byte()?,
            first: self.key()?,
            last: self.key()?,
        })
    }

    fn child(&mut self) -> Result<NodeRef, StoreError> {
        let id = self.id()?;
        if id.kind() != ObjectKind::Projection || id.schema_version() != 1 {
            return Err(self.corrupt());
        }
        self.node_fields(id)
    }

    pub(super) fn entry(&mut self) -> Result<MarkEntry, StoreError> {
        let key = self.key()?;
        let id = self.id()?;
        if key != mark_key(id) {
            return Err(self.corrupt());
        }
        Ok((key, id))
    }

    pub(super) fn finish(&self) -> Result<(), StoreError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(self.corrupt())
        }
    }
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(StoreError::Quota)?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or(StoreError::Quota)?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn id(&mut self, id: ContentId) -> Result<(), StoreError> {
        id.with_encoded_text(|bytes| {
            self.write(&[u8::try_from(bytes.len()).map_err(|_| StoreError::Quota)?])?;
            self.write(bytes)
        })
    }

    fn fields(
        &mut self,
        count: u64,
        height: u8,
        first: CampaignHash,
        last: CampaignHash,
    ) -> Result<(), StoreError> {
        self.write(&count.to_be_bytes())?;
        self.write(&[height])?;
        self.write(&first.as_bytes())?;
        self.write(&last.as_bytes())
    }

    fn header(
        &mut self,
        tag: u8,
        count: u64,
        height: u8,
        first: CampaignHash,
        last: CampaignHash,
    ) -> Result<(), StoreError> {
        self.write(MAGIC)?;
        self.write(&[VERSION, tag])?;
        self.fields(count, height, first, last)
    }
}
