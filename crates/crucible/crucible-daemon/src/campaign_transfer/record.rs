//! Canonical transfer-journal record files.
//!
//! One record is a directory of page files and a header. Pages hold the
//! transfer's direct objects in the archive plan's visit order, at most one
//! archive inventory page (4,096 entries) each, so no file grows with the
//! archive. The header binds the operation, role, manifest, page count,
//! object count, and a digest over every page's checksum in index order.
//!
//! ```text
//! page-<index:08x>:
//!   "CRUCIBLE-CAMPAIGN-TRANSFER-PG2!!" | version:u32be = 2 | operation[32]
//!   | index:u32be | count:u32be | count * (content_id | logical_length:u64be)
//!   | blake3(preceding bytes)[32]
//! header:
//!   "CRUCIBLE-CAMPAIGN-TRANSFER-V2!!!" | version:u32be = 2 | operation[32]
//!   | role:u8 (0 source, 1 destination) | manifest content_id
//!   | page_count:u32be | object_count:u64be | pages_digest[32]
//!   | blake3(preceding bytes)[32]
//! content_id   = length:u32be | canonical content-ID text
//! pages_digest = blake3("crucible.campaign.transfer-pages.v2"
//!                       | page checksum, for each page in index order)
//! ```
//!
//! Every page except the last is full, so a plan has exactly one paging.

use crucible_campaign::{CampaignArchiveManifestId, CampaignArchivePlan};
use crucible_store::content_store::ContentId;

use super::journal_io::encode_content_id;
use super::{
    CampaignTransferJournalError, CampaignTransferOperationId, CampaignTransferRetentionRoot,
    MAX_TRANSFER_RECORD_BYTES, TransferJournalRole,
};

const HEADER_MAGIC: &[u8; 32] = b"CRUCIBLE-CAMPAIGN-TRANSFER-V2!!!";
const PAGE_MAGIC: &[u8; 32] = b"CRUCIBLE-CAMPAIGN-TRANSFER-PG2!!";
const RECORD_VERSION: u32 = 2;
const PAGES_DIGEST_DOMAIN: &[u8] = b"crucible.campaign.transfer-pages.v2";
const CHECKSUM_BYTES: usize = 32;

/// Direct objects per page, mirroring one archive inventory page.
pub(super) const TRANSFER_PAGE_ENTRIES: usize =
    crucible_campaign::MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES;

/// Pages in one record.
///
/// A plan protects its selected objects (at most every inventory entry), one
/// envelope per inventory page, and the manifest, so this bounds every
/// archive the campaign format admits.
pub(super) const MAX_TRANSFER_RECORD_PAGES: usize =
    (crucible_campaign::MAX_ARCHIVE_INVENTORY_ENTRIES
        + crucible_campaign::MAX_ARCHIVE_INVENTORY_ENTRIES / TRANSFER_PAGE_ENTRIES
        + 1)
    .div_ceil(TRANSFER_PAGE_ENTRIES);

/// Authenticated header of one complete transfer record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TransferHeader {
    pub(super) operation: CampaignTransferOperationId,
    pub(super) role: TransferJournalRole,
    pub(super) manifest: CampaignArchiveManifestId,
    pub(super) page_count: u32,
    pub(super) object_count: u64,
    pub(super) pages_digest: [u8; 32],
}

impl TransferHeader {
    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, CampaignTransferJournalError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HEADER_MAGIC);
        bytes.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.operation.0);
        bytes.push(match self.role {
            TransferJournalRole::Source => 0,
            TransferJournalRole::Destination => 1,
        });
        encode_content_id(self.manifest.content_id(), &mut bytes)?;
        bytes.extend_from_slice(&self.page_count.to_be_bytes());
        bytes.extend_from_slice(&self.object_count.to_be_bytes());
        bytes.extend_from_slice(&self.pages_digest);
        seal(bytes)
    }

    /// Decodes a header, requiring `expected` as its operation when given.
    pub(super) fn from_canonical_bytes(
        bytes: &[u8],
        expected: Option<CampaignTransferOperationId>,
    ) -> Result<Self, CampaignTransferJournalError> {
        let mut cursor = Cursor::new(unseal(bytes)?);
        if cursor.take(HEADER_MAGIC.len())? != HEADER_MAGIC || cursor.u32()? != RECORD_VERSION {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        let operation = cursor.operation()?;
        let role = match cursor.u8()? {
            0 => TransferJournalRole::Source,
            1 => TransferJournalRole::Destination,
            _ => return Err(CampaignTransferJournalError::Corrupt),
        };
        let manifest_content = cursor.content_id()?;
        let manifest = CampaignArchiveManifestId::parse(&format!(
            "crucible.campaign.archive-manifest@{manifest_content}"
        ))
        .map_err(|_| CampaignTransferJournalError::Corrupt)?;
        let page_count = cursor.u32()?;
        let object_count = cursor.u64()?;
        let pages_digest = cursor
            .take(32)?
            .try_into()
            .map_err(|_| CampaignTransferJournalError::Corrupt)?;
        if !cursor.is_eof() {
            return Err(CampaignTransferJournalError::Corrupt);
        }

        // The page and object counts must describe one canonical paging.
        let pages =
            usize::try_from(page_count).map_err(|_| CampaignTransferJournalError::Corrupt)?;
        let full_pages = (pages as u64).saturating_sub(1) * TRANSFER_PAGE_ENTRIES as u64;
        if pages == 0
            || pages > MAX_TRANSFER_RECORD_PAGES
            || object_count <= full_pages
            || object_count > full_pages + TRANSFER_PAGE_ENTRIES as u64
        {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        if expected.is_some_and(|expected| expected != operation) {
            return Err(CampaignTransferJournalError::RecordMismatch);
        }

        let header = Self {
            operation,
            role,
            manifest,
            page_count,
            object_count,
            pages_digest,
        };
        if header.canonical_bytes()? != bytes {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        Ok(header)
    }

    /// Returns the number of objects page `index` must hold.
    pub(super) fn page_entries(&self, index: u32) -> usize {
        if index.saturating_add(1) < self.page_count {
            return TRANSFER_PAGE_ENTRIES;
        }
        let full = u64::from(self.page_count - 1) * TRANSFER_PAGE_ENTRIES as u64;
        // The header decoder bounds the remainder by one page.
        (self.object_count - full) as usize
    }
}

/// One page of direct transfer objects.
pub(super) struct TransferPage {
    pub(super) objects: Vec<CampaignTransferRetentionRoot>,
}

impl TransferPage {
    fn canonical_bytes(
        operation: CampaignTransferOperationId,
        index: u32,
        objects: &[CampaignTransferRetentionRoot],
    ) -> Result<Vec<u8>, CampaignTransferJournalError> {
        let count =
            u32::try_from(objects.len()).map_err(|_| CampaignTransferJournalError::ObjectLimit)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PAGE_MAGIC);
        bytes.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        bytes.extend_from_slice(&operation.0);
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for object in objects {
            encode_content_id(object.id, &mut bytes)?;
            bytes.extend_from_slice(&object.logical_length.to_be_bytes());
        }
        seal(bytes)
    }

    /// Decodes page `index` of `header`'s record.
    pub(super) fn from_canonical_bytes(
        bytes: &[u8],
        header: &TransferHeader,
        index: u32,
    ) -> Result<Self, CampaignTransferJournalError> {
        let mut cursor = Cursor::new(unseal(bytes)?);
        if cursor.take(PAGE_MAGIC.len())? != PAGE_MAGIC
            || cursor.u32()? != RECORD_VERSION
            || cursor.operation()? != header.operation
            || cursor.u32()? != index
        {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        let count = cursor.u32()? as usize;
        if count != header.page_entries(index) {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        let mut objects = Vec::with_capacity(count);
        for _ in 0..count {
            objects.push(CampaignTransferRetentionRoot {
                id: cursor.content_id()?,
                logical_length: cursor.u64()?,
            });
        }
        if !cursor.is_eof() || Self::canonical_bytes(header.operation, index, &objects)? != bytes {
            return Err(CampaignTransferJournalError::Corrupt);
        }
        Ok(Self { objects })
    }
}

/// Running digest over page checksums in index order.
pub(super) struct TransferPagesDigest(blake3::Hasher);

impl TransferPagesDigest {
    pub(super) fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PAGES_DIGEST_DOMAIN);
        Self(hasher)
    }

    /// Folds one sealed page, whose trailing bytes are its checksum.
    pub(super) fn update(&mut self, page: &[u8]) {
        self.0
            .update(&page[page.len().saturating_sub(CHECKSUM_BYTES)..]);
    }

    pub(super) fn finish(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}

/// Receives each sealed page file's index and bytes as it is built.
pub(super) type PageSink<'a> =
    dyn FnMut(u32, &[u8]) -> Result<(), CampaignTransferJournalError> + 'a;

/// Pages a plan's transfer objects and returns the record header.
///
/// Each sealed page is handed to `emit` with its index before the next page
/// is built, so at most one page is resident.
///
/// # Errors
///
/// Returns [`CampaignTransferJournalError`] when the plan's spool cannot be
/// read, the plan protects no object or more objects than one record admits,
/// or `emit` fails.
pub(super) fn encode_record(
    operation: CampaignTransferOperationId,
    role: TransferJournalRole,
    plan: &CampaignArchivePlan,
    emit: &mut PageSink<'_>,
) -> Result<TransferHeader, CampaignTransferJournalError> {
    let mut pager = Pager {
        operation,
        current: Vec::with_capacity(TRANSFER_PAGE_ENTRIES),
        page_count: 0,
        object_count: 0,
        digest: TransferPagesDigest::new(),
    };
    plan.visit_transfer_objects(|id, logical_length| {
        pager.push(CampaignTransferRetentionRoot { id, logical_length }, emit)
    })?;
    pager.flush(emit)?;
    if pager.object_count == 0 {
        return Err(CampaignTransferJournalError::ObjectLimit);
    }

    Ok(TransferHeader {
        operation,
        role,
        manifest: plan.manifest_id(),
        page_count: pager.page_count,
        object_count: pager.object_count,
        pages_digest: pager.digest.finish(),
    })
}

struct Pager {
    operation: CampaignTransferOperationId,
    current: Vec<CampaignTransferRetentionRoot>,
    page_count: u32,
    object_count: u64,
    digest: TransferPagesDigest,
}

impl Pager {
    fn push(
        &mut self,
        root: CampaignTransferRetentionRoot,
        emit: &mut PageSink<'_>,
    ) -> Result<(), CampaignTransferJournalError> {
        self.current.push(root);
        self.object_count = self
            .object_count
            .checked_add(1)
            .ok_or(CampaignTransferJournalError::ObjectLimit)?;
        if self.current.len() == TRANSFER_PAGE_ENTRIES {
            self.flush(emit)?;
        }
        Ok(())
    }

    fn flush(&mut self, emit: &mut PageSink<'_>) -> Result<(), CampaignTransferJournalError> {
        if self.current.is_empty() {
            return Ok(());
        }
        if self.page_count as usize >= MAX_TRANSFER_RECORD_PAGES {
            return Err(CampaignTransferJournalError::ObjectLimit);
        }
        let bytes = TransferPage::canonical_bytes(self.operation, self.page_count, &self.current)?;
        emit(self.page_count, &bytes)?;
        self.digest.update(&bytes);
        self.current.clear();
        self.page_count += 1;
        Ok(())
    }
}

/// Appends the checksum and applies the per-file bound.
fn seal(mut bytes: Vec<u8>) -> Result<Vec<u8>, CampaignTransferJournalError> {
    let digest = blake3::hash(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    if bytes.len() as u64 > MAX_TRANSFER_RECORD_BYTES {
        return Err(CampaignTransferJournalError::ObjectLimit);
    }
    Ok(bytes)
}

/// Checks the per-file bound and checksum, returning the checked payload.
fn unseal(bytes: &[u8]) -> Result<&[u8], CampaignTransferJournalError> {
    if bytes.len() < CHECKSUM_BYTES || bytes.len() as u64 > MAX_TRANSFER_RECORD_BYTES {
        return Err(CampaignTransferJournalError::Corrupt);
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - CHECKSUM_BYTES);
    if blake3::hash(payload).as_bytes() != checksum {
        return Err(CampaignTransferJournalError::Corrupt);
    }
    Ok(payload)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CampaignTransferJournalError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CampaignTransferJournalError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CampaignTransferJournalError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CampaignTransferJournalError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CampaignTransferJournalError> {
        self.take(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| CampaignTransferJournalError::Corrupt)
    }

    fn u64(&mut self) -> Result<u64, CampaignTransferJournalError> {
        self.take(8)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| CampaignTransferJournalError::Corrupt)
    }

    fn operation(&mut self) -> Result<CampaignTransferOperationId, CampaignTransferJournalError> {
        self.take(32)?
            .try_into()
            .map(CampaignTransferOperationId)
            .map_err(|_| CampaignTransferJournalError::Corrupt)
    }

    fn content_id(&mut self) -> Result<ContentId, CampaignTransferJournalError> {
        let length = self.u32()? as usize;
        let text = std::str::from_utf8(self.take(length)?)
            .map_err(|_| CampaignTransferJournalError::Corrupt)?;
        ContentId::parse(text).map_err(|_| CampaignTransferJournalError::Corrupt)
    }

    const fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
