//! Reads one selected pack member through actual bounded physical observations.
//!
//! The detached index is ordinary full-object read data. Header, trailing index,
//! footer, codec prefixes and the complete selected body are separate exact
//! ranges; they never become a fabricated whole-pack receipt. The caller still
//! owns the full detached-index ledger, selected/current checks and independent
//! content/dictionary verification.
//! Native support retains genuine opened descriptors. Ordinary fallback uses
//! fresh visible metadata and exact ranges without claiming Original authority.
//!
//! ```text
//! header:24 | member bodies ... | index:12 + 56 * count | footer:16
//! footer = index-offset:u64le | CRC32C(index):u32le | "TRPE"
//! ```

use crate::bucket::content::corrupt;
use crate::bucket::publication::receipts::RecordRead;
use crate::bucket::{BucketBinding, FileBucket, catalog::Catalog};
use crate::pack::{EntryKind, IndexEntry, MergedEntry, PackIndexSnapshot};
#[cfg(all(feature = "tokio", unix))]
use crate::store::native_publication_effects::{PayloadRangeCapture, RetainedPayloadRanges};
use crate::store::{ByteRange, Clock, ContentValidator, LocalFs, StoreFailure};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_format::pack_format::{FOOTER_SIZE, HEADER_SIZE, Header, PREAMBLE_SIZE, crc32c};

#[path = "ranged_fallback.rs"]
mod fallback;

use fallback::{OrdinaryRangeCapture, OrdinaryRanges};

#[cfg(all(test, feature = "tokio", unix))]
#[path = "ranged_pack/tests.rs"]
pub(in crate::bucket::content) mod tests;

/// Retains actual encoded member data with its separate bounded closing checks.
///
/// Content identity and dictionary checks remain the caller's responsibility.
/// This private data observation neither completes a view nor grants authority.
pub(in crate::bucket) struct PackMemberRead {
    encoded: Vec<u8>,
    plaintext_len: usize,
    retained: RetainedMemberRanges,
}

impl PackMemberRead {
    /// Separates actual member bytes from their retained physical closing data.
    pub(in crate::bucket) fn into_parts(self) -> (Vec<u8>, usize, RetainedMemberRanges) {
        (self.encoded, self.plaintext_len, self.retained)
    }
}

/// Retains actual bounded data with the physical checks its binding can perform.
///
/// Only the native variant retains original descriptors. Ordinary observations
/// check fresh visible inputs and exact ranges without granting actor authority.
pub(in crate::bucket) struct RetainedMemberRanges {
    checks: MemberChecks,
    ordinary_index: Option<OrdinaryRanges>,
}

enum MemberChecks {
    #[cfg(all(feature = "tokio", unix))]
    Native(RetainedPayloadRanges),
    Ordinary(Box<OrdinaryRanges>),
}

impl RetainedMemberRanges {
    /// Freshly checks each actual consumed range using its original read mode.
    ///
    /// # Errors
    /// Rejects changed physical inputs or bytes, unsupported bounded I/O and
    /// actual read failures. A native closing failure never retries ordinarily.
    pub(in crate::bucket) async fn revalidate<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
    ) -> Result<(), StoreFailure> {
        if let Some(index) = &self.ordinary_index {
            index.revalidate(fs).await?;
        }
        match &self.checks {
            #[cfg(all(feature = "tokio", unix))]
            MemberChecks::Native(retained) => retained.revalidate(fs).await,
            MemberChecks::Ordinary(retained) => retained.revalidate(fs).await,
        }
    }
}

enum RangeCapture {
    #[cfg(all(feature = "tokio", unix))]
    Native(PayloadRangeCapture),
    Ordinary(Box<OrdinaryRangeCapture>),
}

/// Selects a bounded data route after the caller's genuine capability probe.
///
/// This choice conveys no actor permission. A positive native result stays
/// native through consumption and closing, even if subsequent I/O fails.
#[derive(Clone, Copy)]
pub(in crate::bucket) enum MemberReadMode {
    /// Uses actual bounded reads with fresh visible metadata checks.
    Ordinary,
    /// Uses genuine retained descriptors after a positive native capability probe.
    #[cfg(all(feature = "tokio", unix))]
    Native,
}

impl RangeCapture {
    async fn capture<F: LocalFs + BucketBinding>(
        fs: &F,
        path: &std::path::Path,
        mode: MemberReadMode,
    ) -> Result<Self, StoreFailure> {
        match mode {
            MemberReadMode::Ordinary => OrdinaryRangeCapture::capture(fs, path)
                .await
                .map(|captured| Self::Ordinary(Box::new(captured))),
            #[cfg(all(feature = "tokio", unix))]
            MemberReadMode::Native => PayloadRangeCapture::capture_ordinary(fs, path)
                .await
                .map(Self::Native),
        }
    }

    fn len(&self) -> u64 {
        match self {
            #[cfg(all(feature = "tokio", unix))]
            Self::Native(captured) => captured.len(),
            Self::Ordinary(captured) => captured.len(),
        }
    }

    fn is_ordinary(&self) -> bool {
        matches!(self, Self::Ordinary(_))
    }

    async fn read_range<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        range: ByteRange,
    ) -> Result<Vec<u8>, StoreFailure> {
        match self {
            #[cfg(all(feature = "tokio", unix))]
            Self::Native(captured) => captured.read_range(fs, range).await,
            Self::Ordinary(captured) => captured.read_range(fs, range).await,
        }
    }

    fn finish(self, ordinary_index: Option<OrdinaryRanges>) -> RetainedMemberRanges {
        let checks = match self {
            #[cfg(all(feature = "tokio", unix))]
            Self::Native(captured) => MemberChecks::Native(captured.finish()),
            Self::Ordinary(captured) => MemberChecks::Ordinary(Box::new((*captured).finish())),
        };
        RetainedMemberRanges {
            checks,
            ordinary_index,
        }
    }
}

/// Reads one exact selected member without consuming unrelated body bytes.
///
/// The caller supplies an actual full detached-index observation, retains its
/// original recipe in the final ledger, and keeps its selected holder when one
/// is available. Native ranges share a genuinely opened descriptor; ordinary ranges
/// carry visible metadata and exact received bytes. Both return their actual
/// recipe for checking at that same final closing boundary.
/// Whole Pack and Index requests use the existing complete container verifier.
///
/// # Errors
/// Preserves selected absence, unsupported retained range I/O and actual read
/// failures; rejects foreign indexes, wrong member identity, framing/index
/// disagreement, unsafe original paths, overflow and changed physical inputs.
pub(in crate::bucket) async fn read_member<F, C, V>(
    bucket: &FileBucket<F, C, V>,
    catalog: &Catalog,
    identity: &Identity,
    index: &RecordRead,
    mode: MemberReadMode,
) -> Result<PackMemberRead, StoreFailure>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let location = bucket.location(catalog, identity)?;
    let id = location.pack();
    let pack_path = bucket.path(&crate::bucket::catalog::registered(&id.pack_key())?);
    let index_path = bucket.path(&crate::bucket::catalog::registered(&id.index_key())?);
    if index.path() != index_path {
        return Err(corrupt(identity));
    }
    let index_bytes = index.bytes().ok_or_else(|| corrupt(identity))?;
    let inventory = catalog
        .inventory
        .as_ref()
        .and_then(|entries| entries.iter().find(|entry| entry.pack_id == *id.as_bytes()));
    let index_identity = match inventory {
        Some(inventory) => TERRANE_V1.from_digest(IdentityKind::Index, &inventory.index_hash),
        None => TERRANE_V1.calculate(IdentityKind::Index, index_bytes),
    }
    .map_err(|_| corrupt(identity))?;
    let pack_identity = inventory
        .map(|inventory| TERRANE_V1.from_digest(IdentityKind::Pack, &inventory.pack_hash))
        .transpose()
        .map_err(|_| corrupt(identity))?;
    let pack_subject = pack_identity.as_ref().unwrap_or(identity);
    if let Some(inventory) = inventory {
        if inventory.index_size != index_bytes.len() as u64 {
            return Err(corrupt(&index_identity));
        }
        TERRANE_V1
            .verify(&index_identity, index_bytes)
            .map_err(|_| corrupt(&index_identity))?;
    }
    let mut captured = RangeCapture::capture(bucket.fs(), &pack_path, mode).await?;
    if inventory.is_some_and(|inventory| inventory.pack_size != captured.len()) {
        return Err(corrupt(pack_subject));
    }
    // The scalar route makes a fresh actual detached-index observation after
    // ordered ancestry capture. It never invents original ancestors for the
    // caller's earlier read. Native requests retain that earlier genuine index
    // descriptor separately in their complete artifact ledger.
    let ordinary_index = if captured.is_ordinary() {
        let mut observed = OrdinaryRangeCapture::capture(bucket.fs(), &index_path).await?;
        if observed.len() != index_bytes.len() as u64
            || !observed.matches_metadata(index.metadata().ok_or_else(|| corrupt(identity))?)?
        {
            return Err(corrupt(identity));
        }
        let actual = observed
            .read_range(
                bucket.fs(),
                ByteRange {
                    start: 0,
                    length: index_bytes.len() as u64,
                },
            )
            .await?;
        if actual != index_bytes {
            return Err(corrupt(identity));
        }
        Some(observed.finish())
    } else {
        None
    };
    let footer_start = captured
        .len()
        .checked_sub(FOOTER_SIZE as u64)
        .ok_or_else(|| corrupt(pack_subject))?;
    let footer = captured
        .read_range(
            bucket.fs(),
            ByteRange {
                start: footer_start,
                length: FOOTER_SIZE as u64,
            },
        )
        .await?;
    let (index_start, crc) = footer_fields(pack_subject, &footer)?;
    let index_length = index_bytes
        .len()
        .checked_sub(HEADER_SIZE)
        .filter(|length| *length >= PREAMBLE_SIZE)
        .ok_or_else(|| corrupt(&index_identity))?;
    // Check footer bounds against the already observed detached length before
    // allocating or reading the embedded index. Untrusted offsets cannot expand
    // this request into the body region or an oversized allocation.
    if index_start < HEADER_SIZE as u64 || index_start > footer_start {
        return Err(corrupt(pack_subject));
    }
    let embedded_length = footer_start
        .checked_sub(index_start)
        .filter(|length| *length >= PREAMBLE_SIZE as u64)
        .ok_or_else(|| corrupt(pack_subject))?;
    if embedded_length != index_length as u64 {
        return Err(corrupt(&index_identity));
    }

    let header = captured
        .read_range(
            bucket.fs(),
            ByteRange {
                start: 0,
                length: HEADER_SIZE as u64,
            },
        )
        .await?;
    let decoded_header = Header::decode(&header).map_err(|_| corrupt(pack_subject))?;
    if decoded_header.id() != id.as_bytes() {
        return Err(corrupt(pack_subject));
    }

    let trailing_index = captured
        .read_range(
            bucket.fs(),
            ByteRange {
                start: index_start,
                length: index_length as u64,
            },
        )
        .await?;
    // The pack's own trailing index is authoritative. Its actual CRC is checked
    // before any entries are decoded or used; the detached copy only agrees or
    // fails with its own identity as the corruption subject.
    if crc32c(&trailing_index) != crc {
        return Err(corrupt(pack_subject));
    }
    let mut embedded_index = header;
    embedded_index.extend_from_slice(&trailing_index);
    if embedded_index != index_bytes {
        return Err(corrupt(&index_identity));
    }
    let layout = MemberLayout::checked(identity, location, catalog, &embedded_index, index_start)?;

    // Preserve the full structural reader's codec/index checks for every chunk
    // without reading unrelated envelopes or plaintext. The selected prefix is
    // checked against its complete body below instead of reading it twice.
    for entry in layout.snapshot.entries() {
        if entry.kind() != EntryKind::Chunk || entry == &layout.member {
            continue;
        }
        let prefix = captured
            .read_range(
                bucket.fs(),
                ByteRange {
                    start: entry.offset(),
                    length: 1,
                },
            )
            .await?;
        if prefix.as_slice() != [entry.codec() as u8] {
            return Err(corrupt(identity));
        }
    }

    let encoded = captured
        .read_range(
            bucket.fs(),
            ByteRange {
                start: layout.member.offset(),
                length: u64::from(layout.member.body_len()),
            },
        )
        .await?;
    if layout.member.kind() == EntryKind::Chunk
        && encoded.first() != Some(&(layout.member.codec() as u8))
    {
        return Err(corrupt(identity));
    }

    Ok(PackMemberRead {
        encoded,
        plaintext_len: layout.member.plaintext_len() as usize,
        retained: captured.finish(ordinary_index),
    })
}

/// Binds selected membership to the CRC-verified embedded index and physical bounds.
struct MemberLayout {
    snapshot: PackIndexSnapshot,
    member: IndexEntry,
}

impl MemberLayout {
    fn checked(
        identity: &Identity,
        location: &MergedEntry,
        catalog: &Catalog,
        index: &[u8],
        index_start: u64,
    ) -> Result<Self, StoreFailure> {
        let reject = || corrupt(identity);
        let id = location.pack();
        let snapshot =
            PackIndexSnapshot::decode(index, catalog.capabilities.generation.unwrap_or(0))
                .map_err(|_| reject())?;
        if snapshot.header().id() != id {
            return Err(reject());
        }

        // Detached decoding already rejects overlap and overflowing endpoints.
        // Bind every endpoint and the final body tail to the real file length;
        // a detached index alone cannot establish the body region's final bound.
        let mut body_end = HEADER_SIZE as u64;
        for entry in snapshot.entries() {
            let end = entry
                .offset()
                .checked_add(u64::from(entry.body_len()))
                .filter(|end| *end <= index_start)
                .ok_or_else(reject)?;
            body_end = body_end.max(end);
        }
        if body_end != index_start {
            return Err(reject());
        }

        let member = snapshot
            .entries()
            .iter()
            .find(|entry| entry.hash() == location.entry().hash())
            .filter(|entry| *entry == location.entry())
            .ok_or_else(reject)?
            .clone();
        if member.kind().identity_kind() != identity.kind()
            || member.hash() != &identity.terrane_v1_digest().map_err(|_| reject())?
        {
            return Err(reject());
        }

        Ok(Self { snapshot, member })
    }
}

fn footer_fields(identity: &Identity, footer: &[u8]) -> Result<(u64, u32), StoreFailure> {
    let reject = || corrupt(identity);
    let offset = footer
        .get(..8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(reject)?;
    let crc = footer
        .get(8..12)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or_else(reject)?;

    if footer.len() != FOOTER_SIZE || footer.get(12..) != Some(b"TRPE".as_slice()) {
        return Err(reject());
    }
    Ok((offset, crc))
}
