//! Finite immutable byte custody for authenticated opposite-direction transfers.

mod compact;
mod compact_decode;

/// Validates bounded source-private content alias data without authority.
pub mod compact_cursor;

use std::collections::BTreeMap;
use std::rc::Rc;

use crucible_node_format::{ContentRef, Id, U64, Validate};

use crate::{ProviderError, bodies::*};

fn serialize_shared_bytes<S: serde::Serializer>(
    bytes: &Rc<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(bytes.as_slice(), serializer)
}

#[cfg(test)]
#[path = "content_installation_tests.rs"]
mod installation_tests;

#[derive(serde::Serialize)]
struct Transfer {
    reference: ContentRef,
    #[serde(serialize_with = "serialize_shared_bytes")]
    bytes: Rc<Vec<u8>>,
    complete: bool,
}

/// Owns verified bytes without claiming that their contents are authentic native receipts.
pub struct ClientContent {
    maximum_bytes: usize,
    maximum_objects: usize,
    maximum_chunk: usize,
    reserved: usize,
    transfers: BTreeMap<Id, Transfer>,
    objects: BTreeMap<String, (ContentRef, Rc<Vec<u8>>)>,
}

impl ClientContent {
    pub(super) fn observe_owned_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        // Content eight owns byte aliases and their capacities. This walk counts
        // each backing view conservatively; it does not mint deduplication credit.
        let Self {
            maximum_bytes,
            maximum_objects,
            maximum_chunk,
            reserved,
            transfers,
            objects,
        } = self;
        observer.observe(maximum_bytes)?;
        observer.observe(maximum_objects)?;
        observer.observe(maximum_chunk)?;
        observer.observe(reserved)?;
        observer.tree::<Id, Transfer>(transfers.len())?;
        for (id, transfer) in transfers {
            let Transfer {
                reference,
                bytes,
                complete,
            } = transfer;
            observer.observe(id)?;
            observer.observe(reference)?;
            observer.shared_original(
                crate::retained_metadata::aliases::MetadataSharedKind::ContentBytes,
                bytes.as_ref(),
            )?;
            observer.vector::<u8>(bytes.capacity())?;
            observer.observe(complete)?;
        }
        observer.tree::<String, (ContentRef, Rc<Vec<u8>>)>(objects.len())?;
        for (key, (reference, bytes)) in objects {
            observer.observe(key)?;
            observer.observe(reference)?;
            observer.shared_original(
                crate::retained_metadata::aliases::MetadataSharedKind::ContentBytes,
                bytes.as_ref(),
            )?;
            observer.vector::<u8>(bytes.capacity())?;
        }
        Ok(())
    }

    pub(super) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        // Alias indices are deterministic local graph edges, never pointers.
        let transfers = super::super::protocol_snapshot::Sequence(move || {
            self.transfers.iter().map(move |(id, transfer)| {
                (
                    id,
                    &transfer.reference,
                    transfer.bytes.as_slice(),
                    transfer.bytes.capacity(),
                    transfer.complete,
                    super::super::protocol_snapshot::Sequence(move || {
                        self.objects.iter().enumerate().filter_map(
                            move |(index, (_, (_, bytes)))| {
                                Rc::ptr_eq(bytes, &transfer.bytes).then_some(index)
                            },
                        )
                    }),
                )
            })
        });
        let objects = super::super::protocol_snapshot::Sequence(move || {
            self.objects.iter().map(|(key, (reference, bytes))| {
                (key, reference, bytes.as_slice(), bytes.capacity())
            })
        });
        (
            self.maximum_bytes,
            self.maximum_objects,
            self.maximum_chunk,
            self.reserved,
            transfers,
            objects,
        )
    }

    pub(super) fn retirement_objects(&self) -> Result<impl serde::Serialize + '_, ProviderError> {
        if self.transfers.values().any(|transfer| !transfer.complete) {
            return Err(ProviderError::Correlation(
                "original content transfer unresolved",
            ));
        }
        for (reference, bytes) in self.objects.values() {
            reference.verify(bytes.as_slice())?;
        }
        Ok((
            &self.transfers,
            self.objects
                .values()
                .map(|(reference, bytes)| (reference, bytes.as_slice()))
                .collect::<Vec<_>>(),
        ))
    }

    pub(super) fn retirement_object_credit(
        &self,
    ) -> Result<impl serde::Serialize + '_, ProviderError> {
        if self.transfers.values().any(|transfer| !transfer.complete) {
            return Err(ProviderError::Correlation(
                "original content transfer unresolved",
            ));
        }
        // Exact content verification remains in the real exporter, after
        // this complete borrowed credit passes and before any owning copies.
        Ok((
            &self.transfers,
            super::history_credit::Sequence(|| {
                self.objects
                    .values()
                    .map(|(reference, bytes)| (reference, bytes.as_slice()))
            }),
        ))
    }

    pub(super) fn preflight_capacity(
        &self,
        objects: usize,
        bytes: usize,
    ) -> Result<(), ProviderError> {
        if self
            .objects
            .len()
            .checked_add(objects)
            .is_none_or(|total| total > self.maximum_objects)
            || self
                .transfers
                .len()
                .checked_add(objects)
                .is_none_or(|total| total > self.maximum_objects)
            || self
                .reserved
                .checked_add(bytes)
                .is_none_or(|total| total > self.maximum_bytes)
        {
            return Err(ProviderError::ResourceExhausted(
                "complete source content response credit",
            ));
        }
        Ok(())
    }

    /// Borrows completed immutable object DATA without hashing or allocating.
    ///
    /// Transfers that have not reached the completed object bank are excluded.
    /// This view verifies neither content hashes nor native meaning; actual
    /// consumers retain their original complete verification and source guards.
    pub(super) fn original_completed_objects_data(
        &self,
    ) -> impl Iterator<Item = (&ContentRef, &[u8])> {
        self.objects
            .values()
            .map(|(reference, bytes)| (reference, bytes.as_slice()))
    }

    pub(super) fn original_completed_objects_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<
                std::collections::btree_map::Values<'static, String, (ContentRef, Rc<Vec<u8>>)>,
            >()
            + std::mem::size_of::<(&(ContentRef, Rc<Vec<u8>>),)>()
            + std::mem::size_of::<(&ContentRef, &[u8])>()
            + std::mem::size_of::<Option<(&ContentRef, &[u8])>>()
    }

    /// Enumerates finite verified object references without granting native authority.
    ///
    /// These references describe byte custody, not a complete semantic receipt
    /// closure. Consumers independently select and validate their actual use.
    pub fn references(&self) -> impl Iterator<Item = &ContentRef> {
        self.objects.values().map(|(reference, _)| reference)
    }

    pub(super) fn byte_ceiling(&self) -> usize {
        self.maximum_bytes
    }

    /// Reserves positive finite transfer and immutable object ceilings.
    ///
    /// # Errors
    /// Rejects zero limits, more than4096 objects, or chunks above1MiB.
    pub fn new(
        maximum_bytes: usize,
        maximum_objects: usize,
        maximum_chunk: usize,
    ) -> Result<Self, ProviderError> {
        if maximum_bytes == 0
            || maximum_objects == 0
            || maximum_objects > 4096
            || maximum_chunk == 0
            || maximum_chunk > 1_048_576
        {
            return Err(ProviderError::ResourceExhausted(
                "invalid client content ceilings",
            ));
        }
        Ok(Self {
            maximum_bytes,
            maximum_objects,
            maximum_chunk,
            reserved: 0,
            transfers: BTreeMap::new(),
            objects: BTreeMap::new(),
        })
    }

    /// Returns exact hash-verified bytes under the original complete reference.
    ///
    /// # Errors
    /// Rejects missing objects or a digest reused with changed metadata.
    pub fn get(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        let (original, bytes) = self
            .objects
            .get(&reference.hash.digest)
            .ok_or(ProviderError::Correlation("client content unavailable"))?;
        if original != reference {
            return Err(ProviderError::Conflict("client content metadata changed"));
        }
        reference.verify(bytes)?;
        Ok(bytes)
    }

    /// Installs independently obtained immutable bytes under the same finite ceiling.
    ///
    /// # Errors
    /// Rejects changed metadata, invalid bytes, or exhausted byte/object capacity.
    pub fn install(&mut self, reference: ContentRef, bytes: Vec<u8>) -> Result<(), ProviderError> {
        reference.verify(&bytes)?;
        if let Some((original, original_bytes)) = self.objects.get(&reference.hash.digest) {
            if original != &reference || original_bytes.as_ref() != &bytes {
                return Err(ProviderError::Conflict("installed content changed"));
            }
            return Ok(());
        }
        self.reserve(bytes.len())?;
        self.objects
            .insert(reference.hash.digest.clone(), (reference, Rc::new(bytes)));
        Ok(())
    }

    /// Installs a complete borrowed roster after checking its aggregate credit.
    ///
    /// Full references and duplicate bodies are checked before the first owned
    /// copy. Installation changes byte custody only; it authenticates no role.
    ///
    /// # Errors
    /// Refuses invalid or conflicting content and exhausted aggregate limits
    /// before copying any supplied body. Allocation failures retain byte custody.
    pub fn install_borrowed<'a>(
        &mut self,
        objects: impl IntoIterator<Item = (&'a ContentRef, &'a [u8])>,
    ) -> Result<(), ProviderError> {
        let prospective = self.preflight_installed(objects)?;
        for (reference, bytes) in prospective {
            let mut owned = Vec::new();
            owned.try_reserve_exact(bytes.len()).map_err(|_| {
                ProviderError::ResourceExhausted("client installed body allocation")
            })?;
            owned.extend_from_slice(bytes);
            self.install(reference.clone(), owned)?;
        }
        Ok(())
    }

    /// Credits a complete borrowed installation before the first owned body copy.
    pub(super) fn preflight_installed<'a>(
        &self,
        objects: impl IntoIterator<Item = (&'a ContentRef, &'a [u8])>,
    ) -> Result<Vec<(&'a ContentRef, &'a [u8])>, ProviderError> {
        let mut prospective: Vec<(&ContentRef, &[u8])> = Vec::new();
        prospective
            .try_reserve_exact(self.maximum_objects)
            .map_err(|_| ProviderError::ResourceExhausted("client prospective installation"))?;
        let mut total = self.reserved;
        let mut occurrences = 0usize;
        for (reference, bytes) in objects {
            occurrences = occurrences
                .checked_add(1)
                .filter(|count| *count <= 8192)
                .ok_or(ProviderError::ResourceExhausted(
                    "client installation occurrences",
                ))?;
            reference.verify(bytes)?;
            if let Some((old, old_bytes)) = self.objects.get(&reference.hash.digest) {
                if old != reference || old_bytes.as_slice() != bytes {
                    return Err(ProviderError::Conflict("installed content changed"));
                }
                continue;
            }
            if let Some((old, old_bytes)) = prospective
                .iter()
                .find(|(old, _)| old.hash.digest == reference.hash.digest)
            {
                if *old != reference || *old_bytes != bytes {
                    return Err(ProviderError::Conflict("prospective content changed"));
                }
                continue;
            }
            if self.objects.len() + prospective.len() >= self.maximum_objects {
                return Err(ProviderError::ResourceExhausted(
                    "client installation objects",
                ));
            }
            total = total
                .checked_add(bytes.len())
                .filter(|size| *size <= self.maximum_bytes)
                .ok_or(ProviderError::ResourceExhausted(
                    "client complete installation bytes",
                ))?;
            prospective.push((reference, bytes));
        }
        Ok(prospective)
    }

    pub(super) fn begin(
        &mut self,
        request: &BlobBeginRequest,
    ) -> Result<BlobBeginResult, ProviderError> {
        request.validate()?;
        if let Some(original) = self.transfers.get(&request.transfer_id) {
            if original.reference != request.content {
                return Err(ProviderError::Conflict("original transfer content changed"));
            }
            return Ok(BlobBeginResult {
                transfer_id: request.transfer_id.clone(),
                next_offset: U64::new(original.bytes.len() as u64),
                maximum_chunk_bytes: U64::new(self.maximum_chunk as u64),
            });
        }
        if self.transfers.len() >= self.maximum_objects {
            return Err(ProviderError::ResourceExhausted(
                "client transfer identities",
            ));
        }
        let length = usize::try_from(request.content.length.get())
            .map_err(|_| ProviderError::ResourceExhausted("client content platform length"))?;
        let existing = self.objects.get(&request.content.hash.digest);
        if existing.is_some_and(|(original, _)| original != &request.content) {
            return Err(ProviderError::Conflict("original content metadata changed"));
        }
        // Reserve the complete advertised length before accepting any chunk.
        // A duplicate digest's second mutable transfer still consumes capacity.
        self.reserve(length)?;
        self.transfers.insert(
            request.transfer_id.clone(),
            Transfer {
                reference: request.content.clone(),
                bytes: Rc::new(Vec::new()),
                complete: false,
            },
        );
        Ok(BlobBeginResult {
            transfer_id: request.transfer_id.clone(),
            next_offset: U64::new(0),
            maximum_chunk_bytes: U64::new(self.maximum_chunk as u64),
        })
    }

    pub(super) fn chunk(
        &mut self,
        request: &BlobChunkRequest,
    ) -> Result<BlobChunkResult, ProviderError> {
        let original =
            self.transfers
                .get_mut(&request.transfer_id)
                .ok_or(ProviderError::Correlation(
                    "chunk before original reservation",
                ))?;
        let offset = usize::try_from(request.offset.get())
            .map_err(|_| ProviderError::ResourceExhausted("client chunk platform offset"))?;
        let bytes = request.bytes.as_slice();
        let end = offset
            .checked_add(bytes.len())
            .ok_or(ProviderError::ResourceExhausted(
                "client chunk offset overflow",
            ))?;
        if bytes.is_empty()
            || bytes.len() > self.maximum_chunk
            || end as u64 > original.reference.length.get()
        {
            return Err(ProviderError::Correlation(
                "chunk exceeds original reservation",
            ));
        }
        if offset < original.bytes.len() {
            if original.bytes.get(offset..end) != Some(bytes) {
                return Err(ProviderError::Conflict("replayed original chunk changed"));
            }
        } else if offset == original.bytes.len() && !original.complete {
            Rc::make_mut(&mut original.bytes).extend_from_slice(bytes);
        } else {
            return Err(ProviderError::Correlation(
                "chunk gap or completed transfer mutation",
            ));
        }
        Ok(BlobChunkResult {
            transfer_id: request.transfer_id.clone(),
            next_offset: U64::new(end as u64),
        })
    }

    pub(super) fn finish(
        &mut self,
        request: &BlobFinishRequest,
    ) -> Result<BlobFinishResult, ProviderError> {
        let original =
            self.transfers
                .get_mut(&request.transfer_id)
                .ok_or(ProviderError::Correlation(
                    "finish before original reservation",
                ))?;
        original.reference.verify(&original.bytes)?;
        if !original.complete {
            if let Some((reference, bytes)) = self.objects.get(&original.reference.hash.digest) {
                if reference != &original.reference || bytes != &original.bytes {
                    return Err(ProviderError::Conflict("finished content changed"));
                }
            } else {
                if self.objects.len() >= self.maximum_objects {
                    return Err(ProviderError::ResourceExhausted(
                        "client content object count",
                    ));
                }
                // Both ledgers retain one immutable allocation. Completed
                // transfer retries cannot mutate it or allocate a second copy.
                self.objects.insert(
                    original.reference.hash.digest.clone(),
                    (original.reference.clone(), Rc::clone(&original.bytes)),
                );
            }
            original.complete = true;
        }
        Ok(BlobFinishResult {
            transfer_id: request.transfer_id.clone(),
            content: original.reference.clone(),
        })
    }

    fn reserve(&mut self, length: usize) -> Result<(), ProviderError> {
        let total = self
            .reserved
            .checked_add(length)
            .ok_or(ProviderError::ResourceExhausted(
                "client content accounting",
            ))?;
        if total > self.maximum_bytes || self.objects.len() >= self.maximum_objects {
            return Err(ProviderError::ResourceExhausted("client content custody"));
        }
        self.reserved = total;
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- invalid immutable transfer fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- These content tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_format::{Bytes, Extensions, canonical};

    #[test]
    fn original_chunks_cannot_be_replaced_or_skipped_and_finish_verifies_hash() {
        let reference = canonical::content_ref(b"abc", "text/plain").unwrap();
        let transfer = Id::new("original").unwrap();
        let mut content = ClientContent::new(6, 4, 3).unwrap();
        content
            .begin(&BlobBeginRequest {
                transfer_id: transfer.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            })
            .unwrap();
        let chunk = |offset, bytes: &[u8]| BlobChunkRequest {
            transfer_id: transfer.clone(),
            offset: U64::new(offset),
            bytes: Bytes::new(bytes.to_vec()),
            extensions: Extensions::new(),
        };

        assert!(content.chunk(&chunk(1, b"bc")).is_err());
        content.chunk(&chunk(0, b"abc")).unwrap();
        assert!(content.chunk(&chunk(0, b"xyz")).is_err());
        content
            .finish(&BlobFinishRequest {
                transfer_id: transfer.clone(),
                extensions: Extensions::new(),
            })
            .unwrap();
        content.chunk(&chunk(0, b"abc")).unwrap();
        assert_eq!(content.get(&reference).unwrap(), b"abc");
    }
}

/// Validates explicit content-eight metadata capacities without granting installation.
pub mod compact_metadata8;

impl ClientContent {
    pub(super) fn fresh_report_requested_layout_data(
        &self,
        raw_capacity: usize,
    ) -> Result<usize, ProviderError> {
        use std::mem::{align_of, size_of};
        let entries = self
            .transfers
            .len()
            .checked_add(self.objects.len())
            .and_then(|n| n.checked_add(2))
            .ok_or(ProviderError::ResourceExhausted(
                "fresh report content tree extent",
            ))?;
        let tree = crate::retained_metadata::requested_storage::tree_storage_data(
            2,
            entries,
            (size_of::<Id>() + size_of::<Transfer>())
                .max(size_of::<String>() + size_of::<(ContentRef, Rc<Vec<u8>>)>()),
            align_of::<Transfer>().max(align_of::<ContentRef>()),
        )?;
        // The single initialized transfer and completed object retain the SAME
        // actual Rc<Vec<u8>>; the two edge headers themselves are inline above.
        [
            tree,
            raw_capacity,
            size_of::<Vec<u8>>(),
            crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                align_of::<Vec<u8>>(),
            )?,
        ]
        .into_iter()
        .try_fold(0usize, |n, bytes| {
            n.checked_add(bytes).ok_or(ProviderError::ResourceExhausted(
                "fresh report content backing",
            ))
        })
    }
}

impl ClientContent {
    // Selected construction retains the independent original body in its
    // caller's slot until all fallible verification/accounting has passed.
    pub(in crate::client) fn install_original_host_startup_from_slot(
        &mut self,
        pending: &mut Option<(ContentRef, Vec<u8>)>,
    ) -> Result<(), ProviderError> {
        let (reference, bytes) = pending.as_ref().ok_or(ProviderError::Correlation(
            "original host content slot absent",
        ))?;
        reference.verify(bytes)?;
        if let Some((original, original_bytes)) = self.objects.get(&reference.hash.digest) {
            if original != reference || original_bytes.as_ref() != bytes {
                return Err(ProviderError::Conflict("installed content changed"));
            }
            // Keep the redundant original in the caller until it explicitly
            // installs its next slot; no fallible step follows this comparison.
            return Ok(());
        }
        self.reserve(bytes.len())?;
        let (reference, bytes) = pending.take().ok_or(ProviderError::Correlation(
            "original host content slot disappeared",
        ))?;
        self.objects
            .insert(reference.hash.digest.clone(), (reference, Rc::new(bytes)));
        Ok(())
    }
}

#[path = "content/host_initial.rs"]
mod host_initial;

impl ClientContent {
    pub(in crate::client) fn original_capture_allocation_body_data(
        &self,
        reference: &ContentRef,
    ) -> Result<&[u8], ProviderError> {
        let refused = || ProviderError::Correlation("original allocation report content differs");
        let (actual, bytes) = self
            .objects
            .get(&reference.hash.digest)
            .ok_or_else(refused)?;
        if actual != reference
            || reference.hash.algorithm != "blake3-256"
            || reference.hash.domain != "cnp.blob.v1"
            || reference.hash.digest.len() != 64
            || !reference
                .hash
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || u64::try_from(bytes.len()).ok() != Some(reference.length.get())
        {
            return Err(refused());
        }
        // Matches canonical::hash framing exactly while keeping the full digest
        // and input bank borrowed. No temporary HashRef/String/Vec is built.
        let domain = b"cnp.blob.v1";
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CNP/1\0");
        hasher.update(
            &u32::try_from(domain.len())
                .map_err(|_| refused())?
                .to_be_bytes(),
        );
        hasher.update(domain);
        hasher.update(&reference.length.get().to_be_bytes());
        hasher.update(bytes);
        let digest = hasher.finalize();
        for (hex, byte) in reference
            .hash
            .digest
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .zip(digest.as_bytes())
        {
            let digit = |value: u8| {
                if value.is_ascii_digit() {
                    value - b'0'
                } else {
                    value - b'a' + 10
                }
            };
            if digit(hex[0]) * 16 + digit(hex[1]) != *byte {
                return Err(refused());
            }
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod allocation_report_tests {
    //! Actual immutable content ownership; this does not construct Source rights.
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn allocation_report_full_reference_hash_and_missing_body_preserve_custody() {
        let bytes = b"original report DATA".to_vec();
        let media = crate::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA;
        let reference = canonical::content_ref(&bytes, media).unwrap();
        let mut content = ClientContent::new(65536, 8, 4096).unwrap();
        assert!(
            content
                .original_capture_allocation_body_data(&reference)
                .is_err()
        );
        let mut pending = Some((reference.clone(), bytes));
        content
            .install_original_host_startup_from_slot(&mut pending)
            .unwrap();
        assert!(pending.is_none());
        let original = content
            .original_capture_allocation_body_data(&reference)
            .unwrap()
            .as_ptr();
        let mut wrong = reference.clone();
        wrong.media_type = "application/json".into();
        assert!(
            content
                .original_capture_allocation_body_data(&wrong)
                .is_err()
        );
        wrong = reference.clone();
        wrong.length = U64::new(reference.length.get() + 1);
        assert!(
            content
                .original_capture_allocation_body_data(&wrong)
                .is_err()
        );
        assert_eq!(
            content
                .original_capture_allocation_body_data(&reference)
                .unwrap()
                .as_ptr(),
            original
        );
        // A changed retained bank cannot pass merely because its map identity is
        // unchanged. Refusal retains that same allocation for custody inspection.
        let (_, body) = content.objects.get_mut(&reference.hash.digest).unwrap();
        Rc::get_mut(body).unwrap()[0] ^= 1;
        assert!(
            content
                .original_capture_allocation_body_data(&reference)
                .is_err()
        );
        assert_eq!(
            content
                .objects
                .get(&reference.hash.digest)
                .unwrap()
                .1
                .as_ptr(),
            original
        );
    }
}

impl ClientContent {
    pub(crate) fn observe_historical_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.observe_owned_metadata(observer)
    }
}

impl ClientContent {
    pub(in crate::client) fn authenticate_selected_restore_transfer_absent(
        &self,
        id: &Id,
    ) -> Result<(), ProviderError> {
        if self.transfers.contains_key(id) {
            return Err(ProviderError::Conflict(
                "selected restore content transfer reused",
            ));
        }
        Ok(())
    }
}

impl ClientContent {
    // Charges both actual retained alias views without assuming deduplication.
    // Existing roots are counted again in the prospective tree geometry so no
    // live root split borrows an old tree allocation as future credit.
    pub(in crate::client) fn selected_restore_held_content_storage_data(
        &self,
        maximum: usize,
    ) -> Result<(usize, usize), ProviderError> {
        use crate::retained_metadata::requested_storage::{
            shared_header_storage_data, tree_storage_data,
        };
        use std::mem::{align_of, size_of};
        let credit = || ProviderError::ResourceExhausted("selected held content layout");
        let growth = |bytes: usize| {
            bytes
                .checked_mul(4)
                .and_then(|n| n.checked_add(8))
                .ok_or_else(credit)
        };
        let transfer_entries = self.transfers.len().checked_add(1).ok_or_else(credit)?;
        let object_entries = self.objects.len().checked_add(1).ok_or_else(credit)?;
        let mut retained = tree_storage_data(
            1,
            transfer_entries,
            size_of::<Id>() + size_of::<Transfer>(),
            align_of::<Id>().max(align_of::<Transfer>()),
        )?;
        retained = retained
            .checked_add(tree_storage_data(
                1,
                object_entries,
                size_of::<String>() + size_of::<(ContentRef, Rc<Vec<u8>>)>(),
                align_of::<String>().max(align_of::<(ContentRef, Rc<Vec<u8>>)>()),
            )?)
            .ok_or_else(credit)?;
        for bytes in [
            growth(128)?,
            growth(64)?,
            // Independent Transfer/Object ContentRef string clones.
            growth("blake3-256".len())?,
            growth("cnp.blob.v1".len())?,
            growth(64)?,
            growth("application/json".len())?,
            growth("blake3-256".len())?,
            growth("cnp.blob.v1".len())?,
            growth(64)?,
            growth("application/json".len())?,
            shared_header_storage_data(2, align_of::<Vec<u8>>())?,
            2 * size_of::<Vec<u8>>(),
            growth(maximum)?,
            growth(maximum)?,
        ] {
            retained = retained.checked_add(bytes).ok_or_else(credit)?;
        }
        // The old bank may coexist with the newly grown Vec during reallocation.
        let mut transient = growth(maximum)?;
        for bytes in [
            growth(64)?,
            growth("cnp.blob.v1".len())?,
            growth("blake3-256".len())?,
            size_of::<crucible_node_format::HashRef>(),
            size_of::<blake3::Hasher>(),
            size_of::<blake3::Hash>(),
        ] {
            transient = transient.checked_add(bytes).ok_or_else(credit)?;
        }
        Ok((retained, transient))
    }
}

#[cfg(test)]
mod selected_restore_layout_tests {
    use super::*;
    use crucible_node_format::{Bytes, Extensions, canonical};

    #[test]
    fn actual_completed_content_aliases_fit_selected_prospective_geometry() {
        let mut content = ClientContent::new(1024, 4, 3).unwrap();
        let (retained, _) = content
            .selected_restore_held_content_storage_data(5)
            .unwrap();
        let id = Id::new("packet-restore-held-transfer-20").unwrap();
        let reference = canonical::content_ref(b"abcde", "application/json").unwrap();
        content
            .authenticate_selected_restore_transfer_absent(&id)
            .unwrap();
        content
            .begin(&BlobBeginRequest {
                transfer_id: id.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            })
            .unwrap();
        assert!(
            content
                .authenticate_selected_restore_transfer_absent(&id)
                .is_err()
        );
        for (offset, bytes) in [(0, &b"abc"[..]), (3, &b"de"[..])] {
            content
                .chunk(&BlobChunkRequest {
                    transfer_id: id.clone(),
                    offset: U64::new(offset),
                    bytes: Bytes::new(bytes.to_vec()),
                    extensions: Extensions::new(),
                })
                .unwrap();
        }
        content
            .finish(&BlobFinishRequest {
                transfer_id: id,
                extensions: Extensions::new(),
            })
            .unwrap();
        assert_eq!(content.get(&reference).unwrap(), b"abcde");
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        content.observe_owned_metadata(&mut observer).unwrap();
        let actual =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())
                .unwrap();
        assert!(
            actual <= retained,
            "actual aliases {actual}, prospective {retained}"
        );
        assert!(
            content
                .selected_restore_held_content_storage_data(usize::MAX)
                .is_err()
        );
    }
}

impl ClientContent {
    // The SDK future row names this private owner's real tree/Transfer layouts.
    // It grants no capacity in the existing receiver and creates no byte bank.
    pub(crate) fn restored_settled_capture_future_content_storage_data(
        lengths: [usize; 4],
        maximum_reference_bytes: usize,
    ) -> Result<usize, ProviderError> {
        use crate::retained_metadata::requested_storage::{
            shared_header_storage_data, tree_storage_data,
        };
        use std::mem::{align_of, size_of};
        let overflow = || ProviderError::ResourceExhausted("settled Capture future content");
        let bytes = lengths.into_iter().try_fold(0usize, |n, length| {
            n.checked_add(length).ok_or_else(overflow)
        })?;
        // Transfer and object roots may alias. Two separately charged views
        // conservatively cover both; no equality-based alias discount is used.
        let payload = bytes.checked_mul(2).ok_or_else(overflow)?;
        let reference_backing = maximum_reference_bytes
            .checked_mul(8)
            .ok_or_else(overflow)?;
        let terms = [
            payload,
            reference_backing,
            8 * size_of::<Vec<u8>>(),
            shared_header_storage_data(8, align_of::<Vec<u8>>())?,
            tree_storage_data(
                1,
                4,
                size_of::<Id>() + size_of::<Transfer>(),
                align_of::<(Id, Transfer)>(),
            )?,
            tree_storage_data(
                1,
                4,
                size_of::<String>() + size_of::<(ContentRef, Rc<Vec<u8>>)>(),
                align_of::<(String, (ContentRef, Rc<Vec<u8>>))>(),
            )?,
        ];
        terms
            .into_iter()
            .try_fold(0usize, |n, term| n.checked_add(term).ok_or_else(overflow))
    }

    pub(crate) fn restored_settled_capture_future_content_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<[usize; 4]>()
            + size_of::<std::array::IntoIter<usize, 4>>()
            + size_of::<[usize; 6]>()
            + size_of::<std::array::IntoIter<usize, 6>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>()
    }
}

impl ClientContent {
    /// Prices all permitted receiver growth during selected Capture exchanges.
    ///
    /// Provider originals reach the unchanged generic receiver before terminal
    /// validation, so wrong-role/incomplete transfers must fit as well. The full
    /// original ceilings also cover already-reserved transfers whose byte banks
    /// can still grow; subtracting only `reserved` would miss those owners.
    /// Existing current allocations are independently counted by raw census.
    pub(crate) fn restored_settled_capture_receiver_storage_data(
        &self,
        maximum_reference_bytes: usize,
    ) -> Result<usize, ProviderError> {
        use crate::retained_metadata::requested_storage::{
            shared_header_storage_data, tree_storage_data,
        };
        use std::mem::{align_of, size_of};
        let add = |left: usize, right: usize| {
            left.checked_add(right)
                .ok_or(ProviderError::ResourceExhausted(
                    "settled Capture receiver geometry",
                ))
        };
        let multiply = |left: usize, right: usize| {
            left.checked_mul(right)
                .ok_or(ProviderError::ResourceExhausted(
                    "settled Capture receiver geometry",
                ))
        };

        // Vec<u8> amortized growth requests at most twice the required extent,
        // with an eight-byte minimum. Count both retained Rc views without an
        // alias discount, including the maps' independent keys/full references.
        let one_view = add(
            multiply(2, self.maximum_bytes)?,
            multiply(8, self.maximum_objects)?,
        )?;
        let payload = multiply(2, one_view)?;
        let handles = multiply(
            multiply(2, self.maximum_objects)?,
            add(
                size_of::<Vec<u8>>(),
                shared_header_storage_data(1, align_of::<Vec<u8>>())?,
            )?,
        )?;
        let metadata = multiply(self.maximum_objects, multiply(4, maximum_reference_bytes)?)?;
        let transfers = tree_storage_data(
            1,
            self.maximum_objects,
            size_of::<Id>() + size_of::<Transfer>(),
            align_of::<(Id, Transfer)>(),
        )?;
        let objects = tree_storage_data(
            1,
            self.maximum_objects,
            size_of::<String>() + size_of::<(ContentRef, Rc<Vec<u8>>)>(),
            align_of::<(String, (ContentRef, Rc<Vec<u8>>))>(),
        )?;
        [payload, handles, metadata, transfers, objects]
            .into_iter()
            .try_fold(0usize, add)
    }

    pub(crate) fn restored_settled_capture_receiver_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<[usize; 5]>()
            + std::mem::size_of::<std::array::IntoIter<usize, 5>>()
            + std::mem::size_of::<Result<usize, ProviderError>>()
    }
}

mod observation_receive;

mod internal_growth;
pub use internal_growth::OriginalClientContentGrowthStorageData;

#[path = "content/capture_current17.rs"]
mod capture_current17;

#[path = "content/capture_encoding17.rs"]
mod capture_encoding17;
