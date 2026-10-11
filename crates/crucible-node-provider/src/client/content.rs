//! Finite immutable byte custody for authenticated opposite-direction transfers.

use std::collections::BTreeMap;
use std::rc::Rc;

use crucible_node_contract::{ContentRef, Id, U64, Validate};

use crate::{ProviderError, bodies::*};

#[cfg(test)]
#[path = "content_installation_tests.rs"]
mod installation_tests;

struct Transfer {
    reference: ContentRef,
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
    use crucible_node_contract::{Bytes, Extensions, canonical};

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
