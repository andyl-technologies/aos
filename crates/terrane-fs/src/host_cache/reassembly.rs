//! Streams a checked ordered source plan without buffering a whole object.
//!
//! Verification and copying use the same ordered source reader. The caller owns
//! any output, including partial output after failure. Allocating an output inode
//! additionally requires the native reservation/custody protocol; this module
//! mints no such receipt or file eligible for a kernel surface.

use super::{NativeChunkSource, NativeHostLayout};
use std::io::{self, Cursor, Read, Write};
use terrane::{
    host::cache::HostReadLocation,
    host::publication::{PublicationClaim, PublicationRecipe},
    store::ChunkPosition,
};
use terrane_core::identity::{IdentityKind, TERRANE_V1};

/// Retains an exact domain-bound source sequence for one verified object claim.
pub struct NativeReassemblyPlan {
    claim: PublicationClaim,
    sources: Vec<NativeChunkSource>,
}

impl NativeReassemblyPlan {
    /// Checks source order, profile, domain, sizes and chunk boundary context.
    ///
    /// Source descriptors originate from actual cache files. No caller-provided
    /// byte buffer, file path or validity boolean can substitute for a source.
    ///
    /// # Errors
    /// Rejects another domain, malformed claim, missing/reordered sources,
    /// incorrect sizes, and relaxed final-chunk checks on nonfinal positions.
    pub fn new<L: HostReadLocation>(
        layout: &NativeHostLayout<L>,
        claim: PublicationClaim,
        sources: Vec<NativeChunkSource>,
    ) -> io::Result<Self> {
        layout.recheck()?;
        if claim.domain() != layout.layout().domain() {
            return Err(invalid("reassembly claim belongs to another domain"));
        }
        let recipe = match claim.canonical_manifest() {
            Some(bytes) => PublicationRecipe::Manifest {
                object: claim.descriptor().clone(),
                canonical_manifest: bytes.to_vec(),
            },
            None => PublicationRecipe::Inline {
                chunk: claim.descriptor().clone(),
            },
        };
        let claim = PublicationClaim::new(
            claim.domain().to_owned(),
            recipe,
            layout.layout().chunk_profile(),
        )?;
        if let Some(manifest) = claim.manifest() {
            if sources.len() != manifest.chunks.len() {
                return Err(invalid("reassembly source count differs from manifest"));
            }
            for (index, (source, chunk)) in sources.iter().zip(&manifest.chunks).enumerate() {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Chunk, &chunk.digest)
                    .map_err(invalid)?;
                let length = usize::try_from(chunk.length).map_err(invalid)?;
                let position = if index + 1 == sources.len() {
                    ChunkPosition::Final
                } else {
                    ChunkPosition::NonFinal
                };
                if !source.matches(
                    claim.domain(),
                    &identity,
                    length,
                    position,
                    layout.layout().chunk_profile(),
                ) {
                    return Err(invalid(
                        "reassembly source differs from ordered manifest declaration",
                    ));
                }
            }
        } else {
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, claim.descriptor().digest())
                .map_err(invalid)?;
            let length = usize::try_from(claim.plaintext_size()).map_err(invalid)?;
            if sources.len() != 1
                || !sources[0].matches(
                    claim.domain(),
                    &identity,
                    length,
                    ChunkPosition::Final,
                    layout.layout().chunk_profile(),
                )
            {
                return Err(invalid(
                    "inline reassembly requires its exact single source",
                ));
            }
        }
        Ok(Self { claim, sources })
    }

    /// Returns the authenticated publication witness for this exact source plan.
    pub fn claim(&self) -> &PublicationClaim {
        &self.claim
    }

    /// Re-verifies actual ordered plaintext and every claimed whole-file hash.
    ///
    /// Memory is bounded by one encoded source chunk, its optional dictionary,
    /// and the bounded plaintext verification buffers. This performs no writes
    /// and does not grant a reservation, retention receipt or publication ACK.
    ///
    /// # Errors
    /// Rejects modified/truncated/reordered sources, invalid codec or boundary
    /// data, differing whole-file hashes, and native read failures.
    pub fn verify(&mut self) -> io::Result<()> {
        let mut reader = SequenceReader {
            sources: self.sources.iter_mut(),
            current: Cursor::new(Vec::new()),
        };
        self.claim.verify_reader(&mut reader)
    }

    /// Streams ordered plaintext into an owned output while verifying the claim.
    ///
    /// A successful result reports the exact verified plaintext length. Memory
    /// remains bounded by individual chunks and their optional dictionaries;
    /// the assembled object is never collected into a whole-object buffer.
    /// This method neither flushes nor synchronizes the output. The caller must
    /// establish and retain native pins, quota funding and output custody before
    /// calling it, then synchronize and independently seal the completed inode.
    ///
    /// # Errors
    /// Rejects changed, truncated, reordered or corrupt source bytes, incorrect
    /// whole-file hashes, and read or write failures. Errors can leave partial
    /// or complete unverified output, which the caller must retain or discard
    /// under its original custody; such bytes are never publication authority.
    pub fn copy_verified(&mut self, output: &mut impl Write) -> io::Result<u64> {
        let mut reader = SequenceReader {
            sources: self.sources.iter_mut(),
            current: Cursor::new(Vec::new()),
        };
        copy_claim(&self.claim, &mut reader, output)
    }
}

fn copy_claim(
    claim: &PublicationClaim,
    source: &mut impl Read,
    output: &mut impl Write,
) -> io::Result<u64> {
    // Verify the same stream that reaches the output, rather than verifying once
    // and then rereading mutable sources in an unchecked second pass.
    let mut reader = CopyingReader { source, output };
    claim.verify_reader(&mut reader)?;
    Ok(claim.plaintext_size())
}

struct CopyingReader<'a, R, W> {
    source: &'a mut R,
    output: &'a mut W,
}

impl<R: Read, W: Write> Read for CopyingReader<'_, R, W> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(bytes)?;
        self.output.write_all(&bytes[..count])?;
        Ok(count)
    }
}

struct SequenceReader<'a> {
    sources: std::slice::IterMut<'a, NativeChunkSource>,
    current: Cursor<Vec<u8>>,
}

impl Read for SequenceReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            let count = self.current.read(output)?;
            if count != 0 {
                return Ok(count);
            }
            let Some(source) = self.sources.next() else {
                return Ok(0);
            };
            self.current = Cursor::new(source.read_verified()?);
        }
    }
}

fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests;
