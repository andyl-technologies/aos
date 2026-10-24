//! Encodes bounded, canonical backing requests without trusting their context.
//!
//! ```text
//! TBC1 | kind:u8 | reserved:3 | exposure:16 | generation:u64le |
//! sequence:u64le | content:32 | path_length:u32le | relative_path
//! ```
//!
//! Successful responses echo the complete request with exactly one descriptor.
//! Any rejected request faults the channel; there is no successful empty reply.

use std::io;
use terrane_format::{identity::Digest, tree_format::ContentRef};

const HEADER: usize = 76;
pub(super) const MAX_PACKET: usize = HEADER + 4096;

/// Names one exposure generation without granting authorization or peer identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureContext {
    pub(super) id: [u8; 16],
    pub(super) generation: u64,
    pub(super) root: Digest,
}

impl ExposureContext {
    /// Parses the public exposure context delivered by the trusted launcher.
    ///
    /// # Errors
    /// Rejects noncanonical identifiers and generation zero.
    pub fn new(id: &str, generation: u64, root: Digest) -> io::Result<Self> {
        if id.len() != 32 || generation == 0 {
            return Err(invalid("invalid exposure context"));
        }
        let mut decoded = [0; 16];
        for (destination, pair) in decoded.iter_mut().zip(id.as_bytes().as_chunks::<2>().0) {
            let digit = |byte| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(invalid("noncanonical exposure identifier")),
            };
            *destination = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Ok(Self {
            id: decoded,
            generation,
            root,
        })
    }
}

/// Selects metadata backing or one exact typed file in the served namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestedBacking {
    /// Requests the exposure's original structural index.
    Index,
    /// Requests a relative file path and its signed typed content reference.
    File {
        /// Names a nonempty canonical relative path in the mapped index.
        path: Vec<u8>,
        /// Names the exact inline chunk or manifest recorded for that path.
        content: ContentRef,
    },
}

/// Retains a bounded decoded request, not a credential or disclosure grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackingRequest {
    pub(super) context: ExposureContext,
    pub(super) sequence: u64,
    pub(super) backing: RequestedBacking,
}

impl BackingRequest {
    /// Constructs a canonical request for an exposure generation.
    ///
    /// # Errors
    /// Rejects sequence zero and invalid or oversized relative paths.
    pub fn new(
        context: ExposureContext,
        sequence: u64,
        backing: RequestedBacking,
    ) -> io::Result<Self> {
        if sequence == 0 {
            return Err(invalid("backing sequence zero"));
        }
        if let RequestedBacking::File { path, .. } = &backing
            && (path.is_empty()
                || path.len() > 4096
                || path.contains(&0)
                || path
                    .split(|byte| *byte == b'/')
                    .any(|part| part.is_empty() || part == b"." || part == b".."))
        {
            return Err(invalid("invalid backing path"));
        }
        Ok(Self {
            context,
            sequence,
            backing,
        })
    }

    /// Borrows the requested index or exact typed file selection.
    pub const fn backing(&self) -> &RequestedBacking {
        &self.backing
    }

    /// Encodes the exact versioned packet without padding or trailing fields.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, hash, path) = match &self.backing {
            RequestedBacking::Index => (1, &self.context.root, &[][..]),
            RequestedBacking::File { path, content } => match content {
                ContentRef::Inline(hash) => (2, hash, path.as_slice()),
                ContentRef::Manifest(hash) => (3, hash, path.as_slice()),
            },
        };
        let mut bytes = Vec::with_capacity(HEADER + path.len());
        bytes.extend_from_slice(b"TBC1");
        bytes.extend_from_slice(&[kind, 0, 0, 0]);
        bytes.extend_from_slice(&self.context.id);
        bytes.extend_from_slice(&self.context.generation.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(hash);
        bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
        bytes.extend_from_slice(path);
        bytes
    }

    /// Checks a complete packet against the independently supplied launch context.
    ///
    /// # Errors
    /// Rejects unknown versions or kinds, nonzero reserved bytes, foreign
    /// context, sequence zero, malformed paths, truncation and trailing bytes.
    pub fn decode(bytes: &[u8], context: &ExposureContext) -> io::Result<Self> {
        if !(HEADER..=MAX_PACKET).contains(&bytes.len())
            || bytes.get(..4) != Some(b"TBC1")
            || bytes[5..8] != [0; 3]
            || bytes[8..24] != context.id
        {
            return Err(invalid("invalid backing envelope"));
        }
        let integer = |range: std::ops::Range<usize>| {
            bytes[range]
                .try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| invalid("truncated backing integer"))
        };
        if integer(24..32)? != context.generation {
            return Err(invalid("foreign backing generation"));
        }
        let length = u32::from_le_bytes(
            bytes[72..76]
                .try_into()
                .map_err(|_| invalid("truncated backing path length"))?,
        ) as usize;
        if bytes.len() - HEADER != length {
            return Err(invalid("backing path length mismatch"));
        }
        let hash = bytes[40..72]
            .try_into()
            .map_err(|_| invalid("truncated backing identity"))?;
        let backing = match bytes[4] {
            1 if hash == context.root && length == 0 => RequestedBacking::Index,
            kind @ (2 | 3) => RequestedBacking::File {
                path: bytes[HEADER..].to_vec(),
                content: if kind == 2 {
                    ContentRef::Inline(hash)
                } else {
                    ContentRef::Manifest(hash)
                },
            },
            _ => return Err(invalid("unknown or inconsistent backing kind")),
        };
        Self::new(context.clone(), integer(32..40)?, backing)
    }
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
