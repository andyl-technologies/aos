//! Implements the exact, shortest-form D-79 record schemas.
//!
//! ```text
//! committed-selection = [0] / [1, RefRecord] / [2]
//! BackendRegistration = {0: 1, 1: binding, 2: phase, 3: digest_or_null}
//! ```

use super::*;
use crate::cbor::{Decoder, write_array, write_bytes, write_map, write_text, write_uint};
use alloc::string::ToString;

trait Record: Sized {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError>;
    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError>;
}

macro_rules! codec {
    ($($record:ty),+ $(,)?) => {$(
        impl $record {
            /// Encodes the untrusted record in its deterministic registered form.
            ///
            /// # Errors
            /// Rejects malformed fields and contradictions decidable from this record.
            pub fn encode(&self) -> Result<Vec<u8>, PublicationError> {
                let mut output = Vec::new();
                self.write(&mut output)?;
                // The same typed decoder validates caller-built values, including
                // length bounds, without introducing a second schema implementation.
                Self::decode(&output)?;
                Ok(output)
            }

            /// Decodes exact canonical bytes without granting publication authority.
            ///
            /// # Errors
            /// Rejects noncanonical CBOR, unknown fields, oversized collections,
            /// invalid record shapes, trailing bytes, and internal contradictions.
            pub fn decode(bytes: &[u8]) -> Result<Self, PublicationError> {
                let mut decoder = Decoder::new(bytes);
                let record = Self::read(&mut decoder)?;
                decoder.finish()?;
                Ok(record)
            }
        }
    )+};
}

codec!(
    BackendBinding,
    BackendRegistration,
    CommittedSelection,
    SelectedHistory,
    PortableCurrent,
    PortableSnapshot,
    PublicationState,
    PublicationCurrent,
    PublicationCommit,
    PublicationProof,
    PublicationTransaction
);

fn array(decoder: &mut Decoder<'_>, count: usize) -> Result<(), PublicationError> {
    if decoder.array(count)? != count {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

fn map(decoder: &mut Decoder<'_>, count: usize) -> Result<(), PublicationError> {
    if decoder.map(count)? != count {
        return Err(PublicationError::Schema);
    }
    key(decoder, 0)?;
    if decoder.uint()? != 1 {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

fn key(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), PublicationError> {
    if decoder.uint()? != expected {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

fn header(output: &mut Vec<u8>, count: usize) {
    write_map(output, count);
    write_uint(output, 0);
    write_uint(output, 1);
}

fn digest<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], PublicationError> {
    decoder
        .bytes(N)?
        .try_into()
        .map_err(|_| PublicationError::Schema)
}

fn null(decoder: &mut Decoder<'_>) -> Result<(), PublicationError> {
    if decoder.simple()? != 0xf6 {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

fn optional<T>(
    decoder: &mut Decoder<'_>,
    read: impl FnOnce(&mut Decoder<'_>) -> Result<T, PublicationError>,
) -> Result<Option<T>, PublicationError> {
    if decoder.peek_major()? == 7 {
        null(decoder)?;
        Ok(None)
    } else {
        Ok(Some(read(decoder)?))
    }
}

fn write_optional<T: ?Sized>(
    output: &mut Vec<u8>,
    value: Option<&T>,
    write: impl FnOnce(&T, &mut Vec<u8>) -> Result<(), PublicationError>,
) -> Result<(), PublicationError> {
    if let Some(value) = value {
        write(value, output)?;
    } else {
        output.push(0xf6);
    }
    Ok(())
}

fn write_digest(value: &RawDigest, output: &mut Vec<u8>) -> Result<(), PublicationError> {
    write_bytes(output, value);
    Ok(())
}

fn text(decoder: &mut Decoder<'_>) -> Result<String, PublicationError> {
    Ok(decoder.text(decoder.remaining().len())?.to_string())
}

fn bytes(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, PublicationError> {
    Ok(decoder.bytes(decoder.remaining().len())?.to_vec())
}

fn write_blob(value: &[u8], output: &mut Vec<u8>) -> Result<(), PublicationError> {
    write_bytes(output, value);
    Ok(())
}

impl Record for BackendBinding {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        let count = decoder.array(6)?;
        let binding = match (decoder.uint()?, count) {
            (0, 6) => Self::Local {
                root: bytes(decoder)?,
                root_device: decoder.uint()?,
                root_inode: decoder.uint()?,
                coordination_device: decoder.uint()?,
                coordination_inode: decoder.uint()?,
            },
            (1, 4) => {
                let provider = match decoder.text(3)? {
                    "s3" => RemoteProvider::S3,
                    "gcs" => RemoteProvider::Gcs,
                    _ => return Err(PublicationError::Schema),
                };
                array(decoder, 4)?;
                let endpoint = decoder.text(4096)?.to_string();
                let bucket = decoder.text(4096)?.to_string();
                let prefix = decoder.bytes(4096)?.to_vec();
                let resource_nonce = digest(decoder)?;
                array(decoder, 2)?;
                let coordination_key = decoder.bytes(4096)?.to_vec();
                let coordination_nonce = digest(decoder)?;
                Self::Remote {
                    provider,
                    endpoint,
                    bucket,
                    prefix,
                    resource_nonce,
                    coordination_key,
                    coordination_nonce,
                }
            }
            _ => return Err(PublicationError::Schema),
        };
        validation::binding(&binding)?;
        Ok(binding)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        validation::binding(self)?;
        match self {
            Self::Local {
                root,
                root_device,
                root_inode,
                coordination_device,
                coordination_inode,
            } => {
                write_array(output, 6);
                write_uint(output, 0);
                write_bytes(output, root);
                for value in [
                    root_device,
                    root_inode,
                    coordination_device,
                    coordination_inode,
                ] {
                    write_uint(output, *value);
                }
            }
            Self::Remote {
                provider,
                endpoint,
                bucket,
                prefix,
                resource_nonce,
                coordination_key,
                coordination_nonce,
            } => {
                write_array(output, 4);
                write_uint(output, 1);
                write_text(
                    output,
                    match provider {
                        RemoteProvider::S3 => "s3",
                        RemoteProvider::Gcs => "gcs",
                    },
                );
                write_array(output, 4);
                write_text(output, endpoint);
                write_text(output, bucket);
                write_bytes(output, prefix);
                write_bytes(output, resource_nonce);
                write_array(output, 2);
                write_bytes(output, coordination_key);
                write_bytes(output, coordination_nonce);
            }
        }
        Ok(())
    }
}

impl Record for BackendRegistration {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        map(decoder, 4)?;
        key(decoder, 1)?;
        let binding = BackendBinding::read(decoder)?;
        key(decoder, 2)?;
        let activation = match decoder.uint()? {
            0 => Activation::Pending,
            1 => Activation::Active,
            _ => return Err(PublicationError::Schema),
        };
        key(decoder, 3)?;
        let genesis = optional(decoder, digest)?;
        if activation == Activation::Active && genesis.is_none() {
            return Err(PublicationError::Contradiction);
        }
        Ok(Self {
            binding,
            activation,
            genesis,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        header(output, 4);
        write_uint(output, 1);
        self.binding.write(output)?;
        write_uint(output, 2);
        write_uint(output, u64::from(self.activation == Activation::Active));
        write_uint(output, 3);
        write_optional(output, self.genesis.as_ref(), write_digest)
    }
}

impl Record for CommittedSelection {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        let count = decoder.array(2)?;
        match (decoder.uint()?, count) {
            (0, 1) => Ok(Self::Never),
            (2, 1) => Ok(Self::Unknown),
            (1, 2) => Ok(Self::Selected(Box::new(RefRecord::decode(
                decoder.raw_value(decoder.remaining().len())?,
            )?))),
            _ => Err(PublicationError::Schema),
        }
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        match self {
            Self::Never => {
                write_array(output, 1);
                write_uint(output, 0);
            }
            Self::Unknown => {
                write_array(output, 1);
                write_uint(output, 2);
            }
            Self::Selected(record) => {
                write_array(output, 2);
                write_uint(output, 1);
                output.extend_from_slice(&record.encode()?);
            }
        }
        Ok(())
    }
}

fn history(decoder: &mut Decoder<'_>) -> Result<Vec<HistoryEntry>, PublicationError> {
    let count = decoder.array(decoder.remaining().len())?;
    let mut rows = Vec::new();
    for _ in 0..count {
        array(decoder, 2)?;
        rows.push(HistoryEntry {
            name: text(decoder)?,
            selection: CommittedSelection::read(decoder)?,
        });
    }
    validation::history(&rows)?;
    Ok(rows)
}

fn write_history(output: &mut Vec<u8>, rows: &[HistoryEntry]) -> Result<(), PublicationError> {
    validation::history(rows)?;
    write_array(output, rows.len());
    for row in rows {
        write_array(output, 2);
        write_text(output, &row.name);
        row.selection.write(output)?;
    }
    Ok(())
}

fn sources(decoder: &mut Decoder<'_>) -> Result<Vec<SourceLineage>, PublicationError> {
    let count = decoder.array(decoder.remaining().len())?;
    let mut rows = Vec::new();
    for _ in 0..count {
        array(decoder, 2)?;
        rows.push(SourceLineage {
            name: text(decoder)?,
            digest: digest(decoder)?,
        });
    }
    validation::sources(&rows)?;
    Ok(rows)
}

fn write_sources(output: &mut Vec<u8>, rows: &[SourceLineage]) -> Result<(), PublicationError> {
    validation::sources(rows)?;
    write_array(output, rows.len());
    for row in rows {
        write_array(output, 2);
        write_text(output, &row.name);
        write_bytes(output, &row.digest);
    }
    Ok(())
}

impl Record for SelectedHistory {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        map(decoder, 3)?;
        key(decoder, 1)?;
        let branches = history(decoder)?;
        key(decoder, 2)?;
        let origin = BackendBinding::read(decoder)?;
        Ok(Self { branches, origin })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        header(output, 3);
        write_uint(output, 1);
        write_history(output, &self.branches)?;
        write_uint(output, 2);
        self.origin.write(output)
    }
}

fn snapshot_pointer(decoder: &mut Decoder<'_>) -> Result<PortableCurrent, PublicationError> {
    array(decoder, 2)?;
    let pointer = PortableCurrent {
        key: text(decoder)?,
        digest: digest(decoder)?,
    };
    validation::snapshot_key(&pointer.key)?;
    Ok(pointer)
}

fn write_pointer(pointer: &PortableCurrent, output: &mut Vec<u8>) -> Result<(), PublicationError> {
    validation::snapshot_key(&pointer.key)?;
    write_array(output, 2);
    write_text(output, &pointer.key);
    write_bytes(output, &pointer.digest);
    Ok(())
}

impl Record for PortableCurrent {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        map(decoder, 3)?;
        key(decoder, 1)?;
        let key_value = text(decoder)?;
        validation::snapshot_key(&key_value)?;
        key(decoder, 2)?;
        Ok(Self {
            key: key_value,
            digest: digest(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        header(output, 3);
        write_uint(output, 1);
        write_text(output, &self.key);
        write_uint(output, 2);
        write_bytes(output, &self.digest);
        Ok(())
    }
}

impl Record for PortableSnapshot {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        map(decoder, 5)?;
        key(decoder, 1)?;
        let revision = decoder.uint()?;
        key(decoder, 2)?;
        let origin = BackendBinding::read(decoder)?;
        key(decoder, 3)?;
        let count = decoder.array(decoder.remaining().len())?;
        let mut projection = Vec::new();
        for _ in 0..count {
            array(decoder, 2)?;
            projection.push(ProjectionEntry {
                key: text(decoder)?,
                value: optional(decoder, bytes)?,
            });
        }
        key(decoder, 4)?;
        let predecessor = optional(decoder, snapshot_pointer)?;
        let record = Self {
            revision,
            origin,
            projection,
            predecessor,
        };
        validation::snapshot(&record)?;
        Ok(record)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        validation::snapshot(self)?;
        header(output, 5);
        write_uint(output, 1);
        write_uint(output, self.revision);
        write_uint(output, 2);
        self.origin.write(output)?;
        write_uint(output, 3);
        write_array(output, self.projection.len());
        for row in &self.projection {
            write_array(output, 2);
            write_text(output, &row.key);
            write_optional(output, row.value.as_deref(), write_blob)?;
        }
        write_uint(output, 4);
        write_optional(output, self.predecessor.as_ref(), write_pointer)
    }
}

impl Record for PublicationState {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        let fields = decoder.map(8)?;
        if !matches!(fields, 7 | 8) {
            return Err(PublicationError::Schema);
        }
        key(decoder, 0)?;
        if decoder.uint()? != 1 {
            return Err(PublicationError::Schema);
        }
        key(decoder, 1)?;
        let revision = decoder.uint()?;
        key(decoder, 2)?;
        let loss_generation = decoder.uint()?;
        key(decoder, 3)?;
        let sources = sources(decoder)?;
        key(decoder, 4)?;
        let binding = BackendBinding::read(decoder)?;
        key(decoder, 5)?;
        let branches = history(decoder)?;
        key(decoder, 6)?;
        let guard = optional(decoder, digest)?;
        let burn_owners = if fields == 8 {
            key(decoder, 7)?;
            let count = decoder.array(decoder.remaining().len())?;
            // Counts can be backed by padding rather than complete typed rows.
            // Grow only after a whole canonical owner has been checked.
            let mut owners = Vec::new();
            for _ in 0..count {
                let start = decoder.position();
                decoder.skip_value(decoder.remaining().len())?;
                owners.push(
                    PermanentBurnOwner::decode(decoder.slice(start, decoder.position())?)
                        .map_err(|_| PublicationError::Schema)?,
                );
            }
            Some(owners)
        } else {
            None
        };
        let record = Self {
            revision,
            loss_generation,
            sources,
            binding,
            branches,
            guard,
            burn_owners,
        };
        validation::state(&record)?;
        Ok(record)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        validation::state(self)?;
        header(output, 7 + usize::from(self.burn_owners.is_some()));
        write_uint(output, 1);
        write_uint(output, self.revision);
        write_uint(output, 2);
        write_uint(output, self.loss_generation);
        write_uint(output, 3);
        write_sources(output, &self.sources)?;
        write_uint(output, 4);
        self.binding.write(output)?;
        write_uint(output, 5);
        write_history(output, &self.branches)?;
        write_uint(output, 6);
        write_optional(output, self.guard.as_ref(), write_digest)?;
        if let Some(owners) = &self.burn_owners {
            write_uint(output, 7);
            write_array(output, owners.len());
            for owner in owners {
                output.extend(owner.encode().map_err(|_| PublicationError::Schema)?);
            }
        }
        Ok(())
    }
}

impl Record for PublicationCurrent {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        map(decoder, 3)?;
        key(decoder, 1)?;
        let revision = decoder.uint()?;
        key(decoder, 2)?;
        Ok(Self {
            revision,
            digest: digest(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        header(output, 3);
        write_uint(output, 1);
        write_uint(output, self.revision);
        write_uint(output, 2);
        write_bytes(output, &self.digest);
        Ok(())
    }
}

impl Record for PublicationCommit {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        map(decoder, 5)?;
        key(decoder, 1)?;
        let revision = decoder.uint()?;
        key(decoder, 2)?;
        let predecessor = optional(decoder, digest)?;
        key(decoder, 3)?;
        let transaction_key = text(decoder)?;
        validation::transaction_key(&transaction_key)?;
        key(decoder, 4)?;
        let transaction_digest = digest(decoder)?;
        if (revision == 0) != predecessor.is_none() {
            return Err(PublicationError::Contradiction);
        }
        Ok(Self {
            revision,
            predecessor,
            transaction_key,
            transaction_digest,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        header(output, 5);
        write_uint(output, 1);
        write_uint(output, self.revision);
        write_uint(output, 2);
        write_optional(output, self.predecessor.as_ref(), write_digest)?;
        write_uint(output, 3);
        write_text(output, &self.transaction_key);
        write_uint(output, 4);
        write_bytes(output, &self.transaction_digest);
        Ok(())
    }
}

impl Record for PublicationProof {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        let count = decoder.array(5)?;
        let proof = match (decoder.uint()?, count) {
            (0, 1) => Self::Raw,
            (1, 2) => Self::Candidate(digest(decoder)?),
            (4, 2) => Self::Guard(digest(decoder)?),
            (3, 3) => Self::PermanentRetirement {
                authorization: decoder
                    .bytes(super::super::retirement::MAX_RECORD_BYTES)?
                    .to_vec(),
                carried: sources(decoder)?,
            },
            (2, 5) => {
                let fence_key = text(decoder)?;
                validation::fence_key(&fence_key)?;
                let fence_digest = digest(decoder)?;
                let count = decoder.array(decoder.remaining().len())?;
                let mut removed = Vec::new();
                for _ in 0..count {
                    array(decoder, 2)?;
                    removed.push(RemovedPack {
                        pack: digest(decoder)?,
                        index: digest(decoder)?,
                    });
                }
                let carried = sources(decoder)?;
                Self::Collection {
                    fence_key,
                    fence_digest,
                    removed,
                    carried,
                }
            }
            _ => return Err(PublicationError::Schema),
        };
        validation::proof(&proof)?;
        Ok(proof)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        validation::proof(self)?;
        match self {
            Self::Raw => {
                write_array(output, 1);
                write_uint(output, 0);
            }
            Self::Candidate(digest) | Self::Guard(digest) => {
                write_array(output, 2);
                write_uint(
                    output,
                    if matches!(self, Self::Candidate(_)) {
                        1
                    } else {
                        4
                    },
                );
                write_bytes(output, digest);
            }
            Self::PermanentRetirement {
                authorization,
                carried,
            } => {
                write_array(output, 3);
                write_uint(output, 3);
                write_bytes(output, authorization);
                write_sources(output, carried)?;
            }
            Self::Collection {
                fence_key,
                fence_digest,
                removed,
                carried,
            } => {
                write_array(output, 5);
                write_uint(output, 2);
                write_text(output, fence_key);
                write_bytes(output, fence_digest);
                write_array(output, removed.len());
                for row in removed {
                    write_array(output, 2);
                    write_bytes(output, &row.pack);
                    write_bytes(output, &row.index);
                }
                write_sources(output, carried)?;
            }
        }
        Ok(())
    }
}

fn embedded_state(decoder: &mut Decoder<'_>) -> Result<PublicationState, PublicationError> {
    PublicationState::decode(decoder.bytes(decoder.remaining().len())?)
}

fn write_state(state: &PublicationState, output: &mut Vec<u8>) -> Result<(), PublicationError> {
    write_bytes(output, &state.encode()?);
    Ok(())
}

fn slot(decoder: &mut Decoder<'_>) -> Result<PredecessorSlot, PublicationError> {
    array(decoder, 2)?;
    Ok(PredecessorSlot {
        revision: decoder.uint()?,
        digest: digest(decoder)?,
    })
}

fn write_slot(slot: &PredecessorSlot, output: &mut Vec<u8>) -> Result<(), PublicationError> {
    write_array(output, 2);
    write_uint(output, slot.revision);
    write_bytes(output, &slot.digest);
    Ok(())
}

impl Record for PublicationTransaction {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationError> {
        map(decoder, 8)?;
        key(decoder, 1)?;
        let nonce = digest(decoder)?;
        key(decoder, 2)?;
        let old = optional(decoder, embedded_state)?;
        key(decoder, 3)?;
        let new = embedded_state(decoder)?;
        key(decoder, 4)?;
        let count = decoder.array(decoder.remaining().len())?;
        let mut changes = Vec::new();
        for _ in 0..count {
            array(decoder, 3)?;
            changes.push(LogicalChange {
                key: text(decoder)?,
                expected: optional(decoder, bytes)?,
                new: optional(decoder, bytes)?,
            });
        }
        key(decoder, 5)?;
        let proof = PublicationProof::read(decoder)?;
        key(decoder, 6)?;
        let predecessor = optional(decoder, slot)?;
        key(decoder, 7)?;
        let snapshot = snapshot_pointer(decoder)?;
        let record = Self {
            nonce,
            old,
            new,
            changes,
            proof,
            predecessor,
            snapshot,
        };
        validation::transaction(&record)?;
        Ok(record)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), PublicationError> {
        validation::transaction(self)?;
        header(output, 8);
        write_uint(output, 1);
        write_bytes(output, &self.nonce);
        write_uint(output, 2);
        write_optional(output, self.old.as_ref(), write_state)?;
        write_uint(output, 3);
        write_state(&self.new, output)?;
        write_uint(output, 4);
        write_array(output, self.changes.len());
        for row in &self.changes {
            write_array(output, 3);
            write_text(output, &row.key);
            write_optional(output, row.expected.as_deref(), write_blob)?;
            write_optional(output, row.new.as_deref(), write_blob)?;
        }
        write_uint(output, 5);
        self.proof.write(output)?;
        write_uint(output, 6);
        write_optional(output, self.predecessor.as_ref(), write_slot)?;
        write_uint(output, 7);
        write_pointer(&self.snapshot, output)
    }
}

#[cfg(test)]
mod tests;
