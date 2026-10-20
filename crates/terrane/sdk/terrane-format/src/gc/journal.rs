//! Encodes exact physical incarnation journals and recoverable deletion intent.
//!
//! Physical ownership never grants current reachability or lease authority.
//! Opaque file identity bytes require actual backend descriptor comparison.
//! The types in this module preserve ordinary D-78 local-v1 bytes. Permanent
//! D-82 ownership and copied retirement use the separate retirement module.
//! Claimed elapsed bounds do not prove that any clock actually waited.
//!
//! ```text
//! CreationJournal = {0:1,1:key,2:nonce,3:state,?4:binding,?5:identity,?6:owner}
//! LocalDeleteOperation = {0:1,1:authorization,2:phase,3:revision,4:current-lease}
//! ```

use super::{GcError, GcLease, key};
use crate::bucket::Tombstone;
use crate::{
    cbor::{self, Decoder},
    identity::{Digest, IdentityKind, TERRANE_V1},
    pack_format,
};
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Binds exact canonical artifact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactBinding {
    /// Whole pack identity and size.
    Pack {
        /// Immutable digest.
        digest: Digest,
        /// Encoded size.
        size: u64,
    },
    /// Detached index identity and size.
    Index {
        /// Immutable digest.
        digest: Digest,
        /// Encoded size.
        size: u64,
    },
    /// Canonical tombstone bytes.
    Trash(Vec<u8>),
}

/// Identifies an exact physical artifact incarnation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactVersion {
    /// Registered artifact key.
    pub key: String,
    /// Secure fresh incarnation nonce.
    pub nonce: Digest,
    /// Canonical bytes binding.
    pub binding: ArtifactBinding,
    /// Untrusted opaque backend descriptor identity.
    pub file_identity: Vec<u8>,
}

/// Enforces the registered state-specific field combinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalState {
    /// Durable intent before physical creation.
    Pending,
    /// Durable current version, without an absolute creation timestamp.
    Committed {
        /// Exact binding.
        binding: ArtifactBinding,
        /// Untrusted backend identity.
        file_identity: Vec<u8>,
    },
    /// Exact physical ownership established by durable authorization.
    DeleteOwned {
        /// Exact binding.
        binding: ArtifactBinding,
        /// Untrusted backend identity.
        file_identity: Vec<u8>,
        /// Registered operation key.
        operation_key: String,
        /// Raw canonical authorization digest.
        authorization: Digest,
    },
    /// Invalidated by restore or recreation.
    Invalidated,
}

/// Stores protected evidence of one artifact incarnation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreationJournal {
    /// Exact registered artifact key.
    pub key: String,
    /// Secure incarnation nonce.
    pub nonce: Digest,
    /// State-specific fields.
    pub state: JournalState,
}

/// Represents immutable local-v1 physical intent before journal retirement.
///
/// Nonces, descriptor identities and elapsed bounds are untrusted claims until
/// independently qualified by the backend; encoding or decoding grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteAuthorization {
    /// Secure operation nonce.
    pub nonce: Digest,
    /// Active exclusion pack identifier.
    pub pack_id: [u8; 16],
    /// Active exclusion cycle.
    pub cycle: u64,
    /// Active exclusion epoch.
    pub epoch: u64,
    /// Original whole lease, not current effect authority.
    pub original_lease: GcLease,
    /// Exact D in whole seconds.
    pub deletion_seconds: u64,
    /// Exact versions in pack, index, trash order.
    pub artifacts: [ArtifactVersion; 3],
    /// Verified detached-index bytes retained for fresh reconciliation.
    pub index_witness: Vec<u8>,
    /// Already completed conservative elapsed lower bound in nanoseconds.
    pub elapsed_ns: u64,
}

/// Records monotone exact-operation progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeletePhase {
    /// Authorization durable before retirement.
    Authorized = 0,
    /// All owned journals durable.
    Invalidated = 1,
    /// Exact pack absence durably synchronized.
    PackAbsent = 2,
    /// Exact index absence durably synchronized.
    IndexAbsent = 3,
    /// Both containers confirmed absent by authoritative catalog.
    ContainersConfirmed = 4,
    /// Exact trash removed and synchronized.
    Done = 5,
    /// Ownership cancelled before restore or recreation.
    Cancelled = 6,
}

/// Represents local-v1 progress while preserving immutable physical intent.
///
/// The separately typed permanent-v2 operation never inherits this Done or
/// Cancelled behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteOperation {
    /// Immutable original authorization.
    pub authorization: DeleteAuthorization,
    /// Current durable phase.
    pub phase: DeletePhase,
    /// Conditional update revision.
    pub revision: u64,
    /// Whole current effect lease, checked independently by backend.
    pub current_lease: GcLease,
}

impl ArtifactBinding {
    fn write(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Pack { digest, size } | Self::Index { digest, size } => {
                cbor::write_array(bytes, 3);
                cbor::write_uint(bytes, u64::from(matches!(self, Self::Index { .. })));
                cbor::write_bytes(bytes, digest);
                cbor::write_uint(bytes, *size);
            }
            Self::Trash(tombstone) => {
                cbor::write_array(bytes, 2);
                cbor::write_uint(bytes, 2);
                cbor::write_bytes(bytes, tombstone);
            }
        }
    }

    fn read(decoder: &mut Decoder<'_>) -> Result<Self, GcError> {
        let count = decoder.array(3)?;
        match (decoder.uint()?, count) {
            (0, 3) => Ok(Self::Pack {
                digest: digest(decoder)?,
                size: decoder.uint()?,
            }),
            (1, 3) => Ok(Self::Index {
                digest: digest(decoder)?,
                size: decoder.uint()?,
            }),
            (2, 2) => {
                let bytes = decoder.bytes(128)?.to_vec();
                Tombstone::decode(&bytes).map_err(|_| GcError::Schema)?;
                Ok(Self::Trash(bytes))
            }
            _ => Err(GcError::Schema),
        }
    }
}

impl ArtifactVersion {
    fn write(&self, bytes: &mut Vec<u8>) {
        cbor::write_array(bytes, 4);
        cbor::write_text(bytes, &self.key);
        cbor::write_bytes(bytes, &self.nonce);
        self.binding.write(bytes);
        cbor::write_bytes(bytes, &self.file_identity);
    }

    fn read(decoder: &mut Decoder<'_>) -> Result<Self, GcError> {
        if decoder.array(4)? != 4 {
            return Err(GcError::Schema);
        }
        Ok(Self {
            key: {
                let value = decoder.text(59)?;
                artifact_key(value)?;
                String::from(value)
            },
            nonce: digest(decoder)?,
            binding: ArtifactBinding::read(decoder)?,
            file_identity: identity(decoder)?,
        })
    }
}

impl CreationJournal {
    /// Encodes canonical state-specific incarnation evidence.
    ///
    /// # Errors
    /// Rejects malformed artifact keys, bindings, identities or ownership keys.
    pub fn encode(&self) -> Result<Vec<u8>, GcError> {
        self.validate()?;

        let (state, count) = match self.state {
            JournalState::Pending => (0, 4),
            JournalState::Committed { .. } => (1, 6),
            JournalState::DeleteOwned { .. } => (2, 7),
            JournalState::Invalidated => (3, 4),
        };
        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, count);
        field(&mut bytes, 0, 1);
        cbor::write_uint(&mut bytes, 1);
        cbor::write_text(&mut bytes, &self.key);
        cbor::write_uint(&mut bytes, 2);
        cbor::write_bytes(&mut bytes, &self.nonce);
        field(&mut bytes, 3, state);
        match &self.state {
            JournalState::Committed {
                binding,
                file_identity,
            }
            | JournalState::DeleteOwned {
                binding,
                file_identity,
                ..
            } => {
                cbor::write_uint(&mut bytes, 4);
                binding.write(&mut bytes);
                cbor::write_uint(&mut bytes, 5);
                cbor::write_bytes(&mut bytes, file_identity);
            }
            _ => {}
        }
        if let JournalState::DeleteOwned {
            operation_key,
            authorization,
            ..
        } = &self.state
        {
            cbor::write_uint(&mut bytes, 6);
            cbor::write_array(&mut bytes, 2);
            cbor::write_text(&mut bytes, operation_key);
            cbor::write_bytes(&mut bytes, authorization);
        }
        Ok(bytes)
    }

    /// Decodes only exact registered canonical field combinations.
    ///
    /// # Errors
    /// Rejects noncanonical or trailing bytes and mismatched associations.
    pub fn decode(bytes: &[u8]) -> Result<Self, GcError> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder.map(7)?;
        key(&mut decoder, 0)?;
        if decoder.uint()? != 1 {
            return Err(GcError::Schema);
        }
        key(&mut decoder, 1)?;
        let name = decoder.text(59)?;
        artifact_key(name)?;
        let name = String::from(name);
        key(&mut decoder, 2)?;
        let nonce = digest(&mut decoder)?;
        key(&mut decoder, 3)?;
        let tag = decoder.uint()?;
        let state = match (tag, count) {
            (0, 4) => JournalState::Pending,
            (3, 4) => JournalState::Invalidated,
            (1, 6) | (2, 7) => {
                key(&mut decoder, 4)?;
                let binding = ArtifactBinding::read(&mut decoder)?;
                key(&mut decoder, 5)?;
                let file_identity = identity(&mut decoder)?;
                if tag == 1 {
                    JournalState::Committed {
                        binding,
                        file_identity,
                    }
                } else {
                    key(&mut decoder, 6)?;
                    if decoder.array(2)? != 2 {
                        return Err(GcError::Schema);
                    }
                    let operation_key = decoder.text(128)?;
                    operation_key_parts(operation_key)?;
                    let operation_key = String::from(operation_key);
                    let authorization = digest(&mut decoder)?;
                    JournalState::DeleteOwned {
                        binding,
                        file_identity,
                        operation_key,
                        authorization,
                    }
                }
            }
            _ => return Err(GcError::Schema),
        };
        decoder.finish()?;

        let value = Self {
            key: name,
            nonce,
            state,
        };
        value.validate()?;

        Ok(value)
    }

    fn validate(&self) -> Result<(), GcError> {
        let (kind, pack, cycle) = artifact_key(&self.key)?;
        match &self.state {
            JournalState::Committed {
                binding,
                file_identity,
            }
            | JournalState::DeleteOwned {
                binding,
                file_identity,
                ..
            } => {
                validate_binding(binding, kind, pack, cycle)?;
                if !(1..=128).contains(&file_identity.len()) {
                    return Err(GcError::Schema);
                }
            }
            _ => {}
        }
        if let JournalState::DeleteOwned { operation_key, .. } = &self.state {
            let (owner_cycle, owner_pack, _) = operation_key_parts(operation_key)?;
            if owner_pack != pack || cycle.is_some_and(|cycle| cycle != owner_cycle) {
                return Err(GcError::Schema);
            }
        }
        Ok(())
    }

    /// Constructs an owned-journal proposal from matching committed evidence.
    ///
    /// The proposal requires durable conditional publication and independent
    /// current backend authorization before any physical effect.
    ///
    /// # Errors
    /// Rejects noncommitted journals and changed or unrelated artifact versions.
    pub fn own(&self, authorization: &DeleteAuthorization) -> Result<Self, GcError> {
        authorization.validate()?;

        let version = authorization
            .artifacts
            .iter()
            .find(|version| version.key == self.key)
            .ok_or(GcError::Schema)?;
        let JournalState::Committed {
            binding,
            file_identity,
        } = &self.state
        else {
            return Err(GcError::Schema);
        };
        if self.nonce != version.nonce
            || *binding != version.binding
            || *file_identity != version.file_identity
        {
            return Err(GcError::Schema);
        }
        Ok(Self {
            key: self.key.clone(),
            nonce: self.nonce,
            state: JournalState::DeleteOwned {
                binding: binding.clone(),
                file_identity: file_identity.clone(),
                operation_key: authorization.operation_key(),
                authorization: authorization.digest()?,
            },
        })
    }
}

impl DeleteAuthorization {
    /// Returns the exact registered operation key.
    pub fn operation_key(&self) -> String {
        format!(
            "gc/{}/delete/{}/{}",
            self.cycle,
            hex(&self.pack_id),
            hex(&self.nonce)
        )
    }

    /// Encodes immutable canonical physical intent.
    ///
    /// # Errors
    /// Rejects artifact associations, invalid witness, inadequate wait or overflow.
    pub fn encode(&self) -> Result<Vec<u8>, GcError> {
        self.validate()?;

        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, 7);
        cbor::write_uint(&mut bytes, 0);
        cbor::write_bytes(&mut bytes, &self.nonce);
        cbor::write_uint(&mut bytes, 1);
        cbor::write_array(&mut bytes, 3);
        cbor::write_bytes(&mut bytes, &self.pack_id);
        cbor::write_uint(&mut bytes, self.cycle);
        cbor::write_uint(&mut bytes, self.epoch);
        cbor::write_uint(&mut bytes, 2);
        bytes.extend(self.original_lease.encode()?);
        field(&mut bytes, 3, self.deletion_seconds);
        cbor::write_uint(&mut bytes, 4);
        cbor::write_array(&mut bytes, 3);
        for artifact in &self.artifacts {
            artifact.write(&mut bytes);
        }
        cbor::write_uint(&mut bytes, 5);
        cbor::write_bytes(&mut bytes, &self.index_witness);
        field(&mut bytes, 6, self.elapsed_ns);
        Ok(bytes)
    }

    /// Returns raw BLAKE3 over exact canonical authorization bytes.
    ///
    /// # Errors
    /// Rejects invalid immutable authorization.
    pub fn digest(&self) -> Result<Digest, GcError> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }

    fn read(decoder: &mut Decoder<'_>) -> Result<Self, GcError> {
        if decoder.map(7)? != 7 {
            return Err(GcError::Schema);
        }
        key(decoder, 0)?;
        let nonce = digest(decoder)?;
        key(decoder, 1)?;
        if decoder.array(3)? != 3 {
            return Err(GcError::Schema);
        }
        let pack_id = decoder.bytes(16)?.try_into().map_err(|_| GcError::Schema)?;
        let cycle = decoder.uint()?;
        let epoch = decoder.uint()?;
        key(decoder, 2)?;
        let original_lease = lease(decoder)?;
        key(decoder, 3)?;
        let deletion_seconds = decoder.uint()?;
        key(decoder, 4)?;
        if decoder.array(3)? != 3 {
            return Err(GcError::Schema);
        }
        let artifacts = [
            ArtifactVersion::read(decoder)?,
            ArtifactVersion::read(decoder)?,
            ArtifactVersion::read(decoder)?,
        ];
        key(decoder, 5)?;
        let witness = decoder.bytes(decoder.remaining().len())?;
        key(decoder, 6)?;
        let elapsed_ns = decoder.uint()?;
        let mut value = Self {
            nonce,
            pack_id,
            cycle,
            epoch,
            original_lease,
            deletion_seconds,
            artifacts,
            index_witness: Vec::new(),
            elapsed_ns,
        };
        // Check exact index count, body bounds, identity and size associations
        // before retaining an owned copy of the untrusted witness.
        value.validate_with_witness(witness)?;
        value.index_witness = witness.to_vec();
        Ok(value)
    }

    fn validate(&self) -> Result<(), GcError> {
        self.validate_with_witness(&self.index_witness)
    }

    fn validate_with_witness(&self, witness: &[u8]) -> Result<(), GcError> {
        self.original_lease.encode()?;
        let required = self
            .deletion_seconds
            .checked_mul(1_000_000_000)
            .ok_or(GcError::Exhausted)?;
        if self.elapsed_ns < required {
            return Err(GcError::Window);
        }
        let pack = hex(&self.pack_id);
        let expected = [
            format!("objects/pack/{}/{}.pack", &pack[..2], pack),
            format!("objects/pack/{}/{}.idx", &pack[..2], pack),
            format!("trash/{}/{}", self.cycle, pack),
        ];
        for (kind, (version, expected)) in self.artifacts.iter().zip(expected).enumerate() {
            if version.key != expected || !(1..=128).contains(&version.file_identity.len()) {
                return Err(GcError::Schema);
            }
            validate_binding(&version.binding, kind as u8, self.pack_id, Some(self.cycle))?;
        }
        let (header, records) =
            pack_format::decode_detached_index(witness).map_err(|_| GcError::Schema)?;
        if *header.id() != self.pack_id {
            return Err(GcError::Schema);
        }
        let ArtifactBinding::Pack {
            size: pack_size, ..
        } = self.artifacts[0].binding
        else {
            return Err(GcError::Schema);
        };
        let body_end = pack_size
            .checked_sub(witness.len() as u64)
            .and_then(|size| size.checked_add(pack_format::HEADER_SIZE as u64))
            .and_then(|size| size.checked_sub(pack_format::FOOTER_SIZE as u64))
            .ok_or(GcError::Schema)?;
        if body_end < pack_format::HEADER_SIZE as u64
            || records.iter().any(|record| {
                record
                    .offset
                    .checked_add(u64::from(record.body_len))
                    .is_none_or(|end| end > body_end)
            })
        {
            return Err(GcError::Schema);
        }
        let ArtifactBinding::Index { digest, size } = self.artifacts[1].binding else {
            return Err(GcError::Schema);
        };
        let actual = TERRANE_V1
            .calculate(IdentityKind::Index, witness)
            .map_err(|_| GcError::Schema)?;
        if actual.terrane_v1_digest().map_err(|_| GcError::Schema)? != digest
            || size != witness.len() as u64
        {
            return Err(GcError::Schema);
        }
        let ArtifactBinding::Trash(bytes) = &self.artifacts[2].binding else {
            return Err(GcError::Schema);
        };
        if Tombstone::decode(bytes).map_err(|_| GcError::Schema)?.epoch != self.epoch {
            return Err(GcError::Schema);
        }
        Ok(())
    }
}

impl DeleteOperation {
    /// Encodes canonical conditional progress.
    ///
    /// # Errors
    /// Rejects invalid authorization or whole lease.
    pub fn encode(&self) -> Result<Vec<u8>, GcError> {
        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, 5);
        field(&mut bytes, 0, 1);
        cbor::write_uint(&mut bytes, 1);
        bytes.extend(self.authorization.encode()?);
        field(&mut bytes, 2, self.phase as u64);
        field(&mut bytes, 3, self.revision);
        cbor::write_uint(&mut bytes, 4);
        bytes.extend(self.current_lease.encode()?);
        Ok(bytes)
    }

    /// Decodes canonical progress bound to its exact registered operation key.
    ///
    /// # Errors
    /// Rejects malformed fields, phases, associations or mismatched operation key.
    pub fn decode(bytes: &[u8], operation_key: &str) -> Result<Self, GcError> {
        operation_key_parts(operation_key)?;
        let mut decoder = Decoder::new(bytes);
        if decoder.map(5)? != 5 {
            return Err(GcError::Schema);
        }
        key(&mut decoder, 0)?;
        if decoder.uint()? != 1 {
            return Err(GcError::Schema);
        }
        key(&mut decoder, 1)?;
        let authorization = DeleteAuthorization::read(&mut decoder)?;
        key(&mut decoder, 2)?;
        let phase = match decoder.uint()? {
            0 => DeletePhase::Authorized,
            1 => DeletePhase::Invalidated,
            2 => DeletePhase::PackAbsent,
            3 => DeletePhase::IndexAbsent,
            4 => DeletePhase::ContainersConfirmed,
            5 => DeletePhase::Done,
            6 => DeletePhase::Cancelled,
            _ => return Err(GcError::Schema),
        };
        key(&mut decoder, 3)?;
        let revision = decoder.uint()?;
        key(&mut decoder, 4)?;
        let current_lease = lease(&mut decoder)?;
        decoder.finish()?;
        authorization.validate()?;
        if authorization.operation_key() != operation_key {
            return Err(GcError::Schema);
        }
        Ok(Self {
            authorization,
            phase,
            revision,
            current_lease,
        })
    }

    /// Advances one phase or cancels without modifying physical authorization.
    ///
    /// This validates CAS intent, never external physical effects or current roots.
    ///
    /// # Errors
    /// Rejects skipped/terminal phases and revision overflow.
    pub fn advance(&self, phase: DeletePhase, current_lease: GcLease) -> Result<Self, GcError> {
        if matches!(self.phase, DeletePhase::Done | DeletePhase::Cancelled)
            || (phase != DeletePhase::Cancelled && phase as u8 != self.phase as u8 + 1)
        {
            return Err(GcError::Schema);
        }
        let value = Self {
            authorization: self.authorization.clone(),
            phase,
            revision: self.revision.checked_add(1).ok_or(GcError::Exhausted)?,
            current_lease,
        };
        value.encode()?;

        Ok(value)
    }
}

fn field(bytes: &mut Vec<u8>, key: u64, value: u64) {
    cbor::write_uint(bytes, key);
    cbor::write_uint(bytes, value);
}

fn digest(decoder: &mut Decoder<'_>) -> Result<Digest, GcError> {
    decoder.bytes(32)?.try_into().map_err(|_| GcError::Schema)
}

fn identity(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, GcError> {
    let value = decoder.bytes(128)?.to_vec();
    if value.is_empty() {
        return Err(GcError::Schema);
    }
    Ok(value)
}

fn lease(decoder: &mut Decoder<'_>) -> Result<GcLease, GcError> {
    let start = decoder.position();
    if decoder.map(3)? != 3 {
        return Err(GcError::Schema);
    }
    key(decoder, 1)?;
    decoder.text(decoder.remaining().len())?;
    key(decoder, 2)?;
    decoder.uint()?;
    key(decoder, 3)?;
    decoder.uint()?;
    GcLease::decode(decoder.slice(start, decoder.position())?)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn unhex<const N: usize>(value: &str) -> Result<[u8; N], GcError> {
    if value.len() != N * 2 {
        return Err(GcError::Schema);
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(GcError::Schema),
        };
        *out = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(bytes)
}

fn decimal(value: &str) -> Result<u64, GcError> {
    let parsed = value.parse::<u64>().map_err(|_| GcError::Schema)?;
    if parsed.to_string() != value {
        return Err(GcError::Schema);
    }
    Ok(parsed)
}

fn artifact_key(value: &str) -> Result<(u8, [u8; 16], Option<u64>), GcError> {
    let mut pieces = value.split('/');
    match pieces.next() {
        Some("objects") => {
            if pieces.next() != Some("pack") {
                return Err(GcError::Schema);
            }
            let prefix = pieces.next().ok_or(GcError::Schema)?;
            let file = pieces.next().ok_or(GcError::Schema)?;
            let (name, kind) = file
                .strip_suffix(".pack")
                .map(|name| (name, 0))
                .or_else(|| file.strip_suffix(".idx").map(|name| (name, 1)))
                .ok_or(GcError::Schema)?;
            let pack = unhex(name)?;
            if prefix != &name[..2] || pieces.next().is_some() {
                return Err(GcError::Schema);
            }
            Ok((kind, pack, None))
        }
        Some("trash") => {
            let cycle = decimal(pieces.next().ok_or(GcError::Schema)?)?;
            let pack = unhex(pieces.next().ok_or(GcError::Schema)?)?;
            if pieces.next().is_some() {
                return Err(GcError::Schema);
            }
            Ok((2, pack, Some(cycle)))
        }
        _ => Err(GcError::Schema),
    }
}

fn operation_key_parts(value: &str) -> Result<(u64, [u8; 16], Digest), GcError> {
    let mut pieces = value.split('/');
    if pieces.next() != Some("gc") {
        return Err(GcError::Schema);
    }
    let cycle = decimal(pieces.next().ok_or(GcError::Schema)?)?;
    if pieces.next() != Some("delete") {
        return Err(GcError::Schema);
    }
    let pack = unhex(pieces.next().ok_or(GcError::Schema)?)?;
    let nonce = unhex(pieces.next().ok_or(GcError::Schema)?)?;
    if pieces.next().is_some() {
        return Err(GcError::Schema);
    }
    Ok((cycle, pack, nonce))
}

fn validate_binding(
    binding: &ArtifactBinding,
    kind: u8,
    pack: [u8; 16],
    cycle: Option<u64>,
) -> Result<(), GcError> {
    match (binding, kind) {
        (ArtifactBinding::Pack { .. }, 0) | (ArtifactBinding::Index { .. }, 1) => Ok(()),
        (ArtifactBinding::Trash(bytes), 2) => {
            if bytes.is_empty() || bytes.len() > 128 {
                return Err(GcError::Schema);
            }
            let trash = Tombstone::decode(bytes).map_err(|_| GcError::Schema)?;
            if trash.pack_id != pack || cycle.is_some_and(|cycle| cycle != trash.cycle) {
                return Err(GcError::Schema);
            }
            Ok(())
        }
        _ => Err(GcError::Schema),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod golden_tests;
