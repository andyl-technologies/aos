//! Durable controller-owned publisher capability registry.
//!
//! The registry stores complete validated [`CapabilityRecord`] values in the
//! protected controller journal. Through this facade each capability ID is
//! immutable: an active record may become a tombstone, but neither state may be
//! replaced by a new record. Loading validates the materialized namespace before
//! any lookup is allowed. The trusted controller must make this facade the sole
//! writer of the namespace; generic journal writes do not enforce its history.
//!
//! This is an administrative persistence boundary. Its mutation methods are
//! intended only for an already-authenticated protected controller path. A
//! successful lookup does not authenticate a request, evaluate a capability,
//! establish revocation currentness, or create a publication completion permit.
//!
//! Namespace records use the binary key `"capability/" || capability_id` and
//! one strict canonical JSON value:
//!
//! ```text
//! {"version":1,"state":0,"capability":{...complete CapabilityRecord...}}
//! ```
//!
//! State `0` is active and state `1` is revoked. Both encodings have equal
//! length so a tombstone consumes no additional materialized-value allowance.
//! Journal append capacity for administrative maintenance remains an external
//! provisioning requirement; a revocation is never reported before its commit.

use std::io;

use aos_sandbox_core::{CapabilityId, CapabilityRecord};
use serde::{Deserialize, Serialize};

use crate::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};

const RECORD_VERSION_V1: u16 = 1;
const RECORD_FAMILY: &[u8] = b"capability/";
const RECORD_KEY_BYTES: usize = RECORD_FAMILY.len() + 16;
const MAXIMUM_ENTRIES: usize = 65_536;
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_MATERIALIZED_BYTES: usize = 512 * 1024 * 1024;

/// Bounds registry replay and per-mutation encoding work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherAuthorityLimits {
    maximum_entries: usize,
    maximum_record_bytes: usize,
    maximum_materialized_bytes: usize,
}

impl PublisherAuthorityLimits {
    /// Constructs limits within the fixed implementation ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError::InvalidLimits`] if any limit is zero
    /// or exceeds its implementation ceiling.
    pub fn new(
        maximum_entries: usize,
        maximum_record_bytes: usize,
        maximum_materialized_bytes: usize,
    ) -> Result<Self, PublisherAuthorityError> {
        if maximum_entries == 0
            || maximum_entries > MAXIMUM_ENTRIES
            || maximum_record_bytes == 0
            || maximum_record_bytes > MAXIMUM_RECORD_BYTES
            || maximum_materialized_bytes == 0
            || maximum_materialized_bytes > MAXIMUM_MATERIALIZED_BYTES
        {
            return Err(PublisherAuthorityError::InvalidLimits);
        }
        Ok(Self {
            maximum_entries,
            maximum_record_bytes,
            maximum_materialized_bytes,
        })
    }
}

impl Default for PublisherAuthorityLimits {
    fn default() -> Self {
        Self {
            maximum_entries: MAXIMUM_ENTRIES,
            maximum_record_bytes: MAXIMUM_RECORD_BYTES,
            maximum_materialized_bytes: MAXIMUM_MATERIALIZED_BYTES,
        }
    }
}

/// Provides exclusive, validated access to durable publisher capabilities.
pub struct PublisherCapabilityRegistry<'journal> {
    journal: &'journal mut Journal,
    limits: PublisherAuthorityLimits,
    entries: usize,
    materialized_bytes: usize,
}

impl<'journal> PublisherCapabilityRegistry<'journal> {
    /// Validates and borrows the complete durable publisher-authority namespace.
    ///
    /// The journal must have been opened through a protected opener. This scan
    /// validates every key and value before returning, while retaining only
    /// aggregate counters; subsequent lookups decode one directly indexed value.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] if the journal is unprotected or
    /// poisoned, limits are exceeded, or any retained key or value is malformed,
    /// unsupported, noncanonical, or bound to a different capability ID.
    pub fn load(
        journal: &'journal mut Journal,
        limits: PublisherAuthorityLimits,
    ) -> Result<Self, PublisherAuthorityError> {
        journal.ensure_protected_authority()?;
        let mut entries = 0_usize;
        let mut materialized_bytes = 0_usize;
        for (key, value) in journal.records(RecordNamespace::PublisherAuthority) {
            entries = entries
                .checked_add(1)
                .ok_or(PublisherAuthorityError::LimitExceeded("entry count"))?;
            if entries > limits.maximum_entries {
                return Err(PublisherAuthorityError::LimitExceeded("entry count"));
            }
            capability_id_from_key(key)?;
            if value.len() > limits.maximum_record_bytes {
                return Err(PublisherAuthorityError::LimitExceeded("record bytes"));
            }
            materialized_bytes = materialized_bytes
                .checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(PublisherAuthorityError::LimitExceeded("materialized bytes"))?;
            if materialized_bytes > limits.maximum_materialized_bytes {
                return Err(PublisherAuthorityError::LimitExceeded("materialized bytes"));
            }
            decode_record(key, value, limits.maximum_record_bytes)?;
        }

        Ok(Self {
            journal,
            limits,
            entries,
            materialized_bytes,
        })
    }

    /// Resolves one current active record by its immutable capability ID.
    ///
    /// Returned records are owned so no unvalidated journal bytes escape. The
    /// caller must still authenticate its request and call the capability's
    /// authorization API with controller-owned dynamic context.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError::UnknownCapability`] when no ID was
    /// installed, [`PublisherAuthorityError::Revoked`] for a tombstone, or a
    /// fail-closed journal/record error if current authority cannot be trusted.
    pub fn resolve_current(
        &self,
        id: CapabilityId,
    ) -> Result<CapabilityRecord, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let key = capability_key(id);
        let value = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let record = decode_record(&key, value, self.limits.maximum_record_bytes)?;
        match record.state {
            DurableCapabilityStateV1::Active => Ok(record.capability),
            DurableCapabilityStateV1::Revoked => Err(PublisherAuthorityError::Revoked),
        }
    }

    /// Durably installs one controller-issued capability under a fresh ID.
    ///
    /// The caller is the trusted administrative controller path and must have
    /// authenticated and authorized issuance before this call. Existing active
    /// records and tombstones are never replaced, including by identical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] for a zero or previously used ID,
    /// exceeded bounds, encoding failure, invalid transaction identity, or a
    /// journal durability failure. Ambiguous durability poisons subsequent reads.
    pub fn install_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        capability: CapabilityRecord,
    ) -> Result<CommitResult, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let id = capability.id();
        if id.as_bytes() == &[0; 16] {
            return Err(PublisherAuthorityError::UnspecifiedCapability);
        }
        let key = capability_key(id);
        if self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .is_some()
        {
            return Err(PublisherAuthorityError::CapabilityIdAlreadyUsed);
        }
        if self.entries >= self.limits.maximum_entries {
            return Err(PublisherAuthorityError::LimitExceeded("entry count"));
        }
        let value = encode_record(
            DurableCapabilityStateV1::Active,
            &capability,
            self.limits.maximum_record_bytes,
        )?;
        let next_materialized_bytes = self
            .materialized_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(PublisherAuthorityError::LimitExceeded("materialized bytes"))?;
        if next_materialized_bytes > self.limits.maximum_materialized_bytes {
            return Err(PublisherAuthorityError::LimitExceeded("materialized bytes"));
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherAuthority,
                key.to_vec(),
                value,
            )],
        )?;
        let result = self.journal.commit(&transaction)?;
        self.entries += 1;
        self.materialized_bytes = next_materialized_bytes;
        Ok(result)
    }

    /// Durably replaces one active capability with an irreversible tombstone.
    ///
    /// The tombstone retains the complete original claims for recovery and
    /// administrative audit, and this facade forbids rebinding the ID. This
    /// method performs no authorization itself; only the trusted administrative
    /// controller path may invoke it.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError::UnknownCapability`] for an unused ID,
    /// [`PublisherAuthorityError::Revoked`] for an existing tombstone, or
    /// another registry/journal error before reporting durable completion.
    pub fn revoke_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        id: CapabilityId,
    ) -> Result<CommitResult, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let key = capability_key(id);
        let current = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let current_length = current.len();
        let record = decode_record(&key, current, self.limits.maximum_record_bytes)?;
        if record.state == DurableCapabilityStateV1::Revoked {
            return Err(PublisherAuthorityError::Revoked);
        }
        let value = encode_record(
            DurableCapabilityStateV1::Revoked,
            &record.capability,
            self.limits.maximum_record_bytes,
        )?;
        let next_materialized_bytes = self
            .materialized_bytes
            .checked_sub(current_length)
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(PublisherAuthorityError::LimitExceeded("materialized bytes"))?;
        if next_materialized_bytes > self.limits.maximum_materialized_bytes {
            return Err(PublisherAuthorityError::LimitExceeded("materialized bytes"));
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherAuthority,
                key.to_vec(),
                value,
            )],
        )?;
        let result = self.journal.commit(&transaction)?;
        self.materialized_bytes = next_materialized_bytes;
        Ok(result)
    }
}

/// Reports a durable publisher capability registry failure.
#[derive(Debug, thiserror::Error)]
pub enum PublisherAuthorityError {
    /// Registry limits are zero or exceed fixed implementation ceilings.
    #[error("publisher authority registry limits are invalid")]
    InvalidLimits,
    /// A bounded registry dimension was exceeded.
    #[error("publisher authority registry limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// The protected record uses an unsupported version.
    #[error("unsupported publisher authority record version {0}")]
    UnsupportedVersion(u16),
    /// A protected record has malformed or noncanonical JSON.
    #[error("malformed publisher authority record")]
    MalformedRecord,
    /// A journal key is not the exact capability ID stored in its value.
    #[error("publisher authority record key does not match its capability ID")]
    CapabilityKeyMismatch,
    /// The reserved all-zero capability ID was supplied.
    #[error("publisher capability ID is unspecified")]
    UnspecifiedCapability,
    /// An immutable capability ID already has an active record or tombstone.
    #[error("publisher capability ID was already used")]
    CapabilityIdAlreadyUsed,
    /// No durable record exists for the requested capability ID.
    #[error("publisher capability is unknown")]
    UnknownCapability,
    /// The requested capability has a durable revocation tombstone.
    #[error("publisher capability is revoked")]
    Revoked,
    /// The underlying protected journal failed or became unsafe to read.
    #[error("publisher authority journal failed: {0}")]
    Journal(#[from] JournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableCapabilityStateV1 {
    Active,
    Revoked,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct DurableCapabilityRecordWireV1 {
    version: u16,
    state: u8,
    capability: CapabilityRecord,
}

struct DecodedCapabilityRecordV1 {
    state: DurableCapabilityStateV1,
    capability: CapabilityRecord,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DurableCapabilityRecordRefV1<'a> {
    version: u16,
    state: u8,
    capability: &'a CapabilityRecord,
}

fn capability_key(id: CapabilityId) -> [u8; RECORD_KEY_BYTES] {
    let mut key = [0_u8; RECORD_KEY_BYTES];
    key[..RECORD_FAMILY.len()].copy_from_slice(RECORD_FAMILY);
    key[RECORD_FAMILY.len()..].copy_from_slice(id.as_bytes());
    key
}

fn capability_id_from_key(key: &[u8]) -> Result<CapabilityId, PublisherAuthorityError> {
    if key.len() != RECORD_KEY_BYTES || !key.starts_with(RECORD_FAMILY) {
        return Err(PublisherAuthorityError::MalformedRecord);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&key[RECORD_FAMILY.len()..]);
    if bytes == [0; 16] {
        return Err(PublisherAuthorityError::MalformedRecord);
    }
    Ok(CapabilityId::from_bytes(bytes))
}

fn decode_record(
    key: &[u8],
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<DecodedCapabilityRecordV1, PublisherAuthorityError> {
    let key_id = capability_id_from_key(key)?;
    if bytes.len() > maximum_bytes {
        return Err(PublisherAuthorityError::LimitExceeded("record bytes"));
    }
    let decoded: DurableCapabilityRecordWireV1 =
        serde_json::from_slice(bytes).map_err(|_| PublisherAuthorityError::MalformedRecord)?;
    if decoded.version != RECORD_VERSION_V1 {
        return Err(PublisherAuthorityError::UnsupportedVersion(decoded.version));
    }
    let state = match decoded.state {
        0 => DurableCapabilityStateV1::Active,
        1 => DurableCapabilityStateV1::Revoked,
        _ => return Err(PublisherAuthorityError::MalformedRecord),
    };
    if decoded.capability.id() != key_id {
        return Err(PublisherAuthorityError::CapabilityKeyMismatch);
    }
    let canonical = encode_record(state, &decoded.capability, maximum_bytes)?;
    if canonical != bytes {
        return Err(PublisherAuthorityError::MalformedRecord);
    }
    Ok(DecodedCapabilityRecordV1 {
        state,
        capability: decoded.capability,
    })
}

fn encode_record(
    state: DurableCapabilityStateV1,
    capability: &CapabilityRecord,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PublisherAuthorityError> {
    let record = DurableCapabilityRecordRefV1 {
        version: RECORD_VERSION_V1,
        state: state.wire_value(),
        capability,
    };
    let mut writer = BoundedWriter::new(maximum_bytes);
    if serde_json::to_writer(&mut writer, &record).is_err() {
        return if writer.exceeded {
            Err(PublisherAuthorityError::LimitExceeded("record bytes"))
        } else {
            Err(PublisherAuthorityError::MalformedRecord)
        };
    }
    Ok(writer.bytes)
}

impl DurableCapabilityStateV1 {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Revoked => 1,
        }
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum_bytes: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum_bytes.min(8 * 1024)),
            maximum_bytes,
            exceeded: false,
        }
    }
}

impl io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next_length) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("publisher authority record is too large"));
        };
        if next_length > self.maximum_bytes {
            self.exceeded = true;
            return Err(io::Error::other("publisher authority record is too large"));
        }
        if next_length > self.bytes.capacity() {
            let target_capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(next_length)
                .min(self.maximum_bytes);
            self.bytes
                .try_reserve_exact(target_capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use aos_sandbox_core::{
        AuditId, CapabilityDraft, ChannelBinding, DelegationLimits, Grant, GrantId, ObjectDigest,
        Operation, OperationSet, PrincipalId, ProjectId, ResourceDimension, ResourceId,
        ResourceKind, ResourceVector, Revision, RevocationScopeId, Selector,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::JournalLimits;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-publisher-authority-{label}-{}-{}",
                std::process::id(),
                CapabilityId::new()
            ));
            fs::create_dir(&path).unwrap_or_else(|error| panic!("create test directory: {error}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("protect test directory: {error}"));
            Self(path)
        }

        fn open(&self) -> Journal {
            let uid = fs::metadata(&self.0)
                .unwrap_or_else(|error| panic!("stat test directory: {error}"))
                .uid();
            Journal::open_protected_at_uid(
                &self.0,
                "authority.journal",
                JournalLimits::default(),
                uid,
            )
            .map(|(journal, _)| journal)
            .unwrap_or_else(|error| panic!("open protected test journal: {error}"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn capability(id: CapabilityId, expires_at: i64) -> CapabilityRecord {
        let grant = Grant::new(
            GrantId::from_bytes([2; 16]),
            ResourceKind::CachePublish,
            OperationSet::one(Operation::Publish),
            Selector::Resource {
                resource: ResourceId::from_bytes([3; 16]),
            },
            false,
        )
        .unwrap_or_else(|error| panic!("create test grant: {error}"));
        CapabilityRecord::issue(CapabilityDraft {
            id,
            issuer: PrincipalId::from_bytes([4; 16]),
            audience: PrincipalId::from_bytes([5; 16]),
            holder: PrincipalId::from_bytes([6; 16]),
            channel_binding: ChannelBinding::new([7; 32]),
            root_subject: PrincipalId::from_bytes([8; 16]),
            project: ProjectId::from_bytes([9; 16]),
            sandbox: None,
            incarnation: None,
            grants: vec![grant],
            policy_digest: ObjectDigest::from_bytes([10; 32]),
            assignment_epoch: None,
            not_before: 100,
            expires_at,
            revocation_scope: RevocationScopeId::from_bytes([11; 16]),
            revocation_generation: Revision::new(12),
            delegation: DelegationLimits::new(
                0,
                0,
                ResourceVector::ZERO.with(ResourceDimension::StorageBytes, 4096),
            ),
            parent_decision: AuditId::from_bytes([13; 16]),
        })
        .unwrap_or_else(|error| panic!("issue test capability: {error}"))
    }

    fn put_raw(journal: &mut Journal, transaction: u8, key: Vec<u8>, value: Vec<u8>) {
        let transaction = JournalTransaction::new(
            [transaction; 16],
            vec![JournalRecord::put(
                RecordNamespace::PublisherAuthority,
                key,
                value,
            )],
        )
        .unwrap_or_else(|error| panic!("create raw transaction: {error}"));
        journal
            .commit(&transaction)
            .unwrap_or_else(|error| panic!("commit raw transaction: {error}"));
    }

    fn reopen(path: &Path) -> Journal {
        let uid = fs::metadata(path)
            .unwrap_or_else(|error| panic!("stat test directory: {error}"))
            .uid();
        Journal::open_protected_at_uid(path, "authority.journal", JournalLimits::default(), uid)
            .map(|(journal, _)| journal)
            .unwrap_or_else(|error| panic!("reopen protected test journal: {error}"))
    }

    #[test]
    fn install_lookup_restart_and_id_collision_are_fail_closed() {
        let directory = TestDirectory::new("install");
        let mut journal = directory.open();
        let id = CapabilityId::from_bytes([1; 16]);
        let original = capability(id, 200);
        {
            let mut registry = PublisherCapabilityRegistry::load(
                &mut journal,
                PublisherAuthorityLimits::default(),
            )
            .unwrap_or_else(|error| panic!("load empty registry: {error}"));
            registry
                .install_from_trusted_controller([1; 16], original.clone())
                .unwrap_or_else(|error| panic!("install capability: {error}"));
            assert_eq!(
                registry
                    .resolve_current(id)
                    .unwrap_or_else(|error| panic!("resolve installed capability: {error}")),
                original
            );
            assert!(matches!(
                registry.install_from_trusted_controller([2; 16], original.clone()),
                Err(PublisherAuthorityError::CapabilityIdAlreadyUsed)
            ));
            assert!(matches!(
                registry.install_from_trusted_controller([3; 16], capability(id, 201)),
                Err(PublisherAuthorityError::CapabilityIdAlreadyUsed)
            ));
        }
        drop(journal);

        let mut reopened = reopen(&directory.0);
        let registry =
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default())
                .unwrap_or_else(|error| panic!("reload registry: {error}"));
        assert_eq!(
            registry
                .resolve_current(id)
                .unwrap_or_else(|error| panic!("resolve reloaded capability: {error}")),
            original
        );
    }

    #[test]
    fn revocation_tombstone_survives_restart_and_compaction() {
        let directory = TestDirectory::new("revoke");
        let mut journal = directory.open();
        let id = CapabilityId::from_bytes([14; 16]);
        let original = capability(id, 200);
        let encoded = encode_record(
            DurableCapabilityStateV1::Active,
            &original,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode exact-limit record: {error}"));
        let exact_limits =
            PublisherAuthorityLimits::new(1, encoded.len(), RECORD_KEY_BYTES + encoded.len())
                .unwrap_or_else(|error| panic!("construct exact limits: {error}"));
        {
            let mut registry = PublisherCapabilityRegistry::load(&mut journal, exact_limits)
                .unwrap_or_else(|error| panic!("load empty registry: {error}"));
            registry
                .install_from_trusted_controller([1; 16], original.clone())
                .unwrap_or_else(|error| panic!("install capability: {error}"));
            registry
                .revoke_from_trusted_controller([2; 16], id)
                .unwrap_or_else(|error| panic!("revoke capability: {error}"));
            assert!(matches!(
                registry.resolve_current(id),
                Err(PublisherAuthorityError::Revoked)
            ));
            assert!(matches!(
                registry.revoke_from_trusted_controller([3; 16], id),
                Err(PublisherAuthorityError::Revoked)
            ));
            assert!(matches!(
                registry.install_from_trusted_controller([4; 16], original),
                Err(PublisherAuthorityError::CapabilityIdAlreadyUsed)
            ));
        }
        journal
            .compact()
            .unwrap_or_else(|error| panic!("compact authority journal: {error}"));
        drop(journal);

        let mut reopened = reopen(&directory.0);
        let registry =
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default())
                .unwrap_or_else(|error| panic!("reload compacted registry: {error}"));
        assert!(matches!(
            registry.resolve_current(id),
            Err(PublisherAuthorityError::Revoked)
        ));
    }

    #[test]
    fn strict_record_validation_rejects_substitution_and_noncanonical_bytes() {
        let id = CapabilityId::from_bytes([15; 16]);
        let record = capability(id, 200);
        let canonical = encode_record(
            DurableCapabilityStateV1::Active,
            &record,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode test record: {error}"));
        assert!(canonical.starts_with(b"{\"version\":1,\"state\":0,\"capability\":"));
        assert_eq!(canonical.len(), 1_068);
        assert_eq!(
            format!("{:x}", Sha256::digest(&canonical)),
            "a7eb0f1c0e6306a04252c17046788aa1680081b4405fea31f8791c629982e331"
        );

        let mut duplicate = b"{\"version\":1,".to_vec();
        duplicate.extend_from_slice(&canonical[1..]);
        assert!(matches!(
            decode_record(&capability_key(id), &duplicate, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let capability_field = canonical
            .windows(b",\"capability\":".len())
            .position(|window| window == b",\"capability\":")
            .unwrap_or_else(|| panic!("capability field absent"));
        let mut reordered = b"{\"state\":0,\"version\":1".to_vec();
        reordered.extend_from_slice(&canonical[capability_field..]);
        assert!(matches!(
            decode_record(&capability_key(id), &reordered, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let mut unknown_version = canonical.clone();
        let position = unknown_version
            .windows(b"\"version\":1".len())
            .position(|window| window == b"\"version\":1")
            .unwrap_or_else(|| panic!("version field absent"));
        unknown_version[position + b"\"version\":".len()] = b'2';
        assert!(matches!(
            decode_record(&capability_key(id), &unknown_version, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::UnsupportedVersion(2))
        ));

        let mut unknown_state = canonical.clone();
        let position = unknown_state
            .windows(b"\"state\":0".len())
            .position(|window| window == b"\"state\":0")
            .unwrap_or_else(|| panic!("state field absent"));
        unknown_state[position + b"\"state\":".len()] = b'2';
        assert!(matches!(
            decode_record(&capability_key(id), &unknown_state, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let mut unknown_field = b"{\"extra\":1,".to_vec();
        unknown_field.extend_from_slice(&canonical[1..]);
        for malformed in [unknown_field, [canonical.clone(), b"\n".to_vec()].concat()] {
            assert!(matches!(
                decode_record(&capability_key(id), &malformed, MAXIMUM_RECORD_BYTES),
                Err(PublisherAuthorityError::MalformedRecord)
            ));
        }
        assert!(matches!(
            decode_record(
                &capability_key(CapabilityId::from_bytes([16; 16])),
                &canonical,
                MAXIMUM_RECORD_BYTES,
            ),
            Err(PublisherAuthorityError::CapabilityKeyMismatch)
        ));
        assert!(matches!(
            decode_record(b"capability/short", &canonical, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let mut invalid_capability = canonical.clone();
        let expiry = invalid_capability
            .windows(b"\"expires_at\":200".len())
            .position(|window| window == b"\"expires_at\":200")
            .unwrap_or_else(|| panic!("expiry field absent"));
        let digits = expiry + b"\"expires_at\":".len();
        invalid_capability[digits..digits + 3].copy_from_slice(b"100");
        assert!(matches!(
            decode_record(
                &capability_key(id),
                &invalid_capability,
                MAXIMUM_RECORD_BYTES,
            ),
            Err(PublisherAuthorityError::MalformedRecord)
        ));
    }

    #[test]
    fn replay_rejects_malformed_and_zero_id_records_for_the_entire_facade() {
        let directory = TestDirectory::new("malformed-replay");
        let mut journal = directory.open();
        put_raw(
            &mut journal,
            1,
            capability_key(CapabilityId::from_bytes([17; 16])).to_vec(),
            b"{}".to_vec(),
        );
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default(),),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let zero_directory = TestDirectory::new("zero-replay");
        let mut zero_journal = zero_directory.open();
        let zero = capability(CapabilityId::from_bytes([0; 16]), 200);
        let value = encode_record(
            DurableCapabilityStateV1::Active,
            &zero,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode zero-ID record: {error}"));
        put_raw(
            &mut zero_journal,
            1,
            capability_key(zero.id()).to_vec(),
            value,
        );
        assert!(matches!(
            PublisherCapabilityRegistry::load(
                &mut zero_journal,
                PublisherAuthorityLimits::default(),
            ),
            Err(PublisherAuthorityError::MalformedRecord)
        ));
    }

    #[test]
    fn encoding_and_replay_limits_apply_before_registry_acceptance() {
        let directory = TestDirectory::new("limits");
        let mut journal = directory.open();
        let id = CapabilityId::from_bytes([18; 16]);
        let record = capability(id, 200);
        let encoded = encode_record(
            DurableCapabilityStateV1::Active,
            &record,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode test record: {error}"));
        let limits =
            PublisherAuthorityLimits::new(1, encoded.len() - 1, MAXIMUM_MATERIALIZED_BYTES)
                .unwrap_or_else(|error| panic!("construct test limits: {error}"));
        {
            let mut registry = PublisherCapabilityRegistry::load(&mut journal, limits)
                .unwrap_or_else(|error| panic!("load empty limited registry: {error}"));
            assert!(matches!(
                registry.install_from_trusted_controller([1; 16], record),
                Err(PublisherAuthorityError::LimitExceeded("record bytes"))
            ));
            assert!(matches!(
                registry.resolve_current(id),
                Err(PublisherAuthorityError::UnknownCapability)
            ));
        }

        put_raw(
            &mut journal,
            2,
            capability_key(id).to_vec(),
            encoded.clone(),
        );
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, limits),
            Err(PublisherAuthorityError::LimitExceeded("record bytes"))
        ));
        let aggregate_limits =
            PublisherAuthorityLimits::new(1, encoded.len(), RECORD_KEY_BYTES + encoded.len() - 1)
                .unwrap_or_else(|error| panic!("construct aggregate limits: {error}"));
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, aggregate_limits),
            Err(PublisherAuthorityError::LimitExceeded("materialized bytes"))
        ));

        let second_id = CapabilityId::from_bytes([19; 16]);
        let second = capability(second_id, 200);
        let second_value = encode_record(
            DurableCapabilityStateV1::Active,
            &second,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode second test record: {error}"));
        put_raw(
            &mut journal,
            3,
            capability_key(second_id).to_vec(),
            second_value,
        );
        let count_limits =
            PublisherAuthorityLimits::new(1, MAXIMUM_RECORD_BYTES, MAXIMUM_MATERIALIZED_BYTES)
                .unwrap_or_else(|error| panic!("construct count limits: {error}"));
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, count_limits),
            Err(PublisherAuthorityError::LimitExceeded("entry count"))
        ));
    }

    #[test]
    fn zero_id_install_is_rejected_before_any_durable_mutation() {
        let directory = TestDirectory::new("zero-install");
        let mut journal = directory.open();
        let sequence = journal.snapshot_sequence();
        let zero = capability(CapabilityId::from_bytes([0; 16]), 200);
        let mut registry =
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default())
                .unwrap_or_else(|error| panic!("load empty registry: {error}"));
        assert!(matches!(
            registry.install_from_trusted_controller([1; 16], zero),
            Err(PublisherAuthorityError::UnspecifiedCapability)
        ));
        assert_eq!(registry.journal.snapshot_sequence(), sequence);
    }
}
