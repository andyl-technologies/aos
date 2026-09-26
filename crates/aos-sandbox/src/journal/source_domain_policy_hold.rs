//! Source-domain-wide custody for one closed policy-binding proposal.
//!
//! ```text
//! AOSSDH01 | version=1 | phase=held|released | reserved[5]=0 |
//! operation[16] | sandbox[16] | controller-source[32] | ancestry[32] |
//! binding[32] | epoch[8] | SHA-256[32]
//! ```
//!
//! The one protected source-domain journal owns hierarchy, environment, Git,
//! and lifecycle records. This hold freezes all of their writes after process
//! death, but grants no publication or effect authority.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const KEY: &[u8] = b"\0aos-source-domain-policy-hold-v1\0";
const MAGIC: &[u8; 8] = b"AOSSDH01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.source-domain-policy-hold.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-domain-policy-hold-transaction.v1\0";
const RECORD_BYTES: usize = 184;
const JOURNAL_NAME: &str = "source-domains-v1.journal";

/// Identifies one exact, nonauthorizing source-domain policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDomainPolicyHoldV1 {
    operation: OperationId,
    sandbox: SandboxId,
    controller_source: ObjectDigest,
    ancestry: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
    held: bool,
}

impl SourceDomainPolicyHoldV1 {
    /// Constructs custody for the exact ancestry used in a closed proposal.
    ///
    /// # Errors
    ///
    /// Rejects a zero identity, commitment, or epoch.
    pub fn new(
        operation: OperationId,
        sandbox: SandboxId,
        controller_source: ObjectDigest,
        ancestry: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, JournalError> {
        let hold = Self {
            operation,
            sandbox,
            controller_source,
            ancestry,
            binding,
            epoch,
            held: true,
        };
        hold.validate()?;
        Ok(hold)
    }

    /// Returns the accepted Create operation fixed by this hold.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the accepted Create sandbox fixed by this hold.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the Controller source commitment observed under its writer.
    #[must_use]
    pub const fn controller_source(self) -> ObjectDigest {
        self.controller_source
    }

    /// Returns the exact hierarchy ancestry head held for this Create.
    #[must_use]
    pub const fn ancestry(self) -> ObjectDigest {
        self.ancestry
    }

    /// Returns the root binding digest fixed before Q04 submission.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root handoff epoch fixed before Q04 submission.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether source-domain writers remain frozen.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    /// Returns the digest of the exact canonical held or released record.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Source hold.
    pub fn record_digest(self) -> Result<ObjectDigest, JournalError> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    fn validate(self) -> Result<(), JournalError> {
        if self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.controller_source.as_bytes() == &[0; 32]
            || self.ancestry.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn encode(self) -> Result<[u8; RECORD_BYTES], JournalError> {
        self.validate()?;
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = if self.held { 1 } else { 2 };
        bytes[16..32].copy_from_slice(self.operation.as_bytes());
        bytes[32..48].copy_from_slice(self.sandbox.as_bytes());
        bytes[48..80].copy_from_slice(self.controller_source.as_bytes());
        bytes[80..112].copy_from_slice(self.ancestry.as_bytes());
        bytes[112..144].copy_from_slice(self.binding.as_bytes());
        bytes[144..152].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..152])
            .finalize();
        bytes[152..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let hold = Self {
            operation: OperationId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            sandbox: SandboxId::from_bytes(
                bytes[32..48]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            controller_source: ObjectDigest::from_bytes(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            ancestry: ObjectDigest::from_bytes(
                bytes[80..112]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[112..144]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[144..152]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            held: bytes[10] == 1,
        };
        if hold.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(hold)
    }
}

fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<SourceDomainPolicyHoldV1>, JournalError> {
    let mut records = state
        .range((RecordNamespace::SourceDomainPolicyHold, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::SourceDomainPolicyHold);
    let record = records.next();
    if records.next().is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    match record {
        Some(((_, key), value)) if key.as_slice() == KEY => {
            SourceDomainPolicyHoldV1::decode(value).map(Some)
        }
        Some(_) => Err(JournalError::ProtectedBoundary),
        None => Ok(None),
    }
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if current(state)?.is_some_and(SourceDomainPolicyHoldV1::is_held)
        || transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::SourceDomainPolicyHold)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if current(state)?.is_some_and(SourceDomainPolicyHoldV1::is_held) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn transaction(hold: SourceDomainPolicyHoldV1) -> Result<JournalTransaction, JournalError> {
    let bytes = hold.encode()?;
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::SourceDomainPolicyHold,
            KEY.to_vec(),
            bytes.to_vec(),
        )],
    )
}

pub(super) fn release_transaction(
    expected: SourceDomainPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    if !expected.is_held() {
        return Err(JournalError::ProtectedBoundary);
    }
    transaction(SourceDomainPolicyHoldV1 {
        held: false,
        ..expected
    })
}

pub(super) fn ensure_source_domain(journal: &Journal) -> Result<(), JournalError> {
    journal.ensure_protected_authority()?;
    if journal
        .protected
        .as_ref()
        .map(|location| location.name.as_str())
        != Some(JOURNAL_NAME)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl Journal {
    /// Durably freezes the fixed source-domain writer before Q04 submission.
    ///
    /// The exact held record survives transport loss or process death. Its
    /// release needs privileged root cold readback and a held Controller writer.
    ///
    /// # Errors
    ///
    /// Rejects non-source storage, an existing hold, a non-held candidate,
    /// invalid fields, or insufficient capacity for eventual exact release.
    pub(crate) fn acquire_source_domain_policy_hold_v1(
        &mut self,
        hold: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_source_domain(self)?;
        if !hold.held || current(&self.state)?.is_some_and(SourceDomainPolicyHoldV1::is_held) {
            return Err(JournalError::ProtectedBoundary);
        }
        let acquire = transaction(hold)?;
        let release = transaction(SourceDomainPolicyHoldV1 {
            held: false,
            ..hold
        })?;
        // No ordinary source-domain commit can race after acquisition.
        self.preflight_transactions_with_capacity_scope(
            &[acquire.clone(), release],
            None,
            false,
            true,
        )?;
        self.commit_with_capacity_scope(&acquire, None, false, true, false)?;
        if current(&self.state)? != Some(hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads exact source-domain custody under its protected writer.
    ///
    /// # Errors
    ///
    /// Rejects non-source storage or malformed custody.
    pub(crate) fn source_domain_policy_hold_v1(
        &self,
    ) -> Result<Option<SourceDomainPolicyHoldV1>, JournalError> {
        ensure_source_domain(self)?;
        current(&self.state)
    }

    pub(crate) fn release_source_domain_policy_hold_after_root_readback_v1(
        &mut self,
        expected: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_source_domain(self)?;
        if !expected.held || current(&self.state)? != Some(expected) {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = SourceDomainPolicyHoldV1 {
            held: false,
            ..expected
        };
        let transaction = transaction(released)?;
        self.commit_with_capacity_scope(&transaction, None, false, true, false)?;
        if current(&self.state)? != Some(released) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    use super::*;
    use crate::hierarchy::protected_journal::HierarchyProtectedJournalOwnerV1;
    use crate::journal::JournalLimits;
    use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-source-domain-policy-hold-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).expect("test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protected directory mode");
            Self(path)
        }

        fn open(&self) -> Journal {
            let uid = fs::metadata(&self.0).expect("directory metadata").uid();
            Journal::open_protected_at_uid(&self.0, JOURNAL_NAME, JournalLimits::default(), uid)
                .expect("protected source-domain reopen")
                .0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hold() -> SourceDomainPolicyHoldV1 {
        SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            7,
        )
        .expect("valid source-domain hold")
    }

    fn ordinary_transaction(namespace: RecordNamespace, id: u8) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                namespace,
                b"ordinary".to_vec(),
                b"value".to_vec(),
            )],
        )
        .expect("ordinary transaction")
    }

    #[test]
    fn lost_reply_freezes_all_source_domain_writers_after_reopen() {
        let directory = TestDirectory::new();
        let mut source_domains = directory.open();
        let expected = hold();
        assert!(
            source_domains
                .acquire_source_domain_policy_hold_v1(SourceDomainPolicyHoldV1 {
                    held: false,
                    ..expected
                })
                .is_err()
        );
        source_domains
            .acquire_source_domain_policy_hold_v1(expected)
            .expect("durable source-domain hold before root submit");
        drop(source_domains);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.source_domain_policy_hold_v1().unwrap(),
            Some(expected)
        );
        for (index, namespace) in [
            RecordNamespace::DesiredState,
            RecordNamespace::Operation,
            RecordNamespace::Effect,
            RecordNamespace::PublisherPolicy,
        ]
        .into_iter()
        .enumerate()
        {
            let transaction = ordinary_transaction(namespace, index as u8 + 10);
            assert!(matches!(
                reopened.commit(&transaction),
                Err(JournalError::ProtectedBoundary)
            ));
            assert!(matches!(
                reopened.preflight_transactions(&[transaction]),
                Err(JournalError::ProtectedBoundary)
            ));
        }
        assert!(matches!(
            reopened.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(
            reopened
                .acquire_source_domain_policy_hold_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn exact_cold_release_restores_writes_and_wrong_binding_does_not() {
        let directory = TestDirectory::new();
        let expected = hold();
        directory
            .open()
            .acquire_source_domain_policy_hold_v1(expected)
            .unwrap();

        let mut reopened = directory.open();
        let wrong_binding = SourceDomainPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([6; 32]),
            ..expected
        };
        assert!(
            reopened
                .release_source_domain_policy_hold_after_root_readback_v1(wrong_binding)
                .is_err()
        );
        assert!(
            reopened
                .commit(&ordinary_transaction(RecordNamespace::DesiredState, 9))
                .is_err()
        );
        reopened
            .release_source_domain_policy_hold_after_root_readback_v1(expected)
            .expect("exact root readback checked by caller");
        assert!(
            !reopened
                .source_domain_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
        reopened
            .commit(&ordinary_transaction(RecordNamespace::DesiredState, 9))
            .expect("source-domain writes restored");
    }

    #[test]
    fn format_rejects_noncanonical_or_corrupt_custody() {
        let expected = hold();
        let mut bytes = expected.encode().unwrap();
        assert_eq!(SourceDomainPolicyHoldV1::decode(&bytes).unwrap(), expected);
        bytes[11] = 1;
        assert!(SourceDomainPolicyHoldV1::decode(&bytes).is_err());
        bytes = expected.encode().unwrap();
        bytes[183] ^= 1;
        assert!(SourceDomainPolicyHoldV1::decode(&bytes).is_err());
    }

    #[test]
    fn acquisition_reserves_capacity_for_cold_release() {
        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits {
            maximum_transactions: 1,
            ..JournalLimits::default()
        };
        let (mut journal, _) =
            Journal::open_protected_at_uid(&directory.0, JOURNAL_NAME, limits, uid).unwrap();
        assert!(
            journal
                .acquire_source_domain_policy_hold_v1(hold())
                .is_err()
        );
        assert_eq!(journal.source_domain_policy_hold_v1().unwrap(), None);
    }

    #[test]
    fn hold_cannot_be_redirected_to_another_protected_journal() {
        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let (mut other, _) = Journal::open_protected_at_uid(
            &directory.0,
            "not-source-domains.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();

        assert!(matches!(
            other.acquire_source_domain_policy_hold_v1(hold()),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn held_record_does_not_displace_typed_hierarchy_replay() {
        let directory = TestDirectory::new();
        let mut owner = ProtectedSourceDomainJournalOwnerV1::from_test_journal(directory.open());
        owner.acquire_closed_policy_source_hold_v1(hold()).unwrap();
        drop(owner);

        let mut reopened = ProtectedSourceDomainJournalOwnerV1::from_test_journal(directory.open());
        HierarchyProtectedJournalOwnerV1::claim(&mut reopened)
            .expect("typed hierarchy replay ignores the distinct hold namespace");
        assert!(
            reopened
                .closed_policy_source_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
    }
}
