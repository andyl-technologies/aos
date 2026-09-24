//! Controller-wide durable custody for one closed policy-binding proposal.
//!
//! ```text
//! AOSCTH01 | version=1 | phase=held|released | reserved[5]=0 |
//! operation[16] | sandbox[16] | source[32] | binding[32] | epoch[8] |
//! SHA-256[32]
//! ```
//!
//! This record freezes every Controller journal mutation, including after a
//! crash and reopen. It does not freeze source-domain or Cache owners and does
//! not authorize public Create, policy publication, or an effect.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const KEY: &[u8] = b"\0aos-controller-policy-hold-v1\0";
const MAGIC: &[u8; 8] = b"AOSCTH01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-hold.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-hold-transaction.v1\0";
const RECORD_BYTES: usize = 152;

/// Identifies one exact, nonauthorizing Controller policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyHoldV1 {
    operation: OperationId,
    sandbox: SandboxId,
    source: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
    held: bool,
}

impl ControllerPolicyHoldV1 {
    /// Constructs the exact hold to persist before root Q04 submission.
    ///
    /// # Errors
    ///
    /// Rejects zero identifiers, commitments, or epoch.
    pub fn new(
        operation: OperationId,
        sandbox: SandboxId,
        source: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, JournalError> {
        let hold = Self {
            operation,
            sandbox,
            source,
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

    /// Returns the query-time Controller source commitment.
    #[must_use]
    pub const fn source(self) -> ObjectDigest {
        self.source
    }

    /// Returns the root binding digest fixed before submission.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root handoff epoch fixed before submission.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether the Controller writer remains frozen.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    fn validate(self) -> Result<(), JournalError> {
        if self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.source.as_bytes() == &[0; 32]
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
        bytes[48..80].copy_from_slice(self.source.as_bytes());
        bytes[80..112].copy_from_slice(self.binding.as_bytes());
        bytes[112..120].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..120])
            .finalize();
        bytes[120..].copy_from_slice(&checksum);
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
            source: ObjectDigest::from_bytes(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[80..112]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[112..120]
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
) -> Result<Option<ControllerPolicyHoldV1>, JournalError> {
    let mut records = state
        .range((RecordNamespace::ControllerPolicyHold, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::ControllerPolicyHold);
    let record = records.next();
    if records.next().is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    match record {
        Some(((namespace, key), value))
            if *namespace == RecordNamespace::ControllerPolicyHold && key.as_slice() == KEY =>
        {
            ControllerPolicyHoldV1::decode(value).map(Some)
        }
        Some(_) => Err(JournalError::ProtectedBoundary),
        None => Ok(None),
    }
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if current(state)?.is_some_and(ControllerPolicyHoldV1::is_held)
        || transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::ControllerPolicyHold)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if current(state)?.is_some_and(ControllerPolicyHoldV1::is_held) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn transaction(hold: ControllerPolicyHoldV1) -> Result<JournalTransaction, JournalError> {
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
            RecordNamespace::ControllerPolicyHold,
            KEY.to_vec(),
            bytes.to_vec(),
        )],
    )
}

fn ensure_controller(journal: &Journal) -> Result<(), JournalError> {
    journal.ensure_protected_authority()?;
    if journal
        .protected
        .as_ref()
        .map(|location| location.name.as_str())
        != Some("controller.journal")
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl Journal {
    /// Durably freezes the protected Controller journal before root Q04 submission.
    ///
    /// A lost root reply leaves this hold intact across process death. The
    /// caller must not release it on successful terminal-ACK write alone.
    ///
    /// # Errors
    ///
    /// Rejects an unprotected journal, existing held or malformed custody,
    /// invalid fields, or a failed durable write/readback.
    pub fn acquire_controller_policy_hold_v1(
        &mut self,
        hold: ControllerPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        if !hold.is_held() || current(&self.state)?.is_some_and(ControllerPolicyHoldV1::is_held) {
            return Err(JournalError::ProtectedBoundary);
        }
        let acquire = transaction(hold)?;
        let release = transaction(ControllerPolicyHoldV1 {
            held: false,
            ..hold
        })?;
        // All later Controller commits are fenced, so this reserves the
        // bounded journal room needed for exact cold release.
        self.preflight_transactions_with_capacity_scope(
            &[acquire.clone(), release],
            None,
            false,
            true,
        )?;
        self.commit_with_capacity_scope(&acquire, None, false, true)?;
        if current(&self.state)? != Some(hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads the exact Controller custody state under its protected writer.
    ///
    /// This observation does not attest the root owner's state.
    ///
    /// # Errors
    ///
    /// Rejects unprotected or malformed custody.
    pub fn controller_policy_hold_v1(
        &self,
    ) -> Result<Option<ControllerPolicyHoldV1>, JournalError> {
        ensure_controller(self)?;
        current(&self.state)
    }

    pub(crate) fn release_controller_policy_hold_after_root_readback_v1(
        &mut self,
        expected: ControllerPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        if !expected.held || current(&self.state)? != Some(expected) {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        let transaction = transaction(released)?;
        self.commit_with_capacity_scope(&transaction, None, false, true)?;
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
    use crate::journal::JournalLimits;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-controller-policy-hold-{}-{}",
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
            Journal::open_protected_at_uid(
                &self.0,
                "controller.journal",
                JournalLimits::default(),
                uid,
            )
            .expect("protected Controller reopen")
            .0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hold() -> ControllerPolicyHoldV1 {
        ControllerPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            7,
        )
        .expect("valid hold")
    }

    fn ordinary_transaction() -> JournalTransaction {
        JournalTransaction::new(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"ordinary".to_vec(),
                b"value".to_vec(),
            )],
        )
        .expect("ordinary transaction")
    }

    #[test]
    fn lost_root_reply_freezes_controller_after_crash_and_reopen() {
        let directory = TestDirectory::new();
        let mut controller = directory.open();
        let expected = hold();
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        assert!(
            controller
                .acquire_controller_policy_hold_v1(released)
                .is_err()
        );
        assert_eq!(controller.controller_policy_hold_v1().unwrap(), None);
        controller
            .acquire_controller_policy_hold_v1(expected)
            .expect("durable hold before root submit");
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_hold_v1().unwrap(),
            Some(expected)
        );
        assert!(matches!(
            reopened.commit(&ordinary_transaction()),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            reopened.preflight_transactions(&[ordinary_transaction()]),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            reopened.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(
            reopened
                .acquire_controller_policy_hold_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn exact_cold_release_restores_writes_but_wrong_binding_does_not() {
        let directory = TestDirectory::new();
        let mut controller = directory.open();
        let expected = hold();
        controller
            .acquire_controller_policy_hold_v1(expected)
            .unwrap();
        drop(controller);

        let mut reopened = directory.open();
        let wrong_binding = ControllerPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([5; 32]),
            ..expected
        };
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(wrong_binding)
                .is_err()
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
        reopened
            .release_controller_policy_hold_after_root_readback_v1(expected)
            .expect("exact root-released evidence is checked by caller");
        assert!(
            !reopened
                .controller_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
        reopened
            .commit(&ordinary_transaction())
            .expect("writes restored");
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn format_rejects_noncanonical_or_corrupt_custody() {
        let expected = hold();
        let mut bytes = expected.encode().unwrap();
        assert_eq!(ControllerPolicyHoldV1::decode(&bytes).unwrap(), expected);
        bytes[11] = 1;
        assert!(ControllerPolicyHoldV1::decode(&bytes).is_err());
        bytes = expected.encode().unwrap();
        bytes[119] ^= 1;
        assert!(ControllerPolicyHoldV1::decode(&bytes).is_err());
    }

    #[test]
    fn acquisition_reserves_capacity_for_exact_cold_release() {
        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits {
            maximum_transactions: 1,
            ..JournalLimits::default()
        };
        let (mut controller, _) =
            Journal::open_protected_at_uid(&directory.0, "controller.journal", limits, uid)
                .expect("protected Controller");

        assert!(
            controller
                .acquire_controller_policy_hold_v1(hold())
                .is_err()
        );
        assert_eq!(controller.controller_policy_hold_v1().unwrap(), None);
    }
}
