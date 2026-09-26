//! Protected acknowledgment of an already terminal, permanently blocked operation.
//!
//! ```text
//! key   = "abandon/" || target operation[16]
//! value = AOSOAB01 || recovery operation[16] || target operation[16] ||
//!         action[1] || principal[16] || project[16] ||
//!         idempotency digest[32] || public request digest[32] ||
//!         recovery request binding[32] || target version digest[32] ||
//!         SHA-256 of all preceding value bytes[32]
//! ```
//!
//! This record acknowledges the blocked state. It does not change the target
//! operation, authorize dispatch, or claim that residual resources were cleaned.

use aos_sandbox_core::{ObjectDigest, OperationId, PrincipalId, ProjectId};
use sha2::{Digest as _, Sha256};

use crate::{JournalRecord, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSOAB01";
const KEY_PREFIX: &[u8] = b"abandon/";
const ACTION_ABANDON: u8 = 2;
const VALUE_BYTES: usize = 8 + 16 + 16 + 1 + 16 + 16 + 32 + 32 + 32 + 32 + 32;
const IDEMPOTENCY_DOMAIN: &[u8] = b"aos.sandbox.operator-abandon-idempotency.v1\0";
const VERSION_DOMAIN: &[u8] = b"aos.sandbox.operator-abandon-target-version.v1\0";

pub(crate) fn key_v1(target: OperationId) -> Vec<u8> {
    [KEY_PREFIX, target.as_bytes().as_slice()].concat()
}

pub(crate) fn is_acknowledgment_record_v1(record: &JournalRecord) -> bool {
    record.namespace() == RecordNamespace::OperatorRecovery
        && record.key().len() == KEY_PREFIX.len() + 16
        && record.key().starts_with(KEY_PREFIX)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_v1(
    recovery: OperationId,
    target: OperationId,
    principal: PrincipalId,
    project: ProjectId,
    idempotency_key: &[u8],
    request_digest: [u8; 32],
    request_binding: ObjectDigest,
    target_version: &[u8],
) -> Option<JournalRecord> {
    if recovery.as_bytes() == &[0; 16]
        || target.as_bytes() == &[0; 16]
        || principal.as_bytes() == &[0; 16]
        || project.as_bytes() == &[0; 16]
        || idempotency_key.is_empty()
        || target_version.is_empty()
    {
        return None;
    }
    let idempotency_digest = bounded_digest(IDEMPOTENCY_DOMAIN, idempotency_key);
    let version_digest = bounded_digest(VERSION_DOMAIN, target_version);
    let mut value = Vec::with_capacity(VALUE_BYTES);
    value.extend_from_slice(MAGIC);
    value.extend_from_slice(recovery.as_bytes());
    value.extend_from_slice(target.as_bytes());
    value.push(ACTION_ABANDON);
    value.extend_from_slice(principal.as_bytes());
    value.extend_from_slice(project.as_bytes());
    value.extend_from_slice(&idempotency_digest);
    value.extend_from_slice(&request_digest);
    value.extend_from_slice(request_binding.as_bytes());
    value.extend_from_slice(&version_digest);
    let checksum: [u8; 32] = Sha256::digest(&value).into();
    value.extend_from_slice(&checksum);

    Some(JournalRecord::put(
        RecordNamespace::OperatorRecovery,
        key_v1(target),
        value,
    ))
}

pub(crate) fn validates_record_v1(
    record: &JournalRecord,
    recovery: OperationId,
    target: OperationId,
    idempotency_key: &[u8],
    request_digest: [u8; 32],
) -> bool {
    if record.namespace() != RecordNamespace::OperatorRecovery || record.key() != key_v1(target) {
        return false;
    }
    let Some(value) = record.value() else {
        return false;
    };
    if value.len() != VALUE_BYTES
        || value.get(..8) != Some(MAGIC.as_slice())
        || value.get(8..24) != Some(recovery.as_bytes().as_slice())
        || value.get(24..40) != Some(target.as_bytes().as_slice())
        || value[40] != ACTION_ABANDON
        || value.get(73..105)
            != Some(bounded_digest(IDEMPOTENCY_DOMAIN, idempotency_key).as_slice())
        || value.get(105..137) != Some(request_digest.as_slice())
    {
        return false;
    }
    let checksum: [u8; 32] = Sha256::digest(&value[..VALUE_BYTES - 32]).into();
    value[VALUE_BYTES - 32..] == checksum
}

fn bounded_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgment_binds_identity_and_rejects_tampering() {
        let recovery = OperationId::from_bytes([1; 16]);
        let target = OperationId::from_bytes([2; 16]);
        let record = record_v1(
            recovery,
            target,
            PrincipalId::from_bytes([3; 16]),
            ProjectId::from_bytes([4; 16]),
            b"same-key",
            [5; 32],
            ObjectDigest::from_bytes([6; 32]),
            b"version",
        )
        .expect("valid acknowledgment");
        assert!(validates_record_v1(
            &record,
            recovery,
            target,
            b"same-key",
            [5; 32]
        ));
        assert!(!validates_record_v1(
            &record,
            OperationId::from_bytes([9; 16]),
            target,
            b"same-key",
            [5; 32],
        ));
        assert!(!validates_record_v1(
            &record,
            recovery,
            target,
            b"other-key",
            [5; 32]
        ));

        let mut tampered = record.value().expect("value").to_vec();
        tampered[41] ^= 1;
        let tampered =
            JournalRecord::put(RecordNamespace::OperatorRecovery, key_v1(target), tampered);
        assert!(!validates_record_v1(
            &tampered,
            recovery,
            target,
            b"same-key",
            [5; 32]
        ));

        let different_key = record_v1(
            recovery,
            target,
            PrincipalId::from_bytes([3; 16]),
            ProjectId::from_bytes([4; 16]),
            b"other-key",
            [5; 32],
            ObjectDigest::from_bytes([6; 32]),
            b"version",
        )
        .expect("different-key acknowledgment");
        assert_ne!(record.value(), different_key.value());

        assert!(
            crate::OperationPlan::completed_operator_abandon(
                recovery,
                target,
                crate::IdempotencyKey::new(b"same-key".to_vec()).expect("idempotency"),
                [5; 32],
                b"desired".to_vec(),
                b"state".to_vec(),
                record.clone(),
            )
            .is_ok()
        );

        assert!(
            crate::OperationPlan::completed_operator_abandon(
                recovery,
                OperationId::from_bytes([7; 16]),
                crate::IdempotencyKey::new(b"same-key".to_vec()).expect("idempotency"),
                [5; 32],
                b"desired".to_vec(),
                b"state".to_vec(),
                record,
            )
            .is_err()
        );
    }
}
