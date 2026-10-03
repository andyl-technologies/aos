//! Domain-separated transactions for protected owner signer pin admission.

use sha2::{Digest as _, Sha256};

use crate::journal::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};

/// Constructs the one-record transaction after role-specific pin validation.
pub(super) fn owner_pin_transaction(
    domain: &[u8],
    key: &[u8],
    credential: &[u8],
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(credential)
        .finalize();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest[..16]);

    JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            key.to_vec(),
            credential.to_vec(),
        )],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_compiler::{
        cache_readback_pin::CACHE_PIN_KEY, controller_hold_pin::CONTROLLER_HOLD_PIN_KEY,
        source_hold_pin::SOURCE_HOLD_PIN_KEY,
    };

    #[test]
    fn owner_pin_transactions_preserve_each_domain_and_exact_record() {
        let credential = b"test-pin";
        let cases: [(&[u8], &[u8], [u8; 16]); 3] = [
            (
                b"aos.sandbox.policy-controller-hold-pin-transaction.v1\0",
                CONTROLLER_HOLD_PIN_KEY,
                [
                    0x4f, 0xaf, 0x22, 0xb5, 0x46, 0x31, 0x12, 0xda, 0x3b, 0xc0, 0x6f, 0x69, 0x08,
                    0xdc, 0x93, 0x38,
                ],
            ),
            (
                b"aos.sandbox.policy-source-hold-pin-transaction.v1\0",
                SOURCE_HOLD_PIN_KEY,
                [
                    0x81, 0x84, 0xcc, 0x9f, 0x44, 0xbe, 0xcb, 0x39, 0x4e, 0xe6, 0x73, 0x70, 0x9c,
                    0x01, 0x15, 0x42,
                ],
            ),
            (
                b"aos.sandbox.policy-cache-readback-pin-transaction.v1\0",
                CACHE_PIN_KEY,
                [
                    0x7c, 0x85, 0xd4, 0xe2, 0x8c, 0x3d, 0xc0, 0x00, 0x93, 0x0c, 0xd6, 0xdd, 0xcf,
                    0x80, 0x14, 0x27,
                ],
            ),
        ];

        for (domain, key, expected_id) in cases {
            let transaction = owner_pin_transaction(domain, key, credential).unwrap();
            assert_eq!(*transaction.id(), expected_id);
            assert_eq!(transaction.records().len(), 1);
            assert_eq!(
                transaction.records()[0].namespace(),
                RecordNamespace::DesiredState
            );
            assert_eq!(transaction.records()[0].key(), key);
            assert_eq!(
                transaction.records()[0].value(),
                Some(credential.as_slice())
            );
        }
    }
}
