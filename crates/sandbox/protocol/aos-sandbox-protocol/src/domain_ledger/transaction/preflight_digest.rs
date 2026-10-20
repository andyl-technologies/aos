//! Owns the existing target-local transaction preflight comparison byte recipe.
//!
//! This hash describes supplied transaction DATA. It cannot seal a protected
//! snapshot, native commit, writer association, role effect or paid operation.
//! Length fields retain the original target usize width; this is not a new
//! cross-architecture wire format or a durable proof.

use sha2::{Digest, Sha256};
use super::JournalTransaction;

const AUTHORITY_PREFLIGHT_DOMAIN: &[u8] = b"aos.sandbox.journal.authority-preflight.v1\0";

/// Hashes supplied transaction DATA in the original preflight comparison order.
///
/// Actual private role owners separately retain their genuine snapshot and
/// current native association. No admission follows from a matching digest.
pub fn transaction_preflight_comparison_digest_v1(transactions: &[JournalTransaction]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_PREFLIGHT_DOMAIN);
    digest.update(transactions.len().to_be_bytes());

    for transaction in transactions {
        digest.update(transaction.id());
        digest.update(transaction.records().len().to_be_bytes());

        for record in transaction.records() {
            digest.update([record.namespace() as u8]);
            digest.update(record.key().len().to_be_bytes());
            digest.update(record.key());

            match record.value() {
                Some(value) => {
                    digest.update([1]);
                    digest.update(value.len().to_be_bytes());
                    digest.update(value);
                }
                None => digest.update([0]),
            }
        }
    }

    digest.finalize().into()
}
