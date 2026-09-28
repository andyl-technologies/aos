//! Durable deletion receipts and recovery decisions for one physical object.
//!
//! A pending delete without a receipt has an unknown provider outcome. It must
//! keep the key fenced: observing absence does not prove that an already
//! dispatched deletion has finished, and retrying could delete a replacement.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteClaim {
    pub claim_id: String,
    pub expected_etag: String,
    pub expected_size: u64,
    pub expected_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DeleteOutcome {
    Deleted { etag: String },
    NotFound,
    PreconditionFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteReceipt {
    pub claim: DeleteClaim,
    pub outcome: DeleteOutcome,
}

/// Chooses a terminal replay or admits the first dispatch of a deletion.
pub(crate) fn recover_delete(
    claim: &DeleteClaim,
    receipt: Option<&DeleteReceipt>,
    pending: Option<&DeleteClaim>,
) -> Result<Option<DeleteOutcome>> {
    if let Some(receipt) = receipt {
        if receipt.claim != *claim {
            bail!("delete claim changed identity");
        }
        return Ok(Some(receipt.outcome.clone()));
    }

    if let Some(pending) = pending {
        if pending != claim {
            bail!("another object deletion is pending");
        }
        bail!("object deletion outcome is unknown; provider settlement is required");
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{recover_delete, DeleteClaim, DeleteOutcome, DeleteReceipt};

    fn claim(id: &str) -> DeleteClaim {
        DeleteClaim {
            claim_id: id.into(),
            expected_etag: "\"original-etag\"".into(),
            expected_size: 42,
            expected_hash: None,
        }
    }

    #[test]
    fn crash_after_dispatch_cannot_admit_a_second_delete_or_another_claim() {
        let original = claim("action-one");
        assert_eq!(recover_delete(&original, None, None).unwrap(), None);

        // The request may still be running even when HEAD would report absence.
        // Only a stored terminal receipt can settle this durable pending claim.
        let persisted = serde_json::to_vec(&original).unwrap();
        let restored: DeleteClaim = serde_json::from_slice(&persisted).unwrap();
        let error = recover_delete(&original, None, Some(&restored)).unwrap_err();
        assert!(error
            .to_string()
            .contains("provider settlement is required"));

        let next = claim("action-two");
        assert!(recover_delete(&next, None, Some(&restored)).is_err());
    }

    #[test]
    fn terminal_receipt_replays_across_restart_and_a_later_mutation() {
        let original = claim("action-one");
        let receipt = DeleteReceipt {
            claim: original.clone(),
            outcome: DeleteOutcome::Deleted {
                etag: original.expected_etag.clone(),
            },
        };
        let persisted = serde_json::to_vec(&receipt).unwrap();
        let restored: DeleteReceipt = serde_json::from_slice(&persisted).unwrap();

        for pending in [None, Some(&original), Some(&claim("action-two"))] {
            assert_eq!(
                recover_delete(&original, Some(&restored), pending).unwrap(),
                Some(receipt.outcome.clone())
            );
        }

        let mut changed = original;
        changed.expected_size += 1;
        assert!(recover_delete(&changed, Some(&restored), None).is_err());
    }
}
