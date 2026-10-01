//! Durable mutation receipts and recovery decisions for one physical object.
//!
//! A pending mutation without a receipt has an unknown provider outcome. It must
//! keep the key fenced: observing absence does not prove that an already
//! dispatched deletion has finished, and retrying could delete a replacement.
//! Receipts and unknown fences have no automatic retirement. These records
//! cover deployment R2; external S3 execution does not use this contract yet.
//!
//! `pending-mutation` retains the exact dispatched intent. Each terminal
//! `mutation-receipt:<operation_id>` stores that intent and its acknowledged
//! outcome separately. Existing `pending-delete` and `delete-receipt:<claim_id>`
//! records remain readable and fenced without migration. A receipt has this form:
//!
//! ```json
//! {
//!   "mutation": {
//!     "operation_id": "complete:provider-upload-digest",
//!     "key": "oci/blobs/sha256/object",
//!     "kind": "multipart_completion",
//!     "fingerprint": "sha256-of-exact-key-kind-and-provider-payload"
//!   },
//!   "outcome": { "kind": "multipart_completed", "etag": "provider-etag" }
//! }
//! ```

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(crate) mod external;

/// Distinguishes visible provider effects that share the physical-key fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MutationKind {
    Mirror,
    EmptyPut,
    MultipartCompletion,
    StagingDelete,
}

/// Identifies one provider attempt independently of its HTTP delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mutation {
    /// Caller-retained effect identity; retries reuse it with the same payload.
    pub operation_id: String,
    /// Full physical R2 key, including the frozen placement prefix.
    pub key: String,
    /// Provider effect whose acknowledgement the receipt proves.
    pub kind: MutationKind,
    /// SHA-256 of the exact key, kind, and provider payload.
    pub fingerprint: String,
}

impl Mutation {
    /// Binds replay identity to the exact provider payload before dispatch.
    ///
    /// # Errors
    /// Returns an error for an empty, oversized, or invalid operation ID, or
    /// when the payload cannot be serialized for its fingerprint.
    pub(crate) fn new<T: Serialize>(
        key: &str,
        operation_id: &str,
        kind: MutationKind,
        payload: &T,
    ) -> Result<Self> {
        if operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            bail!("invalid mutation operation ID");
        }
        let encoded = serde_json::to_vec(&(key, &kind, payload))?;
        Ok(Self {
            operation_id: operation_id.into(),
            key: key.into(),
            kind,
            fingerprint: hex::encode(Sha256::digest(encoded)),
        })
    }
}

/// Retains the provider acknowledgement needed to replay a visible effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum MutationOutcome {
    Mirror { progress: aos_hub_core::mirror_work::MirrorProgress },
    Acknowledged,
    MultipartCompleted { etag: String },
}

/// Persists an exact provider attempt and its terminal acknowledgement.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MutationReceipt {
    /// Exact dispatch identity checked before replaying the outcome.
    pub mutation: Mutation,
    /// Result stored only after the provider's mutation promise resolved.
    pub outcome: MutationOutcome,
}

/// Rejects provider observations while any dispatched mutation may still finish.
///
/// # Errors
/// Returns an error while a generalized mutation or prior delete is fenced.
pub(crate) fn ensure_ready(
    pending: Option<&Mutation>,
    legacy_delete: Option<&DeleteClaim>,
) -> Result<()> {
    if pending.is_some() || legacy_delete.is_some() {
        bail!("object mutation outcome is unknown; provider settlement is required");
    }
    Ok(())
}

/// Runs a provider observation only inside a settled mutation boundary.
///
/// # Errors
/// Returns an error before invoking the provider while either kind of fence is
/// present, or propagates an error from the admitted provider observation.
pub(crate) async fn observe_when_ready<T, F, Fut>(
    pending: Option<&Mutation>,
    legacy_delete: Option<&DeleteClaim>,
    observe: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    ensure_ready(pending, legacy_delete)?;
    observe().await
}

/// Replays an exact receipt or admits a first dispatch, preserving old fences.
///
/// # Errors
/// Returns an error for a changed identity/payload, an incompatible recorded
/// outcome, or a pending mutation without a matching terminal receipt.
pub(crate) fn recover_mutation(
    mutation: &Mutation,
    receipt: Option<&MutationReceipt>,
    pending: Option<&Mutation>,
    legacy_delete: Option<&DeleteClaim>,
) -> Result<Option<MutationOutcome>> {
    if let Some(receipt) = receipt {
        if receipt.mutation != *mutation {
            bail!("object mutation changed identity or payload");
        }
        let valid_outcome = matches!(
            (&mutation.kind, &receipt.outcome),
            (MutationKind::Mirror, MutationOutcome::Mirror { .. }) |
            (
                MutationKind::MultipartCompletion,
                MutationOutcome::MultipartCompleted { .. }
            ) | (
                MutationKind::EmptyPut | MutationKind::StagingDelete,
                MutationOutcome::Acknowledged
            )
        );
        if !valid_outcome {
            bail!("object mutation receipt has an incompatible outcome");
        }
        return Ok(Some(receipt.outcome.clone()));
    }

    ensure_ready(pending, legacy_delete)?;
    Ok(None)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteClaim {
    pub claim_id: String,
    pub expected_etag: String,
    pub expected_size: u64,
    pub expected_hash: Option<String>,
    #[serde(default)]
    pub expected_provider_version: Option<String>,
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

    if claim.expected_provider_version.is_none() {
        bail!("delete claim has no upload version; collect and review a fresh inventory");
    }

    Ok(None)
}

/// Matches the frozen incarnation against one provider metadata snapshot.
pub(crate) fn matches_delete_observation(
    claim: &DeleteClaim,
    head: &crate::r2_adapter::R2HeadObject,
) -> bool {
    head.size == claim.expected_size
        && head.etag == claim.expected_etag
        && Some(head.version.as_str()) == claim.expected_provider_version.as_deref()
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_ready, matches_delete_observation, observe_when_ready, recover_delete,
        recover_mutation, DeleteClaim, DeleteOutcome, DeleteReceipt, Mutation, MutationKind,
        MutationOutcome, MutationReceipt,
    };

    fn claim(id: &str) -> DeleteClaim {
        DeleteClaim {
            claim_id: id.into(),
            expected_etag: "\"original-etag\"".into(),
            expected_size: 42,
            expected_hash: None,
            expected_provider_version: Some("original-upload-version".into()),
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

    #[test]
    fn legacy_terminal_receipt_replays_before_missing_version_rejection() {
        let mut legacy = claim("legacy-action");
        legacy.expected_provider_version = None;
        let persisted = serde_json::to_vec(&DeleteReceipt {
            claim: legacy.clone(),
            outcome: DeleteOutcome::Deleted {
                etag: legacy.expected_etag.clone(),
            },
        })
        .unwrap();
        let restored: DeleteReceipt = serde_json::from_slice(&persisted).unwrap();
        let unrelated = claim("unrelated-action");

        assert_eq!(
            recover_delete(&legacy, Some(&restored), Some(&unrelated)).unwrap(),
            Some(restored.outcome.clone())
        );
        assert!(recover_delete(&legacy, None, None)
            .unwrap_err()
            .to_string()
            .contains("fresh inventory"));
        assert!(recover_delete(&legacy, None, Some(&legacy)).is_err());
    }

    #[test]
    fn versionless_inner_request_marks_the_protocol_and_rejects_an_old_guard() {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OldDeleteClaim {
            claim_id: String,
            expected_etag: String,
            expected_size: u64,
            expected_hash: Option<String>,
        }

        let mut legacy = claim("legacy-action");
        legacy.expected_provider_version = None;
        let current = serde_json::to_value(&legacy).unwrap();
        assert_eq!(
            current.get("expected_provider_version"),
            Some(&serde_json::Value::Null)
        );
        assert!(serde_json::from_value::<OldDeleteClaim>(current.clone()).is_err());

        let mut historical = current;
        historical
            .as_object_mut()
            .unwrap()
            .remove("expected_provider_version");
        let old: OldDeleteClaim = serde_json::from_value(historical.clone()).unwrap();
        assert_eq!(old.claim_id, legacy.claim_id);
        assert_eq!(old.expected_etag, legacy.expected_etag);
        assert_eq!(old.expected_size, legacy.expected_size);
        assert_eq!(old.expected_hash, legacy.expected_hash);
        assert_eq!(
            serde_json::from_value::<DeleteClaim>(historical).unwrap(),
            legacy
        );
    }

    #[test]
    fn identical_recreation_cannot_match_the_frozen_upload_incarnation() {
        let original = claim("delayed-first-dispatch");
        let mut provider = crate::r2_adapter::R2HeadObject {
            size: original.expected_size,
            etag: original.expected_etag.clone(),
            version: original.expected_provider_version.clone().unwrap(),
        };
        assert!(matches_delete_observation(&original, &provider));

        // Identical bytes can recreate the size and ETag, but not this version.
        provider.version = "replacement-upload-version".into();
        assert!(!matches_delete_observation(&original, &provider));

        let mut legacy = original;
        legacy.expected_provider_version = None;
        assert!(!matches_delete_observation(&legacy, &provider));
    }

    #[test]
    fn same_action_cannot_replay_with_another_upload_version() {
        let original = claim("same-action");
        let receipt = DeleteReceipt {
            claim: original.clone(),
            outcome: DeleteOutcome::NotFound,
        };
        let mut changed = original;
        changed.expected_provider_version = Some("replacement-upload-version".into());

        assert!(recover_delete(&changed, Some(&receipt), None).is_err());
    }

    fn mutation(kind: MutationKind, id: &str) -> Mutation {
        Mutation::new(
            "oci/blobs/sha256/object",
            id,
            kind,
            &("upload-one", ["part-one"]),
        )
        .unwrap()
    }

    fn outcome(kind: &MutationKind) -> MutationOutcome {
        match kind {
            MutationKind::MultipartCompletion => MutationOutcome::MultipartCompleted {
                etag: "\"completed-etag\"".into(),
            },
            _ => MutationOutcome::Acknowledged,
        }
    }

    #[test]
    fn every_visible_mutation_fences_late_provider_io_after_serialized_restart() {
        for kind in [
            MutationKind::EmptyPut,
            MutationKind::MultipartCompletion,
            MutationKind::StagingDelete,
        ] {
            let original = mutation(kind.clone(), "original");
            assert_eq!(recover_mutation(&original, None, None, None).unwrap(), None);

            // Dispatch was durably recorded; its provider promise outlives the
            // process. Restart loses that promise, but must preserve its fence.
            let stored = serde_json::to_vec(&original).unwrap();
            let restored: Mutation = serde_json::from_slice(&stored).unwrap();
            let replacement = mutation(MutationKind::EmptyPut, "replacement");
            assert!(recover_mutation(&original, None, Some(&restored), None).is_err());
            assert!(recover_mutation(&replacement, None, Some(&restored), None).is_err());

            // Inject the outstanding effect after recovery. Absence before a
            // late PUT, or after a late DELETE, cannot make GC ready. There is
            // no terminal receipt, including when the provider did finish.
            let mut provider_object = None;
            assert!(ensure_ready(Some(&restored), None).is_err());
            if kind != MutationKind::StagingDelete {
                provider_object = Some("late-object");
            }
            assert_eq!(
                provider_object.is_some(),
                kind != MutationKind::StagingDelete
            );
            assert!(ensure_ready(Some(&restored), None).is_err());
            assert!(recover_mutation(&replacement, None, Some(&restored), None).is_err());
            assert_eq!(serde_json::to_vec(&restored).unwrap(), stored);
        }
    }

    #[test]
    fn receipts_survive_restart_before_unlock_and_replay_after_replacement() {
        for kind in [
            MutationKind::EmptyPut,
            MutationKind::MultipartCompletion,
            MutationKind::StagingDelete,
        ] {
            let original = mutation(kind.clone(), "original");
            let receipt = MutationReceipt {
                mutation: original.clone(),
                outcome: outcome(&kind),
            };
            let stored = serde_json::to_vec(&(Some(&original), &receipt)).unwrap();
            let (pending, restored): (Option<Mutation>, MutationReceipt) =
                serde_json::from_slice(&stored).unwrap();

            // Receipt persistence precedes fence removal. Replay requires no
            // second effect; readiness stays conservative until that removal.
            assert!(ensure_ready(pending.as_ref(), None).is_err());
            assert_eq!(
                recover_mutation(&original, Some(&restored), pending.as_ref(), None).unwrap(),
                Some(receipt.outcome.clone())
            );
            let later = mutation(MutationKind::EmptyPut, "later");
            assert_eq!(
                recover_mutation(&original, Some(&restored), Some(&later), None).unwrap(),
                Some(receipt.outcome)
            );
            assert!(ensure_ready(Some(&later), None).is_err());
            assert!(ensure_ready(None, None).is_ok());
        }
    }

    #[test]
    fn same_operation_rejects_changed_key_kind_upload_or_parts() {
        let original = mutation(MutationKind::MultipartCompletion, "operation-one");
        let receipt = MutationReceipt {
            mutation: original.clone(),
            outcome: outcome(&original.kind),
        };
        let changes = [
            Mutation::new(
                "different-key",
                "operation-one",
                original.kind.clone(),
                &("upload-one", ["part-one"]),
            )
            .unwrap(),
            Mutation::new(
                &original.key,
                "operation-one",
                MutationKind::StagingDelete,
                &("upload-one", ["part-one"]),
            )
            .unwrap(),
            Mutation::new(
                &original.key,
                "operation-one",
                original.kind.clone(),
                &("upload-two", ["part-one"]),
            )
            .unwrap(),
            Mutation::new(
                &original.key,
                "operation-one",
                original.kind.clone(),
                &("upload-one", ["part-two"]),
            )
            .unwrap(),
        ];
        for changed in changes {
            assert_eq!(changed.operation_id, original.operation_id);
            assert!(recover_mutation(&changed, Some(&receipt), None, None).is_err());
        }
        let incompatible = MutationReceipt {
            mutation: original.clone(),
            outcome: MutationOutcome::Acknowledged,
        };
        assert!(recover_mutation(&original, Some(&incompatible), None, None).is_err());
    }

    #[test]
    fn legacy_delete_fences_new_mutations_and_new_fences_block_gc_observation() {
        let legacy = claim("old-action");
        let current = mutation(MutationKind::MultipartCompletion, "current-operation");
        assert!(recover_mutation(&current, None, None, Some(&legacy)).is_err());
        assert!(ensure_ready(None, Some(&legacy)).is_err());
        assert!(ensure_ready(Some(&current), None).is_err());

        let receipt = MutationReceipt {
            mutation: current.clone(),
            outcome: outcome(&current.kind),
        };
        assert_eq!(
            recover_mutation(&current, Some(&receipt), None, Some(&legacy)).unwrap(),
            Some(receipt.outcome)
        );
        assert!(ensure_ready(None, Some(&legacy)).is_err());

        // Existing claim receipts remain replayable without touching any new
        // fence or reissuing their provider deletion.
        let old_receipt = DeleteReceipt {
            claim: legacy.clone(),
            outcome: DeleteOutcome::NotFound,
        };
        assert_eq!(
            recover_delete(&legacy, Some(&old_receipt), None).unwrap(),
            Some(DeleteOutcome::NotFound)
        );
        assert!(ensure_ready(Some(&current), None).is_err());
    }

    #[test]
    fn operation_identity_is_bounded_before_persistence() {
        for id in ["", "invalid/operation", &"x".repeat(129)] {
            assert!(Mutation::new("key", id, MutationKind::EmptyPut, &()).is_err());
        }
    }

    #[tokio::test]
    async fn unknown_completion_denies_head_without_calling_provider_before_or_after_late_io() {
        use std::cell::Cell;

        let pending = mutation(MutationKind::MultipartCompletion, "late-completion");
        let persisted = serde_json::to_vec(&pending).unwrap();
        let restored: Mutation = serde_json::from_slice(&persisted).unwrap();
        let head_calls = Cell::new(0);
        let provider_object = Cell::new(None);
        let head = || {
            head_calls.set(head_calls.get() + 1);
            std::future::ready(Ok(provider_object.get()))
        };

        // The provider would report absence. The production observation helper
        // must refuse before issuing HEAD, so GC cannot consume that absence.
        assert!(observe_when_ready(Some(&restored), None, head)
            .await
            .is_err());
        assert_eq!(head_calls.get(), 0);

        // Inject completion of the lost provider operation after restart.
        // Knowing its new metadata is not a durable acknowledgement receipt.
        provider_object.set(Some("late-etag"));
        assert!(observe_when_ready(Some(&restored), None, head)
            .await
            .is_err());
        assert_eq!(head_calls.get(), 0);

        // A settled key permits the same provider call; observation has no
        // ability to clear or alter the persisted unknown fence.
        assert_eq!(
            observe_when_ready(None, None, head).await.unwrap(),
            Some("late-etag")
        );
        assert_eq!(head_calls.get(), 1);
        assert_eq!(serde_json::to_vec(&restored).unwrap(), persisted);
    }
}
