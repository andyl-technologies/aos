//! Durable control-plane reservations and monotonic physical admission.
//!
//! This journal never reads a provider, object receipt, or pending mutation.
//! Blocking, retirement, credential changes and expiry cannot settle effects.
//! Its immutable reservations and control receipts have no automatic expiry.
//!
//! The durable adapter stores lossless versioned JSON strings:
//!
//! ```json
//! {"version":1,"value":{"generation":1}}
//! ```

use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use aos_hub_core::storage_authority::control::{
    StorageAuthorityControlReceipt, StorageAuthorityDeniedTransition, StorageAuthorityOperation,
    StorageAuthorityPublication, StorageAuthorityRequest, StorageAuthorityResponse,
};
use aos_hub_core::storage_authority::{
    PhysicalStorageAuthorityId, StorageAuthorityAdmissionState, StorageAuthorityRemoteWatermark,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Durable ledger I/O under one addressed DO gate for the entire operation.
pub(crate) trait AuthorityJournal {
    /// Loads a permanent reservation or exact current authority state.
    ///
    /// # Errors
    /// Returns an error for unavailable or corrupt durable storage.
    async fn get(&mut self, key: &str) -> Result<Option<Value>>;

    /// Atomically persists reservations, current state and its receipt together.
    ///
    /// # Errors
    /// Returns an error without acknowledging control when persistence fails.
    async fn put_atomic(&mut self, values: BTreeMap<String, Value>) -> Result<()>;
}

/// Partitions API calls while preserving one surrounding SQLite transaction.
pub(crate) fn write_batches(values: BTreeMap<String, Value>) -> Vec<BTreeMap<String, Value>> {
    let mut values = values.into_iter();
    let mut batches = Vec::new();
    loop {
        let batch = values.by_ref().take(128).collect::<BTreeMap<_, _>>();
        if batch.is_empty() {
            return batches;
        }
        batches.push(batch);
    }
}

/// Versioned lossless JSON entry, stored as a JavaScript string by DO KV.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalValue {
    version: u8,
    value: Value,
}

/// Encodes an exact entry without converting its integer values to JS numbers.
///
/// # Errors
/// Returns an error when the entry cannot be serialized as JSON.
pub(crate) fn encode_journal_value(value: &Value) -> Result<String> {
    serde_json::to_string(&JournalValue {
        version: 1,
        value: value.clone(),
    })
    .context("encoding versioned authority entry")
}

/// Decodes only the supported journal encoding; legacy data never creates absence.
///
/// # Errors
/// Returns an error for malformed, legacy, or unsupported entry encodings.
pub(crate) fn decode_journal_value(encoded: &str) -> Result<Value> {
    let entry: JournalValue =
        serde_json::from_str(encoded).context("decoding versioned authority entry")?;
    ensure!(entry.version == 1, "unsupported authority entry encoding");
    Ok(entry.value)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutorDomain {
    namespace: String,
    executor: String,
}

/// Immutable transport edge, separate from the unchanged SQL publication parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DenialTransitionReceipt {
    transition: StorageAuthorityDeniedTransition,
    operation_digest: String,
    control_receipt: StorageAuthorityControlReceipt,
}

/// Processes an already authenticated bounded request under the ledger gate.
///
/// Old exact control returns its immutable receipt alongside the **latest**
/// durable watermark. SQL restore cannot obtain freshly signed stale admission
/// by replaying an old signed publication. Time limits stop new admission only.
///
/// # Errors
/// Returns an error for stale/conflicting control, changed immutable facts,
/// domain mismatch, exhausted membership limits, or failed durable I/O.
pub(crate) async fn handle<J: AuthorityJournal>(
    journal: &mut J,
    request: &StorageAuthorityRequest,
    deployment: &str,
    namespace: &str,
    executor: &str,
    now: i64,
) -> Result<StorageAuthorityResponse> {
    request.validate(deployment, namespace, now)?;
    let domain = ExecutorDomain {
        namespace: namespace.into(),
        executor: executor.into(),
    };
    if let Some(existing) = journal.get("domain").await? {
        ensure!(
            existing == serde_json::to_value(&domain)?,
            "executor's physical domain changed"
        );
    }

    // Fresh readiness reads the compact watermark, not the potentially large
    // root fact bundle. The three records are persisted in one transaction.
    if let StorageAuthorityOperation::Watermark(authority) = &request.operation {
        let watermark: Option<StorageAuthorityRemoteWatermark> = journal
            .get(&authority_key(authority, "watermark"))
            .await?
            .map(serde_json::from_value)
            .transpose()?;
        if let Some(watermark) = &watermark {
            ensure!(
                &watermark.authority_id == authority
                    && watermark.guard_namespace_id == namespace
                    && watermark.generation > 0
                    && watermark.generation
                        <= aos_hub_core::storage_authority::control::MAX_AUTHORITY_GENERATION
                    && watermark.digest.len() == 64
                    && watermark
                        .digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                "stored authority watermark is corrupt"
            );
        }
        return response(request, deployment, namespace, now, watermark, None);
    }

    let head_key = authority_key(request.authority_id(), "head");
    let current: Option<StorageAuthorityPublication> = journal
        .get(&head_key)
        .await?
        .map(serde_json::from_value)
        .transpose()?;
    if let Some(current) = &current {
        current.validate(namespace, executor)?;
    }
    let (latest, control_receipt) = match &request.operation {
        StorageAuthorityOperation::Watermark(_) => (current, None),
        StorageAuthorityOperation::Publish(publication)
        | StorageAuthorityOperation::DenyFromWatermark(StorageAuthorityDeniedTransition {
            publication,
            ..
        }) => {
            publication.validate(namespace, executor)?;
            let denial = match &request.operation {
                StorageAuthorityOperation::DenyFromWatermark(transition) => {
                    transition.validate(namespace, executor)?;
                    Some(transition)
                }
                _ => None,
            };
            let receipt_key = authority_key(
                request.authority_id(),
                &format!("receipt/{}", publication.generation),
            );
            let expected_receipt = StorageAuthorityControlReceipt {
                generation: publication.generation,
                digest: publication.digest.clone(),
                publication_digest: digest(publication)?,
            };

            let denial_key = authority_key(
                request.authority_id(),
                &format!("denial-transition/{}", publication.generation),
            );
            let denial_receipt = denial
                .map(|transition| -> Result<_> {
                    Ok(DenialTransitionReceipt {
                        transition: transition.clone(),
                        operation_digest: digest(transition)?,
                        control_receipt: expected_receipt.clone(),
                    })
                })
                .transpose()?;
            let stored_denial = journal.get(&denial_key).await?;
            if let Some(expected) = &denial_receipt {
                if let Some(stored) = stored_denial {
                    let stored: DenialTransitionReceipt = serde_json::from_value(stored)?;
                    ensure!(
                        stored == *expected,
                        "denial replay changed its immutable remote CAS or facts"
                    );
                    ensure!(
                        journal.get(&receipt_key).await?
                            == Some(serde_json::to_value(&expected_receipt)?),
                        "denial receipt differs from its publication receipt"
                    );
                } else {
                    ensure!(journal.get(&receipt_key).await?.is_none(),
                        "publication already applied without this denial transition; refetch latest state");
                }
            }

            if let Some(stored) = journal.get(&receipt_key).await? {
                let stored: StorageAuthorityControlReceipt = serde_json::from_value(stored)?;
                ensure!(
                    stored == expected_receipt,
                    "control replay changed immutable facts"
                );
                let current = current.context("receipt exists without a durable authority head")?;
                ensure!(
                    current.generation >= stored.generation,
                    "authority head rolled back behind its receipt"
                );
                (Some(current), Some(stored))
            } else {
                if let Some(transition) = denial {
                    ensure!(
                        current.as_ref().map(watermark) == transition.expected_remote,
                        "denial remote CAS is stale; reconcile the fresh remote watermark"
                    );
                    ensure!(
                        publication.generation > current.as_ref().map_or(0, |head| head.generation),
                        "denial cannot overwrite or roll back the remote floor"
                    );
                    if let Some(current) = &current {
                        ensure!(
                            current.generation != publication.admission.expected_generation
                                || Some(&current.digest)
                                    == publication.admission.expected_digest.as_ref(),
                            "denial cannot cross a conflicting SQL predecessor digest"
                        );
                    }
                } else {
                    ensure!(
                        current.as_ref().map_or(0, |head| head.generation)
                            == publication.admission.expected_generation
                            && current.as_ref().map(|head| &head.digest)
                                == publication.admission.expected_digest.as_ref(),
                        "control predecessor is stale; reconcile the fresh remote watermark"
                    );
                }
                if let Some(current) = &current {
                    ensure!(
                        current.admission.state != StorageAuthorityAdmissionState::Retired,
                        "authority retirement is terminal"
                    );
                }
                publication.validate_admission_time(now)?;

                let mut writes = BTreeMap::new();
                reserve(journal, &mut writes, "domain".into(), &domain).await?;
                reserve(
                    journal,
                    &mut writes,
                    authority_key(request.authority_id(), "identity"),
                    &publication.authority,
                )
                .await?;
                reserve(
                    journal,
                    &mut writes,
                    authority_key(request.authority_id(), "managed-prefix"),
                    &publication.authority.qualified_managed_prefix,
                )
                .await?;
                reserve(
                    journal,
                    &mut writes,
                    format!(
                        "physical/{}",
                        publication.authority.physical_resource_evidence_digest
                    ),
                    request.authority_id(),
                )
                .await?;
                for alias in &publication.aliases {
                    reserve(
                        journal,
                        &mut writes,
                        fact_key("alias-id", &alias.alias_id),
                        alias,
                    )
                    .await?;
                    reserve(
                        journal,
                        &mut writes,
                        format!("alias-address/{}", alias.spec.digest()?),
                        alias,
                    )
                    .await?;
                }
                for association in &publication.associations {
                    reserve(
                        journal,
                        &mut writes,
                        fact_key("association", &association.association_id),
                        association,
                    )
                    .await?;
                    reserve(
                        journal,
                        &mut writes,
                        format!(
                            "binding-revision/{}",
                            digest(&(
                                association.binding_stable_id.as_str(),
                                association.binding_resource_version,
                                association.binding_write_revision
                            ))?
                        ),
                        association,
                    )
                    .await?;
                }
                if let Some(attestation) = &publication.attestation {
                    reserve(
                        journal,
                        &mut writes,
                        fact_key("attestation", &attestation.attestation_id),
                        attestation,
                    )
                    .await?;
                }
                writes.insert(receipt_key, serde_json::to_value(&expected_receipt)?);
                if let Some(receipt) = denial_receipt {
                    writes.insert(denial_key, serde_json::to_value(receipt)?);
                }
                writes.insert(head_key, serde_json::to_value(publication)?);
                writes.insert(
                    authority_key(request.authority_id(), "watermark"),
                    serde_json::to_value(watermark(publication))?,
                );
                journal.put_atomic(writes).await?;
                (Some(publication.clone()), Some(expected_receipt))
            }
        }
    };

    response(
        request,
        deployment,
        namespace,
        now,
        latest.as_ref().map(watermark),
        control_receipt,
    )
}

fn response(
    request: &StorageAuthorityRequest,
    deployment: &str,
    namespace: &str,
    now: i64,
    watermark: Option<StorageAuthorityRemoteWatermark>,
    control_receipt: Option<StorageAuthorityControlReceipt>,
) -> Result<StorageAuthorityResponse> {
    Ok(StorageAuthorityResponse {
        version: 1,
        request_digest: digest(request)?,
        nonce: request.nonce.clone(),
        deployment_id: deployment.into(),
        guard_namespace_id: namespace.into(),
        issued_at: now,
        expires_at: request.expires_at,
        watermark,
        control_receipt,
    })
}

fn watermark(publication: &StorageAuthorityPublication) -> StorageAuthorityRemoteWatermark {
    StorageAuthorityRemoteWatermark {
        authority_id: publication.authority.authority_id.clone(),
        guard_namespace_id: publication.authority.guard_namespace_id.clone(),
        generation: publication.generation,
        digest: publication.digest.clone(),
    }
}

async fn reserve<J: AuthorityJournal>(
    journal: &mut J,
    writes: &mut BTreeMap<String, Value>,
    key: String,
    value: &impl Serialize,
) -> Result<()> {
    let proposed = serde_json::to_value(value)?;
    if let Some(existing) = writes.get(&key) {
        ensure!(
            existing == &proposed,
            "publication contains conflicting physical reservations"
        );
    }
    if let Some(existing) = journal.get(&key).await? {
        ensure!(
            existing == proposed,
            "permanent authority reservation differs"
        );
    }
    writes.insert(key, proposed);
    Ok(())
}

fn authority_key(authority: &PhysicalStorageAuthorityId, suffix: &str) -> String {
    format!("authority/{}/{suffix}", authority.as_str())
}

fn fact_key(kind: &str, identity: &str) -> String {
    format!(
        "{kind}/{}",
        hex::encode(Sha256::digest(identity.as_bytes()))
    )
}

fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

#[cfg(test)]
#[path = "hybrid_authority_state/tests.rs"]
mod tests;
