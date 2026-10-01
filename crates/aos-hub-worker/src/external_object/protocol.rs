//! Closed nonsecret compact-turn wire and semantic replay identities.
//!
//! ```text
//! request = {domain, scope, operation}
//! begin = {kind: "begin", intent, lease}
//! terminal = {kind: "terminal", receipt: {turn, outcome}}
//! turn = {intent: {scope, operation_id, context, cohort_digest, effect},
//!         dispatch_nonce}
//! ```

use anyhow::{ensure, Result};
#[cfg(target_arch = "wasm32")]
pub(super) use aos_hub_core::storage_authority::external_object::ExternalObjectHead as HeadValue;
pub(super) use aos_hub_core::storage_authority::external_object::ExternalObjectOutcome as Outcome;
use aos_hub_core::storage_authority::{
    control::StorageAuthorityObjectScope,
    lease::{EpochLeaseFloor, LeaseEffect},
};
use aos_hub_core::storage_work::StorageWorkKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(super) const MAX_MESSAGE: usize = 64 * 1024;
pub(super) const MAX_RECEIPT: usize = 8 * 1024;
pub(super) const GUARD_HEADER: &str = "x-aos-external-object-guard-signature";
pub(super) const SCOPE_HEADER: &str = "x-aos-external-object-scope";
pub(super) const DOMAIN: &str = "aos.external-object-compact-turn.v1";

/// Exact nonsecret turn metadata; tokens and request identities are excluded.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub scope: StorageAuthorityObjectScope,
    pub operation_id: String,
    pub context: String,
    pub cohort_digest: String,
    pub effect: Effect,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Effect {
    Put {
        sha256: String,
        bytes: u32,
    },
    Head,
    ProbeHash {
        maximum_bytes: u32,
    },
    Delete {
        expected:
            aos_hub_core::storage_authority::external_object::deletion::ExternalDeletePrecondition,
    },
}

impl Effect {
    pub(super) fn lease_effect(&self) -> LeaseEffect {
        match self {
            Self::Put { .. } => LeaseEffect::Put,
            Self::Head => LeaseEffect::Head,
            Self::ProbeHash { .. } => LeaseEffect::Read,
            Self::Delete { .. } => LeaseEffect::ConditionalDelete,
        }
    }
}

impl Intent {
    pub(super) fn validate(&self) -> Result<()> {
        self.scope.guard_name()?;
        ensure!(
            id(&self.operation_id)
                && digest_string(&self.context)
                && digest_string(&self.cohort_digest),
            "invalid object turn identity"
        );
        if let Effect::Put { sha256, bytes } = &self.effect {
            ensure!(
                digest_string(sha256)
                    && *bytes as usize <= aos_hub_core::storage_work::MAX_METADATA_BYTES,
                "invalid metadata commitment"
            );
        }
        if let Effect::Delete { expected } = &self.effect {
            expected.validate()?;
        }
        if let Effect::ProbeHash { maximum_bytes } = self.effect {
            ensure!(
                (1..=4096).contains(&maximum_bytes),
                "reserved probe hash bound invalid"
            );
        }
        Ok(())
    }

    pub(super) fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub intent: Intent,
    pub dispatch_nonce: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub turn: Pending,
    pub outcome: Outcome,
}

impl Receipt {
    pub(super) fn validate(&self) -> Result<()> {
        self.turn.intent.validate()?;
        ensure!(
            digest_string(&self.turn.dispatch_nonce),
            "invalid dispatch nonce"
        );
        match (&self.turn.intent.effect, &self.outcome) {
            (Effect::Put { .. }, Outcome::PutAcknowledged) => {}
            (Effect::Head, Outcome::HistoricalHead { object }) => {
                if let Some(value) = object {
                    ensure!(
                        value.bytes.parse::<u64>()?.to_string() == value.bytes,
                        "invalid historical size"
                    );
                    ensure!(value.etag.len() <= 1024, "oversized historical ETag");
                    ensure!(
                        value
                            .provider_version
                            .as_deref()
                            .is_none_or(aos_hub_core::storage_work::valid_provider_version),
                        "invalid provider version"
                    );
                    aos_hub_core::surface_write::strong_if_match_etag(&value.etag)?;
                }
            }
            (
                Effect::Delete { expected },
                Outcome::DeleteAcknowledged {
                    provider_version,
                    etag,
                },
            ) => {
                ensure!(
                    *provider_version == expected.provider_version && *etag == expected.etag,
                    "provider acknowledged another deletion incarnation"
                );
            }
            (Effect::Delete { .. }, Outcome::DeleteAbsent | Outcome::DeletePreconditionFailed) => {}
            (Effect::ProbeHash { maximum_bytes }, Outcome::ProbeEvidence { object, sha256 }) => {
                ensure!(
                    digest_string(sha256)
                        && object.bytes.parse::<u32>()?.to_string() == object.bytes
                        && object.bytes.parse::<u32>()? <= *maximum_bytes
                        && object.provider_version.as_deref().is_none_or(aos_hub_core::storage_work::valid_provider_version),
                    "reserved probe snapshot identity invalid"
                );
                aos_hub_core::surface_write::strong_if_match_etag(&object.etag)?;
            }
            _ => anyhow::bail!("terminal outcome differs from turn"),
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_RECEIPT,
            "oversized terminal receipt"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuardRequest {
    pub domain: String,
    pub scope: StorageAuthorityObjectScope,
    pub operation: GuardOperation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum GuardOperation {
    Lookup { intent: Intent },
    Begin { intent: Intent, lease: String },
    Terminal { receipt: Receipt },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum GuardReply {
    Unseen,
    Dispatch {
        turn: Pending,
        floor: EpochLeaseFloor,
    },
    Terminal {
        receipt: Receipt,
    },
}

pub(super) fn authenticated(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
) -> Result<GuardRequest> {
    ensure!(body.len() <= MAX_MESSAGE, "oversized guard message");
    key.verify_body(signature, body)?;
    let value: GuardRequest = serde_json::from_slice(body)?;
    ensure!(
        value.domain == DOMAIN && serde_json::to_vec(&value)? == body,
        "invalid compact turn domain or encoding"
    );
    value.scope.guard_name()?;
    Ok(value)
}

pub(super) fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

pub(super) fn digest_string(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}
