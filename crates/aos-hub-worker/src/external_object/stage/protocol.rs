//! Compact private stage turns and immutable proof projections; never object bytes.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{DirectManifestPart, DirectPart, WireInteger};
use aos_hub_core::storage_authority::{
    control::StorageAuthorityObjectScope,
    external_object::stage::{
        ExternalStageAdmissionMode, ExternalStageContext, ExternalStageOperation,
        ExternalStageOutcome, ExternalStageResult,
    },
    lease::EpochLeaseFloor,
    StorageGuardStamp,
};
use aos_hub_core::storage_work::StorageWorkKey;
use serde::{Deserialize, Serialize};

use super::super::protocol::{digest, digest_string, id, MAX_MESSAGE};

pub(super) const DOMAIN: &str = "aos.external-stage-compact-turn.v1";
pub(super) const MAX_PART_PAGE: u32 = 32;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub operation_id: String,
    pub context: ExternalStageContext,
    pub operation: ExternalStageOperation,
}

impl Intent {
    pub(super) fn scope(&self) -> Result<StorageAuthorityObjectScope> {
        self.context.scope(self.operation.destination())
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(id(&self.operation_id), "invalid stage effect identity");
        self.context.validate()?;
        self.operation.validate(&self.context)?;
        self.scope()?.guard_name()?;
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_MESSAGE / 2,
            "stage intent exceeds compact journal bound"
        );
        Ok(())
    }

    pub(super) fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Turn {
    pub intent: Intent,
    pub dispatch_nonce: String,
    pub expected_incarnation: WireInteger,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub turn: Turn,
    pub outcome: ExternalStageOutcome,
}

impl Receipt {
    pub(super) fn validate(&self) -> Result<()> {
        self.turn.intent.validate()?;
        ensure!(
            digest_string(&self.turn.dispatch_nonce),
            "invalid stage dispatch nonce"
        );
        let context = &self.turn.intent.context;
        match (&self.turn.intent.operation, &self.outcome) {
            (
                ExternalStageOperation::CreateStage
                | ExternalStageOperation::CreateDestination { .. },
                ExternalStageOutcome::Created { upload_id },
            ) => {
                ensure!(
                    context.intent.byte_size.get() > 0,
                    "empty object cannot have multipart session"
                );
                provider_id(upload_id)?;
            }
            (
                ExternalStageOperation::CreateStage
                | ExternalStageOperation::CreateDestination { .. },
                ExternalStageOutcome::EmptyClosed { etag, guard_stamp },
            ) => {
                ensure!(
                    context.intent.byte_size.get() == 0,
                    "nonempty object cannot use empty PUT"
                );
                etag_stamp(&self.turn, etag, guard_stamp)?;
            }
            (ExternalStageOperation::RegisterParts { .. }, ExternalStageOutcome::Registered) => {}
            (
                ExternalStageOperation::FreezeParts {
                    first_part, parts, ..
                },
                ExternalStageOutcome::Frozen { part_count },
            ) => {
                ensure!(
                    u64::from(*part_count) == u64::from(*first_part) - 1 + parts.len() as u64,
                    "frozen count differs"
                );
            }
            (
                ExternalStageOperation::CompleteStage { upload_id, .. }
                | ExternalStageOperation::CompleteDestination { upload_id, .. },
                ExternalStageOutcome::Closed {
                    upload_id: observed,
                    etag,
                    guard_stamp,
                },
            ) => {
                ensure!(upload_id == observed, "closed provider session differs");
                provider_id(upload_id)?;
                etag_stamp(&self.turn, etag, guard_stamp)?;
            }
            (
                ExternalStageOperation::VerifyClosedStage {
                    close_receipt_digest,
                    ..
                },
                ExternalStageOutcome::Verified {
                    sha256,
                    byte_size,
                    close_receipt_digest: observed,
                },
            ) => {
                ensure!(
                    close_receipt_digest == observed
                        && sha256 == &context.intent.expected_sha256
                        && byte_size == &context.intent.byte_size,
                    "immutable stage verification differs"
                );
            }
            (
                ExternalStageOperation::CopyDestinationPart { part, .. },
                ExternalStageOutcome::Copied {
                    part: observed,
                    etag,
                },
            ) => {
                ensure!(
                    part == observed && aos_hub_core::direct_upload::valid_direct_etag(etag),
                    "copied part differs"
                );
                part.validate(&context.intent)?;
            }
            (
                ExternalStageOperation::AbortStage { upload_id }
                | ExternalStageOperation::AbortDestination { upload_id, .. },
                ExternalStageOutcome::Aborted {
                    upload_id: observed,
                },
            ) => {
                ensure!(upload_id == observed, "aborted provider session differs");
                provider_id(upload_id)?;
            }
            _ => anyhow::bail!("stage terminal outcome differs"),
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_MESSAGE,
            "stage receipt oversized"
        );
        Ok(())
    }

    pub(super) fn result(&self) -> Result<ExternalStageResult> {
        self.validate()?;
        Ok(ExternalStageResult {
            version: 1,
            operation_id: self.turn.intent.operation_id.clone(),
            intent_digest: self.turn.intent.fingerprint()?,
            receipt_digest: digest(self)?,
            outcome: self.outcome.clone(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceProof {
    pub closed: Receipt,
    pub verified: Receipt,
    pub floor: EpochLeaseFloor,
    pub configuration: String,
}

impl SourceProof {
    pub(super) fn validate(&self, context: &ExternalStageContext, expected: &str) -> Result<()> {
        self.closed.validate()?;
        self.verified.validate()?;
        ensure!(
            self.closed.turn.intent.context == *context
                && self.verified.turn.intent.context == *context
                && !self.closed.turn.intent.operation.destination()
                && digest(&self.verified)? == expected
                && self.floor.full_key == context.stage_key()?
                && self.floor.authority.authority_id == context.scope(false)?.physical_authority_id
                && digest_string(&self.configuration),
            "immutable source proof differs"
        );
        let ExternalStageOutcome::Verified {
            close_receipt_digest,
            ..
        } = &self.verified.outcome
        else {
            anyhow::bail!("source lacks full SHA verification");
        };
        ensure!(
            digest(&self.closed)? == *close_receipt_digest,
            "source verification has different close"
        );
        ensure!(
            matches!(
                self.closed.outcome,
                ExternalStageOutcome::Closed { .. } | ExternalStageOutcome::EmptyClosed { .. }
            ),
            "source provider closure absent"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub domain: String,
    pub scope: StorageAuthorityObjectScope,
    pub operation: Operation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Lookup {
        intent: Intent,
    },
    RecoveryRead {
        intent: Intent,
    },
    Delegation {
        intent: Intent,
        write_lease: String,
    },
    Begin {
        admission_mode: ExternalStageAdmissionMode,
        intent: Intent,
        write_lease: String,
        read_lease: String,
        source: Option<SourceProof>,
    },
    Terminal {
        receipt: Receipt,
    },
    ManifestPage {
        turn: Turn,
        first_part: u32,
        limit: u32,
    },
    SourceProof {
        context: ExternalStageContext,
        receipt_digest: String,
        part_number: Option<u32>,
        read_lease: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Reply {
    Unsettled,
    RecoveryRead {
        turn: Turn,
        floor: EpochLeaseFloor,
    },
    Delegation {
        receipt: Receipt,
        floor: EpochLeaseFloor,
    },
    Dispatch {
        turn: Turn,
        floor: EpochLeaseFloor,
        source: Option<SourceProof>,
        #[serde(default)]
        direct_permission_expires_at: Option<WireInteger>,
    },
    Terminal {
        receipt: Receipt,
    },
    ManifestPage {
        parts: Vec<DirectManifestPart>,
        next_part: Option<u32>,
    },
    SourceProof {
        proof: SourceProof,
        part: Option<DirectPart>,
    },
}

pub(super) fn authenticated(key: &StorageWorkKey, signature: &str, body: &[u8]) -> Result<Request> {
    ensure!(body.len() <= MAX_MESSAGE, "stage guard message oversized");
    key.verify_body(signature, body)?;
    let request: Request = serde_json::from_slice(body)?;
    ensure!(
        request.domain == DOMAIN && serde_json::to_vec(&request)? == body,
        "stage guard domain differs"
    );
    request.scope.guard_name()?;
    Ok(request)
}

fn provider_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control),
        "invalid stage provider session"
    );
    Ok(())
}

fn etag_stamp(turn: &Turn, etag: &str, stamp: &StorageGuardStamp) -> Result<()> {
    ensure!(
        aos_hub_core::direct_upload::valid_direct_etag(etag)
            && stamp.physical_authority_id == turn.intent.scope()?.physical_authority_id
            && stamp.incarnation.as_str() == turn.expected_incarnation.get().to_string(),
        "stage acknowledged identity differs"
    );
    Ok(())
}
