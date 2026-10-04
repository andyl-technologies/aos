//! Separately authenticated copy guard controls and private byte continuations.
//!
//! Public application requests cannot carry hash states or part receipts. This
//! wire is available only to the independent physical guard and its executor.
//! Both directions bind a distinct MAC domain and the exact canonical request.
//!
//! ```text
//! request = {domain, scope, original, operation}
//! operation = lookup | begin | terminal | manifest_page
//! reply = {request_digest, value}
//! dispatch = {turn, floor, source_state}
//! ```

use anyhow::{Result, ensure};
use aos_hub_core::{
    db::OciSha256State,
    storage_authority::{
        control::StorageAuthorityObjectScope,
        external_object::copy::{
            ExternalCopyOriginal,
            control::{CopyControl, CopyProgress},
            session::{CopyAction, CopyReceipt, CopyTurn},
        },
        lease::{EpochLeaseFloor, LeaseInteger},
    },
    storage_work::StorageWorkKey,
};
use serde::{Deserialize, Serialize};

use super::super::protocol::{MAX_MESSAGE, digest, digest_string};

pub(super) const DOMAIN: &str = "aos.external-copy-private-turn.v1";
pub(super) const PATH: &str = "/copy-turn";
const REPLY_DOMAIN: &[u8] = b"aos.external-copy-private-reply.v1\0";
pub(super) const MAX_PART_PAGE: u32 = 32;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub domain: String,
    pub request_nonce: String,
    pub permission_expires_at: LeaseInteger,
    pub scope: StorageAuthorityObjectScope,
    pub original: ExternalCopyOriginal,
    pub operation: Operation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Lookup,
    SourceRead {
        read_lease: String,
    },
    Begin {
        control: CopyControl,
        write_lease: String,
    },
    Terminal {
        receipt: CopyReceipt,
    },
    ManifestPage {
        turn: CopyTurn,
        first_part: u32,
        limit: u32,
    },
}

impl Request {
    /// Checks private selectors without treating them as current lease authority.
    ///
    /// # Errors
    /// Refuses foreign domains, malformed originals or a caller-selected turn.
    pub(super) fn validate(&self) -> Result<()> {
        self.original.validate()?;
        self.scope.guard_name()?;
        ensure!(
            self.domain == DOMAIN
                && digest_string(&self.request_nonce)
                && self.permission_expires_at.get() > 0
                && serde_json::to_vec(self)?.len() <= MAX_MESSAGE,
            "copy guard domain or input bound differs"
        );
        match &self.operation {
            Operation::Lookup => {}
            Operation::SourceRead { read_lease } => {
                ensure!(!read_lease.is_empty(), "copy read lease absent");
            }
            Operation::Begin {
                control,
                write_lease,
            } => {
                ensure!(
                    *control != CopyControl::Status && !write_lease.is_empty(),
                    "copy dispatch selection or lease absent"
                );
            }
            Operation::Terminal { receipt } => self.validate_turn(&receipt.turn)?,
            Operation::ManifestPage {
                turn,
                first_part,
                limit,
            } => {
                self.validate_turn(turn)?;
                ensure!(
                    matches!(turn.action, CopyAction::Complete { .. })
                        && *first_part > 0
                        && (1..=MAX_PART_PAGE).contains(limit),
                    "copy manifest page selector differs"
                );
            }
        }
        Ok(())
    }

    fn validate_turn(&self, turn: &CopyTurn) -> Result<()> {
        ensure!(
            turn.copy_id == self.original.copy_id()?
                && turn.original_digest == self.original.fingerprint()?
                && turn.action_id == turn.action.operation_id(&self.original)?,
            "copy turn original differs"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Part {
    pub number: u32,
    pub etag: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Reply {
    Unseen,
    Progress {
        progress: CopyProgress,
    },
    ReadAuthorized {
        floor: EpochLeaseFloor,
    },
    Dispatch {
        turn: CopyTurn,
        floor: EpochLeaseFloor,
        source_state: Option<OciSha256State>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination_stamp: Option<aos_hub_core::storage_authority::StorageGuardStamp>,
    },
    ManifestPage {
        parts: Vec<Part>,
        next_part: Option<u32>,
    },
}

impl Reply {
    fn validate(&self, request: &Request) -> Result<()> {
        match (self, &request.operation) {
            (Self::Unseen, Operation::Lookup) => {}
            (Self::ReadAuthorized { floor }, Operation::SourceRead { .. }) => {
                ensure!(
                    floor.full_key == request.scope.full_key
                        && floor.authority.authority_id == request.scope.physical_authority_id,
                    "copy read floor physical identity differs"
                );
            }
            (
                Self::Progress { progress },
                Operation::Lookup | Operation::Begin { .. } | Operation::Terminal { .. },
            ) => progress.validate(&request.original)?,
            (
                Self::Dispatch {
                    turn,
                    floor,
                    source_state,
                    destination_stamp,
                },
                Operation::Begin { .. },
            ) => {
                ensure!(
                    match (request.original.destination_incarnation()?, destination_stamp) {
                        (aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::ProviderVersion, None) => true,
                        (aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::GuardedClosure, Some(stamp)) =>
                            stamp.physical_authority_id == request.scope.physical_authority_id,
                        _ => false,
                    },
                    "copy destination incarnation projection differs"
                );
                request.validate_turn(turn)?;
                ensure!(
                    digest_string(&turn.dispatch_nonce)
                        && floor.full_key == request.scope.full_key
                        && floor.authority.authority_id == request.scope.physical_authority_id,
                    "copy private dispatch physical identity differs"
                );
                match (&turn.action, source_state) {
                    (
                        CopyAction::Part {
                            offset,
                            source_state_digest,
                            ..
                        },
                        Some(state),
                    ) => {
                        state.validate()?;
                        ensure!(
                            state.total_bytes == *offset && digest(state)? == *source_state_digest,
                            "copy private continuation differs from exact turn"
                        );
                    }
                    (CopyAction::Part { .. }, None) => anyhow::bail!("copy continuation absent"),
                    (_, Some(_)) => anyhow::bail!("unexpected copy continuation"),
                    (_, None) => {}
                }
            }
            (
                Self::ManifestPage { parts, next_part },
                Operation::ManifestPage {
                    first_part, limit, ..
                },
            ) => {
                ensure!(
                    !parts.is_empty() && parts.len() <= *limit as usize,
                    "copy manifest page bound differs"
                );
                for (index, part) in parts.iter().enumerate() {
                    let number = first_part
                        .checked_add(index as u32)
                        .ok_or_else(|| anyhow::anyhow!("copy manifest page overflow"))?;
                    let (_, bytes) = request.original.part_range(number)?;
                    ensure!(
                        part.number == number
                            && part.bytes == bytes
                            && !part.etag.is_empty()
                            && part.etag.len() <= 1024
                            && !part.etag.chars().any(char::is_control)
                            && digest_string(&part.sha256),
                        "copy manifest part differs"
                    );
                }
                let end = first_part
                    .checked_add(parts.len() as u32)
                    .ok_or_else(|| anyhow::anyhow!("copy manifest page overflow"))?;
                ensure!(
                    *next_part == (end <= request.original.part_count()?).then_some(end),
                    "copy manifest continuation differs"
                );
            }
            _ => anyhow::bail!("copy guard reply is for another operation"),
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    request_digest: String,
    value: Reply,
}

/// Authenticates a private request before interpreting continuation selectors.
///
/// # Errors
/// Refuses malformed, noncanonical, oversized or unauthenticated controls.
pub(super) fn authenticate(key: &StorageWorkKey, signature: &str, body: &[u8]) -> Result<Request> {
    ensure!(body.len() <= MAX_MESSAGE, "copy guard request oversized");
    key.verify_body(signature, body)?;
    let request: Request = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&request)? == body,
        "noncanonical copy guard request"
    );
    request.validate()?;
    Ok(request)
}

/// Signs private state only for its exact independently authenticated request.
///
/// # Errors
/// Refuses malformed selectors or a reply exceeding the compact wire bound.
pub(super) fn sign_reply(
    key: &StorageWorkKey,
    request: &Request,
    value: Reply,
) -> Result<(Vec<u8>, String)> {
    request.validate()?;
    value.validate(request)?;
    let body = serde_json::to_vec(&Envelope {
        request_digest: digest(request)?,
        value,
    })?;
    ensure!(body.len() <= MAX_MESSAGE, "copy guard reply oversized");
    let signature = key.sign_body(&[REPLY_DOMAIN, &body].concat())?;
    Ok((body, signature))
}

/// Verifies the exact private state source before a byte executor uses it.
///
/// # Errors
/// Refuses a changed request, wrong key/domain, noncanonical JSON or oversized reply.
pub(super) fn verify_reply(
    key: &StorageWorkKey,
    request: &Request,
    signature: &str,
    body: &[u8],
) -> Result<Reply> {
    request.validate()?;
    ensure!(body.len() <= MAX_MESSAGE, "copy guard reply oversized");
    key.verify_body(signature, &[REPLY_DOMAIN, body].concat())?;
    let envelope: Envelope = serde_json::from_slice(body)?;
    ensure!(
        envelope.request_digest == digest(request)? && serde_json::to_vec(&envelope)? == body,
        "copy guard reply original differs"
    );
    envelope.value.validate(request)?;
    Ok(envelope.value)
}

#[cfg(test)]
mod tests;
