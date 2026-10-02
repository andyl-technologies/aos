//! Authenticated private source-closure and bounded range selectors.
//!
//! These requests address the existing exact source-key guard. Discovery has
//! no provider permission. A range carries the original and separately issued
//! read lease; its reply describes a pre-existing closure, not stream success.
//!
//! ```text
//! request = {domain, nonce, profile_digest, expires_at, scope, selector?, plan, operation}
//! operation = lookup | check {original} | range {original, read_lease, offset, bytes}
//!           | inspect_range {closure, read_lease, etag, offset, bytes}
//! reply = {request_digest, closure}
//! ```
//!
//! The plan is the authenticated application request. Copy operations retain
//! its exact selector; bounded inspection uses its own Read plan and a closure
//! loaded from the same permanent source guard. Neither path invents a copy
//! original or accepts a discovered HEAD as source custody.

use anyhow::{ensure, Result};
use aos_hub_core::{
    storage_authority::{
        control::StorageAuthorityObjectScope,
        external_object::copy::{
            original_lookup::CopyOriginalSelector, source::CopySourceClosure, ExternalCopyOriginal,
        },
        lease::LeaseInteger,
    },
    storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan},
};
use serde::{Deserialize, Serialize};

use super::super::protocol::{digest, digest_string, MAX_MESSAGE};

pub(super) const PATH: &str = "/copy-source";
pub(super) const DOMAIN: &str = "aos.external-copy-protected-source.v2";
const REPLY_DOMAIN: &[u8] = b"aos.external-copy-protected-source-reply.v2\0";
pub(super) const RECEIPT_HEADER: &str = "x-aos-copy-source-closure";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub domain: String,
    pub nonce: String,
    pub profile_digest: String,
    pub expires_at: LeaseInteger,
    pub scope: StorageAuthorityObjectScope,
    pub selector: Option<CopyOriginalSelector>,
    pub plan: StorageWorkPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_transfer: Option<crate::direct_upload::provider_capacity::transfer::Ticket>,
    pub operation: Operation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Lookup,
    Check {
        original: ExternalCopyOriginal,
    },
    Range {
        original: ExternalCopyOriginal,
        read_lease: String,
        offset: u64,
        bytes: u64,
    },
    InspectRange {
        closure: CopySourceClosure,
        read_lease: String,
        etag: String,
        offset: u64,
        bytes: u64,
    },
}

impl Request {
    /// Checks closed selectors without authenticating a lease or accessing storage.
    ///
    /// # Errors
    /// Refuses malformed physical/original pins, excessive geometry or absent lease.
    pub(super) fn validate(&self) -> Result<()> {
        self.scope.guard_name()?;
        self.plan
            .validate_observation_shape(&self.plan.deployment_id)?;
        if let Some(ticket) = &self.capacity_transfer {
            ticket.validate()?;
            ensure!(matches!(self.operation, Operation::Range { .. })
                && ticket.request_digest == self.capacity_digest()?,
                "protected capacity transfer differs from its exact range");
        }
        if let Some(selector) = &self.selector {
            selector.validate()?;
        }
        ensure!(
            self.domain == DOMAIN
                && digest_string(&self.nonce)
                && digest_string(&self.profile_digest)
                && self
                    .selector
                    .as_ref()
                    .is_none_or(|selector| self.profile_digest == selector.profile_digest)
                && self.expires_at.get() == self.plan.expires_at
                && self.expires_at.get() > 0
                && serde_json::to_vec(self)?.len() <= MAX_MESSAGE,
            "protected source selector malformed or oversized"
        );
        if let Some(selector) = &self.selector {
            ensure!(
                self.plan.binding_id == selector.destination.binding_id.get()
                    && self.plan.binding_resource_version
                        == selector.binding_resource_version.get()
                    && self.plan.binding_snapshot_revision.as_ref()
                        == Some(&selector.snapshot_revision)
                    && self.plan.placement_id == selector.destination.placement_id.get()
                    && self.plan.placement_resource_version
                        == selector.destination.resource_version.get()
                    && self.plan.placement_prefix == selector.destination.prefix,
                "protected source application selects another current destination"
            );
            match &self.plan.operation {
                StorageWorkOperation::Head { path } => ensure!(
                    matches!(self.operation, Operation::Lookup) && path == &selector.path,
                    "protected metadata lookup path differs"
                ),
                StorageWorkOperation::CopyObject {
                    source_placement_id,
                    source_placement_resource_version,
                    source_prefix,
                    path,
                    expected_size,
                    expected_etag,
                } => {
                    let original = match &self.operation {
                        Operation::Check { original } | Operation::Range { original, .. } => {
                            original
                        }
                        _ => anyhow::bail!("protected copy plan lacks its actual original"),
                    };
                    ensure!(
                        *source_placement_id == original.source.placement_id.get()
                            && *source_placement_resource_version
                                == original.source.resource_version.get()
                            && source_prefix == &original.source.prefix
                            && path == &original.path
                            && *expected_size == original.source_object.bytes.get() as u64
                            && expected_etag == &original.source_object.etag,
                        "protected copy read plan differs from the immutable source"
                    );
                }
                _ => anyhow::bail!("protected copy plan operation differs"),
            }
        }
        match &self.operation {
            Operation::Lookup => {
                ensure!(
                    self.selector.is_some()
                        || matches!(
                            self.plan.operation,
                            StorageWorkOperation::InspectSha256 { .. }
                        ),
                    "protected source lookup lacks a signed read selector"
                );
            }
            Operation::Check { original } | Operation::Range { original, .. } => {
                original.validate()?;
                ensure!(
                    original.version == 2
                        && self.selector.as_ref()
                            == Some(&CopyOriginalSelector::from_original(original)?),
                    "protected source original differs from its selector"
                );
            }
            Operation::InspectRange {
                closure,
                read_lease,
                etag,
                offset,
                bytes,
            } => {
                closure.validate()?;
                aos_hub_core::surface_write::strong_if_match_etag(etag)?;
                ensure!(
                    closure
                        .etag
                        .as_ref()
                        .is_none_or(|selected| selected == etag),
                    "protected inspection tag differs from the retained closure"
                );
                ensure!(
                    self.selector.is_none()
                        && !read_lease.is_empty()
                        && *bytes > 0
                        && *bytes <= aos_hub_core::direct_upload::MAX_DIRECT_PART_BYTES
                        && offset
                            .checked_add(*bytes)
                            .is_some_and(|end| end <= closure.bytes.get() as u64),
                    "protected inspection geometry differs"
                );
                match &self.plan.operation {
                    StorageWorkOperation::InspectSha256 {
                        expected_sha256,
                        max_source_bytes,
                        ..
                    } => {
                        ensure!(
                            closure.bytes.get() as u64 <= *max_source_bytes
                                && expected_sha256
                                    .as_ref()
                                    .is_none_or(|hash| hash.eq_ignore_ascii_case(&closure.sha256)),
                            "protected inspection exceeds signed hash bounds"
                        );
                    }
                    _ => anyhow::bail!("protected inspection lacks a signed read operation"),
                }
            }
        }
        if let Operation::Range {
            original,
            read_lease,
            offset,
            bytes,
        } = &self.operation
        {
            let part = offset
                .checked_div(original.part_bytes.get() as u64)
                .and_then(|index| u32::try_from(index + 1).ok())
                .ok_or_else(|| anyhow::anyhow!("protected source part overflows"))?;
            ensure!(
                !read_lease.is_empty() && original.part_range(part)? == (*offset, *bytes),
                "protected source range differs from exact part geometry"
            );
        }
        Ok(())
    }

    /// Commits the exact range before its one-use capacity ticket is attached.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    pub(super) fn capacity_digest(&self) -> Result<String> {
        let mut original = self.clone();
        original.capacity_transfer = None;
        digest(&original)
    }

    /// Checks live permission after each await without extending the original cutoff.
    ///
    /// # Errors
    /// Refuses elapsed deadlines or an unbounded request lifetime.
    pub(super) fn current(&self, latest_now: i64) -> Result<()> {
        self.validate()?;
        ensure!(
            self.expires_at
                .get()
                .checked_sub(latest_now)
                .is_some_and(|remaining| (1..=60).contains(&remaining)),
            "protected source request expired or unbounded"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    request_digest: String,
    closure: CopySourceClosure,
}

/// Authenticates canonical selectors before interpreting physical scope.
///
/// # Errors
/// Refuses oversized, unauthenticated, noncanonical or intrinsically invalid bytes.
pub(super) fn authenticate(key: &StorageWorkKey, signature: &str, body: &[u8]) -> Result<Request> {
    ensure!(
        body.len() <= MAX_MESSAGE,
        "protected source request oversized"
    );
    key.verify_body(signature, body)?;
    let request: Request = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&request)? == body,
        "protected source request noncanonical"
    );
    request.validate()?;
    Ok(request)
}

/// Signs exact retained metadata without declaring range EOF or provider effects.
///
/// # Errors
/// Refuses changed incarnation, malformed closure or an excessive response.
pub(super) fn sign_reply(
    key: &StorageWorkKey,
    request: &Request,
    closure: CopySourceClosure,
) -> Result<(Vec<u8>, String)> {
    request.validate()?;
    closure.validate()?;
    if let Operation::Check { original } | Operation::Range { original, .. } = &request.operation {
        closure.validate_for(original)?;
    } else if let Operation::InspectRange {
        closure: expected, ..
    } = &request.operation
    {
        ensure!(closure == *expected, "protected inspection closure changed");
    }
    let body = serde_json::to_vec(&Reply {
        request_digest: digest(request)?,
        closure,
    })?;
    ensure!(
        body.len() <= MAX_MESSAGE,
        "protected source reply oversized"
    );
    let signature = key.sign_body(&[REPLY_DOMAIN, &body].concat())?;
    Ok((body, signature))
}

/// Verifies the exact protected source declaration without granting body authority.
///
/// # Errors
/// Refuses another request, wrong MAC/domain, malformed or noncanonical metadata.
pub(super) fn verify_reply(
    key: &StorageWorkKey,
    request: &Request,
    signature: &str,
    body: &[u8],
) -> Result<CopySourceClosure> {
    request.validate()?;
    ensure!(
        body.len() <= MAX_MESSAGE,
        "protected source reply oversized"
    );
    key.verify_body(signature, &[REPLY_DOMAIN, body].concat())?;
    let reply: Reply = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&reply)? == body && reply.request_digest == digest(request)?,
        "protected source reply differs"
    );
    reply.closure.validate()?;
    if let Operation::Check { original } | Operation::Range { original, .. } = &request.operation {
        reply.closure.validate_for(original)?;
    } else if let Operation::InspectRange {
        closure: expected, ..
    } = &request.operation
    {
        ensure!(
            reply.closure == *expected,
            "protected inspection closure changed"
        );
    }
    Ok(reply.closure)
}

#[cfg(test)]
mod tests;
