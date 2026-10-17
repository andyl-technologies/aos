//! Authenticated private source-closure and bounded range selectors.
//!
//! These requests address the existing exact source-key guard. Discovery has
//! no provider permission. A range carries the original and separately issued
//! read lease; its reply authenticates source selection, not stream success.
//!
//! ```text
//! request = {domain, nonce, profile_digest, expires_at, scope, selector?, plan, operation}
//! operation = lookup | check {original} | range {original, read_lease, offset, bytes}
//!           | inspect_range {closure, read_lease, etag, offset, bytes}
//!           | inspect_versioned_lookup {read_lease}
//!           | inspect_versioned_range {source, read_lease, offset, bytes}
//! reply = {request_digest, closure}
//! ```
//!
//! The plan is the authenticated application request. Copy operations retain
//! its exact selector; bounded inspection uses its own Read plan and a closure
//! loaded from the same permanent source guard. Neither path invents a copy
//! original or accepts a discovered HEAD as permanent source custody. Installed
//! immutable-version inspection instead authenticates the real version/tag/size
//! under a separate reply domain and requires exact conditional range receipts.

use anyhow::{Result, ensure};
use aos_hub_core::{
    storage_authority::{
        control::StorageAuthorityObjectScope,
        external_object::copy::{
            ExternalCopyOriginal, original_lookup::CopyOriginalSelector, source::CopySourceClosure,
        },
        lease::LeaseInteger,
    },
    storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan},
};
use serde::{Deserialize, Serialize};

use super::super::protocol::{MAX_MESSAGE, digest, digest_string};

pub(in crate::external_object) const PATH: &str = "/copy-source";
pub(in crate::external_object) const DOMAIN: &str = "aos.external-copy-protected-source.v2";
const REPLY_DOMAIN: &[u8] = b"aos.external-copy-protected-source-reply.v2\0";
pub(in crate::external_object) const RECEIPT_HEADER: &str = "x-aos-copy-source-closure";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Request {
    pub domain: String,
    pub nonce: String,
    pub profile_digest: String,
    pub expires_at: LeaseInteger,
    pub scope: StorageAuthorityObjectScope,
    pub selector: Option<CopyOriginalSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection: Option<super::super::inspection::selection::Selection>,
    pub plan: StorageWorkPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_transfer: Option<crate::direct_upload::provider_capacity::transfer::Ticket>,
    pub operation: Operation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::external_object) enum Operation {
    Lookup,
    InspectLookup {
        read_lease: String,
    },
    InspectVersionedLookup {
        read_lease: String,
    },
    InspectVersionedRange {
        source: aos_hub_core::storage_work::StorageObjectIdentity,
        read_lease: String,
        offset: u64,
        bytes: u64,
    },
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
    pub(in crate::external_object) fn validate(&self) -> Result<()> {
        self.scope.guard_name()?;
        self.plan
            .validate_observation_shape(&self.plan.deployment_id)?;
        if let Some(ticket) = &self.capacity_transfer {
            ticket.validate()?;
            ensure!(
                (matches!(self.operation, Operation::Range { .. })
                    || self.inspection.is_some()
                        && matches!(
                            self.operation,
                            Operation::InspectRange { .. }
                                | Operation::InspectVersionedRange { .. }
                        ))
                    && ticket.request_digest == self.capacity_digest()?,
                "protected capacity transfer differs from its exact range"
            );
        }
        if let Some(inspection) = &self.inspection {
            inspection.validate(&self.plan)?;
            ensure!(
                self.selector.is_none(),
                "inspection cannot borrow a copy selector"
            );
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
                    .is_none_or(|selector| self.profile_digest
                        == selector.transfer.as_ref().map_or(
                            selector.profile_digest.as_str(),
                            |transfer| transfer.source_binding.profile_digest.as_str()
                        ))
                && self.expires_at.get() == self.plan.expires_at
                && self.expires_at.get() > 0
                && serde_json::to_vec(self)?.len() <= MAX_MESSAGE,
            "protected source selector malformed or oversized"
        );
        if let Some(selector) = &self.selector {
            if let Some(transfer) = &selector.transfer {
                let binding = &transfer.source_binding;
                ensure!(
                    self.plan.binding_id == binding.binding_id.get()
                        && self.plan.binding_resource_version
                            == binding.binding_resource_version.get()
                        && self.plan.binding_snapshot_revision.as_ref()
                            == Some(&binding.snapshot_revision)
                        && self.plan.placement_id == selector.source.placement_id.get()
                        && self.plan.placement_resource_version
                            == selector.source.resource_version.get()
                        && self.plan.placement_prefix == selector.source.prefix
                        && self
                            .plan
                            .credential_references
                            .iter()
                            .any(|credential| credential.purpose == "read"
                                && credential.generation == binding.read_generation.get()),
                    "protected source selects another independently authorized source binding"
                );
            } else {
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
            }
            match &self.plan.operation {
                StorageWorkOperation::Head { path } => ensure!(
                    (matches!(self.operation, Operation::Lookup)
                        || selector.transfer.is_some()
                            && matches!(
                                self.operation,
                                Operation::Check { .. } | Operation::Range { .. }
                            ))
                        && path == &selector.path,
                    "protected metadata lookup path differs"
                ),
                StorageWorkOperation::CopyObject {
                    source_placement_id,
                    source_placement_resource_version,
                    source_prefix,
                    path,
                    expected_size,
                    expected_etag,
                    ..
                } => {
                    ensure!(
                        selector.transfer.is_none(),
                        "cross-binding protected read lacks independent source plan"
                    );
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
            Operation::InspectVersionedLookup { read_lease } => {
                ensure!(
                    self.inspection.is_some() && self.selector.is_none() && !read_lease.is_empty(),
                    "versioned lookup lacks typed Read permission"
                );
            }
            Operation::InspectVersionedRange {
                source,
                read_lease,
                offset,
                bytes,
            } => {
                let selection = self
                    .inspection
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("versioned selection absent"))?;
                super::super::inspection::versioned::validate_identity(self, source)?;
                ensure!(
                    self.selector.is_none()
                        && !read_lease.is_empty()
                        && (*bytes > 0 || source.size == 0 && *offset == 0)
                        && *bytes <= aos_hub_core::direct_upload::MAX_DIRECT_PART_BYTES
                        && offset
                            .checked_add(*bytes)
                            .is_some_and(|end| end <= source.size)
                        && source.size <= selection.maximum_bytes
                        && !matches!(self.plan.operation, StorageWorkOperation::Head { .. }),
                    "versioned inspection geometry differs"
                );
                if let StorageWorkOperation::HashOciRange {
                    start,
                    end,
                    total,
                    strong_etag,
                    expected_provider_version,
                    guarded_source,
                    ..
                } = &self.plan.operation
                {
                    ensure!(
                        guarded_source.is_none()
                            && expected_provider_version == &source.provider_version
                            && *total == source.size
                            && strong_etag == &source.etag
                            && *offset >= *start
                            && offset.checked_add(*bytes).is_some_and(|limit| end
                                .checked_add(1)
                                .is_some_and(|signed| limit <= signed)),
                        "versioned inventory interval or original source differs"
                    );
                }
                if let StorageWorkOperation::InspectOciRange { start, end, .. } =
                    &self.plan.operation
                {
                    ensure!(
                        *offset >= *start
                            && offset.checked_add(*bytes).is_some_and(|limit| end
                                .checked_add(1)
                                .is_some_and(|signed| limit <= signed)),
                        "versioned OCI subinterval differs from signed range"
                    );
                }
            }
            Operation::InspectLookup { read_lease } => {
                ensure!(
                    self.inspection.is_some() && !read_lease.is_empty(),
                    "inspection lookup lacks a typed read lease"
                );
            }
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
                    original.source_incarnation()? == aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::GuardedClosure
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
                    _ if self.inspection.is_some() => {
                        ensure!(
                            !matches!(self.plan.operation, StorageWorkOperation::Head { .. }),
                            "protected metadata HEAD cannot authorize a source range"
                        );
                        let selection = self
                            .inspection
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("typed selection absent"))?;
                        ensure!(
                            closure.bytes.get() as u64 <= selection.maximum_bytes
                                && selection
                                    .expected_sha256
                                    .as_ref()
                                    .is_none_or(|hash| hash == &closure.sha256),
                            "typed inspection closure exceeds source bounds"
                        );
                        if let StorageWorkOperation::InspectOciRange { start, end, .. } =
                            &self.plan.operation
                        {
                            ensure!(
                                *offset >= *start
                                    && offset.checked_add(*bytes).is_some_and(|limit| end
                                        .checked_add(1)
                                        .is_some_and(|signed| limit <= signed)),
                                "typed OCI subinterval differs from its exact signed range"
                            );
                        }
                        if let StorageWorkOperation::HashOciRange {
                            start,
                            end,
                            guarded_source,
                            ..
                        } = &self.plan.operation
                        {
                            let guarded = guarded_source.as_ref().ok_or_else(|| {
                                anyhow::anyhow!("protected inventory closure absent")
                            })?;
                            ensure!(
                                guarded.scope == self.scope
                                    && guarded.closure == *closure
                                    && *offset >= *start
                                    && offset.checked_add(*bytes).is_some_and(|limit| end
                                        .checked_add(1)
                                        .is_some_and(|signed| limit <= signed)),
                                "protected inventory changed its closed source or signed interval"
                            );
                        }
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
    pub(in crate::external_object) fn capacity_digest(&self) -> Result<String> {
        let mut original = self.clone();
        original.capacity_transfer = None;
        digest(&original)
    }

    /// Checks live permission after each await without extending the original cutoff.
    ///
    /// # Errors
    /// Refuses elapsed deadlines or an unbounded request lifetime.
    pub(in crate::external_object) fn current(&self, latest_now: i64) -> Result<()> {
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
pub(in crate::external_object) fn authenticate(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
) -> Result<Request> {
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
pub(in crate::external_object) fn sign_reply(
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
pub(in crate::external_object) fn verify_reply(
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

/// Authenticated transient lookup result, never permission or durable absence.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct InspectionLookup {
    pub request_digest: String,
    pub closure: Option<CopySourceClosure>,
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versioned_source: Option<aos_hub_core::storage_work::StorageObjectIdentity>,
}

const INSPECTION_REPLY_DOMAIN: &[u8] = b"aos.external-protected-inspection-lookup.v1\0";

pub(in crate::external_object) fn sign_inspection_lookup(
    key: &StorageWorkKey,
    request: &Request,
    closure: Option<CopySourceClosure>,
    etag: Option<String>,
) -> Result<(Vec<u8>, String)> {
    request.validate()?;
    ensure!(
        matches!(request.operation, Operation::InspectLookup { .. }),
        "lookup result lacks typed request"
    );
    let reply = InspectionLookup {
        request_digest: digest(request)?,
        closure,
        etag,
        versioned_source: None,
    };
    validate_inspection_lookup(request, &reply)?;
    let body = serde_json::to_vec(&reply)?;
    ensure!(
        body.len() <= MAX_MESSAGE,
        "inspection lookup result oversized"
    );
    let signature = key.sign_body(&[INSPECTION_REPLY_DOMAIN, &body].concat())?;
    Ok((body, signature))
}

pub(in crate::external_object) fn verify_inspection_lookup(
    key: &StorageWorkKey,
    request: &Request,
    signature: &str,
    body: &[u8],
) -> Result<InspectionLookup> {
    request.validate()?;
    ensure!(
        body.len() <= MAX_MESSAGE,
        "inspection lookup reply oversized"
    );
    key.verify_body(signature, &[INSPECTION_REPLY_DOMAIN, body].concat())?;
    let reply: InspectionLookup = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&reply)? == body,
        "inspection lookup reply noncanonical"
    );
    validate_inspection_lookup(request, &reply)?;
    Ok(reply)
}

fn validate_inspection_lookup(request: &Request, reply: &InspectionLookup) -> Result<()> {
    ensure!(
        reply.versioned_source.is_none(),
        "protected lookup cannot adopt provider versions"
    );
    ensure!(
        matches!(request.operation, Operation::InspectLookup { .. })
            && reply.request_digest == digest(request)?,
        "inspection lookup correlation differs"
    );
    match (&reply.closure, &reply.etag) {
        (None, None) => Ok(()),
        (Some(closure), Some(etag)) => {
            closure.validate()?;
            request.scope.validate_stamp(&closure.guard_stamp)?;
            aos_hub_core::surface_write::strong_if_match_etag(etag)?;
            let selected = request
                .inspection
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("inspection source absent"))?;
            ensure!(
                closure.bytes.get() as u64 <= selected.maximum_bytes
                    && closure.etag.as_ref().is_none_or(|actual| actual == etag)
                    && selected
                        .expected_sha256
                        .as_ref()
                        .is_none_or(|actual| actual == &closure.sha256),
                "inspection lookup closure differs"
            );
            Ok(())
        }
        _ => anyhow::bail!("inspection lookup has incomplete source identity"),
    }
}

const VERSIONED_REPLY_DOMAIN: &[u8] = b"aos.external-versioned-inspection-source.v1\0";

/// Authenticates actual versioned discovery or an exact conditional range identity.
///
/// # Errors
/// Refuses another mode, physical selection or malformed provider identity.
pub(in crate::external_object) fn sign_versioned_source(
    key: &StorageWorkKey,
    request: &Request,
    source: Option<aos_hub_core::storage_work::StorageObjectIdentity>,
) -> Result<(Vec<u8>, String)> {
    request.validate()?;
    let reply = InspectionLookup {
        request_digest: digest(request)?,
        closure: None,
        etag: source.as_ref().map(|source| source.etag.clone()),
        versioned_source: source,
    };
    validate_versioned_source(request, &reply)?;
    let body = serde_json::to_vec(&reply)?;
    ensure!(
        body.len() <= MAX_MESSAGE,
        "versioned source receipt oversized"
    );
    let signature = key.sign_body(&[VERSIONED_REPLY_DOMAIN, &body].concat())?;
    Ok((body, signature))
}

/// Verifies a mode-separated provider identity without creating a producer closure.
///
/// # Errors
/// Refuses wrong MAC, nonce, mode, source selection or noncanonical bytes.
pub(in crate::external_object) fn verify_versioned_source(
    key: &StorageWorkKey,
    request: &Request,
    signature: &str,
    body: &[u8],
) -> Result<InspectionLookup> {
    request.validate()?;
    ensure!(
        body.len() <= MAX_MESSAGE,
        "versioned source receipt oversized"
    );
    key.verify_body(signature, &[VERSIONED_REPLY_DOMAIN, body].concat())?;
    let reply: InspectionLookup = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&reply)? == body,
        "versioned source receipt noncanonical"
    );
    validate_versioned_source(request, &reply)?;
    Ok(reply)
}

fn validate_versioned_source(request: &Request, reply: &InspectionLookup) -> Result<()> {
    ensure!(
        reply.request_digest == digest(request)? && reply.closure.is_none(),
        "versioned source correlation or mode differs"
    );
    match &request.operation {
        Operation::InspectVersionedLookup { .. } => {}
        Operation::InspectVersionedRange { source, .. } => ensure!(
            reply.versioned_source.as_ref() == Some(source),
            "versioned range source changed"
        ),
        _ => anyhow::bail!("versioned receipt has another operation"),
    }
    if let Some(source) = &reply.versioned_source {
        super::super::inspection::versioned::validate_identity(request, source)?;
        ensure!(
            reply.etag.as_ref() == Some(&source.etag),
            "versioned tag differs"
        );
    } else {
        ensure!(reply.etag.is_none(), "absent versioned source has a tag");
    }
    Ok(())
}
