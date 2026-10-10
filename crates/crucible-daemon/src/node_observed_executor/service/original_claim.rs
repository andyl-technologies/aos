//! Excludes competing preparation routes before any native allocation.
//!
//! ```text
//! OriginalClaim.1 = execution + route + exact original request ContentId
//! ```
//!
//! One common compare-and-exchange selects the original route. The publication
//! guard protects its immutable children from GC; it is deliberately not used
//! as a mutex. A retained claim supplies custody, never dispatch permission.

use super::{NodeObservationServiceError, refused};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};
use crucible_node_contract::canonical;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

const MAXIMUM_RECORDS: usize = 4096;
const MAXIMUM_REQUEST_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Route {
    Ordinary,
    Conditional,
    Capability,
    Root,
    Debug,
    DebugPreserving,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    format: String,
    version: u32,
    execution: String,
    route: Route,
    request: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Quota {
    format: String,
    version: u32,
    consumed: usize,
}

/// Distinguishes a new original reservation from retained historical custody.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Reservation {
    Original,
    Retained,
}

#[derive(Clone)]
pub(super) struct OriginalClaims {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

impl OriginalClaims {
    pub(super) fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        if !refs.capabilities().durable {
            return Err(refused("original route claims require durable refs"));
        }
        Ok(Self { blobs, refs })
    }

    /// Reserves exactly one original route without executing or authenticating it.
    pub(super) fn reserve(
        &self,
        execution: &str,
        route: Route,
        request: &[u8],
    ) -> Result<Reservation, NodeObservationServiceError> {
        super::conditional_preparation::validate_execution(execution)?;
        if request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(refused("original route request exceeds finite byte credit"));
        }
        let request_id = ContentId::for_bytes(ObjectKind::Trace, 1, request);
        let name = claim_ref(execution)?;
        let _publication = self.refs.acquire_publication_guard().map_err(refused)?;
        self.check_legacy_routes(execution, route)?;
        if let Some(existing) = self.refs.read_ref(&name).map_err(refused)? {
            return self.match_original(existing, execution, route, request_id);
        }

        // Quota is consumed before publishing a contender. Losing contenders
        // may consume credit, but can never exceed the finite lifetime ceiling.
        self.reserve_credit()?;
        self.put(request_id, request)?;
        let bytes = encode(&Claim {
            format: "crucible.original-node-preparation-claim".into(),
            version: 1,
            execution: execution.into(),
            route,
            request: request_id.encode(),
        })?;
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        self.put(identity, &bytes)?;
        match self
            .refs
            .compare_exchange(&name, None, identity)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == identity => Ok(Reservation::Original),
            RefCasOutcome::Conflict {
                current: Some(existing),
                ..
            } => self.match_original(existing, execution, route, request_id),
            _ => Err(refused("original route claim requires reconciliation")),
        }
    }

    /// Checks retained ownership while the caller already protects publication from GC.
    pub(super) fn existing(
        &self,
        execution: &str,
        route: Route,
        request: &[u8],
    ) -> Result<bool, NodeObservationServiceError> {
        super::conditional_preparation::validate_execution(execution)?;
        if request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(refused("original route request exceeds finite byte credit"));
        }
        self.check_legacy_routes(execution, route)?;
        let Some(identity) = self
            .refs
            .read_ref(&claim_ref(execution)?)
            .map_err(refused)?
        else {
            return Ok(false);
        };
        self.match_original(
            identity,
            execution,
            route,
            ContentId::for_bytes(ObjectKind::Trace, 1, request),
        )?;
        Ok(true)
    }

    pub(super) fn retention_roots(
        &self,
    ) -> Result<BTreeSet<ContentId>, NodeObservationServiceError> {
        let namespace = RefName::new("node-original-preparation-claims").map_err(refused)?;
        let mut after = None;
        let mut roots = BTreeSet::new();
        let mut count = 0;
        loop {
            let page = self
                .refs
                .scan_refs(&namespace, after.as_ref(), 64)
                .map_err(refused)?;
            for entry in page.entries() {
                count += 1;
                if count > MAXIMUM_RECORDS {
                    return Err(refused("original claim inventory exceeds finite credit"));
                }
                let execution = entry
                    .name()
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refused("original claim namespace differs"))?;
                let claim = self.read_claim(entry.target(), execution)?;
                roots.insert(entry.target());
                roots.insert(ContentId::parse(&claim.request).map_err(refused)?);
            }
            after = page.next_after().cloned();
            if after.is_none() {
                break;
            }
        }
        if let Some(identity) = self.refs.read_ref(&quota_ref()?).map_err(refused)? {
            if self.read_quota(identity)? < count {
                return Err(refused("original claim quota omits retained custody"));
            }
            roots.insert(identity);
        } else if count != 0 {
            return Err(refused("original claim quota is absent"));
        }
        Ok(roots)
    }

    fn check_legacy_routes(
        &self,
        execution: &str,
        route: Route,
    ) -> Result<(), NodeObservationServiceError> {
        for (original, namespace) in [
            (Route::Capability, "node-capability-preparations"),
            (Route::Conditional, "node-conditional-preparations"),
            (Route::Root, "node-root-preparations"),
            (Route::Debug, "node-debug-preparations"),
            (Route::DebugPreserving, "node-preserving-debug-preparations"),
        ] {
            if original != route
                && self
                    .refs
                    .read_ref(&RefName::new(format!("{namespace}/{execution}")).map_err(refused)?)
                    .map_err(refused)?
                    .is_some()
            {
                return Err(refused(
                    "execution nonce belongs to another original preparation route",
                ));
            }
        }
        Ok(())
    }

    fn match_original(
        &self,
        identity: ContentId,
        execution: &str,
        route: Route,
        request: ContentId,
    ) -> Result<Reservation, NodeObservationServiceError> {
        let claim = self.read_claim(identity, execution)?;
        if claim.route != route || claim.request != request.encode() {
            return Err(refused(
                "execution nonce already owns another original route or request",
            ));
        }
        Ok(Reservation::Retained)
    }

    fn read_claim(
        &self,
        identity: ContentId,
        execution: &str,
    ) -> Result<Claim, NodeObservationServiceError> {
        let bytes = self.read_bytes(identity, 1024)?;
        let claim: Claim =
            serde_json::from_value(canonical::parse_json(&bytes, 1024).map_err(refused)?)
                .map_err(refused)?;
        super::conditional_preparation::validate_execution(execution)?;
        if claim.format != "crucible.original-node-preparation-claim"
            || claim.version != 1
            || claim.execution != execution
            || encode(&claim)? != bytes
        {
            return Err(refused("original route claim scope or edition differs"));
        }
        let request = ContentId::parse(&claim.request).map_err(refused)?;
        self.read_bytes(request, MAXIMUM_REQUEST_BYTES)?;
        Ok(claim)
    }

    fn reserve_credit(&self) -> Result<(), NodeObservationServiceError> {
        let reference = quota_ref()?;
        for _ in 0..64 {
            let current = self.refs.read_ref(&reference).map_err(refused)?;
            let consumed = current
                .map(|id| self.read_quota(id))
                .transpose()?
                .unwrap_or(0);
            if consumed >= MAXIMUM_RECORDS {
                return Err(refused("original route lifetime claim credit exhausted"));
            }
            let bytes = encode(&Quota {
                format: "crucible.original-node-preparation-quota".into(),
                version: 1,
                consumed: consumed + 1,
            })?;
            let next = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
            self.put(next, &bytes)?;
            match self
                .refs
                .compare_exchange(&reference, current, next)
                .map_err(refused)?
            {
                RefCasOutcome::Advanced { next: actual } if actual == next => return Ok(()),
                RefCasOutcome::Conflict { .. } => continue,
                _ => return Err(refused("original route quota requires reconciliation")),
            }
        }
        Err(refused(
            "original route quota contention exceeds finite credit",
        ))
    }

    fn read_quota(&self, identity: ContentId) -> Result<usize, NodeObservationServiceError> {
        let bytes = self.read_bytes(identity, 1024)?;
        let quota: Quota =
            serde_json::from_value(canonical::parse_json(&bytes, 1024).map_err(refused)?)
                .map_err(refused)?;
        if quota.format != "crucible.original-node-preparation-quota"
            || quota.version != 1
            || quota.consumed > MAXIMUM_RECORDS
            || encode(&quota)? != bytes
        {
            return Err(refused("original route quota scope or edition differs"));
        }
        Ok(quota.consumed)
    }

    fn read_bytes(
        &self,
        identity: ContentId,
        maximum: usize,
    ) -> Result<Vec<u8>, NodeObservationServiceError> {
        let bytes = self
            .blobs
            .read(identity, None)
            .and_then(|body| body.read_all(maximum as u64))
            .map_err(refused)?;
        if ContentId::for_bytes(ObjectKind::Trace, 1, &bytes) != identity {
            return Err(refused("original route immutable body differs"));
        }
        Ok(bytes)
    }

    fn put(&self, identity: ContentId, bytes: &[u8]) -> Result<(), NodeObservationServiceError> {
        if !self
            .blobs
            .put_if_absent(identity, &BlobHandle::from_bytes(bytes.to_vec()))
            .map_err(refused)?
            .is_durable()
        {
            return Err(refused("original route immutable body is not durable"));
        }
        Ok(())
    }
}

fn claim_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    RefName::new(format!("node-original-preparation-claims/{execution}")).map_err(refused)
}

fn quota_ref() -> Result<RefName, NodeObservationServiceError> {
    RefName::new("node-original-preparation-quota/records").map_err(refused)
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, NodeObservationServiceError> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(refused)?).map_err(refused)
}

#[cfg(test)]
mod tests;
