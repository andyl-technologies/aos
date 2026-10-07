//! Owns current-policy repository authorization from specification 22.
//!
//! Admission binds a verified capability to the freshly read complete ref
//! record and canonical tree evidence. Historical signatures establish content
//! authenticity; current ACLs decide whether a request may change the ref.

#[cfg(feature = "std")]
mod admission;
#[cfg(feature = "std")]
mod attributes;
#[cfg(all(feature = "std", unix))]
pub(crate) mod cold_fork;
#[cfg(feature = "std")]
mod consumed;
#[cfg(feature = "std")]
pub(crate) use consumed::registration as consumed_registration;
#[cfg(feature = "std")]
mod existing;
mod history;
#[cfg(feature = "std")]
pub mod index_backfill;
#[cfg(feature = "std")]
pub mod index_maintenance;
#[cfg(feature = "std")]
mod join;
#[cfg(feature = "std")]
mod merge;
#[cfg(feature = "std")]
mod original;
#[cfg(feature = "std")]
pub(crate) use original::{
    ControlExclusion, RetainedControls, consumed_pins as publication_original_pins,
};
#[cfg(feature = "std")]
mod policy;
mod read;
#[cfg(feature = "std")]
mod requalification;
mod scope;
mod snapshot;
mod staged;
#[cfg(feature = "std")]
mod tag;
mod time;

#[cfg(test)]
mod principal_tests;

use std::time::SystemTime;

use terrane_core::auth::{self, IssuerKey, Request, RequestRoot, Verb, Verbs, VerifiedToken};
use terrane_core::properties::{
    self, Defaults, EffectiveProperties, PropertyName, RootLayer, Value,
};
use terrane_core::refs::{Locality, RefName, RefRecord};

use crate::store::{Clock, Store, StoreErrorKind, StoreFailure};

#[cfg(feature = "std")]
pub(crate) use admission::AdmittedCommit;
#[cfg(feature = "std")]
pub(crate) use consumed::ConsumedResolver;
pub(crate) use history::HistoryObservation;
#[cfg(feature = "std")]
pub(crate) use join::{JoinKind, JoinRequest};
#[cfg(feature = "std")]
pub(crate) use merge::RebaseRequest;
#[cfg(feature = "std")]
pub(crate) use original::{AssociationView, BootstrapView, RegistrationView};
#[cfg(feature = "std")]
pub use original::{OriginalAuthority, OriginalCommitContext, RetainedBootstrap};
pub use read::{AuthorizedSnapshot, indexes};
pub(crate) use snapshot::{TreeEvidence, invalid};
pub use staged::{CommitRequest, StagedUpload};
#[cfg(feature = "std")]
pub(crate) use tag::TagPublication;

/// Supplies trusted defaults for a repository's policy resolution.
#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// Configured authority store expression name.
    pub store_name: String,
    /// Local ownership hint for callers explicitly encoding a root domain.
    pub private_domain: String,
    /// Immutable locality of this authority.
    pub home: Locality,
    /// Trusted bootstrap ACL for a branch that does not yet exist.
    pub initial_acl: Vec<(String, u8)>,
    /// Chunk profile minimum needed to validate canonical tree witnesses.
    pub min_chunk_size: u64,
    /// Canonical domain physically isolated by the opened authority route.
    pub storage_domain: String,
    /// Registered profile name used by the opened content route.
    pub chunk_profile_name: String,
    /// Exact chunk profile and seed used by the opened content route.
    pub chunk_profile: Box<terrane_core::chunking::ChunkProfile>,
    /// Trusted live policy authority; absence uses verified original authoring scope.
    pub policy_authority: Option<String>,
}

/// Retains a fresh, currently authorized ref snapshot without exposing a permit constructor.
#[derive(Clone)]
pub struct AuthorizedRef {
    reference: String,
    record: Option<RefRecord>,
    token: VerifiedToken,
    verb: Verb,
    root_paths: Vec<Vec<u8>>,
    root_domains: Vec<String>,
    surface: String,
    token_bytes: Vec<u8>,
}

impl std::fmt::Debug for AuthorizedRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedRef")
            .field("reference", &self.reference)
            .field("record", &self.record)
            .field("token", &self.token)
            .field("verb", &self.verb)
            .field("root_paths", &self.root_paths)
            .field("root_domains", &self.root_domains)
            .field("surface", &self.surface)
            .finish_non_exhaustive()
    }
}

impl AuthorizedRef {
    /// Returns the actual root paths checked against token and current ACLs.
    ///
    /// This snapshot grants no enduring authority. Reads and mutations must
    /// recheck current policy before their effects.
    pub fn root_paths(&self) -> &[Vec<u8>] {
        &self.root_paths
    }

    /// Returns the exact complete ref value checked against current policy.
    pub fn record(&self) -> Option<&RefRecord> {
        self.record.as_ref()
    }

    /// Returns the authenticated subject of the authorizing capability.
    pub fn subject(&self) -> &str {
        &self.token.authority().subject
    }

    /// Compares the authenticated principal name and kind of two captured requests.
    ///
    /// DOM-24 pairs independently authorized source and destination requests.
    /// Groups and issuer keys remain independently checked claims; equality
    /// grants no current token, ACL, scope or publication authority.
    pub(crate) fn same_principal(&self, other: &Self) -> bool {
        let left = self.token.authority();
        let right = other.token.authority();
        left.subject == right.subject && left.kind == right.kind
    }

    /// Returns the canonical reference bound to this authorization.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the operation checked against token and current ACL.
    pub const fn verb(&self) -> Verb {
        self.verb
    }
}

/// Enforces current token and root ACL authority before repository effects.
pub struct Guard<S, C> {
    store: S,
    clock: C,
    keys: Vec<IssuerKey>,
    config: GuardConfig,
    #[cfg(feature = "std")]
    interpretation: history::completion::InterpretationSelection,
    #[cfg(feature = "std")]
    original_verifier: std::sync::RwLock<Option<original::OriginalVerifier>>,
    #[cfg(feature = "std")]
    original_baselines:
        std::sync::RwLock<std::collections::BTreeMap<(String, u64), RetainedBootstrap>>,
    #[cfg(feature = "std")]
    original_commits: std::sync::RwLock<
        std::collections::BTreeMap<terrane_core::identity::Digest, OriginalCommitContext>,
    >,
}

impl<S, C> Guard<S, C> {
    /// Creates the repository's single authorization enforcement point.
    pub fn new(store: S, clock: C, keys: Vec<IssuerKey>, config: GuardConfig) -> Self {
        Self {
            store,
            clock,
            keys,
            config,
            #[cfg(feature = "std")]
            interpretation: history::completion::InterpretationSelection::Legacy,
            #[cfg(feature = "std")]
            original_verifier: std::sync::RwLock::new(None),
            #[cfg(feature = "std")]
            original_baselines: std::sync::RwLock::new(std::collections::BTreeMap::new()),
            #[cfg(feature = "std")]
            original_commits: std::sync::RwLock::new(std::collections::BTreeMap::new()),
        }
    }

    /// Creates an enforcement point with explicitly selected current active semantics.
    ///
    /// Actual full verification binds each reached signed view independently;
    /// selection grants no current or Original authority.
    #[cfg(feature = "std")]
    pub fn new_active(store: S, clock: C, keys: Vec<IssuerKey>, config: GuardConfig) -> Self {
        let mut guard = Self::new(store, clock, keys, config);
        guard.interpretation = history::completion::InterpretationSelection::Active;
        guard
    }

    /// Returns the actual constructor-selected semantic input without granting authority.
    pub(crate) fn semantic_selection(&self) -> terrane_core::properties::selected::Selection {
        #[cfg(feature = "std")]
        {
            self.interpretation.semantics()
        }
        #[cfg(not(feature = "std"))]
        {
            terrane_core::properties::selected::Selection::Legacy
        }
    }

    pub(crate) fn store(&self) -> &S {
        &self.store
    }

    #[cfg(feature = "std")]
    pub(crate) fn clock(&self) -> &C {
        &self.clock
    }

    pub(crate) fn config(&self) -> &GuardConfig {
        &self.config
    }

    pub(crate) fn keys(&self) -> &[IssuerKey] {
        &self.keys
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Resolves every canonical graft occurrence before signing or verifying
    /// authoring assertions. Neither caller labels nor the signature alone
    /// establish which disclosure domain the immutable tree actually has.
    pub(crate) fn authoring_roots(
        &self,
        evidence: &TreeEvidence,
    ) -> Result<Vec<(Vec<u8>, String)>, StoreFailure> {
        let mut roots = Vec::new();
        for occurrence in evidence.occurrences(self.config.min_chunk_size)? {
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let effective = self
                .semantic_selection()
                .resolve(&layers, self.defaults_for(evidence))
                .map_err(|_| invalid())?;
            roots.push((
                occurrence.path,
                domain_label(&effective).map_err(|_| invalid())?.to_owned(),
            ));
        }
        roots.sort();
        if roots.is_empty() || roots.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid());
        }
        Ok(roots)
    }

    /// Authorizes an operation against the freshly loaded ref and current root policies.
    ///
    /// Paths name every touched root or entry using canonical absolute bytes.
    /// An empty list checks the whole root, including its ACL. Initial branch
    /// creation uses the configured bootstrap ACL, never candidate properties.
    ///
    /// # Errors
    /// Denies malformed tokens, expired keys, missing root authority, or a
    /// request routed away from the ref's home. Preserves storage failures
    /// encountered while reading the current policy and its tree witnesses.
    pub async fn authorize(
        &self,
        reference: &str,
        token: &[u8],
        verb: Verb,
        paths: &[Vec<u8>],
        surface: &str,
    ) -> Result<AuthorizedRef, StoreFailure> {
        self.authorize_observed(
            reference,
            token,
            verb,
            paths,
            surface,
            HistoryObservation::default(),
        )
        .await
    }

    /// Checks current policy without reacquiring a supplied held backend exclusion.
    ///
    /// # Errors
    /// Preserves current token, ACL, canonical history, and underlying storage failures.
    pub(crate) async fn authorize_observed(
        &self,
        reference: &str,
        token: &[u8],
        verb: Verb,
        paths: &[Vec<u8>],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<AuthorizedRef, StoreFailure> {
        self.authorize_observed_with_evidence(reference, token, verb, paths, surface, observation)
            .await
            .map(|(authorized, _)| authorized)
    }

    /// Retains the fresh tree used for this exact current-policy authorization.
    ///
    /// Evidence belongs to the returned complete ref and the same observation;
    /// it cannot replace a fresh authorization in a subsequent operation.
    ///
    /// # Errors
    /// Preserves current token, ACL, canonical history, and storage failures.
    async fn authorize_observed_with_evidence(
        &self,
        reference: &str,
        token: &[u8],
        verb: Verb,
        paths: &[Vec<u8>],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<(AuthorizedRef, Option<TreeEvidence>), StoreFailure> {
        RefName::parse(reference).map_err(|_| denied(reference, verb))?;
        let now = self.now(reference, verb)?;
        let verified = auth::verify(token, &self.keys, now).map_err(|_| denied(reference, verb))?;
        let record = self.store.ref_get(reference).await?;
        if record
            .as_ref()
            .is_some_and(|value| value.home != self.config.home)
        {
            return Err(denied(reference, verb));
        }

        let evidence = match &record {
            Some(record) => Some(
                self.verified_tree_observed(record.commit, observation)
                    .await?
                    .evidence,
            ),
            None => None,
        };
        let requested_paths = if paths.is_empty() {
            vec![b"/".to_vec()]
        } else {
            paths.to_vec()
        };
        let requested = match &evidence {
            Some(evidence) => requested_paths
                .iter()
                .map(|path| evidence.containing_root(path, self.config.min_chunk_size))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| denied(reference, verb))?,
            None => requested_paths,
        };
        let mut domains = Vec::with_capacity(requested.len());
        for path in &requested {
            if let Some(evidence) = &evidence {
                let path_layers = evidence
                    .policy_path(path, self.config.min_chunk_size)
                    .map_err(|_| denied(reference, verb))?;
                let layers = path_layers
                    .iter()
                    .map(|(properties, overrides)| RootLayer {
                        properties,
                        overrides,
                    })
                    .collect::<Vec<_>>();
                let policy = self
                    .semantic_selection()
                    .resolve(&layers, self.defaults_for(evidence))
                    .map_err(|_| denied(reference, verb))?;
                self.check_acl(&verified, &policy, reference, verb)?;
                domains.push(
                    domain_label(&policy)
                        .map_err(|_| denied(reference, verb))?
                        .to_owned(),
                );
            } else {
                if !acl_permits(
                    &self
                        .config
                        .initial_acl
                        .iter()
                        .map(|(name, mask)| (name.as_str(), *mask))
                        .collect::<Vec<_>>(),
                    &verified,
                    verb,
                ) {
                    return Err(denied(reference, verb));
                }
                domains.push(self.config.storage_domain.clone());
            }
        }
        let roots = requested
            .iter()
            .zip(&domains)
            .map(|(path, domain)| RequestRoot { path, domain })
            .collect::<Vec<_>>();
        let epoch = record.as_ref().map_or(0, |value| value.writer_epoch);
        verified
            .authorize(&Request {
                reference: reference.as_bytes(),
                verb,
                roots: &roots,
                now,
                surface,
                locality: &self.config.home,
                epochs: &[(reference, epoch)],
            })
            .map_err(|_| denied(reference, verb))?;

        let authorized = AuthorizedRef {
            reference: reference.to_owned(),
            record,
            token: verified,
            verb,
            root_paths: requested,
            root_domains: domains,
            surface: surface.to_owned(),
            token_bytes: token.to_vec(),
        };
        self.refresh_authorized_time(&authorized)?;
        Ok((authorized, evidence))
    }

    /// Refreshes token authority for the actual previously checked request without I/O.
    ///
    /// The native producer must separately retain and verify current whole refs,
    /// ACL witnesses, selected Guard configuration and backend/control exclusions.
    /// This check alone grants neither fresh ACL nor physical publication authority.
    /// Retained capability bytes are intentionally omitted from debug output.
    ///
    /// # Errors
    /// Rejects clock failure, current issuer retirement, token expiry or caveats,
    /// or a mismatch in the authenticated request principal.
    pub(crate) fn refresh_authorized_time(
        &self,
        authorized: &AuthorizedRef,
    ) -> Result<(), StoreFailure> {
        time::refresh(&self.keys, &self.config.home, &self.clock, authorized)
    }

    /// Retains actual successful requests and this injected clock for final dispatch.
    ///
    /// Each exact request is freshly authenticated against this Guard's configured
    /// issuer rows before retention. Later boundaries reauthorize its opaque
    /// verified token at current time and recheck the original deadline.
    ///
    /// This time check grants no standalone current ACL or physical authority.
    /// The selected producer must retain and validate the actual backend and
    /// protected controls independently through acknowledgment.
    ///
    /// # Errors
    /// Rejects unsupported clock retention, elapsed deadlines or current request
    /// expiry, caveat and configured issuer failures.
    #[cfg(feature = "std")]
    pub(crate) fn retain_request_checks(
        &self,
        requests: &[AuthorizedRef],
        started: std::time::Duration,
        maximum: std::time::Duration,
    ) -> Result<time::RetainedRequests, StoreFailure> {
        let clock = self
            .clock
            .retain_native_clock()
            .map_err(time::retention_failure)?;
        time::RetainedRequests::new(
            clock,
            self.keys.clone(),
            self.config.home.clone(),
            requests.to_vec(),
            started,
            maximum,
        )
    }

    /// Issues a domain capability bound to a freshly authorized canonical root occurrence.
    ///
    /// # Errors
    /// Denies token or current ACL failures, missing roots, changed authority
    /// records, malformed domains, and a root routed to another namespace.
    pub async fn domain_access(
        &self,
        reference: &str,
        token: &[u8],
        verb: Verb,
        path: &[u8],
        surface: &str,
    ) -> Result<crate::domain::DomainAccess, StoreFailure> {
        let authorization = self
            .authorize(reference, token, verb, &[path.to_vec()], surface)
            .await?;
        let record = authorization
            .record()
            .ok_or_else(|| denied(reference, verb))?;
        let evidence = self.verified_tree(record.commit).await?.evidence;
        let occurrences = evidence.occurrences(self.config.min_chunk_size)?;
        let occurrence = occurrences
            .iter()
            .filter(|root| {
                path == root.path
                    || (root.path == b"/" && path.starts_with(b"/"))
                    || path
                        .strip_prefix(root.path.as_slice())
                        .is_some_and(|suffix| suffix.starts_with(b"/"))
            })
            .max_by_key(|root| root.path.len())
            .ok_or_else(|| denied(reference, verb))?;
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let effective = self
            .semantic_selection()
            .resolve(&layers, self.defaults_for(&evidence))
            .map_err(|_| denied(reference, verb))?;
        let domain = domain_label(&effective).map_err(|_| denied(reference, verb))?;
        if domain != self.config.storage_domain
            || self.store.ref_get(reference).await?.as_ref() != Some(record)
        {
            return Err(denied(reference, verb));
        }
        let root = terrane_core::identity::TERRANE_V1
            .from_digest(terrane_core::identity::IdentityKind::Node, &occurrence.root)
            .map_err(|_| denied(reference, verb))?;
        let access = crate::domain::DomainAccess::authorized(
            crate::domain::DomainBinding {
                domain: domain.to_owned(),
                reference: reference.to_owned(),
                root,
                path: occurrence.path.clone(),
            },
            verb,
            authorization.subject().to_owned(),
            authorization.token.authority().token_id,
        )?;
        // Root policy authorization does not prove that an arbitrary hash is
        // reachable. Content permits are issued separately for exact files.
        Ok(access.with_reference_record(record.clone()))
    }

    pub(crate) fn now(&self, reference: &str, verb: Verb) -> Result<u64, StoreFailure> {
        self.clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|time| time.as_secs())
            .map_err(|_| denied(reference, verb))
    }

    // A physical namespace label is a routing constraint, not ownership evidence.
    pub(crate) fn defaults_for<'a>(&'a self, evidence: &'a TreeEvidence) -> Defaults<'a> {
        Defaults {
            store: &self.config.store_name,
            private_domain: &evidence.default_domain,
            home: self.config.home.region.as_deref().unwrap_or("local"),
        }
    }

    fn check_acl(
        &self,
        token: &VerifiedToken,
        policy: &EffectiveProperties<'_>,
        reference: &str,
        verb: Verb,
    ) -> Result<(), StoreFailure> {
        let Some(Value::Grants(grants)) = policy.get(PropertyName::Acl) else {
            return Err(denied(reference, verb));
        };
        if acl_permits(grants, token, verb) {
            Ok(())
        } else {
            Err(denied(reference, verb))
        }
    }
}

fn acl_permits(grants: &[(&str, u8)], token: &VerifiedToken, verb: Verb) -> bool {
    let authority = token.authority();
    grants.iter().any(|(name, mask)| {
        (*name == authority.subject
            || authority
                .groups
                .iter()
                .any(|group| *name == group || name.strip_prefix("group:") == Some(group.as_str())))
            && Verbs::new(*mask).is_ok_and(|verbs| verbs.contains(verb))
    })
}

pub(crate) fn domain_label<'a>(
    policy: &'a EffectiveProperties<'_>,
) -> Result<&'a str, properties::Error> {
    match policy.get(PropertyName::Domain) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(properties::Error::InvalidValue),
    }
}

pub(crate) fn denied(reference: &str, verb: Verb) -> StoreFailure {
    let verb = match verb {
        Verb::Read => "read",
        Verb::Fork => "fork",
        Verb::Commit => "commit",
        Verb::Tag => "tag",
        Verb::Admin => "admin",
    };
    StoreFailure::new(StoreErrorKind::Denied {
        verb,
        pattern: reference.to_owned(),
    })
}

// Collection verifies historical inputs through the same genuine Guard.
#[cfg(feature = "std")]
#[path = "gc/authority.rs"]
pub(crate) mod collection_authority;
