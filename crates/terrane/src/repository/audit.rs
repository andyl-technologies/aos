//! Records domain route state through ordinary guarded administrative commits.
//!
//! An administrative repository uses a separate private domain, restricted
//! administrator readers, an empty tree, and `retain = forever`. Registration,
//! intent, and completion retain that exact tree and form one parent chain on
//! the deterministic authoritative head. Missing or malformed state denies
//! reopening; an advisory ref or bucket listing never enables a domain.

use super::{
    CommitMetadata, Error, LocalAuthority, PreparedTree, Repository,
    audit_codec::{self, RouteMessage},
};
use crate::{
    domain::{self, DomainAccess, DomainAdminRequest, DomainDeletionAudit, DomainDeletionEvent},
    guard::AuthorizedSnapshot,
    store::{Clock, InvalidReason, LocalFs, Store, StoreErrorKind, StoreFailure},
};
use std::collections::BTreeSet;
use terrane_core::{
    auth::{Verb, Verbs},
    identity::{Identity, IdentityKind, TERRANE_V1},
    properties::{self, Domain, PropertyName, RootLayer, Value},
    refs::CommitSource,
};

/// Records one registered domain's durable administrative deletion trail.
///
/// The adapter holds ordinary repository signing authority. It is not a
/// presentation surface and never grants access to the data repository.
pub struct RegisteredDomainAudit<'a, S: Store, C: Clock, F: LocalFs> {
    repository: &'a Repository<S, C, F>,
    authority: &'a LocalAuthority,
    domain: String,
    reference: String,
    configured: &'a domain::ConfiguredDomainRoute,
}

impl<S, C, F> Repository<S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    fn check_audit_backend(&self, configured: &domain::ConfiguredDomainRoute) -> Result<(), Error> {
        let root = self.local_backend_root.as_deref().ok_or(Error::Denied)?;
        configured.check_audit_backend(&self.coordinator.guard().config().storage_domain, root)?;
        Ok(())
    }

    /// Registers an active domain on its existing private administrative head.
    ///
    /// The head must have been explicitly initialized with an empty retained
    /// administrative tree. Registration refuses any previous routing state;
    /// it cannot reactivate a deleted domain or replace another registration.
    ///
    /// # Errors
    /// Rejects absent or denied current administration, an open audit domain,
    /// nonempty trees, missing forever retention, unrestricted readers,
    /// previous routing state, stale authority, and publication failures.
    pub async fn register_domain_route(
        &self,
        configured: &domain::ConfiguredDomainRoute,
        authority: &LocalAuthority,
    ) -> Result<Identity, Error> {
        self.check_audit_backend(configured)?;
        let domain = configured.target().domain.as_str();
        let reference = configured.control_ref().to_owned();
        let snapshot = self
            .coordinator
            .guard()
            .read_snapshot(&reference, authority.token(), b"/", "sdk")
            .await?;
        let access = self
            .coordinator
            .guard()
            .domain_access(&reference, authority.token(), Verb::Admin, b"/", "sdk")
            .await?;
        validate_audit_root(&snapshot, self, domain)?;
        let mut pending = vec![snapshot.commit.identity()];
        let mut visited = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            let commit = snapshot.history.commit(&id).ok_or(Error::Denied)?.commit();
            if audit_codec::is_route(&commit.message) {
                return Err(Error::Denied);
            }
            pending.extend(&commit.parents);
        }
        if access
            .reference_record()
            .is_none_or(|record| record.commit != snapshot.commit.identity())
        {
            return Err(Error::Denied);
        }
        let event = DomainDeletionEvent {
            domain: domain.to_owned(),
            roots: Vec::new(),
            subject: access.subject().to_owned(),
            token_id: *access.token_id(),
        };
        let message = audit_codec::encode(&event, 0, None)?;
        publish(self, authority, &reference, snapshot, message).await
    }

    /// Opens a checked adapter for an already registered administrative route.
    ///
    /// # Errors
    /// Rejects absent, malformed, untrusted, or incorrectly bound registration,
    /// an unsafe audit root, unavailable current Admin authority, and I/O errors.
    pub async fn domain_audit<'a>(
        &'a self,
        configured: &'a domain::ConfiguredDomainRoute,
        authority: &'a LocalAuthority,
    ) -> Result<RegisteredDomainAudit<'a, S, C, F>, Error> {
        self.check_audit_backend(configured)?;
        let domain = configured.target().domain.as_str();
        let audit = RegisteredDomainAudit {
            repository: self,
            authority,
            domain: domain.to_owned(),
            reference: configured.control_ref().to_owned(),
            configured,
        };
        audit.load().await?;
        Ok(audit)
    }
}

impl<S, C, F> RegisteredDomainAudit<'_, S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Returns an administration request bound to the verified domain route.
    ///
    /// # Errors
    /// Rejects missing or malformed routing state, changed current authority,
    /// unsafe retention or reader policy, and failed guarded reads.
    pub async fn administration(&self) -> Result<DomainAdminRequest, Error> {
        let (_, access, _) = self.load().await?;
        Ok(DomainAdminRequest::from_route_authority(
            self.configured,
            access,
        )?)
    }

    async fn load(&self) -> Result<(AuthorizedSnapshot, DomainAccess, RouteMessage), Error> {
        self.repository.check_audit_backend(self.configured)?;
        let guard = self.repository.coordinator.guard();
        let snapshot = guard
            .read_snapshot(&self.reference, self.authority.token(), b"/", "sdk")
            .await?;
        let access = guard
            .domain_access(
                &self.reference,
                self.authority.token(),
                Verb::Admin,
                b"/",
                "sdk",
            )
            .await?;
        if access
            .reference_record()
            .is_none_or(|record| record.commit != snapshot.commit.identity())
        {
            return Err(Error::Denied);
        }
        validate_audit_root(&snapshot, self.repository, &self.domain)?;
        let state = validate_chain(&snapshot, &self.domain)?;
        Ok((snapshot, access, state))
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S, C, F> DomainDeletionAudit for RegisteredDomainAudit<'_, S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    async fn domain_deleted(&self, domain: &str) -> Result<bool, StoreFailure> {
        if domain != self.domain {
            return Err(invalid());
        }
        let (_, _, state) = self.load().await.map_err(failure)?;
        Ok(state.state != 0)
    }

    async fn record_intent(&self, event: &DomainDeletionEvent) -> Result<Identity, StoreFailure> {
        let (snapshot, access, state) = self.load().await.map_err(failure)?;
        check_actor(event, &self.domain, &access)?;
        if state.state != 0 {
            return Err(invalid());
        }
        let message = audit_codec::encode(event, 1, None).map_err(failure)?;
        publish(
            self.repository,
            self.authority,
            &self.reference,
            snapshot,
            message,
        )
        .await
        .map_err(failure)
    }

    async fn record_completion(
        &self,
        event: &DomainDeletionEvent,
        intent: &Identity,
    ) -> Result<Identity, StoreFailure> {
        let (snapshot, access, state) = self.load().await.map_err(failure)?;
        check_actor(event, &self.domain, &access)?;
        let id = intent.terrane_v1_digest().map_err(|_| invalid())?;
        let expected = audit_codec::decode(&audit_codec::encode(event, 1, None).map_err(failure)?)
            .map_err(failure)?;
        if intent.kind() != IdentityKind::Commit
            || state.state != 1
            || snapshot.commit.identity() != id
            || state.event != expected.event
            || state.subject != expected.subject
            || state.token_id != expected.token_id
        {
            return Err(invalid());
        }
        let message = audit_codec::encode(event, 2, Some(id)).map_err(failure)?;
        publish(
            self.repository,
            self.authority,
            &self.reference,
            snapshot,
            message,
        )
        .await
        .map_err(failure)
    }
}

fn check_actor(
    event: &DomainDeletionEvent,
    domain: &str,
    access: &DomainAccess,
) -> Result<(), StoreFailure> {
    if event.domain != domain
        || event.subject != access.subject()
        || &event.token_id != access.token_id()
        || event
            .roots
            .iter()
            .any(|root| root.domain != domain || root.root.kind() != IdentityKind::Node)
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_audit_root<S, C, F>(
    snapshot: &AuthorizedSnapshot,
    repository: &Repository<S, C, F>,
    domain: &str,
) -> Result<(), Error>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    if !matches!(
        Domain::parse(&snapshot.storage_domain),
        Ok(Domain::Private(_))
    ) || snapshot.storage_domain == domain
    {
        return Err(Error::Denied);
    }
    let tree = snapshot.evidence.tree(
        snapshot.evidence.root,
        repository.chunk_profile().minimum() as u64,
    )?;
    if !tree.is_empty() {
        return Err(Error::Denied);
    }
    let properties = tree.props().ok_or(Error::Denied)?;
    let effective = properties::resolve(
        &[RootLayer {
            properties,
            overrides: &[],
        }],
        repository
            .coordinator
            .guard()
            .defaults_for(&snapshot.evidence),
    )
    .map_err(|_| Error::Denied)?;
    if effective.get(PropertyName::Retain) != Some(&Value::Text("forever")) {
        return Err(Error::Denied);
    }
    let Some(Value::Grants(grants)) = effective.get(PropertyName::Acl) else {
        return Err(Error::Denied);
    };
    if grants.is_empty()
        || grants.iter().any(|(_, mask)| match Verbs::new(*mask) {
            Ok(verbs) => verbs.contains(Verb::Read) && !verbs.contains(Verb::Admin),
            Err(_) => true,
        })
    {
        return Err(Error::Denied);
    }
    Ok(())
}

fn validate_chain(snapshot: &AuthorizedSnapshot, domain: &str) -> Result<RouteMessage, Error> {
    let head = audit_codec::decode(&snapshot.commit.commit().message)?;
    let mut current = snapshot.commit.identity();
    let mut newer: Option<RouteMessage> = None;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current) {
            return Err(Error::Denied);
        }
        let verified = snapshot.history.commit(&current).ok_or(Error::Denied)?;
        let commit = verified.commit();
        let state = audit_codec::decode(&commit.message)?;
        if state.domain != domain
            || commit.tree != snapshot.commit.commit().tree
            || state.subject != verified.authority().subject
            || state.token_id != verified.authority().token_id
            || commit.parents.len() != 1
        {
            return Err(Error::Denied);
        }
        if let Some(child) = newer {
            match (child.state, state.state) {
                (2, 1)
                    if child.intent == current
                        && child.event == state.event
                        && child.subject == state.subject
                        && child.token_id == state.token_id => {}
                (1, 0) => {}
                _ => return Err(Error::Denied),
            }
        }
        if state.state == 0 {
            let mut older = commit.parents.clone();
            while let Some(id) = older.pop() {
                if !visited.insert(id) {
                    continue;
                }
                let ancestor = snapshot.history.commit(&id).ok_or(Error::Denied)?.commit();
                if audit_codec::is_route(&ancestor.message) {
                    return Err(Error::Denied);
                }
                older.extend(&ancestor.parents);
            }
            return Ok(head);
        }
        newer = Some(state);
        current = commit.parents[0];
    }
}

async fn publish<S, C, F>(
    repository: &Repository<S, C, F>,
    authority: &LocalAuthority,
    reference: &str,
    snapshot: AuthorizedSnapshot,
    message: String,
) -> Result<Identity, Error>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    let prepared = {
        let tree = snapshot.evidence.tree(
            snapshot.evidence.root,
            repository.chunk_profile().minimum() as u64,
        )?;
        PreparedTree::from_tree(&tree)?
    };
    let mut session = repository
        .begin(reference, authority.token(), "sdk")
        .await?;
    if session
        .record()
        .is_none_or(|record| record.commit != snapshot.commit.identity())
    {
        return Err(Error::Denied);
    }
    let commit = super::local::proposal(
        prepared.root(),
        vec![snapshot.commit.identity()],
        CommitMetadata {
            message,
            process: "domain-administration".into(),
            source: CommitSource::Built,
        },
        &repository.coordinator.guard().config().chunk_profile_name,
    );
    let record = repository
        .commit(
            &mut session,
            prepared,
            authority.commit_request(commit, "sdk".into()),
        )
        .await?;
    Ok(TERRANE_V1.from_digest(IdentityKind::Commit, &record.commit)?)
}

fn invalid() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload {
        rule_id: "DOM-20",
    }))
}
fn failure(error: Error) -> StoreFailure {
    match error {
        Error::Store(error) => error,
        error => {
            StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
        }
    }
}
