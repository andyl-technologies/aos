//! Derives affected canonical root units and authenticates original commit scope.
//!
//! Plans contain canonical change information for authoring; they grant no
//! authority. Only verification against authenticated original token context
//! creates an opaque scope suitable for history and native admission.
//!
//! Implicit domains derive independently from each immutable view root. The
//! supplied defaults provide store/home policy; their routing private-domain
//! label cannot replace an original canonical owner.

mod bootstrap;
mod snapshot;

pub(super) use bootstrap::CheckedBootstrap;
pub use bootstrap::OriginalBootstrapPolicy;

use super::{Rejected, VerifiedHistory};
use crate::{
    auth::{RequestRoot, Verb},
    identity::Digest,
    properties::Defaults,
    refs::Commit,
};
use alloc::{string::String, vec::Vec};
use snapshot::{Root, Snapshot};

pub(super) fn canonical_private_domain(root: Digest) -> Result<String, Rejected> {
    snapshot::private_owner(root)
}

/// Identifies which canonical tree supplies an affected occurrence's policy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RootSide {
    /// Candidate occurrence, including newly published roots.
    Candidate,
    /// Previous occurrence, including removed and moved roots.
    Previous,
}

/// Describes one actual canonical affected root and its effective domain.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AffectedRoot {
    path: Vec<u8>,
    domain: String,
    root: Digest,
    side: RootSide,
    properties_changed: bool,
}

impl AffectedRoot {
    /// Returns the actual absolute root occurrence path.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the canonical effective disclosure domain on this side.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the immutable root identity containing this affected unit.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Returns the canonical candidate or previous policy side.
    pub fn side(&self) -> RootSide {
        self.side
    }

    /// Reports a canonical local or effective root policy change.
    pub fn properties_changed(&self) -> bool {
        self.properties_changed
    }
}

/// Holds canonical authoring changes without token or admission authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootChangePlan {
    candidate: Digest,
    first_parent: Option<Digest>,
    affected: Vec<AffectedRoot>,
    required_admin: Vec<AffectedRoot>,
    fresh: bool,
}

impl RootChangePlan {
    /// Returns the canonical candidate tree identity used to derive this plan.
    pub fn candidate_tree(&self) -> Digest {
        self.candidate
    }

    /// Returns the exact signed first parent selected as the ordinary baseline.
    pub fn first_parent(&self) -> Option<Digest> {
        self.first_parent
    }

    /// Returns affected root units on their actual candidate and previous sides.
    pub fn affected(&self) -> &[AffectedRoot] {
        &self.affected
    }

    /// Returns canonical authority-change units requiring original Admin scope.
    ///
    /// Existing roots use their prior policy. Admin may also be established on
    /// a canonical ancestor; these units do not confer admission authority.
    /// Fresh authoring plans still require a trusted bootstrap comparison in
    /// [`verify_root_context_with_bootstrap`]; no baseline comes from a plan.
    pub fn required_admin(&self) -> &[AffectedRoot] {
        &self.required_admin
    }

    /// Reports complete fresh-materialization planning, without granting a cut.
    pub fn fresh(&self) -> bool {
        self.fresh
    }
}

/// Authenticates a commit's claims and every canonical affected root unit.
///
/// Construction is private. Current operation token, ACL, quota, upload and
/// fencing checks remain native admission responsibilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRootScope {
    view: Digest,
    plan: RootChangePlan,
    claims: Vec<AffectedRoot>,
    bootstrap: Option<bootstrap::CheckedBootstrap>,
}

impl VerifiedRootScope {
    /// Merges compatible checked scope annotations without discarding evidence.
    ///
    /// # Errors
    /// Returns [`Rejected`] for different canonical scope or conflicting retained
    /// physical-authority/ref/epoch/bootstrap ACL associations.
    pub(super) fn merge_checked(&self, other: &Self) -> Result<Self, Rejected> {
        if self.view != other.view || self.plan != other.plan || self.claims != other.claims {
            return Err(Rejected);
        }
        let bootstrap = match (&self.bootstrap, &other.bootstrap) {
            (Some(previous), Some(next)) if previous != next => return Err(Rejected),
            (Some(previous), _) => Some(previous.clone()),
            (None, next) => next.clone(),
        };
        // Ordinary verification may omit an optional annotation, but cannot
        // discard or replace already checked protected configuration evidence.
        Ok(Self {
            view: self.view,
            plan: self.plan.clone(),
            claims: self.claims.clone(),
            bootstrap,
        })
    }

    /// Returns the exact ordinarily signed immutable commit identity.
    pub fn view(&self) -> Digest {
        self.view
    }

    /// Returns the authenticated canonical change plan.
    pub fn changes(&self) -> &RootChangePlan {
        &self.plan
    }

    /// Returns signed claims witnessed against actual candidate or prior roots.
    pub fn claims(&self) -> &[AffectedRoot] {
        &self.claims
    }
}

fn affected(root: &Root, side: RootSide, properties_changed: bool) -> AffectedRoot {
    AffectedRoot {
        path: root.path.clone(),
        domain: root.domain.clone(),
        root: root.identity,
        side,
        properties_changed,
    }
}

fn fresh_plan(
    history: &VerifiedHistory,
    candidate: &Commit,
    defaults: Defaults<'_>,
    selection: crate::properties::selected::Selection,
) -> Result<RootChangePlan, Rejected> {
    let snapshot = snapshot::complete(history, candidate.tree, defaults, selection)?;
    Ok(RootChangePlan {
        candidate: candidate.tree,
        first_parent: candidate.parents.first().copied(),
        affected: snapshot
            .roots
            .values()
            .map(|root| affected(root, RootSide::Candidate, true))
            .collect(),
        fresh: true,
        required_admin: Vec::new(),
    })
}

/// Derives complete fresh root units for unsigned authoring materialization.
///
/// This authoring plan grants no source or parent boundary. Verification permits
/// fresh handling of an unavailable first parent only after a complete checked
/// disclosure batch authenticates that exact edge.
///
/// # Errors
/// Returns [`Rejected`] for missing, cyclic or inconsistent canonical tree/root
/// policy witnesses.
pub fn derive_fresh_roots(
    history: &VerifiedHistory,
    candidate: &Commit,
    defaults: Defaults<'_>,
) -> Result<RootChangePlan, Rejected> {
    fresh_plan(history, candidate, defaults, history.candidate_selection())
}

/// Derives unsigned authoring changes from the canonical ordinary first parent.
///
/// Identical copied trees return an empty change plan without scanning the tree.
/// Parent and candidate nodes must otherwise provide complete canonical witnesses.
///
/// # Errors
/// Returns [`Rejected`] for a missing first parent or canonical witnesses, a
/// graft cycle, or inconsistent root policies.
pub fn derive_root_changes(
    history: &VerifiedHistory,
    candidate: &Commit,
    defaults: Defaults<'_>,
) -> Result<RootChangePlan, Rejected> {
    changes_selected(history, candidate, defaults, history.candidate_selection())
}

fn changes_selected(
    history: &VerifiedHistory,
    candidate: &Commit,
    defaults: Defaults<'_>,
    selection: crate::properties::selected::Selection,
) -> Result<RootChangePlan, Rejected> {
    let Some(first_parent) = candidate.parents.first().copied() else {
        return fresh_plan(history, candidate, defaults, selection);
    };
    let previous = history.commit(&first_parent).ok_or(Rejected)?.commit().tree;
    if previous == candidate.tree && history.view_selection(first_parent)? == selection {
        return Ok(RootChangePlan {
            candidate: candidate.tree,
            first_parent: Some(first_parent),
            affected: Vec::new(),
            required_admin: Vec::new(),
            fresh: false,
        });
    }
    let previous = snapshot::complete(
        history,
        previous,
        defaults,
        history.view_selection(first_parent)?,
    )?;
    let current = snapshot::complete(history, candidate.tree, defaults, selection)?;
    let old_root = previous.roots.get(b"/".as_slice()).ok_or(Rejected)?;
    let new_root = current.roots.get(b"/".as_slice()).ok_or(Rejected)?;
    if old_root.implicit_owner() && new_root.implicit_owner() && old_root.domain != new_root.domain
    {
        // Changing an implicit root's digest cannot silently change its owner.
        // DOM-1 requires materializing the existing label before that edit.
        return Err(Rejected);
    }
    Ok(diff(candidate, &previous, &current))
}

fn diff(candidate: &Commit, previous: &Snapshot, current: &Snapshot) -> RootChangePlan {
    let mut changes = Vec::new();
    let mut required_admin = Vec::new();
    let paths: alloc::collections::BTreeSet<_> =
        previous.roots.keys().chain(current.roots.keys()).collect();
    for path in paths {
        match (previous.roots.get(path), current.roots.get(path)) {
            (Some(old), Some(new)) => {
                let policy_changed = !old.same_policy(new);
                if old.acl_changed(new) {
                    required_admin.push(affected(old, RootSide::Previous, true));
                }
                if policy_changed || old.entries != new.entries {
                    changes.push(affected(old, RootSide::Previous, policy_changed));
                    changes.push(affected(new, RootSide::Candidate, policy_changed));
                }
            }
            (Some(old), None) => changes.push(affected(old, RootSide::Previous, true)),
            (None, Some(new)) => {
                changes.push(affected(new, RootSide::Candidate, true));
            }
            (None, None) => {}
        }
    }
    for new in current.roots.values() {
        let Some(parent) = canonical_ancestor(current, &new.path) else {
            continue;
        };
        let previous_root = previous.roots.get(&new.path);
        let previous_parent = previous.roots.get(&parent.path);
        let acl_changed = previous_root.is_none_or(|old| old.acl_changed(new))
            || previous_parent.is_none_or(|old| old.acl_changed(parent));
        if acl_changed
            && new.widens_delegation(parent)
            && let Some(authority) = canonical_ancestor(previous, &new.path)
        {
            // New or changed delegation must use existing ancestor authority,
            // never an ACL the candidate grants to its changed child.
            required_admin.push(affected(authority, RootSide::Previous, true));
        }
    }
    changes.sort();
    required_admin.sort();
    required_admin.dedup();
    RootChangePlan {
        candidate: candidate.tree,
        first_parent: candidate.parents.first().copied(),
        affected: changes,
        required_admin,
        fresh: false,
    }
}

fn canonical_ancestor<'a>(snapshot: &'a Snapshot, path: &[u8]) -> Option<&'a Root> {
    snapshot
        .roots
        .values()
        .filter(|root| root.path != path && ancestor(&root.path, path))
        .max_by_key(|root| root.path.len())
}

/// Verifies original signed claims against canonical prior/candidate root changes.
///
/// Each claim must name an actual root, never a file path. Broader same-domain
/// canonical ancestor claims may cover affected descendants, but the original
/// authenticated token is independently evaluated on every affected actual root.
/// The stored original epoch context preserves attenuation caveats. Current ACLs
/// and current operation authorization remain native checks.
///
/// A first-parent audit cut is available only from a complete disclosure batch.
/// It requires a complete fresh candidate and actual view-root publication scope.
/// Identical copied trees validate only the bounded claimed root occurrences.
/// Initial and certified-fresh views require the separately trusted input to
/// [`verify_root_context_with_bootstrap`], even for an empty candidate ACL.
///
/// # Errors
/// Returns [`Rejected`] for missing witnesses, unchecked disclosure state,
/// nonexistent or mislabeled claims, uncovered changes, insufficient original
/// grants/caveats, a missing initial bootstrap input, or an unavailable ordinary
/// first parent.
pub fn verify_root_context(
    history: &mut VerifiedHistory,
    view: Digest,
    defaults: Defaults<'_>,
) -> Result<VerifiedRootScope, Rejected> {
    verify_context(history, view, defaults, None)
}

/// Verifies canonical scope with separately trusted original bootstrap evidence.
///
/// `expected_original_authority` must come from protected resolution of the
/// actual original physical authority, independently of the candidate or token
/// issuer. The exact original baseline remains available after destination-only
/// reopening. Ordinary views may also validate this configuration explicitly.
/// Current ACL intersections remain native admission checks.
///
/// # Errors
/// Returns [`Rejected`] for mismatched authority/ref/epoch, invalid baseline
/// grants, missing canonical evidence or insufficient original Commit/Admin.
pub fn verify_root_context_with_bootstrap(
    history: &mut VerifiedHistory,
    view: Digest,
    defaults: Defaults<'_>,
    expected_original_authority: &str,
    policy: OriginalBootstrapPolicy<'_>,
) -> Result<VerifiedRootScope, Rejected> {
    verify_context(
        history,
        view,
        defaults,
        Some((expected_original_authority, policy)),
    )
}

fn verify_context(
    history: &mut VerifiedHistory,
    view: Digest,
    defaults: Defaults<'_>,
    original_bootstrap: Option<(&str, OriginalBootstrapPolicy<'_>)>,
) -> Result<VerifiedRootScope, Rejected> {
    history.require_disclosure_validation(view)?;
    let verified = history.commit(&view).ok_or(Rejected)?;
    let record = verified.commit();
    let context = record
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or(Rejected)?;
    let audit_first = record
        .parents
        .first()
        .is_some_and(|parent| history.disclosure_parents.contains(&(view, *parent)));
    if !audit_first && let Some(first_parent) = record.parents.first() {
        history.require_disclosure_validation(*first_parent)?;
        let parent = history.commit(first_parent).ok_or(Rejected)?;
        if parent.commit().profile_pair.commit_context.is_some()
            && !history.root_scopes.contains_key(first_parent)
        {
            return Err(Rejected);
        }
    }
    let mut plan = if audit_first {
        fresh_plan(history, record, defaults, history.view_selection(view)?)?
    } else {
        changes_selected(history, record, defaults, history.view_selection(view)?)?
    };
    let bootstrap = original_bootstrap
        .map(|(authority, policy)| policy.validate(verified, authority))
        .transpose()?;
    if let Some(original) = &bootstrap {
        let key = (
            original.authority.clone(),
            original.reference.clone(),
            original.writer_epoch,
        );
        if history
            .bootstrap_policies
            .get(&key)
            .is_some_and(|previous| previous != original)
        {
            return Err(Rejected);
        }
    }
    if plan.fresh {
        let original = bootstrap.as_ref().ok_or(Rejected)?;
        let current = snapshot::complete(
            history,
            record.tree,
            defaults,
            history.view_selection(view)?,
        )?;
        let main = current.roots.get(b"/".as_slice()).ok_or(Rejected)?;
        if bootstrap::widens(main.acl().ok_or(Rejected)?, &original.acl) {
            plan.required_admin
                .push(affected(main, RootSide::Candidate, true));
        }
        for child in current.roots.values() {
            if let Some(parent) = canonical_ancestor(&current, &child.path)
                && child.widens_delegation(parent)
            {
                plan.required_admin
                    .push(affected(parent, RootSide::Candidate, true));
            }
        }
        plan.required_admin.sort();
        plan.required_admin.dedup();
    }
    let mut claims = Vec::new();
    for claim in context.roots() {
        let current = snapshot::at_path(
            history,
            record.tree,
            claim.path(),
            defaults,
            history.view_selection(view)?,
        );
        let prior = if audit_first {
            None
        } else {
            record
                .parents
                .first()
                .and_then(|parent| history.commit(parent))
                .map(|parent| {
                    snapshot::at_path(
                        history,
                        parent.commit().tree,
                        claim.path(),
                        defaults,
                        history.view_selection(parent.identity())?,
                    )
                })
        };
        let current = current.ok().filter(|root| root.domain == claim.domain());
        let previous = prior
            .and_then(Result::ok)
            .filter(|root| root.domain == claim.domain());
        match (current, previous) {
            (Some(root), _) => claims.push(affected(&root, RootSide::Candidate, false)),
            (None, Some(root)) => claims.push(affected(&root, RootSide::Previous, false)),
            (None, None) => return Err(Rejected),
        }
    }
    if (plan.fresh || record.parents.is_empty())
        && !claims
            .iter()
            .any(|claim| claim.path == b"/" && claim.side == RootSide::Candidate)
    {
        return Err(Rejected);
    }
    for root in &plan.affected {
        if !claims
            .iter()
            .any(|claim| claim.domain == root.domain && ancestor(&claim.path, &root.path))
        {
            return Err(Rejected);
        }
    }
    let signed_roots: Vec<_> = claims
        .iter()
        .map(|root| RequestRoot {
            path: &root.path,
            domain: &root.domain,
        })
        .collect();
    verified.authorize_original_roots(Verb::Commit, &signed_roots)?;
    if !plan.affected.is_empty() {
        let actual_roots: Vec<_> = plan
            .affected
            .iter()
            .map(|root| RequestRoot {
                path: &root.path,
                domain: &root.domain,
            })
            .collect();
        verified.authorize_original_roots(Verb::Commit, &actual_roots)?;
    }
    for required in &plan.required_admin {
        let tree = match required.side {
            RootSide::Candidate => record.tree,
            RootSide::Previous => record
                .parents
                .first()
                .and_then(|parent| history.commit(parent))
                .map(|parent| parent.commit().tree)
                .ok_or(Rejected)?,
        };
        let mut paths = alloc::vec![b"/".as_slice()];
        paths.extend(
            (1..required.path.len())
                .filter(|position| required.path[*position] == b'/')
                .map(|position| &required.path[..position]),
        );
        if required.path != b"/" {
            paths.push(&required.path);
        }
        let authorized = paths.into_iter().any(|path| {
            let selected_view = match required.side {
                RootSide::Candidate => view,
                RootSide::Previous => match record.parents.first() {
                    Some(parent) => *parent,
                    None => return false,
                },
            };
            history
                .view_selection(selected_view)
                .and_then(|selection| snapshot::at_path(history, tree, path, defaults, selection))
                .is_ok_and(|root| {
                    verified
                        .authorize_original_roots(
                            Verb::Admin,
                            &[RequestRoot {
                                path: &root.path,
                                domain: &root.domain,
                            }],
                        )
                        .is_ok()
                })
        });
        if !authorized {
            return Err(Rejected);
        }
    }
    let mut scope = VerifiedRootScope {
        view,
        plan,
        claims,
        bootstrap,
    };
    if let Some(previous) = history.root_scopes.get(&view) {
        scope = previous.merge_checked(&scope)?;
    }
    if let Some(original) = &scope.bootstrap {
        history.bootstrap_policies.insert(
            (
                original.authority.clone(),
                original.reference.clone(),
                original.writer_epoch,
            ),
            original.clone(),
        );
    }
    history.root_scopes.insert(view, scope.clone());
    Ok(scope)
}

fn ancestor(parent: &[u8], child: &[u8]) -> bool {
    parent == b"/"
        || parent == child
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}
