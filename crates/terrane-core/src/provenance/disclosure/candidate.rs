//! Keeps certificate and origin validation private until the complete batch succeeds.

use super::super::{
    EntryLocation, OriginalBootstrapPolicy, Rejected, VerifiedCommit, VerifiedHistory,
};
use super::{
    DisclosureAuthority, VerifiedDisclosureBatch, VerifiedDisclosureBoundary, key_name,
    statement::{disclosure_target_binding, original, preimage},
    witness::{self, Witness},
};
use crate::{identity::Digest, properties::Defaults, refs::EntryOrigin};
use alloc::{collections::BTreeSet, string::ToString, vec::Vec};
use core::cell::RefCell;
use ed25519_dalek::{Signature, VerifyingKey};

/// Owns provisional evidence with no history, evaluator or boundary accessor.
///
/// Certificate authentication permits planning the remaining immutable loads.
/// Only [`Self::finish`] exposes checked history after every candidate entry and
/// attribute origin has validated. The caller's original history stays unchanged.
pub struct DisclosureCandidate<'a> {
    history: VerifiedHistory,
    view: Digest,
    defaults: Defaults<'a>,
    witness: Witness,
    batch: VerifiedDisclosureBatch,
    retention_cache: RefCell<BTreeSet<(Digest, alloc::string::String)>>,
    bootstrap: Option<(&'a str, OriginalBootstrapPolicy<'a>)>,
}

impl<'a> DisclosureCandidate<'a> {
    /// Authenticates all certificates against the complete canonical candidate.
    ///
    /// `history` must contain the ordinarily verified signed destination and
    /// complete canonical trees for all its graft occurrences. Signature and
    /// original claimed-context authentication come from `verify_history`.
    /// [`Self::finish`] validates actual canonical affected-root scope; native
    /// current operation authorization remains a separate requirement.
    /// Authorities are trusted physical repository configuration, not token keys.
    /// Initial or certified-fresh verification needs [`Self::new_with_bootstrap`]
    /// before finish; an empty candidate ACL does not supply that baseline.
    ///
    /// # Errors
    /// Returns [`Rejected`] for missing canonical evidence, absent certificates,
    /// unknown or ambiguously scoped historical keys, invalid signatures,
    /// unsupported projections, contradictory occurrences or malformed origins.
    pub fn new(
        history: &VerifiedHistory,
        view: Digest,
        authorities: &[DisclosureAuthority<'_>],
        defaults: Defaults<'a>,
    ) -> Result<Self, Rejected> {
        // A bare key/domain pair must never pick among physical repositories.
        for (position, authority) in authorities.iter().enumerate() {
            if authorities[..position].iter().any(|previous| {
                previous.public_key == authority.public_key
                    && previous.domain == authority.domain
                    && previous.repository != authority.repository
            }) {
                return Err(Rejected);
            }
        }
        let witness = witness::enumerate(history, view, defaults)?;
        let record = history.commit(&view).ok_or(Rejected)?.commit();
        let receipts = record
            .profile_pair
            .entry_receipts
            .as_deref()
            .ok_or(Rejected)?;
        let context = record
            .profile_pair
            .commit_context
            .as_ref()
            .ok_or(Rejected)?;
        let binding = disclosure_target_binding(record)?;
        let mut boundaries: Vec<VerifiedDisclosureBoundary> = Vec::new();
        for receipt in receipts
            .iter()
            .filter(|receipt| receipt.disclosure_proof.is_some())
        {
            let location = EntryLocation {
                commit: view,
                root: receipt.root,
                path: receipt.path.clone(),
            };
            let targets: Vec<_> = witness
                .entries
                .iter()
                .filter(|target| target.location == location)
                .collect();
            if targets.is_empty() {
                return Err(Rejected);
            }
            let proof = receipt.disclosure_proof.as_ref().ok_or(Rejected)?;
            let source = receipt.reintroduced_from.as_ref().ok_or(Rejected)?;
            let authority = authorities
                .iter()
                .find(|authority| {
                    key_name(&authority.public_key) == proof.authority_key
                        && authority.domain == proof.source_domain
                        && authority.permits(proof.observed_at).is_ok()
                })
                .ok_or(Rejected)?;
            let target_domain = &targets[0].domain;
            let mut occurrences = Vec::new();
            for target in targets {
                if target.domain != *target_domain {
                    return Err(Rejected);
                }
                // A certified target is covered by an actual same-domain root
                // assertion, possibly a broader canonical ancestor root.
                if !context.roots().iter().any(|claim| {
                    claim.domain() == target.domain
                        && witness
                            .roots
                            .iter()
                            .any(|(path, domain)| path == claim.path() && domain == claim.domain())
                        && ancestor_root(claim.path(), &target.root_path)
                }) {
                    return Err(Rejected);
                }
                occurrences.push(target.root_path.clone());
            }
            VerifyingKey::from_bytes(&authority.public_key)
                .map_err(|_| Rejected)?
                .verify_strict(
                    &preimage(history, &location, receipt, target_domain, binding)?,
                    &Signature::from_bytes(&proof.signature),
                )
                .map_err(|_| Rejected)?;
            occurrences.sort();
            occurrences.dedup();
            boundaries.push(VerifiedDisclosureBoundary {
                target: location,
                source: source.clone(),
                original_introducer: original(&history.entry(&EntryLocation {
                    commit: view,
                    root: receipt.root,
                    path: receipt.path.clone(),
                })?)?,
                authority_repository: authority.repository.to_string(),
                authority_domain: authority.domain.to_string(),
                authority_key: authority.public_key,
                observed_at: proof.observed_at,
                target_domain: target_domain.clone(),
                root_occurrences: occurrences,
                binding,
            });
        }
        if boundaries.is_empty() {
            return Err(Rejected);
        }
        let parents: Vec<_> = record
            .parents
            .iter()
            .copied()
            .filter(|parent| {
                boundaries
                    .iter()
                    .any(|boundary| boundary.source.commit == *parent)
            })
            .collect();
        if record
            .parents
            .first()
            .is_some_and(|parent| parents.contains(parent))
        {
            let root_domain = witness
                .roots
                .iter()
                .find(|(path, _)| path == b"/")
                .map(|(_, domain)| domain)
                .ok_or(Rejected)?;
            if !context
                .roots()
                .iter()
                .any(|claim| claim.path() == b"/" && claim.domain() == root_domain)
            {
                return Err(Rejected);
            }
            for (path, domain) in &witness.roots {
                if !context.roots().iter().any(|claim| {
                    claim.domain() == domain
                        && witness.roots.iter().any(|(actual_path, actual_domain)| {
                            actual_path == claim.path() && actual_domain == claim.domain()
                        })
                        && ancestor_root(claim.path(), path)
                }) {
                    return Err(Rejected);
                }
            }
        }
        let mut dependencies: BTreeSet<_> = record
            .parents
            .iter()
            .copied()
            .filter(|parent| !parents.contains(parent))
            .collect();
        for receipt in receipts {
            if let EntryOrigin::Source(source) = &receipt.origin {
                dependencies.insert(source.commit);
            }
            if receipt.disclosure_proof.is_none()
                && let Some(source) = &receipt.reintroduced_from
            {
                dependencies.insert(source.commit);
            }
            for (_, origin) in receipt.attributes.iter().flatten() {
                if let EntryOrigin::Source(source) = origin {
                    dependencies.insert(source.commit);
                }
            }
        }
        // Skip only authenticated exact content edges, never an independent
        // attribute or another ordinary receipt that happens to share a hash.
        if dependencies
            .iter()
            .any(|identity| parents.contains(identity))
        {
            return Err(Rejected);
        }
        let mut provisional = history.clone();
        for boundary in &boundaries {
            provisional
                .disclosure_boundaries
                .insert(boundary.target.clone(), boundary.clone());
        }
        provisional
            .disclosure_parents
            .extend(parents.iter().map(|parent| (view, *parent)));
        // This marker exists only inside the private candidate until finish.
        provisional.disclosure_verified_views.insert(view);
        provisional.provisional_scopes.insert(view);
        let candidate = Self {
            history: provisional,
            view,
            defaults,
            witness,
            batch: VerifiedDisclosureBatch {
                view,
                boundaries,
                parents,
                dependencies: dependencies.into_iter().collect(),
            },
            retention_cache: RefCell::new(BTreeSet::new()),
            bootstrap: None,
        };
        candidate.check_explicit_origins()?;
        Ok(candidate)
    }

    /// Stages a candidate with explicitly trusted original bootstrap context.
    ///
    /// The authority identity must come from protected physical authority
    /// resolution. The separately retained policy is checked against the signed
    /// original ref/epoch; neither a candidate ACL nor current policy supplies it.
    /// This constructor exposes no authority before the complete batch finishes.
    ///
    /// # Errors
    /// Returns [`Rejected`] for invalid certificates, missing canonical evidence
    /// or mismatched/invalid original bootstrap configuration.
    pub fn new_with_bootstrap(
        history: &VerifiedHistory,
        view: Digest,
        authorities: &[DisclosureAuthority<'_>],
        defaults: Defaults<'a>,
        expected_original_authority: &'a str,
        policy: OriginalBootstrapPolicy<'a>,
    ) -> Result<Self, Rejected> {
        policy.check(
            history.commit(&view).ok_or(Rejected)?,
            expected_original_authority,
        )?;
        let mut candidate = Self::new(history, view, authorities, defaults)?;
        candidate.bootstrap = Some((expected_original_authority, policy));
        Ok(candidate)
    }

    /// Returns the remaining ordinary dependency loads for private validation.
    ///
    /// This planning list is not a collector permit or exposed verified history.
    pub fn required_commits(&self) -> &[Digest] {
        &self.batch.dependencies
    }

    /// Adds an ordinarily authenticated dependency commit to the private batch.
    ///
    /// # Errors
    /// Returns [`Rejected`] for a cycle or conflicting immutable evidence.
    pub fn insert_commit(&mut self, commit: VerifiedCommit) -> Result<(), Rejected> {
        self.history.insert_commit(commit)
    }

    /// Adds already checked dependency histories, including their finished batches.
    ///
    /// This supports publicly retained sources that themselves contain durable
    /// disclosures. No provisional history can be supplied through this API.
    /// The candidate's own complete validation remains mandatory.
    ///
    /// # Errors
    /// Returns [`Rejected`] for profile, graph, tree or boundary conflicts.
    pub fn insert_history(&mut self, history: &VerifiedHistory) -> Result<(), Rejected> {
        self.history.append_evidence(history)
    }

    /// Validates an ordinary dependency's canonical original root scope privately.
    ///
    /// Dependencies are validated from ancestors to descendants. A dependency
    /// containing certificates requires its own completed batch through
    /// [`Self::insert_history`]. The candidate's scope is checked only by finish.
    ///
    /// # Errors
    /// Returns [`Rejected`] for the candidate view, missing canonical evidence,
    /// unchecked parent scopes, raw certificates or invalid original grants.
    pub fn validate_dependency_scope(&mut self, view: Digest) -> Result<(), Rejected> {
        if view == self.view {
            return Err(Rejected);
        }
        super::super::verify_root_context(&mut self.history, view, self.defaults)?;
        Ok(())
    }

    /// Checks a dependency with its separately retained original bootstrap input.
    ///
    /// The protected authority association belongs to that dependency's original
    /// authoring context. It cannot be substituted from this candidate's input.
    ///
    /// # Errors
    /// Returns [`Rejected`] for the candidate view, incomplete witnesses, invalid
    /// original scope or mismatched bootstrap authority/ref/epoch evidence.
    pub fn validate_dependency_scope_with_bootstrap(
        &mut self,
        view: Digest,
        expected_original_authority: &str,
        policy: OriginalBootstrapPolicy<'_>,
    ) -> Result<(), Rejected> {
        if view == self.view {
            return Err(Rejected);
        }
        super::super::verify_root_context_with_bootstrap(
            &mut self.history,
            view,
            self.defaults,
            expected_original_authority,
            policy,
        )?;
        Ok(())
    }

    /// Adds complete canonical ordinary tree evidence to the private batch.
    ///
    /// # Errors
    /// Returns [`Rejected`] for invalid, incomplete or inconsistent witnesses.
    pub fn insert_tree(
        &mut self,
        root: Digest,
        nodes: &[(Digest, Vec<u8>)],
    ) -> Result<(), Rejected> {
        self.history.insert_tree(root, nodes)
    }

    /// Adds complete canonical index tree evidence to the private batch.
    ///
    /// # Errors
    /// Returns [`Rejected`] for invalid, incomplete or inconsistent witnesses.
    pub fn insert_index_tree(
        &mut self,
        root: Digest,
        nodes: &[(Digest, Vec<u8>)],
    ) -> Result<(), Rejected> {
        self.history.insert_index_tree(root, nodes)
    }

    /// Completes all entry and attribute checks before exposing any boundary.
    ///
    /// The returned history contains actual signed public records only. The batch
    /// describes attested private identities as audit boundaries separately.
    /// Complete retained records, siblings, metadata and ordinary ancestry must
    /// all be permissible in their destination domain. Canonical original root
    /// scope is validated after the private origin batch, before either result
    /// becomes accessible.
    ///
    /// # Errors
    /// Returns [`Rejected`] for missing parents, unanchored private inputs,
    /// uncovered sibling content/attributes, nonpublic retained sources,
    /// invalid original root authorization, ambiguous origins, or contradictory
    /// canonical evidence.
    pub fn finish(mut self) -> Result<(VerifiedHistory, VerifiedDisclosureBatch), Rejected> {
        for dependency in &self.batch.dependencies {
            let commit = self.history.commit(dependency).ok_or(Rejected)?;
            witness::enumerate(&self.history, commit.identity(), self.defaults)?;
        }
        let record = self.history.commit(&self.view).ok_or(Rejected)?.commit();
        let view_domain = self
            .witness
            .roots
            .iter()
            .find(|(path, _)| path == b"/")
            .map(|(_, domain)| domain)
            .ok_or(Rejected)?;
        for parent in &record.parents {
            if !self.batch.parents.contains(parent) {
                self.check_retention(*parent, view_domain)?;
            }
        }
        let receipts = record
            .profile_pair
            .entry_receipts
            .as_deref()
            .ok_or(Rejected)?;
        for target in &self.witness.entries {
            let receipt = receipts.iter().find(|receipt| {
                receipt.root == target.location.root && receipt.path == target.location.path
            });
            if let Some(receipt) = receipt {
                if let EntryOrigin::Source(source) = &receipt.origin {
                    self.check_public_source(source, &target.domain)?;
                }
                if receipt.disclosure_proof.is_none()
                    && let Some(source) = &receipt.reintroduced_from
                {
                    self.check_public_source(source, &target.domain)?;
                }
                for (_, origin) in receipt.attributes.iter().flatten() {
                    if let EntryOrigin::Source(source) = origin {
                        self.check_public_source(source, &target.domain)?;
                    }
                }
            }
            self.history.introducing_commit(&target.location)?;
            self.check_public_chain(&target.location, &target.domain, None)?;
            for attribute in self.history.entry(&target.location)?.attrs {
                self.history
                    .attribute_producer(&target.location, attribute.name)?;
                self.check_public_chain(&target.location, &target.domain, Some(attribute.name))?;
            }
        }
        // All retained public ancestry must itself be available; a missing
        // unrelated parent is not hidden by one certified source edge.
        self.history.public_ancestor(self.view, self.view)?;
        match self.bootstrap {
            Some((authority, policy)) => {
                super::super::verify_root_context_with_bootstrap(
                    &mut self.history,
                    self.view,
                    self.defaults,
                    authority,
                    policy,
                )?;
            }
            None => {
                super::super::verify_root_context(&mut self.history, self.view, self.defaults)?;
            }
        }
        self.history.provisional_scopes.remove(&self.view);
        Ok((self.history, self.batch))
    }

    fn check_public_source(
        &self,
        source: &crate::refs::EntrySource,
        domain: &str,
    ) -> Result<(), Rejected> {
        self.history.entry(&EntryLocation {
            commit: source.commit,
            root: source.root,
            path: source.path.clone(),
        })?;
        self.check_retention(source.commit, domain)
    }

    fn check_retention(&self, view: Digest, domain: &str) -> Result<(), Rejected> {
        let key = (view, domain.to_string());
        if self.retention_cache.borrow().contains(&key) {
            return Ok(());
        }
        let checked = witness::retention_closure(&self.history, view, domain, self.defaults)?;
        self.retention_cache
            .borrow_mut()
            .extend(checked.into_iter().map(|view| (view, domain.to_string())));
        Ok(())
    }

    fn check_public_chain(
        &self,
        target: &EntryLocation,
        domain: &str,
        attribute: Option<&str>,
    ) -> Result<(), Rejected> {
        let mut pending = alloc::vec![target.clone()];
        let mut seen = BTreeSet::new();
        while let Some(location) = pending.pop() {
            if !seen.insert(location.clone()) {
                continue;
            }
            if location.commit != self.view {
                self.check_retention(location.commit, domain)?;
            }
            let dependencies = match attribute {
                Some(name) => self.history.attribute_dependencies(&location, name)?,
                None => self.history.dependencies(&location)?,
            };
            pending.extend(dependencies.into_iter().flatten());
        }
        Ok(())
    }

    fn check_explicit_origins(&self) -> Result<(), Rejected> {
        let record = self.history.commit(&self.view).ok_or(Rejected)?.commit();
        let receipts = record
            .profile_pair
            .entry_receipts
            .as_deref()
            .ok_or(Rejected)?;
        for receipt in receipts {
            if !self.witness.entries.iter().any(|target| {
                target.location.root == receipt.root && target.location.path == receipt.path
            }) {
                return Err(Rejected);
            }
        }
        for target in &self.witness.entries {
            let entry = self.history.entry(&target.location)?;
            let receipt = receipts.iter().find(|receipt| {
                receipt.root == target.location.root && receipt.path == target.location.path
            });
            if !self.batch.parents.is_empty() {
                let receipt = receipt.ok_or(Rejected)?;
                if receipt.origin == EntryOrigin::Current
                    && receipt.disclosure_proof.is_none()
                    && receipt.reintroduced_from.is_none()
                {
                    return Err(Rejected);
                }
            }
            if let Some(receipt) = receipt {
                for (name, _) in receipt.attributes.iter().flatten() {
                    if !entry.attrs.iter().any(|attribute| attribute.name == name) {
                        return Err(Rejected);
                    }
                }
            }
            // A copied attribute has no certificate producer authority, even
            // when the private input tree happens to remain locally available.
            if !self.batch.parents.is_empty()
                || receipt.is_some_and(|receipt| receipt.disclosure_proof.is_some())
            {
                for attribute in &entry.attrs {
                    if !receipt
                        .and_then(|receipt| receipt.attributes.as_deref())
                        .is_some_and(|origins| {
                            origins.iter().any(|(name, _)| name == attribute.name)
                        })
                    {
                        return Err(Rejected);
                    }
                }
            }
        }
        Ok(())
    }
}

fn ancestor_root(ancestor: &[u8], descendant: &[u8]) -> bool {
    ancestor == b"/"
        || ancestor == descendant
        || descendant
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}
