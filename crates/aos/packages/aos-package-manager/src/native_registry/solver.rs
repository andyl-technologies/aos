//! Resolves authenticated module candidates and records exact dependency choices.
//!
//! Candidate envelopes are authenticated by the caller before entering this
//! pure solver. A lock records original requirements and immutable choices;
//! replay validates it without consulting registry discovery.
//!
//! ```json
//! {"schema":"aos.package.resolution-lock","edges":[],"requesters":{}}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use aos_activation::adapter::CancellationToken;

use anyhow::{Context, Result, bail, ensure};

use aos_deployment_format::model::{Envelope, ModuleDependency, ModuleSource};

const MAX_SEARCH_STEPS: usize = 100_000;
const MAX_SEARCH_DEPTH: usize = 512;
const MAX_CANDIDATES: usize = 16_384;

use aos_deployment_format::resolution_lock::{LockedEdge, ResolutionLock, matches_requirement};

/// Contains the selected module closure and its reproducible compatibility choices.
#[derive(Debug)]
pub(crate) struct Solution {
    /// Includes each selected package once, including moduleless requesters.
    pub(crate) envelopes: Vec<Envelope>,
    /// Records all dependency edges when the closure contains a ranged dependency.
    pub(crate) lock: Option<ResolutionLock>,
}

/// Searches only caller-authenticated candidates; no I/O or handler execution occurs.
///
/// # Errors
/// Returns an error for conflicting roots, unsatisfiable requirements, ambiguous
/// sources, inconsistent retained choices, cancellation, or exhausted search limits.
pub(crate) fn solve(
    roots: &[Envelope],
    candidates: &[Envelope],
    preferred: Option<&ResolutionLock>,
    preferred_sources: &[ModuleSource],
    refresh_names: Option<&BTreeSet<String>>,
    cancellation: &CancellationToken,
    os_release: Option<&aos_module_docs::runtime::OsRelease>,
) -> Result<Solution> {
    ensure!(
        candidates.len() <= MAX_CANDIDATES,
        "module candidate universe exceeds its bound"
    );
    // The fixed host release filters the universe before dependency search.
    let candidates = candidates
        .iter()
        .filter_map(|candidate| match accepts_os(candidate, os_release) {
            Ok(true) => Some(Ok(candidate.clone())),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>>>()?;
    let mut selected = BTreeMap::new();
    for root in roots {
        check_os_requirement(root, os_release)?;
        let mut normalized = root.clone();
        normalized.package = normalized.package.canonical_catalog();
        if let Some(previous) = selected.insert(root.package.name.clone(), normalized.clone()) {
            ensure!(
                previous == normalized,
                "explicit package roots have conflicting native identities: {}",
                root.package.name
            );
        }
    }
    let policy = SelectionPolicy::new(roots, preferred, preferred_sources, refresh_names)?;
    let mut budget = SearchBudget {
        steps: 0,
        deadline: Instant::now() + Duration::from_secs(30),
        cancellation,
    };
    let selected = search(selected, &candidates, &policy, &mut budget, 0).map_err(|error| {
        let message = format!("module dependency resolution failed: {error}");
        error.context(message)
    })?;
    let envelopes = selected.into_values().collect::<Vec<_>>();
    let ranged = envelopes.iter().any(|envelope| {
        envelope
            .module_dependencies
            .iter()
            .any(ModuleDependency::is_ranged)
    });
    let lock = if ranged {
        let mut edges = Vec::new();
        for envelope in &envelopes {
            for requirement in &envelope.module_dependencies {
                let selected = envelopes
                    .iter()
                    .find(|candidate| candidate.package.name == requirement.seed().name)
                    .context("solved dependency is absent")?;
                edges.push(LockedEdge {
                    requester: envelope.package.canonical_catalog(),
                    requirement: requirement.clone(),
                    selected: selected
                        .module
                        .clone()
                        .context("solved dependency has no module")?,
                });
            }
        }
        Some(ResolutionLock {
            schema: "aos.package.resolution-lock".into(),
            edges,
            requesters: BTreeMap::new(),
        })
    } else {
        None
    };
    Ok(Solution { envelopes, lock })
}

// Refresh selection is scoped to explicit package roots. A shared dependency
// can be refreshed only when no protected root retains its previous choice.
struct SelectionPolicy {
    preferred: BTreeMap<String, ModuleSource>,
    frozen: BTreeMap<String, ModuleSource>,
    refreshed: BTreeSet<String>,
}

impl SelectionPolicy {
    fn new(
        roots: &[Envelope],
        previous: Option<&ResolutionLock>,
        preferred_sources: &[ModuleSource],
        refresh_names: Option<&BTreeSet<String>>,
    ) -> Result<Self> {
        let mut preferred = preferred_sources
            .iter()
            .map(|source| (source.name.clone(), source.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut edges: BTreeMap<&str, Vec<&LockedEdge>> = BTreeMap::new();
        if let Some(lock) = previous {
            for edge in &lock.edges {
                if let Some(previous) =
                    preferred.insert(edge.selected.name.clone(), edge.selected.clone())
                {
                    ensure!(
                        previous == edge.selected,
                        "retained source and dependency lock disagree for {}",
                        edge.selected.name
                    );
                }
                edges.entry(&edge.requester.name).or_default().push(edge);
            }
        }
        let mut policy = Self {
            preferred,
            frozen: BTreeMap::new(),
            refreshed: BTreeSet::new(),
        };
        let Some(refresh_names) = refresh_names else {
            return Ok(policy);
        };

        let mut pending = refresh_names.iter().cloned().collect::<Vec<_>>();
        while let Some(name) = pending.pop() {
            if !policy.refreshed.insert(name.clone()) {
                continue;
            }
            if let Some(children) = edges.get(name.as_str()) {
                pending.extend(children.iter().map(|edge| edge.selected.name.clone()));
            }
        }

        let mut protected = BTreeSet::new();
        let mut pending = roots
            .iter()
            .filter(|root| !refresh_names.contains(&root.package.name))
            .map(|root| root.package.name.clone())
            .collect::<Vec<_>>();
        while let Some(name) = pending.pop() {
            if !protected.insert(name.clone()) {
                continue;
            }
            if let Some(children) = edges.get(name.as_str()) {
                for edge in children {
                    if let Some(previous) = policy
                        .frozen
                        .insert(edge.selected.name.clone(), edge.selected.clone())
                    {
                        ensure!(
                            previous == edge.selected,
                            "retained dependency choices conflict for {}",
                            edge.selected.name
                        );
                    }
                    pending.push(edge.selected.name.clone());
                }
            }
        }
        Ok(policy)
    }

    fn accepts(&self, candidate: &Envelope) -> bool {
        self.frozen
            .get(&candidate.package.name)
            .is_none_or(|source| candidate.module.as_ref() == Some(source))
    }

    // New candidate releases may introduce dependencies absent from the old
    // lock. Propagate refresh intent through their actual declarations as well.
    fn refreshed_names(&self, selected: &BTreeMap<String, Envelope>) -> BTreeSet<String> {
        let mut refreshed = self.refreshed.clone();
        let mut pending = refreshed.iter().cloned().collect::<Vec<_>>();
        while let Some(name) = pending.pop() {
            if let Some(package) = selected.get(&name) {
                for dependency in &package.module_dependencies {
                    let name = &dependency.seed().name;
                    if refreshed.insert(name.clone()) {
                        pending.push(name.clone());
                    }
                }
            }
        }
        refreshed
    }
}

#[derive(Debug)]
struct SearchStopped(&'static str);

impl std::fmt::Display for SearchStopped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for SearchStopped {}

struct SearchBudget<'a> {
    steps: usize,
    deadline: Instant,
    cancellation: &'a CancellationToken,
}

impl SearchBudget<'_> {
    fn check(&self) -> Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(SearchStopped("module solver cancelled").into());
        }
        if self.steps > MAX_SEARCH_STEPS || Instant::now() >= self.deadline {
            return Err(SearchStopped("module solver search budget exceeded").into());
        }
        Ok(())
    }
}

fn search(
    selected: BTreeMap<String, Envelope>,
    candidates: &[Envelope],
    policy: &SelectionPolicy,
    budget: &mut SearchBudget<'_>,
    depth: usize,
) -> Result<BTreeMap<String, Envelope>> {
    budget.steps += 1;
    budget.check()?;
    if depth > MAX_SEARCH_DEPTH {
        return Err(SearchStopped("module solver search depth exceeded").into());
    }
    for candidate in selected.values() {
        ensure!(
            policy.accepts(candidate),
            "module {} is pinned by a package outside the requested upgrade set",
            candidate.package.name
        );
    }
    let refreshed = policy.refreshed_names(&selected);
    let mut requirements: BTreeMap<String, Vec<(&Envelope, &ModuleDependency)>> = BTreeMap::new();
    for requester in selected.values() {
        for requirement in &requester.module_dependencies {
            requirement.check()?;
            requirements
                .entry(requirement.seed().name.clone())
                .or_default()
                .push((requester, requirement));
        }
    }
    let mut next: Option<(String, Vec<Envelope>)> = None;
    for (name, constraints) in &requirements {
        if let Some(candidate) = selected.get(name) {
            for (requester, requirement) in constraints {
                ensure!(
                    matches_requirement(requirement, candidate)?,
                    "{}@{} requires {} but selected {}@{} does not satisfy {}",
                    requester.package.name,
                    requester.package.version,
                    name,
                    candidate.package.name,
                    candidate.package.version,
                    serde_json::to_string(requirement)?
                );
            }
            continue;
        }
        budget.check()?;
        let mut domain = Vec::new();
        for candidate in candidates
            .iter()
            .filter(|candidate| &candidate.package.name == name)
        {
            budget.check()?;
            if policy.accepts(candidate)
                && constraints
                    .iter()
                    .map(|(_, requirement)| matches_requirement(requirement, candidate))
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .all(|matched| *matched)
            {
                let mut normalized = candidate.clone();
                normalized.package = normalized.package.canonical_catalog();
                if !domain.contains(&normalized) {
                    domain.push(normalized);
                }
            }
        }
        ensure!(
            !domain.is_empty(),
            "no authenticated candidate for {} satisfies: {}",
            name,
            constraints
                .iter()
                .map(|(requester, requirement)| format!(
                    "{}@{} -> {:?}",
                    requester.package.name, requester.package.version, requirement
                ))
                .collect::<Vec<_>>()
                .join("; ")
        );
        // Source identity cannot stand for two different payload contexts.
        for (index, candidate) in domain.iter().enumerate() {
            budget.check()?;
            ensure!(
                domain[index + 1..]
                    .iter()
                    .all(|other| candidate.module != other.module
                        || crate::native_registry::same_package_context(candidate, other)),
                "module source has ambiguous authenticated artifact contexts: {name}"
            );
        }
        if !refreshed.contains(name) {
            domain.sort_by_key(|candidate| {
                !candidate
                    .module
                    .as_ref()
                    .is_some_and(|source| policy.preferred.get(&source.name) == Some(source))
            });
        }
        if next
            .as_ref()
            .is_none_or(|(_, previous)| domain.len() < previous.len())
        {
            next = Some((name.clone(), domain));
        }
    }
    let Some((name, domain)) = next else {
        return Ok(selected);
    };
    let mut failures = Vec::new();
    for candidate in domain {
        let mut branch = selected.clone();
        branch.insert(name.clone(), candidate);
        match search(branch, candidates, policy, budget, depth + 1) {
            Ok(solution) => return Ok(solution),
            Err(error) => {
                if error.downcast_ref::<SearchStopped>().is_some() {
                    return Err(error);
                }
                if failures.len() < 4 {
                    failures.push(error.to_string());
                }
            }
        }
    }
    bail!(
        "all candidates for {name} conflict: {}",
        failures.join("; ")
    )
}

/// Checks one authenticated envelope against the fixed runtime host release.
///
/// # Errors
/// Returns an error for an invalid range, a missing host release, or a host
/// release outside the package's declared OS constraint.
pub(crate) fn check_os_requirement(
    envelope: &Envelope,
    release: Option<&aos_module_docs::runtime::OsRelease>,
) -> Result<()> {
    ensure!(
        accepts_os(envelope, release)?,
        "package '{}' requires OS version {}, incompatible with the retained host release",
        envelope.package.name,
        envelope.os_version.as_deref().unwrap_or("unspecified")
    );
    Ok(())
}

fn accepts_os(
    envelope: &Envelope,
    release: Option<&aos_module_docs::runtime::OsRelease>,
) -> Result<bool> {
    let Some(requirement) = &envelope.os_version else {
        return Ok(true);
    };
    let Some(release) = release else {
        return Ok(false);
    };
    let Ok(version) = semver::Version::parse(&release.version) else {
        return Ok(false);
    };
    Ok(semver::VersionReq::parse(requirement)?.matches(&version))
}

#[cfg(test)]
mod tests;
