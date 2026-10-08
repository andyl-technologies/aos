//! Batched, memoized Nix store metadata for registry authoring.
//!
//! Registry publication inspects the complete runtime closure of every root it
//! publishes. The closures of one release overlap heavily, and the metadata of
//! a valid store path is immutable, so [`StoreQueries`] loads each path's
//! validity record once and answers every later question from memory.
//!
//! Records come from `nix-store --dump-db`, which prints Nix's stable
//! validity-registration format for each requested path:
//!
//! ```text
//! /nix/store/<hash>-<name>        store path
//! <64 lowercase hex digits>       SHA-256 NAR hash
//! <decimal>                       NAR size
//! /nix/store/<hash>-<name>.drv    deriver, or an empty line
//! <decimal>                       reference count
//! /nix/store/<hash>-<name>        one line per reference
//! ```
//!
//! Content addresses from `nix store make-content-addressed` are memoized
//! the same way. The command rewrites the complete closure of its arguments
//! but reports a rewrite only for each argument, and a rewrite is a pure
//! function of a path's bytes and its closure. One invocation over many roots
//! therefore reports, for each root, exactly what an invocation for that root
//! alone would, while rewriting shared closure members once rather than once
//! per root. Batches split roots into overlap-aware groups that run
//! concurrently.
//!
//! Every answer is derived from complete, validated records. A missing,
//! malformed, or incomplete record fails the query instead of producing a
//! plausible but partial closure.

use super::{ClosureMemberNar, StorePathInfo, extract_hash, make_content_addressed, nix_command};
use anyhow::{Context, Result, bail};
use aos_core::output::Printer;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard};
use std::thread;

/// Upper bound on concurrent store subprocesses started by one batch.
///
/// Content addressing holds one complete NAR in memory per process, so the
/// bound protects memory on very wide machines as well as the Nix daemon.
const MAX_STORE_WORKERS: usize = 16;

/// Store paths read by one `nix-store --dump-db` invocation; small enough
/// that a release-sized closure spreads across every worker.
const RECORDS_PER_INVOCATION: usize = 512;

/// Root arguments passed to one content-addressing invocation, keeping argument
/// lists far below the kernel's `ARG_MAX`.
const ROOTS_PER_INVOCATION: usize = 4096;

/// Immutable validity metadata for one store path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::registry_ops) struct PathRecord {
    /// NAR hash in `nix-store --query --hash` form (`sha256:<nix32>`).
    pub(in crate::registry_ops) nar_hash: String,
    /// NAR serialization size in bytes.
    pub(in crate::registry_ops) nar_size: u64,
    /// Derivation recorded as the path's producer, when Nix knows it.
    pub(in crate::registry_ops) deriver: Option<String>,
    /// Direct references, including a self-reference, in Nix's order.
    pub(in crate::registry_ops) references: Vec<String>,
}

/// Memoized store metadata shared by every entry of one authoring run.
///
/// The cache never expires entries: it is meant to live for one command, over
/// which a valid store path's metadata cannot change.
#[derive(Debug, Default)]
pub(crate) struct StoreQueries {
    state: Mutex<QueryState>,
}

#[derive(Debug, Default)]
struct QueryState {
    /// Records keyed by full store path. Every loaded record's references are
    /// also loaded, so any key is the root of a complete closure.
    records: HashMap<String, PathRecord>,
    /// Content-addressed hash of each rewritten root, keyed by the root's
    /// input-addressed hash: exactly what Nix reports for that root alone.
    content_addresses: HashMap<String, String>,
}

impl StoreQueries {
    /// Creates an empty cache.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Creates a cache from already complete records, for tests.
    #[cfg(test)]
    fn from_parts(
        records: HashMap<String, PathRecord>,
        content_addresses: HashMap<String, String>,
    ) -> Self {
        Self {
            state: Mutex::new(QueryState {
                records,
                content_addresses,
            }),
        }
    }

    /// Locks the cache state.
    ///
    /// A panic while holding the lock cannot leave a partial record behind,
    /// because records are only inserted after a whole batch validates.
    fn state(&self) -> MutexGuard<'_, QueryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Loads the complete runtime closures of `roots` with batched queries.
    ///
    /// Already loaded paths cost nothing. Missing paths are read breadth-first
    /// with concurrent `nix-store --dump-db` invocations, one round per level
    /// of not yet loaded references, so a closure costs as many rounds as it
    /// is deep rather than one query per member.
    ///
    /// # Errors
    ///
    /// Returns an error when a root is not the canonical path of a valid
    /// store object, a query fails, or a returned record is malformed.
    pub(in crate::registry_ops) fn load_closures(&self, roots: &[&str]) -> Result<()> {
        let mut frontier = {
            let state = self.state();
            roots
                .iter()
                .copied()
                .filter(|root| !state.records.contains_key(*root))
                .map(str::to_string)
                .collect::<BTreeSet<_>>()
        };

        // Records join the shared cache only once their closures are
        // complete, so a failed round never leaves a partial closure behind.
        let mut loaded = HashMap::new();
        while !frontier.is_empty() {
            let requested = frontier.into_iter().collect::<Vec<_>>();
            let records = dump_records_concurrently(&requested)?;

            let state = self.state();
            frontier = records
                .values()
                .flat_map(|record| &record.references)
                .filter(|reference| {
                    !state.records.contains_key(*reference)
                        && !loaded.contains_key(*reference)
                        && !records.contains_key(*reference)
                })
                .cloned()
                .collect();
            drop(state);
            loaded.extend(records);
        }

        self.state().records.extend(loaded);
        Ok(())
    }

    /// Returns the validity record of one store path.
    ///
    /// # Errors
    ///
    /// Returns an error when the path's closure cannot be loaded.
    pub(in crate::registry_ops) fn record(&self, path: &str) -> Result<PathRecord> {
        self.load_closures(&[path])?;
        self.state()
            .records
            .get(path)
            .cloned()
            .with_context(|| format!("no store metadata loaded for {path}"))
    }

    /// Returns every member of `root`'s runtime closure, sorted by path.
    ///
    /// # Errors
    ///
    /// Returns an error when the closure cannot be loaded.
    pub(in crate::registry_ops) fn closure(&self, root: &str) -> Result<Vec<String>> {
        self.load_closures(&[root])?;
        let state = self.state();
        Ok(closure_of(&state.records, root)?
            .into_iter()
            .map(str::to_string)
            .collect())
    }

    /// Returns the same metadata as a sequence of `nix-store --query` calls.
    ///
    /// `references` holds direct reference hashes without a self-reference;
    /// `closure_size` sums the NAR sizes of the complete runtime closure.
    ///
    /// # Errors
    ///
    /// Returns an error when the closure cannot be loaded or its size
    /// overflows.
    pub(in crate::registry_ops) fn introspect(&self, store_path: &str) -> Result<StorePathInfo> {
        self.load_closures(&[store_path])?;
        let state = self.state();
        let record = state
            .records
            .get(store_path)
            .with_context(|| format!("no store metadata loaded for {store_path}"))?;

        let mut closure_size = 0_u64;
        for member in closure_of(&state.records, store_path)? {
            let size = state
                .records
                .get(member)
                .map(|member| member.nar_size)
                .with_context(|| format!("no store metadata loaded for {member}"))?;
            closure_size = closure_size
                .checked_add(size)
                .with_context(|| format!("closure size overflow for {store_path}"))?;
        }

        Ok(StorePathInfo {
            path: store_path.to_string(),
            nar_hash: record.nar_hash.clone(),
            nar_size: record.nar_size,
            references: direct_reference_hashes(&state.records, store_path)?,
            closure_size,
        })
    }

    /// Returns each closure member's hash with its direct dependency hashes.
    ///
    /// Members are sorted by store path; dependencies omit self-references
    /// and follow `nix-store --query --references` order.
    ///
    /// # Errors
    ///
    /// Returns an error when the closure cannot be loaded.
    pub(in crate::registry_ops) fn closure_edges(
        &self,
        root: &str,
    ) -> Result<Vec<(String, Vec<String>)>> {
        self.load_closures(&[root])?;
        let state = self.state();
        closure_of(&state.records, root)?
            .into_iter()
            .map(|member| {
                Ok((
                    extract_hash(member).to_string(),
                    direct_reference_hashes(&state.records, member)?,
                ))
            })
            .collect()
    }

    /// Returns NAR metadata for every closure member, sorted by store path.
    ///
    /// # Errors
    ///
    /// Returns an error when the closure cannot be loaded.
    pub(in crate::registry_ops) fn closure_nars(
        &self,
        root: &str,
    ) -> Result<Vec<ClosureMemberNar>> {
        self.load_closures(&[root])?;
        let state = self.state();
        closure_of(&state.records, root)?
            .into_iter()
            .map(|member| {
                let record = state
                    .records
                    .get(member)
                    .with_context(|| format!("no store metadata loaded for {member}"))?;
                Ok(ClosureMemberNar {
                    path: member.to_string(),
                    nar_hash: record.nar_hash.clone(),
                    nar_size: record.nar_size,
                })
            })
            .collect()
    }

    /// Content-addresses the closures of `roots` with concurrent batches.
    ///
    /// Roots are split into at most [`MAX_STORE_WORKERS`] groups that share
    /// as much of their closures as possible. A group whose invocation fails,
    /// or does not report exactly one rewrite per requested root, is reported
    /// and left unremembered, so [`Self::content_addresses`] retries each of
    /// its roots individually with the established per-root warning.
    ///
    /// # Errors
    ///
    /// Returns an error when closures cannot be loaded, or when two batches
    /// disagree about one root's content address.
    pub(in crate::registry_ops) fn load_content_addresses(
        &self,
        roots: &[&str],
        printer: &Printer,
    ) -> Result<()> {
        self.load_closures(roots)?;
        let (groups, pending) = {
            let state = self.state();
            let pending = roots
                .iter()
                .copied()
                .filter(|root| !state.content_addresses.contains_key(extract_hash(root)))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let groups = partition_by_shared_closure(&state.records, &pending, store_workers())?;
            (groups, pending.len())
        };
        if pending == 0 {
            return Ok(());
        }

        let results = run_concurrently(&groups, |group| make_content_addressed_batch(group));

        let mut state = self.state();
        for (group, result) in groups.iter().zip(results) {
            match result {
                Ok(rewrites) => merge_rewrites(&mut state.content_addresses, rewrites)?,
                Err(error) => printer.warning(&format!(
                    "batched content addressing failed for {} root(s); retrying each \
                     root separately ({error:#})",
                    group.len()
                )),
            }
        }
        Ok(())
    }

    /// Returns the content-address rewrites Nix reports for `root` alone.
    ///
    /// A root rewritten by [`Self::load_content_addresses`] is answered from
    /// memory. Otherwise this runs `nix store make-content-addressed` for
    /// `root` and returns its report unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when the per-root invocation fails.
    pub(in crate::registry_ops) fn content_addresses(
        &self,
        root: &str,
    ) -> Result<HashMap<String, String>> {
        let root_hash = extract_hash(root);
        if let Some(ca) = self.state().content_addresses.get(root_hash) {
            return Ok(HashMap::from([(root_hash.to_string(), ca.clone())]));
        }

        let rewrites = make_content_addressed(root)?;
        if let Some(ca) = rewrites.get(root_hash)
            && rewrites.len() == 1
        {
            self.state()
                .content_addresses
                .insert(root_hash.to_string(), ca.clone());
        }
        Ok(rewrites)
    }
}

/// Returns the bounded store-subprocess worker count for this machine.
fn store_workers() -> usize {
    thread::available_parallelism()
        .map_or(1, NonZeroUsize::get)
        .clamp(1, MAX_STORE_WORKERS)
}

/// Returns direct reference hashes of `path` without its self-reference, in
/// the order `nix-store --query --references` prints them.
fn direct_reference_hashes(
    records: &HashMap<String, PathRecord>,
    path: &str,
) -> Result<Vec<String>> {
    Ok(nix_ordered_references(records, path)?
        .into_iter()
        .filter(|reference| *reference != path)
        .map(|reference| extract_hash(reference).to_string())
        .collect())
}

/// Orders the direct references of `path` as `nix-store --query
/// --references` prints them.
///
/// Nix topologically sorts the reference set, self-reference included, with
/// a depth-first search that visits set members, and each member's own
/// references within the set, in store-path order. It prints the post-order,
/// so a reference always follows the references it depends on. Package
/// metadata records this order, so it is reproduced exactly.
fn nix_ordered_references<'a>(
    records: &'a HashMap<String, PathRecord>,
    path: &str,
) -> Result<Vec<&'a str>> {
    let record = records
        .get(path)
        .with_context(|| format!("no store metadata loaded for {path}"))?;
    let members = record
        .references
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    // A member's references within the set, excluding itself, in path order.
    let children = |member: &str| -> Result<Vec<&'a str>> {
        let record = records
            .get(member)
            .with_context(|| format!("no store metadata loaded for {member}"))?;
        Ok(record
            .references
            .iter()
            .map(String::as_str)
            .filter(|child| *child != member && members.contains(child))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    };

    let mut visited = HashSet::new();
    let mut ordered = Vec::with_capacity(members.len());
    for &start in &members {
        if !visited.insert(start) {
            continue;
        }
        // Each frame holds a member, its children, and the next child index.
        let mut stack = vec![(start, children(start)?, 0_usize)];
        while let Some((member, member_children, next)) = stack.last_mut() {
            let member = *member;
            match member_children.get(*next).copied() {
                Some(child) => {
                    *next += 1;
                    if visited.insert(child) {
                        stack.push((child, children(child)?, 0));
                    }
                }
                None => {
                    stack.pop();
                    ordered.push(member);
                }
            }
        }
    }
    Ok(ordered)
}

/// Returns the sorted closure of `root` from already loaded records.
fn closure_of<'a>(
    records: &'a HashMap<String, PathRecord>,
    root: &str,
) -> Result<BTreeSet<&'a str>> {
    let (root, _) = records
        .get_key_value(root)
        .with_context(|| format!("no store metadata loaded for {root}"))?;
    let mut closure = BTreeSet::from([root.as_str()]);
    let mut stack = vec![root.as_str()];

    while let Some(path) = stack.pop() {
        let record = records
            .get(path)
            .with_context(|| format!("no store metadata loaded for {path}"))?;
        for reference in &record.references {
            let (reference, _) = records.get_key_value(reference).with_context(|| {
                format!("store metadata for {path} references unloaded path {reference}")
            })?;
            if closure.insert(reference.as_str()) {
                stack.push(reference.as_str());
            }
        }
    }

    Ok(closure)
}

/// Reads validity records for `paths` with concurrent `--dump-db` calls.
fn dump_records_concurrently(paths: &[String]) -> Result<HashMap<String, PathRecord>> {
    let chunks = paths.chunks(RECORDS_PER_INVOCATION).collect::<Vec<_>>();
    let results = run_concurrently(&chunks, |chunk| dump_records(chunk));

    let mut records = HashMap::with_capacity(paths.len());
    for result in results {
        records.extend(result?);
    }
    Ok(records)
}

/// Reads validity records for one bounded set of paths.
fn dump_records(paths: &[String]) -> Result<Vec<(String, PathRecord)>> {
    let output = nix_command("nix-store")?
        .arg("--dump-db")
        .args(paths)
        .output()
        .context("running nix-store --dump-db")?;
    if !output.status.success() {
        bail!(
            "nix-store --dump-db failed for {} path(s): {}",
            paths.len(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout =
        String::from_utf8(output.stdout).context("nix-store --dump-db output is not UTF-8")?;
    let records = parse_validity_registrations(&stdout)?;

    // Nix prints one record per argument in argument order, naming each by
    // its canonical store path. Requiring that exact correspondence prevents
    // a record from being bound to another path, and rejects symlinks or
    // subpaths that would otherwise alias a store object.
    let returned = records.iter().map(|(path, _)| path.as_str());
    if !returned.eq(paths.iter().map(String::as_str)) {
        bail!(
            "nix-store --dump-db returned {} record(s) that do not name the {} requested \
             canonical store path(s)",
            records.len(),
            paths.len()
        );
    }
    Ok(records)
}

/// Parses Nix's validity-registration text into path records.
fn parse_validity_registrations(text: &str) -> Result<Vec<(String, PathRecord)>> {
    let mut lines = text.lines();
    let mut records = Vec::new();

    while let Some(path) = lines.next() {
        if path.is_empty() {
            bail!("validity registration contains an empty store path line");
        }
        let mut field = |name: &str| {
            lines
                .next()
                .with_context(|| format!("validity registration for {path} lacks its {name}"))
        };

        let nar_hash = nix32_nar_hash(field("NAR hash")?)
            .with_context(|| format!("parsing NAR hash of {path}"))?;
        let nar_size = field("NAR size")?
            .parse::<u64>()
            .with_context(|| format!("parsing NAR size of {path}"))?;
        let deriver = Some(field("deriver")?)
            .filter(|deriver| !deriver.is_empty())
            .map(str::to_string);
        let reference_count = field("reference count")?
            .parse::<usize>()
            .with_context(|| format!("parsing reference count of {path}"))?;
        let references = (0..reference_count)
            .map(|_| field("reference").map(str::to_string))
            .collect::<Result<Vec<_>>>()?;
        if references.iter().any(String::is_empty) {
            bail!("validity registration for {path} contains an empty reference");
        }

        records.push((
            path.to_string(),
            PathRecord {
                nar_hash,
                nar_size,
                deriver,
                references,
            },
        ));
    }

    Ok(records)
}

/// Converts a base-16 SHA-256 NAR hash to `nix-store --query --hash` form.
fn nix32_nar_hash(base16: &str) -> Result<String> {
    if base16.len() != 64 || !base16.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected a base-16 SHA-256 digest, found {base16:?}");
    }
    let normalized = aos_core::nar::cache::normalize_sha256_nix32(&format!("sha256:{base16}"));
    // A 32-byte digest is 52 nix32 digits; anything else was not converted.
    if normalized.len() != "sha256:".len() + 52 {
        bail!("could not convert NAR hash {base16:?} to nix32");
    }
    Ok(normalized)
}

/// Splits `roots` into at most `groups` groups that share closure members.
///
/// Larger closures are placed first. Each root joins the group whose load,
/// counted in NAR bytes that the group must rewrite, grows least with it; this
/// keeps shared dependencies together while still balancing the heaviest
/// groups. Equal choices resolve to the earlier group, so the partition is
/// deterministic.
fn partition_by_shared_closure<'a>(
    records: &HashMap<String, PathRecord>,
    roots: &[&'a str],
    groups: usize,
) -> Result<Vec<Vec<&'a str>>> {
    let mut closures = roots
        .iter()
        .map(|root| {
            let members = closure_of(records, root)?;
            let bytes = members
                .iter()
                .filter_map(|member| records.get(*member))
                .fold(0_u64, |total, record| total.saturating_add(record.nar_size));
            Ok((*root, members, bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    closures.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(right.0)));

    let group_count = groups.clamp(1, roots.len().max(1));
    let mut members = vec![HashSet::<&str>::new(); group_count];
    let mut loads = vec![0_u64; group_count];
    let mut assigned = vec![Vec::new(); group_count];

    for (root, closure, _) in closures {
        let mut best: Option<(u64, usize, u64)> = None;
        for (index, group) in members.iter().enumerate() {
            let added = closure
                .iter()
                .filter(|member| !group.contains(**member))
                .filter_map(|member| records.get(*member))
                .fold(0_u64, |total, record| total.saturating_add(record.nar_size));
            let load = loads[index].saturating_add(added);
            if best.is_none_or(|(best_load, _, _)| load < best_load) {
                best = Some((load, index, added));
            }
        }
        let Some((_, index, added)) = best else {
            continue;
        };
        members[index].extend(closure);
        loads[index] = loads[index].saturating_add(added);
        assigned[index].push(root);
    }

    Ok(assigned
        .into_iter()
        .filter(|group| !group.is_empty())
        .collect())
}

/// Runs `nix store make-content-addressed` once over several roots.
///
/// Fails unless Nix reports exactly one rewrite for each requested root, the
/// shape a per-root invocation reports, so a batch can never attribute a
/// rewrite that a per-root invocation would not.
fn make_content_addressed_batch(roots: &[&str]) -> Result<HashMap<String, String>> {
    let mut rewrites = HashMap::new();
    for chunk in roots.chunks(ROOTS_PER_INVOCATION) {
        merge_rewrites(&mut rewrites, super::make_content_addressed_paths(chunk)?)?;
    }
    require_rewrite_per_root(roots, &rewrites)?;
    Ok(rewrites)
}

/// Requires `rewrites` to hold exactly one entry for each of `roots`.
fn require_rewrite_per_root(roots: &[&str], rewrites: &HashMap<String, String>) -> Result<()> {
    let requested = roots
        .iter()
        .map(|root| extract_hash(root))
        .collect::<HashSet<_>>();
    if rewrites.len() != requested.len()
        || !rewrites
            .keys()
            .all(|hash| requested.contains(hash.as_str()))
    {
        bail!(
            "nix store make-content-addressed reported {} rewrite(s) for {} requested root(s)",
            rewrites.len(),
            requested.len()
        );
    }
    Ok(())
}

/// Adds `rewrites` to `known`, refusing any disagreement.
fn merge_rewrites(
    known: &mut HashMap<String, String>,
    rewrites: HashMap<String, String>,
) -> Result<()> {
    for (ia, ca) in rewrites {
        match known.get(&ia) {
            Some(existing) if existing != &ca => bail!(
                "content addressing produced both {existing} and {ca} for store path hash {ia}"
            ),
            Some(_) => {}
            None => {
                known.insert(ia, ca);
            }
        }
    }
    Ok(())
}

/// Applies `task` to every item on bounded scoped threads, in item order.
fn run_concurrently<T, R, F>(items: &[T], task: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let workers = store_workers().min(items.len());
    if workers <= 1 {
        return items.iter().map(&task).collect();
    }

    // Workers claim item indexes from a shared counter and report results by
    // index, so completion order never leaks into the returned order.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut results = thread::scope(|scope| {
        let handles = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut completed = Vec::new();
                    loop {
                        let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(item) = items.get(index) else {
                            break completed;
                        };
                        completed.push((index, task(item)));
                    }
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .flat_map(|handle| match handle.join() {
                Ok(completed) => completed,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect::<Vec<_>>()
    });
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

#[cfg(test)]
mod tests;
