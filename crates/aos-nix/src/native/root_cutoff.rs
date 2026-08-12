//! Root-level early-cutoff key derivation and record orchestration helpers.
//!
//! A root cutoff answers a fully warm `instantiate(file, attr)` from a durable
//! record instead of parsing, lowering, and evaluating the expression. The
//! record is keyed by [`root_record_key`], a BLAKE3 digest that folds every
//! input which can change the resulting derivation closure but is not otherwise
//! captured by the record's transitive impure-input trace:
//!
//! * a compiled-in domain salt and format version, so a codec or key change
//!   invalidates every prior record;
//! * the `aos-nix` crate version, so evaluator upgrades never reuse a stale
//!   record;
//! * the entry file's resolved real path and full content bytes (the entry file
//!   is read directly rather than through `builtins.import`, so it never appears
//!   in the trace and must be part of the key);
//! * the selected attribute path; and
//! * the result-affecting evaluator options fingerprint
//!   ([`TreeWalkOptions::result_affecting_fingerprint`]).

use super::*;

use crate::cache::{
    PersistCacheLocations, PersistLatencyClass, PersistLocationHit, RootRecordBundle,
};
use crate::eval::{MemoNetMode, MemoTierEvents};

use super::memo_net;

/// Where a taken root cutoff found its record (RFC-0007 doc 29 tiers).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RootCutoffHitSource {
    /// The primary `AOS_NIX_CACHE` location (L2 primary).
    Primary,
    /// A secondary `AOS_NIX_MEMO_DISK` location of the given class (L2).
    Secondary(PersistLatencyClass),
    /// The `AOS_NIX_MEMO_NET` endpoint (L3), already installed locally.
    Network,
}

/// The compiled-in root-cutoff key domain separator.
const ROOT_CUTOFF_KEY_DOMAIN: &[u8] = b"aos-nix-root-cutoff-key";

/// The bump-able root-cutoff key format version.
///
/// Increment this whenever the record payload layout, the key composition, or
/// the revalidation contract changes in a way that must invalidate every record
/// written by an older binary that shares the same crate version.
///
/// Version history:
///
/// * `2` — recorded impure-input traces are canonicalized (sorted and
///   deduplicated) before writeback, changing the persisted record bytes for
///   an identical evaluation; records written by version `1` binaries simply
///   miss under the new keys and are re-recorded on the next cold evaluation.
const ROOT_CUTOFF_KEY_FORMAT_VERSION: u32 = 2;

/// Computes the durable root-record key for one file-attribute instantiation.
///
/// `entry_real_path` is the resolved (canonicalized) entry file path, `source`
/// is that file's full byte content, `attr` is the requested attribute path,
/// and `options` supplies the result-affecting evaluator settings. The returned
/// key changes if any of those inputs changes, so a record is only ever reused
/// for a byte-identical entry file evaluated with equivalent settings.
pub(super) fn root_record_key(
    entry_real_path: &Path,
    source: &[u8],
    attr: &str,
    options: &TreeWalkOptions,
) -> PersistRootRecordKey {
    let mut hasher = blake3::Hasher::new();
    hash_component(&mut hasher, b"domain", ROOT_CUTOFF_KEY_DOMAIN);
    hash_component(
        &mut hasher,
        b"format_version",
        &ROOT_CUTOFF_KEY_FORMAT_VERSION.to_le_bytes(),
    );
    hash_component(
        &mut hasher,
        b"crate_version",
        env!("CARGO_PKG_VERSION").as_bytes(),
    );
    hash_component(
        &mut hasher,
        b"entry_real_path",
        entry_real_path.as_os_str().as_bytes(),
    );
    hash_component(&mut hasher, b"entry_content", source);
    hash_component(&mut hasher, b"attr", attr.as_bytes());
    hash_component(
        &mut hasher,
        b"options",
        &options.result_affecting_fingerprint(),
    );
    PersistRootRecordKey::from_digest(*hasher.finalize().as_bytes())
}

/// Folds one length-tagged, labeled component into a key hasher.
fn hash_component(hasher: &mut blake3::Hasher, label: &[u8], bytes: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

impl NixNative {
    /// Evaluates `attr` from `file` with a full parse, lower, and evaluation.
    ///
    /// Returns the derivation closure, evaluator stats, and — when the
    /// evaluation produced a complete, fully cacheable impure-input trace — the
    /// cacheable inputs to durably record for future root cutoffs. `options`
    /// must already carry the entry file's path-literal base.
    pub(super) fn eval_file_attr_closure_full(
        &self,
        file: &Path,
        attr: &str,
        options: &TreeWalkOptions,
        source: &[u8],
    ) -> Result<(
        NativeDrvClosure,
        EvalStats,
        Option<Vec<CacheableInputFingerprint>>,
    )> {
        let attr_path = attr_path_drv_path_segments(attr)?;
        let source_name = path_bytes(file)?;
        let source_name_text = String::from_utf8_lossy(&source_name);
        let diagnostic_source = std::str::from_utf8(source)
            .ok()
            .map(|source| NativeDiagnosticSource::new(source_name_text.as_ref(), source, None));
        let ir = self.lower_native_source_bytes(
            source,
            Some(source_name_text.to_string()),
            Some(file),
            None,
            diagnostic_source,
        )?;
        if let Some((feature, span)) = native_instantiation_cli_fallback_feature(&ir, &self.options)
        {
            return Err(NativeEvalError::Unsupported {
                feature: feature.to_string(),
                span: Some(crate::error::SrcSpan {
                    start: span.start,
                    end: span.end,
                }),
            }
            .into());
        }
        let engine = self.tier1_engine_for(&options);
        let outcome =
            eval_instantiation_attr_path_owned_with_options_source_realizer_eval_cache_and_engine(
                &ir,
                &attr_path,
                options.clone(),
                source_name.clone(),
                source.to_vec(),
                self.ifd_realizer.clone(),
                self.eval_cache.clone(),
                engine,
            )
            .map_err(|error| match diagnostic_source {
                Some(diagnostic_source) => native_eval_error_with_source_trace(
                    error,
                    diagnostic_source,
                    self.eval_trace_style(),
                ),
                None => native_eval_error_with_trace(error, None, self.eval_trace_style()),
            })?;
        let stats = *outcome.stats();
        self.observe_eval_cache(&outcome);
        let cacheable_inputs = cacheable_inputs_from_outcome(&outcome);
        let closure = self.native_drv_closure_from_outcome(outcome)?;
        Ok((closure, stats, cacheable_inputs))
    }

    /// Loads and revalidates a durable root-cutoff closure for `key`.
    ///
    /// Locations are probed in tier order — the primary `AOS_NIX_CACHE` root,
    /// then each `AOS_NIX_MEMO_DISK` secondary (fastest class first), then the
    /// `AOS_NIX_MEMO_NET` endpoint. Every candidate record, wherever it came
    /// from, must pass the identical impure-input revalidation before it may
    /// answer; a record that fails revalidation at one location does not stop
    /// the probe (a slower location may hold a record whose observations still
    /// match the current world). A secondary or network hit is promoted into
    /// the primary location so the next run answers from the fast path.
    ///
    /// Returns `None` — falling through to a normal evaluation — when no
    /// location holds a usable record. Failures are logged at debug level and
    /// counted into `events`; they are never surfaced to the caller.
    pub(super) fn load_root_cutoff_closure(
        &self,
        options: &TreeWalkOptions,
        key: PersistRootRecordKey,
        events: &mut MemoTierEvents,
    ) -> Option<(NativeDrvClosure, RootCutoffHitSource)> {
        let root = options.persist_cache_root()?;
        let locations = PersistCacheLocations::open(
            root,
            options.persist_cache_verify(),
            options.memo_disk_locations(),
        )
        .map_err(|error| {
            tracing::debug!(
                target: "aos_nix::cache",
                error = %error,
                "root cutoff could not open the persistent cache"
            );
        })
        .ok()?;

        for (hit, cache) in locations.iter() {
            let record = match cache.load_root_instantiation(key) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(error) => {
                    tracing::debug!(
                        target: "aos_nix::cache",
                        error = %error,
                        "root cutoff record load failed at a location"
                    );
                    continue;
                }
            };
            if !revalidate_cacheable_input_trace(options, record.inputs()) {
                tracing::debug!(
                    target: "aos_nix::cache",
                    "root cutoff record impure inputs failed revalidation"
                );
                events.l2_reval_failures = events.l2_reval_failures.saturating_add(1);
                continue;
            }
            if !record.closure().contains_key(record.root()) {
                tracing::debug!(
                    target: "aos_nix::cache",
                    "root cutoff record omitted its own root derivation"
                );
                continue;
            }
            let source = match hit {
                PersistLocationHit::Primary => RootCutoffHitSource::Primary,
                PersistLocationHit::Secondary(class) => {
                    events.l2_secondary_hits = events.l2_secondary_hits.saturating_add(1);
                    if locations.promote_root_instantiation(key, &record) {
                        events.l2_promotions = events.l2_promotions.saturating_add(1);
                    }
                    RootCutoffHitSource::Secondary(class)
                }
            };
            let (root_path, drvs) = record.into_closure_parts();
            return Some((
                NativeDrvClosure {
                    root: root_path,
                    drvs,
                },
                source,
            ));
        }
        if locations.has_secondaries() {
            events.l2_secondary_misses = events.l2_secondary_misses.saturating_add(1);
        }

        self.load_root_cutoff_closure_from_network(options, key, &locations, events)
    }

    /// Fetches, validates, installs, and answers from an L3 network record.
    ///
    /// A fetched bundle is content-validated by the codec (every blob re-hashes,
    /// the record decodes, the closure is fully covered), then its impure-input
    /// slice is revalidated against the local world exactly like a disk record
    /// — the endpoint is a validation-shaped catalog, never an authority. Only
    /// a record that passes both is installed into the primary location and
    /// used. Any transport or validation failure is a miss plus a process-wide
    /// backoff, never an evaluation error.
    fn load_root_cutoff_closure_from_network(
        &self,
        options: &TreeWalkOptions,
        key: PersistRootRecordKey,
        locations: &PersistCacheLocations,
        events: &mut MemoTierEvents,
    ) -> Option<(NativeDrvClosure, RootCutoffHitSource)> {
        let net = options.memo_net()?;
        let bundle = match memo_net::fetch_root_record_bundle(net, key) {
            memo_net::NetFetchOutcome::Hit(bundle) => bundle,
            memo_net::NetFetchOutcome::Miss => {
                events.net_misses = events.net_misses.saturating_add(1);
                return None;
            }
            memo_net::NetFetchOutcome::Error => {
                events.net_errors = events.net_errors.saturating_add(1);
                return None;
            }
        };
        if !revalidate_cacheable_input_trace(options, bundle.record().inputs()) {
            tracing::debug!(
                target: "aos_nix::cache",
                "network root record impure inputs failed local revalidation"
            );
            events.net_reval_failures = events.net_reval_failures.saturating_add(1);
            return None;
        }
        let record = bundle.record();
        let drvs = bundle.closure();
        let root_path = PathBuf::from(OsStr::from_bytes(record.root_drv()));
        if !drvs.contains_key(&root_path) {
            // Unreachable for a validated bundle; kept as defense in depth.
            events.net_errors = events.net_errors.saturating_add(1);
            return None;
        }
        if let Err(error) = locations.primary().store_root_instantiation(
            key,
            record.root_drv(),
            &drvs,
            record.inputs(),
            record.run_id(),
        ) {
            tracing::debug!(
                target: "aos_nix::cache",
                error = %error,
                "network root record could not be installed into the primary cache"
            );
        }
        events.net_hits = events.net_hits.saturating_add(1);
        Some((
            NativeDrvClosure {
                root: root_path,
                drvs,
            },
            RootCutoffHitSource::Network,
        ))
    }

    /// Shadow-checks a taken root cutoff against a full evaluation.
    ///
    /// The check runs when the global `AOS_NIX_ROOT_CUTOFF_CHECK` switch is on,
    /// or when the hit's tier is covered by `AOS_NIX_MEMO_CHECK` (`l2` for a
    /// secondary-location hit, `l3` for a network hit). A divergent closure is
    /// a loud error: the cutoff must be byte-identical to a fresh evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error if the shadow evaluation itself fails or if its closure
    /// differs from the cutoff-provided closure.
    pub(super) fn verify_root_cutoff_closure(
        &self,
        file: &Path,
        attr: &str,
        options: &TreeWalkOptions,
        source: RootCutoffHitSource,
        closure: &NativeDrvClosure,
        entry_source: &[u8],
    ) -> Result<()> {
        let memo = options.memo_options();
        let check = options.root_cutoff_check()
            || match source {
                RootCutoffHitSource::Primary => false,
                RootCutoffHitSource::Secondary(_) => memo.check_l2,
                RootCutoffHitSource::Network => memo.check_l3,
            };
        if !check {
            return Ok(());
        }
        let (fresh, _, _) = self.eval_file_attr_closure_full(file, attr, options, entry_source)?;
        if fresh != *closure {
            tracing::error!(
                target: "aos_nix::cache",
                file = %file.display(),
                attr,
                ?source,
                "root cutoff closure diverged from a full evaluation"
            );
            return Err(NativeEvalError::Internal {
                message: format!(
                    "root cutoff closure for {} attr {attr} diverged from a full evaluation",
                    file.display()
                ),
            }
            .into());
        }
        Ok(())
    }

    /// Durably records a root-cutoff closure and its impure inputs for `key`.
    ///
    /// Failures are logged at debug level and never surfaced: a record that
    /// cannot be written simply leaves a future run to evaluate normally.
    pub(super) fn store_root_cutoff(
        &self,
        options: &TreeWalkOptions,
        key: PersistRootRecordKey,
        closure: &NativeDrvClosure,
        inputs: &[CacheableInputFingerprint],
    ) {
        let Some(root) = options.persist_cache_root() else {
            return;
        };
        let cache = match PersistCache::open(root) {
            Ok(cache) => cache,
            Err(error) => {
                tracing::debug!(
                    target: "aos_nix::cache",
                    error = %error,
                    "root cutoff could not open the persistent cache for writeback"
                );
                return;
            }
        };
        let root_bytes = closure.root().as_os_str().as_bytes();
        let run_id = root_cutoff_run_id();
        if let Err(error) =
            cache.store_root_instantiation(key, root_bytes, closure.drvs(), inputs, run_id)
        {
            tracing::debug!(
                target: "aos_nix::cache",
                error = %error,
                "root cutoff record writeback failed"
            );
        }
        // Publish to the L3 endpoint only from explicitly writable (rw)
        // configurations — the doc 29 §5.5 CI/trusted-builder policy. Publish
        // failures are logged and ignored; the network tier is advisory.
        if let Some(net) = options.memo_net() {
            if net.mode == MemoNetMode::ReadWrite {
                match RootRecordBundle::from_closure(root_bytes, closure.drvs(), inputs, run_id) {
                    Ok(bundle) => {
                        memo_net::publish_root_record_bundle(net, key, &bundle);
                    }
                    Err(error) => {
                        tracing::debug!(
                            target: "aos_nix::cache",
                            error = %error,
                            "root cutoff network bundle construction failed"
                        );
                    }
                }
            }
        }
    }
}

/// Extracts the fully cacheable impure-input trace of a completed evaluation.
///
/// The extracted trace is canonicalized through
/// [`crate::eval::canonicalize_cacheable_input_trace`] — sorted into a
/// deterministic order and deduplicated — so the recorded bytes do not depend
/// on the force order in which the evaluation happened to observe its inputs.
///
/// Returns `None` when the evaluation's impure-input trace is incomplete (so no
/// durable root record may be written), when any observed input is uncacheable
/// (which cannot occur alongside a complete trace but is rejected defensively
/// so a partial trace is never persisted), or when the same input was observed
/// with two different results within this evaluation (for example a file that
/// changed mid-eval), since such a trace could never revalidate.
fn cacheable_inputs_from_outcome(outcome: &EvalOutcome) -> Option<Vec<CacheableInputFingerprint>> {
    if !outcome.impure_input_trace_complete() {
        return None;
    }
    let trace = outcome.impure_input_trace();
    let mut inputs = Vec::with_capacity(trace.len());
    for fingerprint in trace {
        inputs.push(fingerprint.as_cacheable()?.clone());
    }
    crate::eval::canonicalize_cacheable_input_trace(inputs)
}

/// Returns a coarse wall-clock run id stamped into new root-cutoff records.
///
/// The value is informational bookkeeping only and never affects correctness or
/// the record key; a clock that predates the Unix epoch yields zero.
fn root_cutoff_run_id() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn base_options() -> TreeWalkOptions {
        TreeWalkOptions::new()
    }

    fn key(
        path: &str,
        source: &[u8],
        attr: &str,
        options: &TreeWalkOptions,
    ) -> PersistRootRecordKey {
        root_record_key(&PathBuf::from(path), source, attr, options)
    }

    #[test]
    fn identical_inputs_produce_identical_keys() {
        let options = base_options();
        assert_eq!(
            key("/a/default.nix", b"content", "pkg", &options),
            key("/a/default.nix", b"content", "pkg", &options),
        );
    }

    #[test]
    fn entry_path_changes_the_key() {
        let options = base_options();
        assert_ne!(
            key("/a/default.nix", b"content", "pkg", &options),
            key("/b/default.nix", b"content", "pkg", &options),
        );
    }

    #[test]
    fn entry_content_changes_the_key() {
        let options = base_options();
        assert_ne!(
            key("/a/default.nix", b"content", "pkg", &options),
            key("/a/default.nix", b"content!", "pkg", &options),
        );
    }

    #[test]
    fn attr_changes_the_key() {
        let options = base_options();
        assert_ne!(
            key("/a/default.nix", b"content", "pkg", &options),
            key("/a/default.nix", b"content", "other", &options),
        );
    }

    #[test]
    fn result_affecting_option_changes_the_key() {
        let options = base_options();
        let mut with_system = base_options();
        with_system
            .set_current_system(b"x86_64-linux".to_vec())
            .expect("system sets");
        assert_ne!(
            key("/a/default.nix", b"content", "pkg", &options),
            key("/a/default.nix", b"content", "pkg", &with_system),
        );
    }

    #[test]
    fn component_boundaries_are_unambiguous() {
        let options = base_options();
        // Moving a byte across the path/content boundary must change the key,
        // proving the length prefixes prevent component-concatenation aliasing.
        assert_ne!(
            key("/a/default.nixX", b"content", "pkg", &options),
            key("/a/default.nix", b"Xcontent", "pkg", &options),
        );
    }
}
