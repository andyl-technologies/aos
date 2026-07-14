//! Code-identity context for heap-image closure capture/restore (RFC-0007
//! doc 31 §1 step 3).
//!
//! The closure serializer keys code by content — a module's identity hash —
//! never by per-process [`EvalModuleId`]. The [`EvalHeap`] holds no module
//! table, so the `TreeWalk` supplies the context at the capture/restore call
//! site: [`TreeWalk::snapshot_code_identity`] snapshots every live module's
//! fingerprint into an owned, heap-independent table that serves both
//! directions — fingerprinting at capture ([`LambdaCodeFingerprints`]) and
//! refuse-on-drift resolution at restore ([`LambdaCodeResolver`]).
//!
//! The snapshot is owned (no borrow of the evaluator), so an in-process
//! restore can drop or swap the evaluator's heap between capture and restore
//! while keeping the same identity table.
//!
//! [`EvalHeap`]: crate::eval::heap::EvalHeap

use std::collections::HashMap;

use crate::cache::CacheExprSourceHash;
use crate::eval::heap::{LambdaCodeFingerprints, LambdaCodeResolver};
use crate::eval::module::EvalModuleId;

use super::super::TreeWalk;

/// An owned snapshot of every live module's content fingerprint.
///
/// Produced by [`TreeWalk::snapshot_code_identity`]; serves as both the
/// capture-side [`LambdaCodeFingerprints`] context and the restore-side
/// [`LambdaCodeResolver`]. Two live modules *can* carry one fingerprint (the
/// same file loaded again under a scoped import, for example); the identity
/// hash is the parse-cache key domain, so an equal hash means equal source
/// identity and therefore equal deterministic lowered IR — resolution binds
/// the first such module, which is not a rebind to different code. Refusal is
/// reserved for fingerprints absent from the table (genuine drift).
#[derive(Debug)]
pub(crate) struct TreeWalkCodeIdentity {
    /// Per-module fingerprints, indexed by module id.
    fingerprints: Vec<Option<CacheExprSourceHash>>,
    /// Reverse map to the first module carrying each fingerprint.
    modules_by_fingerprint: HashMap<CacheExprSourceHash, EvalModuleId>,
}

impl LambdaCodeFingerprints for TreeWalkCodeIdentity {
    fn fingerprint(&self, module: EvalModuleId) -> Option<CacheExprSourceHash> {
        self.fingerprints.get(module.index()).copied().flatten()
    }

    fn module_count(&self) -> usize {
        self.fingerprints.len()
    }
}

impl LambdaCodeResolver for TreeWalkCodeIdentity {
    fn resolve(&self, source_hash: CacheExprSourceHash) -> Option<EvalModuleId> {
        self.modules_by_fingerprint.get(&source_hash).copied()
    }
}

impl TreeWalk {
    /// Snapshots the module table's code-identity context for heap-image
    /// closure capture and restore.
    ///
    /// Fingerprints every live module by its cache identity hash (source name
    /// and bytes for source-backed modules, the lowered-IR fingerprint
    /// otherwise). Modules whose identity cannot be hashed stay
    /// unfingerprintable, which makes capture refuse their closures rather
    /// than emit unkeyed code references.
    pub(crate) fn snapshot_code_identity(&self) -> TreeWalkCodeIdentity {
        let mut fingerprints = Vec::with_capacity(self.modules.len());
        let mut modules_by_fingerprint: HashMap<CacheExprSourceHash, EvalModuleId> =
            HashMap::with_capacity(self.modules.len());
        for (index, module) in self.modules.iter().enumerate() {
            let fingerprint = Self::cache_module_identity_hash(module)
                .map(CacheExprSourceHash::from_durable_hash);
            if let Some(fingerprint) = fingerprint {
                // First module wins for a repeated fingerprint: equal identity
                // hashes mean equal source identity and equal deterministic
                // lowered IR (see the type docs), so this is never a rebind to
                // different code.
                modules_by_fingerprint
                    .entry(fingerprint)
                    .or_insert(EvalModuleId::new(index as u32));
            }
            fingerprints.push(fingerprint);
        }
        TreeWalkCodeIdentity {
            fingerprints,
            modules_by_fingerprint,
        }
    }
}

use std::path::PathBuf;

use thiserror::Error;

use super::super::{
    ForceCacheOptionsIdentity, ImportCacheEntry, ImportGlobalScope, ModuleSource, TreeWalkModule,
    annotate_import_ir, nix_lower, parse_bytes_with_symbols, resolve,
};
use crate::compile::IrId;
use crate::eval::heap::{EvalHeap, EvalHeapSnapshotError};
use crate::syntax::Span;
use crate::value::Value;
use crate::value::compressed::CompressedValueWord;
use ratchet_value::heap::HeapImage;

/// One reloadable module of a heap-snapshot manifest (step-4 W2).
///
/// Carries exactly the inputs [`TreeWalk`]'s import path feeds a fresh module
/// — the source name and bytes plus the path-literal base — so the consuming
/// evaluator can rebuild the module and reproduce its content fingerprint.
/// Modules are reloaded with the fresh (non-scoped) lowering; a module
/// originally loaded under `scopedImport` shares its source identity with the
/// fresh flavor (the fingerprint domain does not distinguish them — a
/// recorded hardening candidate in the step-4 spec).
#[derive(Clone, Debug)]
pub(crate) struct SnapshotManifestModule {
    /// The module's source name (its import path bytes).
    pub(crate) name: Vec<u8>,
    /// The module's path-literal base, when it was loaded with one.
    pub(crate) path_literal_base: Option<Vec<u8>>,
    /// The module's source bytes.
    pub(crate) source: Vec<u8>,
}

/// The evaluator-state manifest wrapped around a heap image (step-4 W2).
///
/// A heap image carries values; this manifest carries the per-evaluator state
/// those values depend on: the modules to reload (so content fingerprints
/// re-resolve) and the import-cache seeds (so `import` returns the restored
/// values instead of re-forcing). The W3 storage tier serializes it alongside
/// the image; in-process it is handed across as a struct.
#[derive(Clone, Debug, Default)]
pub(crate) struct HeapSnapshotManifest {
    /// Source-backed modules in capture-time id order.
    pub(crate) modules: Vec<SnapshotManifestModule>,
    /// `(import path, root value word)` seeds for the consuming import cache.
    pub(crate) import_seeds: Vec<(PathBuf, u64)>,
}

/// Adopting a heap snapshot into a fresh evaluator failed.
#[derive(Debug, Error)]
pub(crate) enum HeapSnapshotAdoptError {
    /// Snapshot adoption is serial-only (parallel workers share state the
    /// adopted heap does not carry).
    #[error("heap snapshots cannot be adopted by a parallel evaluator")]
    ParallelMode,
    /// A manifest module failed to parse, resolve, or lower.
    #[error("manifest module {name:?} failed to reload: {message}")]
    ModuleReload {
        /// The failing module's source name.
        name: String,
        /// The front-end failure rendered for diagnostics.
        message: String,
    },
    /// An import seed's value word did not decode.
    #[error("import seed for {path:?} holds an invalid value word")]
    MalformedImportSeed {
        /// The seed's import path.
        path: PathBuf,
    },
    /// The heap-image restore itself refused.
    #[error(transparent)]
    Restore(#[from] EvalHeapSnapshotError),
}

impl TreeWalk {
    /// Captures the evaluator-state manifest for a heap snapshot (step-4 W2):
    /// every source-backed module and every ready import-cache entry.
    pub(crate) fn snapshot_manifest(&self) -> HeapSnapshotManifest {
        let modules = self
            .modules
            .iter()
            .filter_map(|module| {
                module.source.as_ref().map(|source| SnapshotManifestModule {
                    name: source.name.clone(),
                    path_literal_base: module.path_literal_base.clone(),
                    source: source.bytes.clone(),
                })
            })
            .collect();
        let import_seeds = self
            .import_cache
            .iter()
            .filter_map(|(path, entry)| match entry {
                ImportCacheEntry::Ready { value, .. } => Some((path.clone(), value.word().raw())),
                ImportCacheEntry::Evaluating => None,
            })
            .collect();
        HeapSnapshotManifest {
            modules,
            import_seeds,
        }
    }

    /// Adopts a heap snapshot into this (fresh, serial) evaluator: reloads the
    /// manifest modules, restores the image over the reloaded identity, swaps
    /// the heap in, and seeds the import cache (step-4 W2 — the restore seam).
    ///
    /// Call before any evaluation: the current heap is replaced, so values it
    /// already handed out would dangle. Import seeds insert with an incomplete
    /// impure-input trace (`trace: None`), which conservatively disables
    /// downstream force-cache trace completeness for evaluations that hit
    /// them.
    ///
    /// # Errors
    ///
    /// Returns [`HeapSnapshotAdoptError::ParallelMode`] for a parallel
    /// evaluator, [`HeapSnapshotAdoptError::ModuleReload`] when a manifest
    /// module fails the front end, every [`EvalHeapSnapshotError`] restore
    /// refusal (drift, malformed segments, re-intern failures), and
    /// [`HeapSnapshotAdoptError::MalformedImportSeed`] for an invalid seed
    /// word.
    pub(crate) fn adopt_heap_snapshot(
        &mut self,
        manifest: &HeapSnapshotManifest,
        image: &HeapImage,
    ) -> Result<(), HeapSnapshotAdoptError> {
        if self.shared.is_some() {
            return Err(HeapSnapshotAdoptError::ParallelMode);
        }
        let reload_start = std::time::Instant::now();
        for module in &manifest.modules {
            self.reload_snapshot_module(module)?;
        }
        let reload_elapsed = reload_start.elapsed();
        // The resolver must see the RELOADED module table; symbols advanced
        // during reloading, and the restore re-intern advances them further.
        let identity_start = std::time::Instant::now();
        let identity = self.snapshot_code_identity();
        let identity_elapsed = identity_start.elapsed();
        let restore_start = std::time::Instant::now();
        let restored = EvalHeap::from_restored_heap_image_with_code_identity(
            image,
            &identity,
            &mut self.symbols,
        )?;
        let old_heap = std::mem::replace(&mut self.heap, restored);
        drop(old_heap);
        if self.options.eval_stats_dump() || std::env::var_os("AOS_NIX_EVAL_STATS").is_some() {
            eprintln!(
                "adopt decomposition: reload {reload_elapsed:?}, identity {identity_elapsed:?}, restore {:?}",
                restore_start.elapsed()
            );
        }
        for (path, word) in &manifest.import_seeds {
            let word = CompressedValueWord::from_raw(*word)
                .map_err(|_| HeapSnapshotAdoptError::MalformedImportSeed { path: path.clone() })?;
            self.import_cache.insert(
                path.clone(),
                ImportCacheEntry::Ready {
                    value: Value::from_word(word),
                    trace: None,
                    force_cache_trace_complete: false,
                },
            );
        }
        Ok(())
    }

    /// Reloads one manifest module through the fresh-import front end
    /// (parse into the live symbol table, resolve, lower, annotate) without
    /// evaluating it, skipping modules whose exact source is already loaded.
    fn reload_snapshot_module(
        &mut self,
        module: &SnapshotManifestModule,
    ) -> Result<(), HeapSnapshotAdoptError> {
        let already_loaded =
            self.modules.iter().any(|loaded| {
                loaded.source.as_ref().is_some_and(|source| {
                    source.name == module.name && source.bytes == module.source
                }) && loaded.path_literal_base == module.path_literal_base
            });
        if already_loaded {
            return Ok(());
        }
        let reload_error = |message: String| HeapSnapshotAdoptError::ModuleReload {
            name: String::from_utf8_lossy(&module.name).into_owned(),
            message,
        };
        // Parse-cache fast path first (step-4 W3): in production every
        // manifest module is a warm parse-cache entry, so the reload is a
        // cached-IR load plus the symbol remap, not a fresh front-end run.
        let synthetic = IrId::new(0);
        let synthetic_span = Span::new(0, 0);
        let realpath = PathBuf::from(String::from_utf8_lossy(&module.name).into_owned());
        let cached = self
            .load_parse_cached_import(
                synthetic,
                synthetic_span,
                &realpath,
                &module.name,
                &module.source,
                ImportGlobalScope::Fresh,
            )
            .map_err(|error| reload_error(error.to_string()))?;
        let ir = match cached {
            Some(cached) => self
                .remap_cached_import_ir(synthetic, synthetic_span, &module.name, cached.ir)
                .map_err(|error| reload_error(error.to_string()))?,
            None => {
                // The serial fresh-import fast path (eval_load): move the live
                // table into the parser and adopt the grown superset back.
                let live_symbols = std::mem::take(&mut self.symbols);
                let parsed = parse_bytes_with_symbols(&module.source, live_symbols)
                    .map_err(|error| reload_error(error.to_string()))?;
                let resolved = resolve(parsed).map_err(|error| reload_error(error.to_string()))?;
                let mut ir =
                    nix_lower(resolved).map_err(|error| reload_error(error.to_string()))?;
                let _ = annotate_import_ir(&mut ir);
                self.symbols = std::mem::take(&mut ir.symbols);
                ir
            }
        };
        self.modules.push(TreeWalkModule::new(
            ir,
            module.path_literal_base.clone(),
            ForceCacheOptionsIdentity::new(&self.options),
            Some(ModuleSource {
                name: module.name.clone(),
                bytes: module.source.clone(),
            }),
        ));
        Ok(())
    }
}
