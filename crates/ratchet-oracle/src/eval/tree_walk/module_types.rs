//! Loaded-module, cache-identity, and import bookkeeping types
//! (split from tree_walk.rs under the §2 file-size cap).
use super::*;

#[derive(Debug)]
pub(crate) struct RegexCaptureMatch {
    pub(crate) range: std::ops::Range<usize>,
    pub(crate) groups: Vec<Option<std::ops::Range<usize>>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ResolvedSearchPathEntry {
    pub(crate) prefix: Vec<u8>,
    pub(crate) path: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FindFileCacheKey {
    pub(crate) search_path_base: Vec<u8>,
    pub(crate) corepkgs_path: Option<Vec<u8>>,
    pub(crate) entries: Vec<ResolvedSearchPathEntry>,
    pub(crate) lookup: Vec<u8>,
    pub(crate) origin: FindFileLookupOrigin,
}

impl FindFileCacheKey {
    pub(crate) fn new(
        search_path_base: &[u8],
        corepkgs_path: Option<&[u8]>,
        entries: &[ResolvedSearchPathEntry],
        lookup: &[u8],
        origin: FindFileLookupOrigin,
    ) -> Self {
        Self {
            search_path_base: search_path_base.to_vec(),
            corepkgs_path: corepkgs_path.map(<[u8]>::to_vec),
            entries: entries.to_vec(),
            lookup: lookup.to_vec(),
            origin,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FindFileCacheEntry {
    Hit {
        path: Vec<u8>,
        trace: Vec<ImpureInputFingerprint>,
    },
    Miss {
        trace: Vec<ImpureInputFingerprint>,
    },
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum FindFileLookupOrigin {
    AmbientSearchPath,
    LexicalSearchPath,
    ExplicitSearchPath,
}

/// One lowered IR module loaded into a tree-walk evaluator.
#[derive(Clone, Debug)]
pub(crate) struct TreeWalkModule {
    pub(crate) ir: Ir,
    pub(crate) path_literal_base: Option<Vec<u8>>,
    pub(crate) force_cache_options: ForceCacheOptionsIdentity,
    pub(crate) source: Option<ModuleSource>,
    /// Lazily computed ordinary module identity shared by node and derivation
    /// cache keys. A module is immutable after registration, so the digest
    /// remains valid for its lifetime.
    pub(crate) cache_identity_hash: std::cell::OnceCell<Option<crate::cache::DurableBlake3Hash>>,
    pub(crate) dead_binding_eliminations: TreeWalkDeadBindingEliminations,
    /// Whether this module's source file is prelude scaffolding (`lib`/`stdenv`),
    /// classified once at construction from [`ModuleSource::name`]. Read per force
    /// (under `AOS_NIX_EVAL_STATS`) to attribute the prelude-force-share counters
    /// without re-scanning the path. Computed from the `source` passed to
    /// [`Self::new`]; the source-less root module keeps `false`, which is correct
    /// (the evaluation entry point is package-specific, never prelude).
    pub(crate) is_prelude: bool,
}

impl TreeWalkModule {
    pub(crate) fn new(
        ir: Ir,
        path_literal_base: Option<Vec<u8>>,
        force_cache_options: ForceCacheOptionsIdentity,
        source: Option<ModuleSource>,
    ) -> Self {
        let dead_binding_eliminations = TreeWalkDeadBindingEliminations::from_ir(&ir);
        let is_prelude = module_source_is_prelude(source.as_ref());
        Self {
            ir,
            path_literal_base,
            force_cache_options,
            source,
            cache_identity_hash: std::cell::OnceCell::new(),
            dead_binding_eliminations,
            is_prelude,
        }
    }
}

/// Returns whether a module source path is prelude scaffolding.
///
/// Prelude is the `lib` and `stdenv` graph shared identically across every
/// package (the subject of the heap-snapshot payoff, RFC-0007 task #6): a source
/// path is prelude when it contains a `lib` or `stdenv` path component. Used only
/// to seed [`TreeWalkModule::is_prelude`] at module construction.
pub(crate) fn module_source_is_prelude(source: Option<&ModuleSource>) -> bool {
    let Some(source) = source else {
        return false;
    };
    Path::new(OsStr::from_bytes(&source.name))
        .components()
        .any(|component| {
            matches!(
                component,
                Component::Normal(part) if part == OsStr::new("lib") || part == OsStr::new("stdenv")
            )
        })
}

#[derive(Clone, Debug)]
pub(crate) struct ForceCacheOptionsIdentity {
    pub(crate) nix_compat_profile: NixCompatProfile,
    pub(crate) reported_nix_version: Vec<u8>,
    pub(crate) store_dir: Vec<u8>,
    pub(crate) search_path_base: Vec<u8>,
    pub(crate) nix_path: Vec<NixSearchPathEntry>,
    pub(crate) corepkgs_path: Option<Vec<u8>>,
    pub(crate) allowed_paths: Vec<Vec<u8>>,
    pub(crate) allowed_uris: Vec<Vec<u8>>,
    pub(crate) home_dir: Option<Vec<u8>>,
    pub(crate) current_system: Option<Vec<u8>>,
    pub(crate) current_time: Option<i64>,
    pub(crate) eval_mode: EvalMode,
    pub(crate) reject_ambient_search_path: bool,
    pub(crate) reject_unconfigured_impure_builtin_constants: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForceCacheMemoizationAdmission {
    ConditionalThunk,
    SelectedSubstrate,
}

impl ForceCacheMemoizationAdmission {
    pub(crate) const fn admits_on_first_demand(self) -> bool {
        matches!(self, Self::SelectedSubstrate)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ForceCacheSubject {
    pub(crate) lookup_identity: Option<CacheExprIdentity>,
    pub(crate) pure_observation_identity: Option<CacheExprIdentity>,
    pub(crate) impure_observation_identity: Option<CacheExprIdentity>,
    pub(crate) metadata_identity: Option<CacheExprIdentity>,
    pub(crate) persistent_clear_identity: Option<CacheExprIdentity>,
    pub(crate) free_var_value_hashes: Vec<ValueHash>,
    pub(crate) replay_position_module: Option<EvalModuleId>,
    pub(crate) replay_allocation_node: Option<EvalNodeRef>,
    pub(crate) memoization_admission: ForceCacheMemoizationAdmission,
}

#[derive(Debug)]
pub(crate) struct ActiveMemoReadNode {
    pub(crate) node: DemandNodeId,
    pub(crate) memo_reads: BTreeSet<DemandNodeId>,
}

impl ActiveMemoReadNode {
    pub(crate) fn new(node: DemandNodeId) -> Self {
        Self {
            node,
            memo_reads: BTreeSet::new(),
        }
    }

    pub(crate) const fn node(&self) -> DemandNodeId {
        self.node
    }

    pub(crate) fn into_parts(self) -> (DemandNodeId, BTreeSet<DemandNodeId>) {
        (self.node, self.memo_reads)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ModuleSource {
    pub(crate) name: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    line_starts: std::cell::OnceCell<Box<[u32]>>,
}

impl ModuleSource {
    /// Creates source provenance with a lazily built line-start index.
    pub(crate) fn new(name: Vec<u8>, bytes: Vec<u8>) -> Self {
        Self {
            name,
            bytes,
            line_starts: std::cell::OnceCell::new(),
        }
    }

    /// Returns the one-based line and column at `offset`.
    ///
    /// The first query builds a compact newline index. Later queries binary
    /// search it instead of rescanning the source prefix, which matters for
    /// `unsafeGetAttrPos`-heavy nixpkgs evaluation.
    pub(crate) fn line_column_at_offset(&self, offset: usize) -> Option<(i64, i64)> {
        if offset > self.bytes.len() {
            return None;
        }
        let offset = u32::try_from(offset).ok()?;
        let line_starts = self.line_starts.get_or_init(|| {
            let mut starts = vec![0_u32];
            for (index, byte) in self.bytes.iter().copied().enumerate() {
                if byte != b'\n' {
                    continue;
                }
                let Some(next) = index.checked_add(1) else {
                    continue;
                };
                let Ok(next) = u32::try_from(next) else {
                    continue;
                };
                starts.push(next);
            }
            starts.into_boxed_slice()
        });
        let line = line_starts.partition_point(|start| *start <= offset);
        let line_start = *line_starts.get(line.checked_sub(1)?)?;
        let column = offset.checked_sub(line_start)?.checked_add(1)?;
        Some((i64::try_from(line).ok()?, i64::from(column)))
    }

    /// Returns the initialized line-index entry count and owned bytes.
    ///
    /// An unqueried source returns `None`; this diagnostic accessor never
    /// initializes the lazy index.
    pub(crate) fn initialized_line_starts_storage(&self) -> Option<(usize, usize)> {
        self.line_starts.get().map(|starts| {
            (
                starts.len(),
                std::mem::size_of_val::<[u32]>(starts.as_ref()),
            )
        })
    }
}

#[cfg(test)]
mod module_source_tests {
    use super::ModuleSource;

    #[test]
    fn line_index_preserves_offsets_at_newlines_and_end_of_source() {
        let source = ModuleSource::new(b"fixture.nix".to_vec(), b"a\nbc\n".to_vec());

        assert_eq!(source.line_column_at_offset(0), Some((1, 1)));
        assert_eq!(source.line_column_at_offset(1), Some((1, 2)));
        assert_eq!(source.line_column_at_offset(2), Some((2, 1)));
        assert_eq!(source.line_column_at_offset(4), Some((2, 3)));
        assert_eq!(source.line_column_at_offset(5), Some((3, 1)));
        assert_eq!(source.line_column_at_offset(6), None);
        assert_eq!(source.line_column_at_offset(2), Some((2, 1)));
    }

    #[test]
    fn line_index_storage_observation_does_not_initialize_it() {
        let source = ModuleSource::new(b"fixture.nix".to_vec(), b"a\nbc\n".to_vec());

        assert_eq!(source.initialized_line_starts_storage(), None);
        assert_eq!(source.line_column_at_offset(2), Some((2, 1)));
        assert_eq!(
            source.initialized_line_starts_storage(),
            Some((3, 3 * std::mem::size_of::<u32>()))
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TreeWalkDeadBindingKey {
    pub(crate) let_node: u32,
    pub(crate) binding_index: usize,
}

impl TreeWalkDeadBindingKey {
    pub(crate) const fn new(let_node: IrId, binding_index: usize) -> Self {
        Self {
            let_node: let_node.as_u32(),
            binding_index,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TreeWalkDeadBindingEliminations {
    pub(crate) bindings: BTreeSet<TreeWalkDeadBindingKey>,
}

impl TreeWalkDeadBindingEliminations {
    pub(crate) fn from_ir(ir: &Ir) -> Self {
        let Ok(plan) = dead_binding_elimination_plan(ir) else {
            return Self::default();
        };
        let bindings = plan
            .eliminations()
            .iter()
            .filter(|elimination| {
                elimination.replacement() == DeadBindingReplacement::DummyFrameSlot
                    && ir
                        .arena
                        .node(elimination.value())
                        .is_some_and(|node| node.kind == IrKind::ThunkAlloc)
            })
            .map(|elimination| {
                TreeWalkDeadBindingKey::new(elimination.let_node(), elimination.binding_index())
            })
            .collect();
        Self { bindings }
    }

    pub(crate) fn contains(&self, let_node: IrId, binding_index: usize) -> bool {
        self.bindings
            .contains(&TreeWalkDeadBindingKey::new(let_node, binding_index))
    }
}

/// In-process import cache state.
#[derive(Clone, Debug)]
pub(crate) enum ImportCacheEntry {
    Evaluating,
    Ready {
        value: Value,
        trace: Option<Vec<ImpureInputFingerprint>>,
        force_cache_trace_complete: bool,
    },
}

/// Opaque coordinate for one active import-cache miss.
///
/// The token carries only a stack coordinate, rather than borrowing the
/// evaluator, so an explicit demand executor can retain it while continuing
/// to mutate [`TreeWalk`]. Import-cache leases are strictly nested, and the
/// monotonic generation rejects a stale token reused at the same stack depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImportCacheLeaseToken {
    depth: usize,
    generation: u64,
}

impl ImportCacheLeaseToken {
    pub(crate) const fn new(depth: usize, generation: u64) -> Self {
        Self { depth, generation }
    }

    pub(crate) const fn depth(self) -> usize {
        self.depth
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// Bookkeeping retained while an import-cache entry is `Evaluating`.
#[derive(Debug)]
pub(crate) struct ActiveImportCacheLease {
    pub(crate) token: ImportCacheLeaseToken,
    pub(crate) cache_path: PathBuf,
    pub(crate) trace_cursor: ImpureInputTraceCursor,
    pub(crate) allow_empty_impure_trace: bool,
    /// Serial heap allocation watermarks for the default-off import census.
    #[cfg(feature = "candidate_c_value")]
    pub(crate) epoch_census_fence: Option<ImportEpochCensusFence>,
}

/// Result of beginning an import-cache operation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BeginCachedImport {
    /// A completed import was already available.
    Hit(Value),
    /// This evaluator owns the new `Evaluating` entry.
    Miss(ImportCacheLeaseToken),
}

/// Opaque coordinate for one evaluator-owned ordinary thunk claim.
///
/// The generation rejects a stale token after strict stack depth reuse. The
/// claimed thunk itself lives in the evaluator's scanned active-force root
/// stack, so this token can cross allocating continuation steps without
/// borrowing either the heap or the thunk cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForceLeaseToken {
    depth: usize,
    generation: u64,
}

impl ForceLeaseToken {
    pub(crate) const fn new(depth: usize, generation: u64) -> Self {
        Self { depth, generation }
    }

    pub(crate) const fn depth(self) -> usize {
        self.depth
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// Bookkeeping for one detached ordinary thunk claim.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ActiveForceLease {
    pub(crate) token: ForceLeaseToken,
    pub(crate) id: IrId,
    pub(crate) span: Span,
    pub(crate) source_root_index: usize,
    pub(crate) result_root_index: usize,
}

/// Result of trying to begin an evaluator-owned force claim.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BeginForceLease {
    /// The thunk had already published its cached value.
    AlreadyForced(Value),
    /// The evaluator owns a blackholed thunk and its scanned root.
    Claimed(ForceLeaseToken),
    /// The value is not an ordinary reusable Node thunk.
    Declined,
}

/// Opaque coordinate for one evaluator-owned simple lambda call.
///
/// The generation distinguishes later calls that reuse the same strict stack
/// depth. The token owns no borrow, so an explicit demand executor can retain
/// it while the evaluator-owned call context remains installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LambdaCallLeaseToken {
    depth: usize,
    generation: u64,
}

impl LambdaCallLeaseToken {
    pub(crate) const fn new(depth: usize, generation: u64) -> Self {
        Self { depth, generation }
    }

    pub(crate) const fn depth(self) -> usize {
        self.depth
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// Bookkeeping retained while one simple lambda body owns the active context.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ActiveLambdaCallLease {
    pub(crate) token: LambdaCallLeaseToken,
    pub(crate) module: EvalModuleId,
    pub(crate) saved_module: EvalModuleId,
    pub(crate) suspended_env_depth: usize,
    pub(crate) saved_call_depth: usize,
}

/// A simple lambda body made ready for an evaluator continuation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LambdaCallWork {
    /// The owned context lease that must be finished or aborted.
    pub(crate) token: LambdaCallLeaseToken,
    /// The module containing [`Self::body`].
    pub(crate) module: EvalModuleId,
    /// The lambda body to execute in the installed call context.
    pub(crate) body: IrId,
}

/// Result of trying to begin an evaluator-owned simple lambda call.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BeginLambdaCallLease {
    /// The interpreted simple-formal lambda call is installed.
    Ready(LambdaCallWork),
    /// This substrate does not own the requested apply mode.
    Declined,
}

/// Opaque coordinate for one installed imported-module evaluation context.
///
/// The generation distinguishes later leases that reuse the same strict stack
/// depth, while the owned token avoids borrowing the evaluator across explicit
/// demand-machine continuations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImportModuleLeaseToken {
    depth: usize,
    generation: u64,
}

impl ImportModuleLeaseToken {
    pub(crate) const fn new(depth: usize, generation: u64) -> Self {
        Self { depth, generation }
    }

    pub(crate) const fn depth(self) -> usize {
        self.depth
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// Bookkeeping retained while one imported module owns the active context.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ActiveImportModuleLease {
    pub(crate) token: ImportModuleLeaseToken,
    pub(crate) module: EvalModuleId,
    pub(crate) saved_module: EvalModuleId,
    pub(crate) suspended_env_depth: usize,
}

/// Imported module body made ready for an evaluator continuation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ImportModuleWork {
    /// The owned context lease that must be finished or aborted.
    pub(crate) token: ImportModuleLeaseToken,
    /// The registered module containing `root`.
    pub(crate) module: EvalModuleId,
    /// The imported module's root node.
    pub(crate) root: IrId,
}

/// The runtime global scope used while evaluating an imported file.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ImportGlobalScope {
    Fresh,
    Scoped(Value),
}

impl ImportGlobalScope {
    pub(crate) const fn is_scoped(self) -> bool {
        matches!(self, Self::Scoped(_))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TextStoreEntry {
    pub(crate) contents: Vec<u8>,
    pub(crate) references: StringContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImpureInputTraceCursor {
    pub(crate) len: usize,
    pub(crate) complete: bool,
    pub(crate) force_cache_epoch: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ImpureInputTraceSegment {
    pub(crate) trace: Vec<ImpureInputFingerprint>,
    pub(crate) complete: bool,
}

impl ImpureInputTraceSegment {
    pub(crate) fn is_empty_complete(&self) -> bool {
        self.complete && self.trace.is_empty()
    }
}

impl ImpureInputTraceSource for ImpureInputTraceSegment {
    fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
        &self.trace
    }

    fn impure_input_trace_complete(&self) -> bool {
        self.complete
    }
}

pub(crate) struct TreeWalkImpureInputRevalidator<'a> {
    pub(crate) options: &'a TreeWalkOptions,
    pub(crate) trace: Vec<ImpureInputFingerprint>,
}
