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
