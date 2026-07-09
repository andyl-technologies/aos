//! Safe tree-walk evaluator over lowered IR.
//!
//! The tree-walk evaluator is the permanent Phase-1 correctness oracle. These
//! first slices evaluate scalar and list literals, boolean control flow,
//! assertions, boolean operators, string/URI literals and concatenation, list-spine
//! concatenation, static and recursive static attribute-set literals, dynamic
//! string-valued attribute names, static and dynamic string-valued
//! attribute selection, lexical `let` environments, simple and formal-set lambda
//! application, lazy `with` scope lookup, attrset update, thunk forcing, numeric
//! arithmetic, numeric and string/list comparisons, direct strict primops,
//! and scalar/string/function plus structural
//! list/attrset equality to weak head normal form, establishing the arena access
//! and diagnostic surface used by later slices for full string coercion,
//! first-class primitive operations, and derivation boundaries.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::OsStr,
    fmt, fs,
    io::{self, Cursor, Read, Write as _},
    os::unix::ffi::OsStrExt,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::UNIX_EPOCH,
};

use base64::Engine as _;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use md5::{Digest as _, Md5};
use regex::bytes::{Regex, RegexBuilder};
use serde_json::Value as JsonValue;
use sha1::{Digest as _, Sha1};
use sha2::Sha512;
use thiserror::Error;
use toml::{Value as TomlValue, value::Datetime as TomlDatetime};
use url::Url;
use xz2::read::XzDecoder;

use super::env::{
    EvalEnv, EvalEnvError, EvalFrame, EvalScopedGlobalEnv, EvalWithEnv, EvalWithScope,
};
use super::heap::{
    AllocationCollectorPollCopiedHeapFieldWrite, AllocationCollectorPollDirectHeapFieldWrite,
    AllocationCollectorPollForwardingInstallReport, AllocationCollectorPollHeapFieldWritebackSlot,
    AllocationCollectorPollMinorGcCommitBuffers, AllocationCollectorPollMinorGcCommitPlan,
    AllocationCollectorPollMinorGcOwnedCommitBuffers, AllocationCollectorPollMinorGcPlan,
    AllocationCollectorPollMinorGcRelocationDestinations,
    AllocationCollectorPollObjectByteCopyRequest, AllocationCollectorPollReferenceSlot,
    AllocationCollectorPollReferenceSource, AllocationCollectorPollReferenceWritebackPlan,
    AllocationCollectorPollReferenceWritebackReport, AllocationCollectorPollRootReferenceValue,
    AllocationCollectorPollRootValueWritebackSlot, AllocationCollectorPollRootWritebackPlan,
    AllocationCollectorPollRootWritebackReport, AllocationCollectorPollRootWritebackSlot,
    AllocationCollectorPollScan, EvalGcMode, EvalHeap, EvalHeapAttrsMetadata,
    EvalHeapCheapMemoryAdviceReport, EvalHeapCheapMemoryBudgetPlan, EvalHeapColdHashConsedValue,
    EvalHeapError, EvalHeapMemoryBudgetAction, EvalHeapResidentMemoryMode,
    EvalHeapSweepReport, EvalHeapTierBAdmissionReport, EvalHeapWorkerRegionPopReport, EvalLambda,
    EvalPrimOp, EvalPrimOpArg, EvalRootSet, EvalThunk, EvalThunkKind, HeapAllocationDomain,
    HeapEdgeSource, PreciseHeapScan,
};
use super::module::{EvalModuleId, EvalNodeRef};
use super::thunk::{ForceClaim, ForceError, ForceGuard, ThunkState};
use super::thunk_cas::ParallelThunkWorkerId;
use super::thunk_payload::{ParallelThunkPayloadError, TreeWalkParallelThunkCell};
use super::thunk_registry::ParallelForceCycleRegistry;
use super::whnf_tag::{WhnfTagFastPath, classify_whnf_tag_fast_path};
use crate::attrs::{
    AttrEntry, AttrError, AttrPosition, FlatAttrs,
    hamt::{HamtAttrs, HamtError, HamtMergeSummary},
    order::{AttrOrderError, AttrOrderTarget, collect_checked_lexicographic_keys},
    pic::{
        FlatSelectCache, FlatSelectError, FlatSelectOutcome, FlatSelectSource, HamtSelectCache,
        HamtSelectError, HamtSelectOutcome, HamtSelectPolicy, HamtSelectSource, ShapedSelectCache,
        ShapedSelectCacheState, ShapedSelectError, ShapedSelectOutcome, ShapedSelectSource,
        record::{RecordSelectCache, RecordSelectError, RecordSelectOutcome, RecordSelectSource},
    },
    repr::{
        AttrSetConstruction, AttrSetReprDecision, AttrSetReprKind, AttrSetReprPolicy,
        AttrSetReprValue, AttrSetReprValueError,
    },
    select::{
        AttrSelectError, AttrSelectOutcome, AttrSelectRepr, AttrSelectSource, AttrSelectTarget,
        select_slow,
    },
    shape::{
        ShapeError, ShapeHandle, ShapeId, ShapeTable, ShapeTableTransition, ShapedAttrs,
        ShapedAttrsError,
    },
    telemetry::AttrTelemetry,
};
use crate::cache::{
    CacheExprIdentity, CachedDerivationOutputPath, CachedDerivationOutputPaths,
    CachedExpressionValue, CachedParse, CutoffDecision, DemandNodeId, DirEntryInput,
    DurableBlake3Hash, EvalCacheRuntime, FileTypeForInput, ImpureInputFingerprint,
    ImpureInputIdentity, ImpureInputKind, ImpureInputMode, ImpureInputRevalidator,
    ImpureInputTraceSource, InputFingerprintError, MaterializationCostObservation,
    MaterializationCosts, MaterializationDecision, MemoizationDecision, MemoizationSubject,
    NixSha256Digest, ParseCache, ParseCacheError, ParseFileKey, PersistCache,
    PersistDiskLocation, PersistLatencyClass, PersistMaterialization, PersistNodeMetadataKey,
    PersistNodeTracePayload, ValueHash, lowered_ir_fingerprint,
};
use crate::compile::{
    DeadBindingReplacement, Escape, ExprFacts, FrameId, Ir, IrArena, IrAttrPathId,
    IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData, IrDialectOp, IrId, IrKind,
    IrLowerOptions, IrNode, IrShape, IrShapeId, ResolverOptions, ScopeResolver, Strictness,
    dead_binding_elimination_plan, resolve,
};
use crate::heap::{
    AllocationRegionFacts, GcCardTable, GcCardTableClearReport, GcDirtyCard, GcHeapAddress,
    GenerationalGcError, GenerationalGcTier, HeapMemoryBudget, MinorGcCommitReport,
    MinorGcDestinationBases, MinorGcDestinationPlacementPlan, MinorGcForwardingSlot,
    MinorGcObjectByteCopyBuffer, MinorGcObjectCopyPlan, MinorGcOwnedDestinationStorage,
    MinorGcOwnedDestinationStorageCopyReport, MinorGcPlan, MinorGcPromotionPolicy,
    MinorGcSourceObjectBytes, MinorGcSurvivorAction, NurseryObjectLayout, RegionEffect,
    RegionLifetime, RegionPlacement, RegionPlacementReason, RegionPlan, RegionRuntimeTier,
    RegionSharing, RememberedEdge, RememberedSet, RememberedSetEpoch, ResolvedValueGeneration,
};
use crate::list::{NixList, NixListError};
#[cfg(test)]
use crate::runtime::alloc::RuntimeAllocationEntryPoint;
use crate::runtime::alloc::{AllocationCollectorPoll, GcStressPolicy, RuntimeAllocatorTier};
use crate::runtime::builtins::*;
use crate::string::{
    ContextElement, ContextKind, NixString, NixStringError, StringContext, try_clone_bytes,
};
use crate::syntax::{BinOpKind, Span, Symbol, SymbolTable, UnaryOpKind, parse_bytes_with_symbols};
use crate::value::{Value, ValueTag};
use aos_nix_compat::drv_materialize::materialize_drv;
use aos_nix_dialect::{nix_lower, nix_lower_with_options};

mod builtins;

const TO_STRING_ATTR: &[u8] = b"__toString";
const OUT_PATH_ATTR: &[u8] = b"outPath";
const DRV_PATH_ATTR: &[u8] = b"drvPath";
const TYPE_ATTR: &[u8] = b"type";
const NAME_ATTR: &[u8] = b"name";
const ID_ATTR: &[u8] = b"id";
const OWNER_ATTR: &[u8] = b"owner";
const REPO_ATTR: &[u8] = b"repo";
const HOST_ATTR: &[u8] = b"host";
const DIR_ATTR: &[u8] = b"dir";
const BUILDER_ATTR: &[u8] = b"builder";
const SYSTEM_ATTR: &[u8] = b"system";
const ARGS_ATTR: &[u8] = b"args";
const OUTPUTS_ATTR: &[u8] = b"outputs";
const OVERRIDES_ATTR: &[u8] = b"__overrides";
const STRUCTURED_ATTRS_ATTR: &[u8] = b"__structuredAttrs";
const IGNORE_NULLS_ATTR: &[u8] = b"__ignoreNulls";
const OUTPUT_HASH_ATTR: &[u8] = b"outputHash";
const OUTPUT_HASH_ALGO_ATTR: &[u8] = b"outputHashAlgo";
const OUTPUT_HASH_MODE_ATTR: &[u8] = b"outputHashMode";
const CONTENT_ADDRESSED_ATTR: &[u8] = b"__contentAddressed";
const IMPURE_ATTR: &[u8] = b"__impure";
const PATH_ATTR: &[u8] = b"path";
const URL_ATTR: &[u8] = b"url";
const FILTER_ATTR: &[u8] = b"filter";
const RECURSIVE_ATTR: &[u8] = b"recursive";
const SHA256_ATTR: &[u8] = b"sha256";
const REV_ATTR: &[u8] = b"rev";
const REF_ATTR: &[u8] = b"ref";
const SUBMODULES_ATTR: &[u8] = b"submodules";
const SHALLOW_ATTR: &[u8] = b"shallow";
const ALL_REFS_ATTR: &[u8] = b"allRefs";
const EXPORT_IGNORE_ATTR: &[u8] = b"exportIgnore";
const UNPACK_ATTR: &[u8] = b"unpack";
const VERIFY_COMMIT_ATTR: &[u8] = b"verifyCommit";
const KEYTYPE_ATTR: &[u8] = b"keytype";
const PUBLIC_KEY_ATTR: &[u8] = b"publicKey";
const PUBLIC_KEYS_ATTR: &[u8] = b"publicKeys";
const SHORT_REV_ATTR: &[u8] = b"shortRev";
const DIRTY_REV_ATTR: &[u8] = b"dirtyRev";
const DIRTY_SHORT_REV_ATTR: &[u8] = b"dirtyShortRev";
const REV_COUNT_ATTR: &[u8] = b"revCount";
const LAST_MODIFIED_ATTR: &[u8] = b"lastModified";
const LAST_MODIFIED_DATE_ATTR: &[u8] = b"lastModifiedDate";
const NAR_HASH_ATTR: &[u8] = b"narHash";
const PREFIX_ATTR: &[u8] = b"prefix";
const VALUE_ATTR: &[u8] = b"value";
const TOML_TIMESTAMP_TYPE_ATTR: &[u8] = b"_type";
const TOML_TIMESTAMP_TYPE_VALUE: &[u8] = b"timestamp";
const KEY_ATTR: &[u8] = b"key";
const FILE_ATTR: &[u8] = b"file";
const LINE_ATTR: &[u8] = b"line";
const COLUMN_ATTR: &[u8] = b"column";
const CUR_POS_ATTR: &[u8] = b"__curPos";
const NIX_PATH_ATTR: &[u8] = b"__nixPath";
const OPERATOR_ATTR: &[u8] = b"operator";
const START_SET_ATTR: &[u8] = b"startSet";
const HASH_ATTR: &[u8] = b"hash";
const HASH_ALGO_ATTR: &[u8] = b"hashAlgo";
const TO_HASH_FORMAT_ATTR: &[u8] = b"toHashFormat";
const DEFAULT_STORE_DIR: &[u8] = b"/nix/store";
const DEFAULT_MAX_CALL_DEPTH: usize = 10_000;
const MAX_FLAKE_REF_RESOLUTION_DEPTH: usize = 16;
const DEFAULT_FORCE_CACHE_MATERIALIZATION_COSTS: MaterializationCosts =
    MaterializationCosts::new(4, 1, 1, 1);
const PLACEHOLDER_HASH_PREFIX: &[u8] = b"nix-output:";
const UPSTREAM_OUTPUT_PLACEHOLDER_HASH_PREFIX: &[u8] = b"nix-upstream-output:";
const DERIVATION_EXTENSION: &str = ".drv";
const DERIVATION_NAME_MAX_LEN: usize = 211;
const TRACE_PREFIX: &[u8] = b"trace: ";
const WARNING_PREFIX: &[u8] = b"evaluation warning:";
const WARNING_CONTINUATION_INDENT: &[u8] = b"                    ";
const EMPTY_FETCHURL_SHA256_WARNING: &[u8] =
    b"found empty hash, assuming 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='";
const ADD_ERROR_CONTEXT_MESSAGE_CONTEXT: &[u8] =
    b"while evaluating the error message passed to builtins.addErrorContext";
const I64_MAX_EXCLUSIVE_AS_F64: f64 = 9_223_372_036_854_775_808.0;
const NIX_BASE32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";
const DERIVATION_INTERNAL_PATH: &[u8] = b"<nix/derivation-internal.nix>";
static FETCH_TARBALL_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static FETCH_GIT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const DERIVATION_INTERNAL_SOURCE: &str = r#"
# This is the implementation of the ‘derivation’ builtin function.
# It's actually a wrapper around the ‘derivationStrict’ primop.
# Note that the following comment will be shown in :doc in the repl, but not in the manual.

/**
  Create a derivation.

  # Inputs

  The single argument is an attribute set that describes what to build and how to build it.
  See https://nix.dev/manual/nix/2.23/language/derivations

  # Output

  The result is an attribute set that describes the derivation.
  Notably it contains the outputs, which in the context of the Nix language are special strings that refer to the output paths, which may not yet exist.
  The realisation of these outputs only occurs when needed; for example

    * When `nix-build` or a similar command is run, it realises the outputs that were requested on its command line.
      See https://nix.dev/manual/nix/2.23/command-ref/nix-build

    * When `import`, `readFile`, `readDir` or some other functions are called, they have to realise the outputs they depend on.
      This is referred to as "import from derivation".
      See https://nix.dev/manual/nix/2.23/language/import-from-derivation

  Note that `derivation` is very bare-bones, and provides almost no commands during the build.
  Most likely, you'll want to use functions like `stdenv.mkDerivation` in Nixpkgs to set up a basic environment.
*/
drvAttrs @ { outputs ? [ "out" ], ... }:

let

  strict = derivationStrict drvAttrs;

  commonAttrs = drvAttrs // (builtins.listToAttrs outputsList) //
    { all = map (x: x.value) outputsList;
      inherit drvAttrs;
    };

  outputToAttrListElement = outputName:
    { name = outputName;
      value = commonAttrs // {
        outPath = builtins.getAttr outputName strict;
        drvPath = strict.drvPath;
        type = "derivation";
        inherit outputName;
      };
    };

  outputsList = map outputToAttrListElement outputs;

in (builtins.head outputsList).value
"#;

#[derive(Debug)]
struct RegexCaptureMatch {
    range: std::ops::Range<usize>,
    groups: Vec<Option<std::ops::Range<usize>>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ResolvedSearchPathEntry {
    prefix: Vec<u8>,
    path: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindFileCacheKey {
    search_path_base: Vec<u8>,
    corepkgs_path: Option<Vec<u8>>,
    entries: Vec<ResolvedSearchPathEntry>,
    lookup: Vec<u8>,
    origin: FindFileLookupOrigin,
}

impl FindFileCacheKey {
    fn new(
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
enum FindFileCacheEntry {
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
enum FindFileLookupOrigin {
    AmbientSearchPath,
    LexicalSearchPath,
    ExplicitSearchPath,
}

// Type, helper, and error-enum definitions split into concern modules below;
// re-exported here so siblings (and the public path) keep resolving them.
mod api;
mod campaign_counters;
mod error_kind;
mod errors;
mod op_types;
mod options;
mod outcome;
mod toml_normalize;
mod version;
pub(crate) use api::{
    attr_path_segment_is_list_index, parse_attr_path_list_index,
    parse_attr_path_list_index_diagnostic,
};
pub(in crate::eval) use api::{
    eval_derivation_aterm_surfaces_with_options, eval_raw_bytes_with_evaluator_owned,
    eval_raw_bytes_with_post_render_tier_b_admission,
};
pub use api::{
    eval_instantiation_attr_path_owned_with_options_and_realizer,
    eval_instantiation_attr_path_owned_with_options_source_and_realizer,
    eval_instantiation_attr_path_owned_with_options_source_realizer_and_eval_cache,
    eval_instantiation_attr_path_owned_with_options_source_realizer_eval_cache_and_engine,
    eval_number_raw_bytes, eval_number_raw_bytes_with_options, eval_raw_bytes,
    eval_raw_bytes_with_options, eval_raw_bytes_with_options_source, eval_whnf, eval_whnf_owned,
    eval_whnf_owned_with_options, eval_whnf_owned_with_options_and_realizer,
    eval_whnf_owned_with_options_realizer_and_eval_cache,
    eval_whnf_owned_with_options_realizer_eval_cache_and_engine, eval_whnf_with_options,
};
pub use campaign_counters::CampaignCounters;
pub use error_kind::TreeWalkErrorKind;
pub(crate) use errors::ArithmeticOp;
pub use errors::EvalErrorContext;
pub use errors::{EvalErrorLabel, EvalErrorSource, TreeWalkError};
pub(crate) use op_types::*;
pub use options::TreeWalkOptionsError;
pub use options::{MemoNetMode, MemoNetOptions};
pub use options::{canonicalize_policy_path, normalize_absolute_path_bytes};
pub(crate) use options::{
    file_type_name, is_valid_store_path, join_path_literal, join_search_path,
    path_exists_requires_directory, path_is_under_root, path_without_trailing_path_markers,
    search_path_literal_lookup, search_path_suffix, store_path_root,
};
pub use outcome::{
    EvalDerivation, EvalGcStressBoundaryMinorGcCommitApplication,
    EvalGcStressBoundaryMinorGcCommitApplications, EvalGcStressBoundaryMinorGcCommitDryRun,
    EvalGcStressBoundaryMinorGcCommitDryRunSummary, EvalGcStressBoundaryMinorGcCommitPreflight,
    EvalGcStressBoundaryMinorGcCommitPreflights,
    EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit,
    EvalGcStressBoundaryMinorGcForwardingHeaderWrite,
    EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan,
    EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
    EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite,
    EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
    EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes,
    EvalGcStressBoundaryMinorGcLiveDestinationStorage,
    EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings,
    EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveObjectGeneration,
    EvalGcStressBoundaryMinorGcLiveObjectGenerationCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    EvalGcStressBoundaryMinorGcLiveObjectGenerations,
    EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingCommitDryRun,
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
    EvalGcStressBoundaryMinorGcObjectByteCopyApplication,
    EvalGcStressBoundaryMinorGcObjectGenerationWrite,
    EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
    EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport, EvalGcStressBoundaryMinorGcPlans,
    EvalGcStressBoundaryMinorGcReferenceWritebackApplication,
    EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    EvalGcStressBoundaryMinorGcRelocationDestinations, EvalGcStressBoundaryMinorGcRelocationPlan,
    EvalGcStressBoundaryMinorGcRelocationPlans,
    EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
    EvalGcStressBoundaryMinorGcRootWritebackWrite,
    EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport, EvalGcStressBoundaryScans,
    EvalOutcome, EvalStats, EvalTierBTransitionAdmissionApplyError, MemoTierEvents,
    EvalTierBTransitionAdmissionPlan, EvalTierBTransitionAdmissionPlanError,
    EvalTierBTransitionDomain, EvalTierBTransitionDomainPreflight, EvalTierBTransitionPreflight,
    EvalTierBTransitionPreflightError, EvalTierBTransitionRequest, EvalTraceKind, EvalTraceOutput,
    EvalWarningOutput, IfdErrorDetail, IfdRealization, IfdRealizationError, IfdRealizer,
};
pub(crate) use eval_regex_ere::{bracket_expression_end, translate_posix_ere};
pub(crate) use json_float::nlohmann_json_float_bytes;
pub(crate) use toml_normalize::normalize_toml_numeric_overflows;
pub(crate) use version::{
    SplitVersionRanges, base_name_range, compare_version_bytes, parse_drv_name_split,
};

/// Configuration for the in-process content-keyed memoization tiers (MEMO-1).
///
/// Controls the L0 (per-worker, in-thread) and L1 (in-process shared, parallel
/// mode) content memo tables described by RFC-0007's tiered content-keyed
/// memoization design. The store is purely advisory: every knob here is a
/// performance setting that must never change evaluation results, so none of
/// these fields participate in the result-affecting options fingerprint.
///
/// The master switch defaults to **off** for this first landing (the design
/// document defaults it on; flipping the default is gated on corpus
/// measurement).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoOptions {
    /// Master switch for the content memo (`AOS_NIX_MEMO`).
    pub enabled: bool,
    /// Enables the per-worker in-thread tier (`AOS_NIX_MEMO_L0`).
    pub l0_enabled: bool,
    /// Enables the in-process shared tier (`AOS_NIX_MEMO_L1`).
    ///
    /// `None` selects the default policy: on exactly when parallel workers are
    /// configured (the shared tier is pointless in serial mode where L0
    /// already covers the process).
    pub l1_enabled: Option<bool>,
    /// Static recompute-estimate admission floor (`AOS_NIX_MEMO_MIN_COST`).
    ///
    /// Def-sites whose lowered-IR static cost estimate falls below this floor
    /// are never probed or recorded, keeping the memo entirely off the bare
    /// force path for cheap subtrees.
    pub min_cost: u32,
    /// Per-worker L0 entry cap (`AOS_NIX_MEMO_L0_ENTRIES`).
    pub l0_entries: usize,
    /// L1 retained-bytes budget (`AOS_NIX_MEMO_L1_BYTES`).
    pub l1_bytes: u64,
    /// Hits at L1 before an entry is also installed at L0
    /// (`AOS_NIX_MEMO_PROMOTE_HITS`).
    pub promote_hits: u32,
    /// Shadow-checks every L0 hit against a fresh evaluation
    /// (`AOS_NIX_MEMO_CHECK=l0` or `all`).
    pub check_l0: bool,
    /// Shadow-checks every L1 hit against a fresh evaluation
    /// (`AOS_NIX_MEMO_CHECK=l1` or `all`).
    pub check_l1: bool,
    /// Enables the secondary disk locations of the L2 tier
    /// (`AOS_NIX_MEMO_L2`, a kill switch defaulting on).
    ///
    /// This governs only the additive `AOS_NIX_MEMO_DISK` secondaries; the
    /// primary `AOS_NIX_CACHE` location keeps its own existing switches
    /// (root cutoff, force-cache persist layer, parse cache) so disabling L2
    /// never changes primary-location behavior.
    pub l2_enabled: bool,
    /// Shadow-checks every secondary-location (L2) root-cutoff hit
    /// (`AOS_NIX_MEMO_CHECK=l2` or `all`).
    pub check_l2: bool,
    /// Shadow-checks every network-tier (L3) root-cutoff hit
    /// (`AOS_NIX_MEMO_CHECK=l3` or `all`).
    pub check_l3: bool,
}

impl Default for MemoOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            l0_enabled: true,
            l1_enabled: None,
            min_cost: 64,
            l0_entries: 65_536,
            l1_bytes: 256 * 1024 * 1024,
            promote_hits: 2,
            check_l0: false,
            check_l1: false,
            l2_enabled: true,
            check_l2: false,
            check_l3: false,
        }
    }
}

/// Default worker-record growth between Tier-B quiescent sweeps.
///
/// A sweep is considered at an evaluator quiescent point only after at least
/// this many thunks were allocated since the previous sweep. The default is
/// sized so sub-second evaluations (a package instantiate, `bench.wide` at
/// ~250k thunks) never pay for marking, while multi-million-thunk evaluations
/// (system toplevels, long-lived embedders) sweep a bounded number of times
/// with each cycle amortized against seconds of evaluation. Measured on
/// `bench.wide`: one sweep costs roughly 60-70ms and retires ~137k worker
/// records; capture shedding itself is time-neutral. Set
/// `AOS_NIX_GC_THRESHOLD=0` to sweep at every quiescent opportunity (the
/// stress cadence).
pub const DEFAULT_GC_SWEEP_THRESHOLD: u64 = 1_048_576;

/// Runtime options used by the tree-walk evaluator.
///
/// These options carry interpreter settings that C++ Nix normally reads from
/// its process configuration, while keeping the Phase-1 oracle deterministic
/// and independent from ambient host state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkOptions {
    store_dir: Vec<u8>,
    search_path_base: Vec<u8>,
    path_literal_base: Option<Vec<u8>>,
    home_dir: Option<Vec<u8>>,
    eval_mode: EvalMode,
    allowed_paths: Vec<Vec<u8>>,
    allowed_uris: Vec<Vec<u8>>,
    current_system: Option<Vec<u8>>,
    current_time: Option<i64>,
    trace_verbose: bool,
    abort_on_warn: bool,
    max_call_depth: usize,
    parse_toml_timestamps: bool,
    env_vars: BTreeMap<Vec<u8>, Vec<u8>>,
    nix_path: Vec<NixSearchPathEntry>,
    corepkgs_path: Option<Vec<u8>>,
    reject_ambient_search_path: bool,
    reject_unconfigured_impure_builtin_constants: bool,
    parse_cache_root: Option<PathBuf>,
    persist_cache_root: Option<PathBuf>,
    eval_cache_enabled: bool,
    persist_cache_verify: bool,
    root_cutoff_enabled: bool,
    root_cutoff_check: bool,
    eval_stats_dump: bool,
    force_cache_materialization_costs: MaterializationCosts,
    heap_memory_budget: Option<HeapMemoryBudget>,
    heap_tier_b_transition_admission_enabled: bool,
    record_worker_closures_for_gc_scaffolding: bool,
    heap_thread_local_tier_a_enabled: bool,
    gc_stress_policy: GcStressPolicy,
    gc_mode: EvalGcMode,
    gc_sweep_threshold: u64,
    thunk_resolve_barrier_tier: GenerationalGcTier,
    parallel_thunk_payloads_enabled: bool,
    parallel_workers: Option<std::num::NonZeroUsize>,
    parallel_shape_projection: bool,
    attr_shape_mode: AttrShapeMode,
    jit_tier1_publish_enabled: bool,
    parallel_thunk_worker_id: ParallelThunkWorkerId,
    heap_cheap_memory_advice_min_idle_epochs: Option<u64>,
    flake_ref_resolutions: BTreeMap<Vec<u8>, Vec<u8>>,
    memo: MemoOptions,
    memo_disk_locations: Vec<PersistDiskLocation>,
    memo_net: Option<MemoNetOptions>,
    #[cfg(test)]
    fetch_tree_url_responses: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Default for TreeWalkOptions {
    fn default() -> Self {
        Self {
            store_dir: DEFAULT_STORE_DIR.to_vec(),
            search_path_base: b"/".to_vec(),
            path_literal_base: None,
            home_dir: None,
            eval_mode: EvalMode::default(),
            allowed_paths: Vec::new(),
            allowed_uris: Vec::new(),
            current_system: None,
            current_time: None,
            trace_verbose: false,
            abort_on_warn: false,
            max_call_depth: DEFAULT_MAX_CALL_DEPTH,
            parse_toml_timestamps: false,
            env_vars: BTreeMap::new(),
            nix_path: Vec::new(),
            corepkgs_path: None,
            reject_ambient_search_path: false,
            reject_unconfigured_impure_builtin_constants: false,
            parse_cache_root: None,
            persist_cache_root: None,
            eval_cache_enabled: false,
            persist_cache_verify: false,
            root_cutoff_enabled: false,
            root_cutoff_check: false,
            eval_stats_dump: false,
            force_cache_materialization_costs: DEFAULT_FORCE_CACHE_MATERIALIZATION_COSTS,
            heap_memory_budget: None,
            heap_tier_b_transition_admission_enabled: false,
            record_worker_closures_for_gc_scaffolding: false,
            heap_thread_local_tier_a_enabled: false,
            gc_stress_policy: GcStressPolicy::disabled(),
            gc_mode: EvalGcMode::Off,
            gc_sweep_threshold: DEFAULT_GC_SWEEP_THRESHOLD,
            thunk_resolve_barrier_tier: GenerationalGcTier::OneShotArena,
            parallel_thunk_payloads_enabled: false,
            parallel_workers: None,
            parallel_shape_projection: false,
            attr_shape_mode: AttrShapeMode::default(),
            jit_tier1_publish_enabled: false,
            parallel_thunk_worker_id: ParallelThunkWorkerId::FIRST,
            heap_cheap_memory_advice_min_idle_epochs: None,
            flake_ref_resolutions: BTreeMap::new(),
            memo: MemoOptions::default(),
            memo_disk_locations: Vec::new(),
            memo_net: None,
            #[cfg(test)]
            fetch_tree_url_responses: BTreeMap::new(),
        }
    }
}

/// Hidden-class shape strategy for heap attrset records (RFC-0007 §09).
///
/// Selected through `AOS_NIX_SHAPES` (`off` / `transient` / `record`).
/// Every mode produces byte-identical evaluation results; the mode changes
/// only how attrset selects are served.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AttrShapeMode {
    /// No shape projection: attrset records carry no projected shape id and
    /// every select uses the flat key-validated slot cache or binary search.
    Off,
    /// The L2-P4 baseline: allocations project shapes through the transition
    /// tree and shaped selects rebuild a transient [`ShapedAttrs`] view per
    /// lookup. Measured a net loss on the package corpus, retained as the
    /// comparison baseline while the record mode is calibrated.
    #[default]
    Transient,
    /// Heap-resident shaped layout: the projected shape id stored in the
    /// record at construction is the select guard, and the flat symbol-order
    /// payload is the slot layout itself - a shaped select is a shape-id
    /// compare plus a constant-offset entry load, with no transient view.
    /// Static literal sites resolve their shape once and reuse the handle,
    /// and same-key-set `//` results keep the left operand's shape id.
    Record,
}

/// Filesystem and impurity policy used by the tree-walk evaluator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EvalMode {
    /// Allows evaluator-time filesystem access without an allow-list.
    #[default]
    Impure,
    /// Restricts evaluator-time filesystem access to explicitly allowed paths.
    Restricted,
    /// Models pure evaluation by allowing only explicitly allowed paths.
    Pure,
}

/// A configured entry in the Nix search path used by `<...>` and `findFile`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixSearchPathEntry {
    prefix: Vec<u8>,
    path: Vec<u8>,
}

impl NixSearchPathEntry {
    /// Creates a search-path entry from a lookup prefix and path.
    ///
    /// The empty prefix models bare search-path roots. The path text is kept
    /// as provided so `builtins.nixPath` reflects configured entries without
    /// normalizing their spelling.
    ///
    /// # Errors
    ///
    /// This constructor currently accepts all byte strings and does not fail.
    pub fn new(
        prefix: impl Into<Vec<u8>>,
        path: impl Into<Vec<u8>>,
    ) -> Result<Self, TreeWalkOptionsError> {
        Ok(Self {
            prefix: prefix.into(),
            path: path.into(),
        })
    }

    /// Returns the search-path prefix matched against lookup paths.
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Returns the configured filesystem path for this search-path entry.
    pub fn path(&self) -> &[u8] {
        &self.path
    }
}

#[derive(Debug, Default)]
enum EvalStderr {
    #[default]
    Process,
    #[cfg(test)]
    Buffer(Vec<u8>),
}

impl EvalStderr {
    fn write_trace_line(&mut self, message: &[u8]) {
        match self {
            Self::Process => {
                let mut stderr = io::stderr().lock();
                let _ = stderr.write_all(TRACE_PREFIX);
                let _ = stderr.write_all(message);
                let _ = stderr.write_all(b"\n");
            }
            #[cfg(test)]
            Self::Buffer(buffer) => {
                buffer.extend_from_slice(TRACE_PREFIX);
                buffer.extend_from_slice(message);
                buffer.extend_from_slice(b"\n");
            }
        }
    }

    fn write_all(&mut self, bytes: &[u8]) {
        match self {
            Self::Process => {
                let mut stderr = io::stderr().lock();
                let _ = stderr.write_all(bytes);
            }
            #[cfg(test)]
            Self::Buffer(buffer) => buffer.extend_from_slice(bytes),
        }
    }

    #[cfg(test)]
    fn capture(&mut self) {
        *self = Self::Buffer(Vec::new());
    }

    #[cfg(test)]
    fn captured(&self) -> &[u8] {
        match self {
            Self::Process => &[],
            Self::Buffer(buffer) => buffer,
        }
    }
}

/// One lowered IR module loaded into a tree-walk evaluator.
#[derive(Clone, Debug)]
struct TreeWalkModule {
    ir: Ir,
    path_literal_base: Option<Vec<u8>>,
    force_cache_options: ForceCacheOptionsIdentity,
    source: Option<ModuleSource>,
    dead_binding_eliminations: TreeWalkDeadBindingEliminations,
}

impl TreeWalkModule {
    fn new(
        ir: Ir,
        path_literal_base: Option<Vec<u8>>,
        force_cache_options: ForceCacheOptionsIdentity,
        source: Option<ModuleSource>,
    ) -> Self {
        let dead_binding_eliminations = TreeWalkDeadBindingEliminations::from_ir(&ir);
        Self {
            ir,
            path_literal_base,
            force_cache_options,
            source,
            dead_binding_eliminations,
        }
    }
}

#[derive(Clone, Debug)]
struct ForceCacheOptionsIdentity {
    store_dir: Vec<u8>,
    search_path_base: Vec<u8>,
    nix_path: Vec<NixSearchPathEntry>,
    corepkgs_path: Option<Vec<u8>>,
    allowed_paths: Vec<Vec<u8>>,
    allowed_uris: Vec<Vec<u8>>,
    home_dir: Option<Vec<u8>>,
    current_system: Option<Vec<u8>>,
    current_time: Option<i64>,
    eval_mode: EvalMode,
    reject_ambient_search_path: bool,
    reject_unconfigured_impure_builtin_constants: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForceCacheMemoizationAdmission {
    ConditionalThunk,
    SelectedSubstrate,
}

impl ForceCacheMemoizationAdmission {
    const fn admits_on_first_demand(self) -> bool {
        matches!(self, Self::SelectedSubstrate)
    }
}

#[derive(Clone, Debug)]
struct ForceCacheSubject {
    lookup_identity: Option<CacheExprIdentity>,
    pure_observation_identity: Option<CacheExprIdentity>,
    impure_observation_identity: Option<CacheExprIdentity>,
    metadata_identity: Option<CacheExprIdentity>,
    persistent_clear_identity: Option<CacheExprIdentity>,
    free_var_value_hashes: Vec<ValueHash>,
    replay_position_module: Option<EvalModuleId>,
    replay_allocation_node: Option<EvalNodeRef>,
    memoization_admission: ForceCacheMemoizationAdmission,
}

#[derive(Debug)]
struct ActiveMemoReadNode {
    node: DemandNodeId,
    memo_reads: BTreeSet<DemandNodeId>,
}

impl ActiveMemoReadNode {
    fn new(node: DemandNodeId) -> Self {
        Self {
            node,
            memo_reads: BTreeSet::new(),
        }
    }

    const fn node(&self) -> DemandNodeId {
        self.node
    }

    fn into_parts(self) -> (DemandNodeId, BTreeSet<DemandNodeId>) {
        (self.node, self.memo_reads)
    }
}

#[derive(Clone, Debug)]
struct ModuleSource {
    name: Vec<u8>,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TreeWalkDeadBindingKey {
    let_node: u32,
    binding_index: usize,
}

impl TreeWalkDeadBindingKey {
    const fn new(let_node: IrId, binding_index: usize) -> Self {
        Self {
            let_node: let_node.as_u32(),
            binding_index,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct TreeWalkDeadBindingEliminations {
    bindings: BTreeSet<TreeWalkDeadBindingKey>,
}

impl TreeWalkDeadBindingEliminations {
    fn from_ir(ir: &Ir) -> Self {
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

    fn contains(&self, let_node: IrId, binding_index: usize) -> bool {
        self.bindings
            .contains(&TreeWalkDeadBindingKey::new(let_node, binding_index))
    }
}

/// In-process import cache state.
#[derive(Clone, Debug)]
enum ImportCacheEntry {
    Evaluating,
    Ready {
        value: Value,
        trace: Option<Vec<ImpureInputFingerprint>>,
        force_cache_trace_complete: bool,
    },
}

/// The runtime global scope used while evaluating an imported file.
#[derive(Clone, Copy, Debug)]
enum ImportGlobalScope {
    Fresh,
    Scoped(Value),
}

impl ImportGlobalScope {
    const fn is_scoped(self) -> bool {
        matches!(self, Self::Scoped(_))
    }
}

#[derive(Clone, Debug)]
struct TextStoreEntry {
    contents: Vec<u8>,
    references: StringContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ImpureInputTraceCursor {
    len: usize,
    complete: bool,
    force_cache_epoch: u64,
}

#[derive(Clone, Debug)]
struct ImpureInputTraceSegment {
    trace: Vec<ImpureInputFingerprint>,
    complete: bool,
}

impl ImpureInputTraceSegment {
    fn is_empty_complete(&self) -> bool {
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

struct TreeWalkImpureInputRevalidator<'a> {
    options: &'a TreeWalkOptions,
    trace: Vec<ImpureInputFingerprint>,
}

#[derive(Clone, Debug)]
struct FetchUrlArguments {
    url: Vec<u8>,
    name: String,
    expected_sha256: Option<NixSha256Digest>,
}

#[derive(Clone, Debug)]
struct FetchTarballArguments {
    url: Vec<u8>,
    name: String,
    expected_sha256: Option<NixSha256Digest>,
}

#[derive(Clone, Debug)]
struct FetchGitArguments {
    url: Vec<u8>,
    transport_url: Option<Vec<u8>>,
    name: String,
    rev: Option<Vec<u8>>,
    reference: Option<Vec<u8>>,
    submodules: bool,
    shallow: bool,
    all_refs: bool,
    export_ignore: bool,
    extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone, Debug)]
struct FetchMercurialArguments {
    url: Vec<u8>,
    rev: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct GitPublicKeyEntry {
    keytype: Vec<u8>,
    key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct FetchGitResult {
    out_path: Vec<u8>,
    rev: String,
    dirty_rev: Option<String>,
    dirty_short_rev: Option<String>,
    rev_count: usize,
    last_modified: i64,
    last_modified_date: Vec<u8>,
    nar_hash: Vec<u8>,
    submodules: bool,
}

type FlakeRefAttrs = BTreeMap<Vec<u8>, FlakeRefAttrValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
enum FlakeRefAttrValue {
    String(Vec<u8>),
    Int(u64),
    Bool(bool),
}

#[derive(Clone, Debug)]
enum FetchTreeArguments {
    Path {
        path: Vec<u8>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    },
    File {
        url: Vec<u8>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    },
    Tarball {
        url: Vec<u8>,
        transport_url: Vec<u8>,
        dir: Option<Vec<u8>>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        last_modified_from_lock: bool,
        rev: Option<Vec<u8>>,
        rev_count: Option<usize>,
    },
    Forge {
        canonical_uri: Vec<u8>,
        archive_url: Vec<u8>,
        dir: Option<Vec<u8>>,
        check_archive_url_access: bool,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        rev: Vec<u8>,
    },
    Git {
        args: FetchGitArguments,
        dir: Option<Vec<u8>>,
        expected_nar_hash: Option<NixSha256Digest>,
        expected_last_modified: Option<i64>,
        expected_rev_count: Option<usize>,
        dirty_rev: Option<Vec<u8>>,
        dirty_short_rev: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug)]
struct FetchTreeResult {
    out_path: Vec<u8>,
    nar_hash: Vec<u8>,
    last_modified: Option<i64>,
    last_modified_date: Option<Vec<u8>>,
    rev: Option<Vec<u8>>,
    dirty_rev: Option<Vec<u8>>,
    dirty_short_rev: Option<Vec<u8>>,
    rev_count: Option<usize>,
    submodules: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FetchTarballCompression {
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

#[derive(Clone, Copy, Debug)]
struct AttrUpdateTelemetryState {
    override_chain_depth: usize,
    // Active update projection reads the left heap value metadata; this field is
    // still used by the test-only telemetry wrapper that synthesizes chains.
    #[allow(dead_code)]
    projected_repr: AttrSetReprKind,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct AttrUpdateMergeProjection {
    left_repr: AttrSetReprKind,
    override_chain_depth: usize,
    decision: AttrSetReprDecision,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(super) enum AttrUpdateTelemetryDispatchError {
    #[error("flat attrset operand normalization failed: {0}")]
    Flat(#[from] AttrError),
    #[error("HAMT operand normalization failed: {0}")]
    Hamt(#[from] HamtError),
    #[error("representation-dispatched update failed: {0}")]
    Repr(#[from] AttrSetReprValueError),
}

type AttrUpdateTelemetryNodeKey = (u32, u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActivePrimopArgFrame {
    start: usize,
    len: usize,
}

#[derive(Debug)]
struct SuspendedTreeWalkEnv {
    env: Vec<Arc<EvalFrame>>,
    with_scopes: Vec<EvalWithScope>,
    scoped_globals: Vec<Value>,
}

impl SuspendedTreeWalkEnv {
    fn new(
        env: Vec<Arc<EvalFrame>>,
        with_scopes: Vec<EvalWithScope>,
        scoped_globals: Vec<Value>,
    ) -> Self {
        Self {
            env,
            with_scopes,
            scoped_globals,
        }
    }
}

/// A safe recursive evaluator for lowered IR.
#[derive(Debug)]
pub struct TreeWalk {
    modules: Vec<TreeWalkModule>,
    current_module: EvalModuleId,
    symbols: SymbolTable,
    heap: EvalHeap,
    /// The active lexical frame stack.
    ///
    /// Every mutation must go through the `push_env_frame` /
    /// `pop_env_frame` / `swap_env_frames` / `restore_env_frames` helpers so
    /// [`Self::env_generation`] is bumped and the capture cache stays
    /// coherent.
    env: Vec<Arc<EvalFrame>>,
    /// Generation counter bumped on every [`Self::env`] mutation.
    ///
    /// Keys [`Self::env_capture_cache`]: a cached [`EvalEnv`] snapshot is
    /// valid exactly while the generation it was captured under is current.
    env_generation: u64,
    /// The last [`EvalEnv`] captured from [`Self::env`], keyed by the
    /// generation it was captured under.
    ///
    /// Thunk allocation captures the same environment many times between
    /// frame-stack mutations; replaying the cached snapshot turns those
    /// captures into O(1) `Arc` clones.
    env_capture_cache: Option<(u64, EvalEnv)>,
    with_scopes: Vec<EvalWithScope>,
    scoped_globals: Vec<Value>,
    options: TreeWalkOptions,
    stats: EvalStats,
    /// Process-wide environment capture counters observed at construction;
    /// `stats_snapshot` reports the movement since this baseline (doc 30 FV-0).
    campaign_env_baseline: super::env::capture_stats::EnvCaptureStats,
    attr_telemetry: AttrTelemetry,
    shape_table: Option<ShapeTable>,
    flat_select_caches: SelectCacheMap<(u32, u32, usize), FlatSelectCache>,
    shaped_select_caches: SelectCacheMap<(u32, u32, usize), ShapedSelectCache>,
    record_select_caches: SelectCacheMap<(u32, u32, usize), RecordSelectCache>,
    hamt_select_caches: SelectCacheMap<(u32, u32, usize), HamtSelectCache>,
    /// Per-site resolved shapes for static attrset literals
    /// ([`AttrShapeMode::Record`] only): a static site's key sequence is
    /// fixed, so its transition-tree walk resolves once and later
    /// allocations at the site reuse the interned handle.
    static_literal_shapes: SelectCacheMap<(u32, u32), ShapeHandle>,
    attr_update_node_states: BTreeMap<AttrUpdateTelemetryNodeKey, AttrUpdateTelemetryState>,
    /// Whether `//` merges record per-merge attrset telemetry.
    ///
    /// The telemetry pipeline (shape census, representation-policy dispatch,
    /// and override-chain node states) re-walks every merge result and is
    /// consumed only by in-process measurement snapshots, so production
    /// evaluation disables it and takes the linear
    /// [`FlatAttrs::update_right_biased`] fast path instead. Enabled by
    /// default under `cfg(test)` and via the `AOS_NIX_ATTR_TELEMETRY`
    /// environment variable; both paths produce representation-identical
    /// attrset values.
    attr_update_telemetry_enabled: bool,
    trace_output: Vec<EvalTraceOutput>,
    warning_output: Vec<EvalWarningOutput>,
    impure_input_trace: Vec<ImpureInputFingerprint>,
    impure_input_trace_complete: bool,
    force_cache_impure_trace_epoch: u64,
    active_memo_read_nodes: Vec<ActiveMemoReadNode>,
    active_derivation_trace_cursors: Vec<ImpureInputTraceCursor>,
    persist_force_cache_hit_keys: Vec<PersistNodeMetadataKey>,
    stderr: EvalStderr,
    find_file_cache: BTreeMap<FindFileCacheKey, FindFileCacheEntry>,
    find_file_cache_hits: usize,
    find_file_cache_misses: usize,
    known_derivations: BTreeMap<nix_compat::store_path::StorePath<String>, KnownDerivation>,
    /// Cross-worker shared state for one parallel evaluation (L2-P3b).
    ///
    /// `Some` exactly while this evaluator participates in a parallel demand
    /// pool: the main worker between pool spawn and finish, and helper
    /// workers for their whole lifetime. Serial evaluation never sets it.
    shared: Option<Arc<parallel_demand::SharedEvalContext>>,
    /// Consumed prefix of the shared known-derivation log.
    shared_known_derivations_cursor: usize,
    /// Consumed prefix of the shared text-store log.
    shared_text_store_cursor: usize,
    /// Consumed prefix of the shared import-result log.
    shared_import_log_cursor: usize,
    /// Last observed [`parallel_demand::SharedEvalContext`] version.
    shared_version_seen: u64,
    import_cache: BTreeMap<PathBuf, ImportCacheEntry>,
    /// Path prefixes confirmed to contain no symlink component during
    /// force-cache traceability checks. The Nix store is immutable for the
    /// duration of an evaluation, so `symlink_metadata` results are stable and
    /// can be memoized; imports under a shared store path would otherwise
    /// re-`lstat` every ancestor component on each resolution.
    import_traceable_nonsymlink_prefixes: HashSet<PathBuf>,
    /// Memoizes `import` path resolution keyed by the coerced request bytes.
    ///
    /// Resolving an `import` argument to its `(target, realpath)` pair requires
    /// an `fs::metadata` probe (directory promotion to `default.nix`) and an
    /// `fs::canonicalize` (realpath). The canonicalized realpath is the
    /// [`import_cache`](Self::import_cache) key, so both syscalls run *before*
    /// the value cache is consulted and would otherwise repeat on every import
    /// of an already-evaluated file. The filesystem is immutable for the
    /// duration of an evaluation, so the resolution is stable and cacheable.
    import_paths_cache: HashMap<Vec<u8>, (PathBuf, PathBuf)>,
    parse_cache: Option<ParseCache>,
    persist_cache: Option<PersistCache>,
    /// Opened secondary L2 disk locations in probe order (MEMO-2 §5.4).
    ///
    /// Populated alongside [`Self::persist_cache`] from
    /// `TreeWalkOptions::memo_disk_locations`; empty when none are configured
    /// or none opened. Import-time parse-artifact probes fall through to
    /// these after a primary miss and promote hits into the primary.
    persist_secondary_caches: Vec<(PersistLatencyClass, PersistCache)>,
    persist_cache_open_attempted: bool,
    eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    // Cached "is any forced-expression cache observable" predicate, computed once
    // at construction. True when the in-memory eval cache runtime is enabled or a
    // persistent cache root is configured. When false, the per-force force-cache
    // subject/payload content hashing is pure waste (every observation is a
    // no-op), so the hot path skips it entirely. See `force_memoized_claimed_thunk`.
    force_cache_active: bool,
    import_parse_cache_hits: usize,
    import_parse_cache_misses: usize,
    text_store: BTreeMap<Vec<u8>, TextStoreEntry>,
    // In-process replacement for `nix-store --check-validity` subprocess spawns
    // during forced fetches: a lazily-opened read-only SQLite reader of the store
    // path database plus a per-run memo. Falls back to the subprocess when the
    // database cannot be read. See `store_validity`.
    store_validity_checker: StoreValidityChecker,
    ifd_realizer: Option<IfdRealizer>,
    call_depth: usize,
    order_sensitive_binding_depth: usize,
    active_composite_accumulator_depth: usize,
    active_root_eval_node: Option<IrId>,
    active_gc_stress_accumulator_allocation_node: Option<IrId>,
    active_gc_stress_primop_arg_root_admission_depth: usize,
    active_force_roots: Vec<Value>,
    active_primop_arg_roots: Vec<EvalPrimOpArg>,
    active_primop_arg_frames: Vec<ActivePrimopArgFrame>,
    transient_value_stack_roots: Vec<Value>,
    suspended_env_roots: Vec<SuspendedTreeWalkEnv>,
    thunk_resolve_remembered_set: RememberedSet,
    thunk_resolve_card_table: GcCardTable,
    // Effective Tier-B live-reclamation mode for this evaluation. Copied from
    // options at construction with the parallel quiescence pin applied, so the
    // force hot path reads one field instead of re-deriving the pin.
    gc_mode: EvalGcMode,
    // Worker-record count observed by the last quiescent sweep, for the
    // growth-threshold cadence.
    gc_records_at_last_sweep: u64,
    // Quiescent-sweep requests declined because the evaluator held transient
    // roots or an in-flight force (diagnostic counter).
    gc_sweeps_skipped_nonquiescent: u64,
    // The most recent quiescent sweep's cycle report, for stats surfaces.
    gc_last_sweep_report: Option<EvalHeapSweepReport>,
    // Lazy identity primops expose their returned argument thunk to strict consumers.
    // Keyed by thunk payload bits and used only for membership tests, so an
    // unordered `HashSet` gives O(1) probes on the per-force hot path.
    lazy_identity_thunks: HashSet<u64>,
    // Empty-list foldl' returns keep the initial accumulator lazy, but attr consumers
    // must still demand it when coercing to an attrset. A subset of
    // `lazy_identity_thunks`, likewise membership-only.
    lazy_foldl_initial_thunks: HashSet<u64>,
    // Type-erased tier-1 native-entry publish side-table, keyed by thunk payload
    // bits. Additive and off the force hot path: force never reads it. See
    // `tier1_publish` and `publish_tier1_slot`.
    tier1_publish_slots: HashMap<u64, OpaqueTier1Slot>,
    // Tier-1 native entries shared across every thunk instance of a def-site,
    // keyed by `(module_index << 32) | ir_root`. Tier-1 code is compiled per IR
    // body, so a hot def-site's published entry dispatches for all its instances.
    // Populated only when a `tier1_engine` promotes a body. See `Tier1Engine`.
    tier1_def_site_slots: HashMap<u64, OpaqueTier1Slot>,
    // Def-sites the tier-1 engine has permanently decided not to dispatch
    // (blacklisted or gated as delegate-only). Keyed by the def-site body's
    // `EvalNodeRef` so the force path can consult it with only a cheap
    // `EvalThunk::body_ref` field read, skipping the engine hook (and its heap
    // and side-table lookups) for a decided cold def-site's later instances.
    tier1_skipped_def_sites: HashSet<EvalNodeRef>,
    // Tier-2 compiled lambda entries shared across every closure instance of a
    // lambda def-site, keyed by `(module_index << 32) | body_ir_id`. Populated
    // only when a `tier1_engine` promotes a lambda body through the tier-2
    // apply seam. See `tier2_apply`.
    tier2_def_site_slots: HashMap<u64, OpaqueTier1Slot>,
    // Lambda def-sites the engine has permanently decided not to dispatch
    // through the tier-2 apply seam (blacklisted or gated), as a per-module
    // bit vector indexed by the lambda body's IR id. The apply path is far
    // hotter than the force path, so the decided check must not hash: two
    // indexed loads and a bit test keep the per-apply hook tax negligible on
    // apply-dominated workloads that promote nothing.
    tier2_skipped_def_sites: Vec<Box<[u64]>>,
    // The number of distinct decided (skipped) tier-2 def-sites, for
    // diagnostics; the bit vector itself has no cheap population count.
    tier2_skipped_def_site_total: usize,
    // Optional pluggable tier-1 JIT engine consulted once per claimed serial
    // force. `None` (the default) leaves the force path byte-for-byte unchanged.
    // Held by `Rc` so the force path can clone it out and release the field
    // borrow before handing the engine `&mut self`. See `Tier1Engine`.
    tier1_engine: Option<Rc<dyn Tier1Engine>>,
    // Shared cross-worker wait registry for parallel thunk forcing. Present
    // exactly when parallel thunk payloads are enabled; every parallel cell
    // allocated by this evaluator is bound to it so waiters can detect
    // cross-worker deadlock cycles before parking. Workers sharing one demand
    // graph must share one registry (see `set_parallel_force_registry`).
    parallel_force_registry: Option<Arc<ParallelForceCycleRegistry>>,
    // Per-worker in-thread content memo (MEMO-1 L0). `Some` exactly when
    // `MemoOptions` enables the L0 tier; `None` keeps the force path free of
    // any memo bookkeeping. See `memo` and `eval_core::memo`.
    memo_l0: Option<memo::MemoL0Table>,
    // Per-def-site static admission decisions for the content memo, computed
    // once per `(module, node)` body and reused by every later force of any
    // thunk instance of that def-site. This is the runtime realization of the
    // design's "admission flags on lowered nodes": non-admitted def-sites pay
    // one hash-map probe per force and nothing else.
    memo_def_sites: HashMap<EvalNodeRef, memo::MemoDefSiteState>,
    // Per-eval memo of captured values known to have no durable hash (keyed
    // by value payload bits). Purely advisory: a stale entry can only cause
    // a spurious memo decline. See `eval_core::memo`.
    memo_unhashable_values: HashSet<u64>,
    #[cfg(test)]
    tree_walk_list_wrapper_calls: usize,
    #[cfg(test)]
    gc_stress_permanent_root_allocation_dispatches: Vec<RuntimeAllocationEntryPoint>,
}

/// Reports cold hash-consed values ensured in the indexed persistent value pack.
///
/// This is an explicit out-of-core spill precursor report. It describes cold
/// permanent values that were captured as replayable force-cache payloads and
/// made addressable in the persistent cache's indexed `values/` pack. It does
/// not imply that evaluator heap records were evicted or replaced with
/// content-hash handles.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColdHashConsedValueMaterializationReport {
    candidates: usize,
    candidate_bytes: usize,
    captured: usize,
    uncapturable: usize,
    materialized: usize,
    skipped: usize,
    errors: usize,
    cache_unavailable: usize,
    persistent_payload_bytes: u128,
    materialized_hashes: Vec<ValueHash>,
}

impl ColdHashConsedValueMaterializationReport {
    fn record_candidates(&mut self, values: &[EvalHeapColdHashConsedValue]) {
        self.candidates = values.len();
        self.candidate_bytes = values.iter().fold(0usize, |bytes, value| {
            bytes.saturating_add(value.size_bytes())
        });
    }

    fn record_captured(&mut self, payload: &CachedExpressionValue) {
        self.captured = self.captured.saturating_add(1);
        self.persistent_payload_bytes = self
            .persistent_payload_bytes
            .saturating_add(payload.persistent_payload_len());
    }

    fn record_materialized(&mut self, value_hash: ValueHash) {
        self.materialized = self.materialized.saturating_add(1);
        self.materialized_hashes.push(value_hash);
    }

    /// Returns the number of cold hash-consed records selected before capture.
    pub const fn candidates(&self) -> usize {
        self.candidates
    }

    /// Returns the logical allocation bytes covered by selected candidates.
    pub const fn candidate_bytes(&self) -> usize {
        self.candidate_bytes
    }

    /// Returns the number of candidates captured as replayable value payloads.
    pub const fn captured(&self) -> usize {
        self.captured
    }

    /// Returns the number of candidates that could not be captured.
    pub const fn uncapturable(&self) -> usize {
        self.uncapturable
    }

    /// Returns the number of captured payloads ensured in the indexed value pack.
    pub const fn materialized(&self) -> usize {
        self.materialized
    }

    /// Returns the number of captured payloads skipped by the materializer.
    pub const fn skipped(&self) -> usize {
        self.skipped
    }

    /// Returns the number of snapshot, hashing, or write errors observed.
    pub const fn errors(&self) -> usize {
        self.errors
    }

    /// Returns the number of candidates skipped because no persistent cache opened.
    pub const fn cache_unavailable(&self) -> usize {
        self.cache_unavailable
    }

    /// Returns the replayable payload bytes represented by captured candidates.
    pub const fn persistent_payload_bytes(&self) -> u128 {
        self.persistent_payload_bytes
    }

    /// Returns the value hashes ensured in the indexed value pack.
    pub fn materialized_hashes(&self) -> &[ValueHash] {
        &self.materialized_hashes
    }
}

/// The *derivation hash modulo* (`hashDerivationModulo`) of a derivation.
///
/// Nix derivation/store identity rests on three distinct SHA-256 values that are
/// easy to conflate when all are bare `[u8; 32]`: the derivation-hash-modulo (the
/// recursive ATerm-with-input-substitution hash that seeds input-addressed output
/// paths), the raw `.drv` ATerm hash, and an output/content-address digest. This
/// newtype carries only a [`NixSha256Digest`] and exposes named accessors at the
/// serialization/output-path boundary so internal BLAKE3 cache hashes cannot be
/// passed as derivation modulo hashes without an explicit domain conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DerivationHashModulo(NixSha256Digest);

impl DerivationHashModulo {
    fn from_nix_sha256_digest(digest: NixSha256Digest) -> Self {
        Self(digest)
    }

    #[cfg(test)]
    fn from_sha256_bytes(bytes: [u8; 32]) -> Self {
        Self::from_nix_sha256_digest(NixSha256Digest::from_bytes(bytes))
    }

    const fn nix_sha256_digest(self) -> NixSha256Digest {
        self.0
    }
}

#[derive(Clone, Debug)]
struct KnownDerivation {
    id: IrId,
    span: Span,
    derivation: nix_compat::derivation::Derivation,
    hash_derivation_modulo: DerivationHashModulo,
    output_names: BTreeSet<String>,
    output_resolution: DerivationOutputResolution,
    aterm_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct KnownDerivationInputHashes {
    hashes: BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
    has_deferred: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DerivationOutputResolution {
    StaticPaths,
    FloatingCa(FloatingCaOutput),
    Impure(FloatingCaOutput),
    DeferredPlaceholders,
}

impl DerivationOutputResolution {
    fn has_deferred_outputs(self) -> bool {
        !matches!(self, Self::StaticPaths)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FloatingCaOutput {
    method: FloatingCaMethod,
    hash_algo: nix_compat::nixhash::HashAlgo,
}

impl FloatingCaOutput {
    fn aterm_hash_algo(self) -> String {
        let mut algo = String::new();
        if matches!(self.method, FloatingCaMethod::Recursive) {
            algo.push_str("r:");
        }
        algo.push_str(&self.hash_algo.to_string());
        algo
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FloatingCaMethod {
    Flat,
    Recursive,
}

#[derive(Debug)]
struct StructuredAttrsJson {
    bytes: Vec<u8>,
    has_fields: bool,
}

impl StructuredAttrsJson {
    fn new() -> Self {
        Self {
            bytes: b"{".to_vec(),
            has_fields: false,
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.bytes.push(b'}');
        self.bytes
    }
}

// The `impl TreeWalk` body is split across concern-focused submodules below.
// Each submodule re-opens `impl TreeWalk` and shares this module's private
// items via `use super::*;`.
mod alloc_intern;
mod coerce_paths;
mod tier1_dispatch;
mod derivation_build;
mod derivation_serialize;
mod eval_apply;
mod eval_codec;
mod eval_compare;
mod eval_core;
mod eval_derivation;
mod eval_hash;
mod eval_import;
mod eval_impure_inputs;
mod import_persist_locations;
mod eval_list_filter;
mod eval_list_group;
mod eval_list_map;
mod eval_load;
mod eval_numeric;
mod eval_path_ops;
mod eval_primop_apply;
mod memo;
mod parallel_demand;
mod parallel_import;
mod parallel_shape;
mod eval_primop_bind;
mod eval_raw;
mod eval_regex;
mod eval_regex_ere;
mod eval_session;
mod json_float;
mod eval_sort;
mod eval_source;
mod eval_stats;
mod eval_trace;
mod fetch_git_clone;
mod fetch_git_store;
mod fetch_git_tree;
mod fetch_tree_access;
mod fetch_tree_args;
mod fetch_tree_forge;
mod flake_git;
mod flake_ref;
mod gc_sweep;
mod region;
mod safepoint_roots;
mod select_cache_hash;
use select_cache_hash::SelectCacheMap;
mod serialize_xml;
mod store_validity;
use store_validity::StoreValidityChecker;
mod fold_genlist;
mod tier1_publish;
pub use tier1_publish::{
    OpaqueTier1Slot, Tier1Engine, Tier1ForceHook, Tier2ApplyHook, Tier2FilterHook, Tier2FoldHook,
};
mod tier2_apply;

pub use eval_impure_inputs::{
    canonicalize_cacheable_input_trace, revalidate_cacheable_input_trace,
};
pub use gc_sweep::TreeWalkGcSweepError;
pub use safepoint_roots::{
    TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
    TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointMinorGcRootWritebackReport,
    TreeWalkSafepointRootError, TreeWalkSafepointRootWritebackError, TreeWalkSafepointScanError,
};

#[cfg(test)]
mod tests;
