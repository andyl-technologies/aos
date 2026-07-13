use super::super::ThunkState;
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::cache::{
    CacheExprSourceHash, CachedExpressionValue, DirEntryInput, EvalCache, EvalCacheRuntime,
    FileTypeForInput, ImpureInputFingerprint, ImpureInputMode, ImpureTraceStatus,
    MaterializationReuse, PersistCache, PersistNodeMetadataKey, UncacheableInput, ValueHash,
};
use crate::compile::{
    EffectClass, FrameId, FrameInfo, IrArena, IrBinding, IrData, IrFacts, IrInlineCacheSiteId,
    IrNode, IrShape, IrWithChain, resolve as resolve_ast,
};
use crate::runtime::builtins::{BUILTINS, Builtin, BuiltinDirect, BuiltinEffect, direct_builtin};
use crate::string::{ContextElement, StringContext};
use crate::syntax::{ParseErrorKind, Symbol, SymbolTable, parse_bytes, parse_str};
use crate::value::HeapObject;

const PINNED_BUILTIN_SURFACE_EXPERIMENTAL_FEATURES: &str = "flakes";

const PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES: &[&str] = &[
    "abort",
    "add",
    "addDrvOutputDependencies",
    "addErrorContext",
    "all",
    "any",
    "appendContext",
    "attrNames",
    "attrValues",
    "baseNameOf",
    "bitAnd",
    "bitOr",
    "bitXor",
    "break",
    "builtins",
    "catAttrs",
    "ceil",
    "compareVersions",
    "concatLists",
    "concatMap",
    "concatStringsSep",
    "convertHash",
    "currentSystem",
    "currentTime",
    "deepSeq",
    "derivation",
    "derivationStrict",
    "dirOf",
    "div",
    "elem",
    "elemAt",
    "false",
    "fetchGit",
    "fetchMercurial",
    "fetchTarball",
    "fetchTree",
    "fetchurl",
    "filter",
    "filterSource",
    "findFile",
    "flakeRefToString",
    "floor",
    "foldl'",
    "fromJSON",
    "fromTOML",
    "functionArgs",
    "genList",
    "genericClosure",
    "getAttr",
    "getContext",
    "getEnv",
    "getFlake",
    "groupBy",
    "hasAttr",
    "hasContext",
    "hashFile",
    "hashString",
    "head",
    "import",
    "intersectAttrs",
    "isAttrs",
    "isBool",
    "isFloat",
    "isFunction",
    "isInt",
    "isList",
    "isNull",
    "isPath",
    "isString",
    "langVersion",
    "length",
    "lessThan",
    "listToAttrs",
    "map",
    "mapAttrs",
    "match",
    "mul",
    "nixPath",
    "nixVersion",
    "null",
    "parseDrvName",
    "parseFlakeRef",
    "partition",
    "path",
    "pathExists",
    "placeholder",
    "readDir",
    "readFile",
    "readFileType",
    "removeAttrs",
    "replaceStrings",
    "scopedImport",
    "seq",
    "sort",
    "split",
    "splitVersion",
    "storeDir",
    "storePath",
    "stringLength",
    "sub",
    "substring",
    "tail",
    "throw",
    "toFile",
    "toJSON",
    "toPath",
    "toString",
    "toXML",
    "trace",
    "traceVerbose",
    "true",
    "tryEval",
    "typeOf",
    "unsafeDiscardOutputDependency",
    "unsafeDiscardStringContext",
    "unsafeGetAttrPos",
    "warn",
    "zipAttrsWith",
];

const PRESENT_UNIMPLEMENTED_BUILTIN_STUBS: &[&str] = &["fetchMercurial"];

const VERSION_GATED_BUILTIN_NAMES: &[&str] = &[
    "addDrvOutputDependencies",
    "convertHash",
    "fetchTree",
    "readFileType",
    "warn",
];

const LIB_NOT_BUILTIN_NAMES: &[&str] = &[
    "toLower",
    "toUpper",
    "toTOML",
    "concatStrings",
    "stringToCharacters",
    "splitString",
    "hasPrefix",
    "hasSuffix",
    "optionalString",
    "removePrefix",
    "removeSuffix",
    "escapeShellArg",
    "versionAtLeast",
    "versionOlder",
    "foldr",
    "foldl",
    "reverse",
    "range",
    "remove",
    "zipWith",
    "flatten",
    "unique",
    "last",
    "init",
    "take",
    "drop",
    "count",
    "imap0",
    "forEach",
    "optionals",
    "mapAttrsToList",
    "filterAttrs",
    "recursiveUpdate",
    "attrByPath",
    "optionalAttrs",
    "mapAttrs'",
    "genAttrs",
    "nameValuePair",
    "id",
    "const",
    "flip",
    "composeManyExtensions",
    "pipe",
    "fix",
    "makeExtensible",
    "importJSON",
    "importTOML",
];

mod support;
use support::*;
// Explicitly shadow `crate::compile::lower` (glob-imported via `use super::*`)
// with the test-helper `lower`, matching the original flat-module behavior where
// the helper was a local item that shadowed the glob.
use support::lower;

mod analysis_soundness;
mod attr_shape_modes;
#[cfg(feature = "candidate_c_value")]
mod heap_census;
#[cfg(feature = "candidate_c_value")]
mod heap_snapshot;
mod attrs_1;
mod attrs_2;
mod attrs_3;
mod builtins_list_1;
mod builtins_list_2;
mod builtins_list_3;
mod builtins_list_4;
mod builtins_list_5;
mod call_summary;
mod chunk_e;
mod coercion;
mod context_1;
mod context_2;
mod context_3;
mod control;
mod convert_hash;
mod derivation_1;
mod derivation_2;
mod derivation_2_cache_paths;
mod derivation_2_force_cache;
mod derivation_2_observation;
mod derivation_2_support;
mod derivation_2_validation;
mod derivation_3;
mod derivation_cache;
mod derivation_cache_file_metadata;
mod derivation_cache_hash_file;
mod derivation_cache_read_file_stale;
mod derivation_cache_support;
mod escape_signature;
mod eval_stack;
mod fetch_git;
mod fetch_git_reuse;
mod fetch_tarball;
mod fetch_tree_1;
mod fetch_tree_2;
mod fetch_tree_3;
mod fetchurl;
mod filesystem_1;
mod filesystem_2;
mod flake;
mod gc;
mod hash;
mod hash_file_surface;
mod memo_l0;
mod numeric;
mod options;
mod parallel_demand_pool;
mod parallel_shared_heap;
mod parse;
mod path_store;
mod properties;
mod regex;
mod regex_ere;
mod region;
mod safepoint_roots;
mod search_path;
mod source_path_surfaces;
mod stats;
mod strings_1;
mod strings_2;
mod strings_3;
mod sync_safety;
mod toml;
mod trace;
