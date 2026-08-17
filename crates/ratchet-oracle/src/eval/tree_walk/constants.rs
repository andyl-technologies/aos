//! Attribute-name byte constants and evaluator tuning constants
//! (split from tree_walk.rs under the §2 file-size cap).
use super::*;

pub(crate) const TO_STRING_ATTR: &[u8] = b"__toString";
pub(crate) const OUT_PATH_ATTR: &[u8] = b"outPath";
pub(crate) const DRV_PATH_ATTR: &[u8] = b"drvPath";
pub(crate) const TYPE_ATTR: &[u8] = b"type";
pub(crate) const NAME_ATTR: &[u8] = b"name";
pub(crate) const ID_ATTR: &[u8] = b"id";
pub(crate) const OWNER_ATTR: &[u8] = b"owner";
pub(crate) const REPO_ATTR: &[u8] = b"repo";
pub(crate) const HOST_ATTR: &[u8] = b"host";
pub(crate) const DIR_ATTR: &[u8] = b"dir";
pub(crate) const BUILDER_ATTR: &[u8] = b"builder";
pub(crate) const SYSTEM_ATTR: &[u8] = b"system";
pub(crate) const ARGS_ATTR: &[u8] = b"args";
pub(crate) const OUTPUTS_ATTR: &[u8] = b"outputs";
pub(crate) const OVERRIDES_ATTR: &[u8] = b"__overrides";
pub(crate) const STRUCTURED_ATTRS_ATTR: &[u8] = b"__structuredAttrs";
pub(crate) const IGNORE_NULLS_ATTR: &[u8] = b"__ignoreNulls";
pub(crate) const OUTPUT_HASH_ATTR: &[u8] = b"outputHash";
pub(crate) const OUTPUT_HASH_ALGO_ATTR: &[u8] = b"outputHashAlgo";
pub(crate) const OUTPUT_HASH_MODE_ATTR: &[u8] = b"outputHashMode";
pub(crate) const CONTENT_ADDRESSED_ATTR: &[u8] = b"__contentAddressed";
pub(crate) const IMPURE_ATTR: &[u8] = b"__impure";
pub(crate) const PATH_ATTR: &[u8] = b"path";
pub(crate) const URL_ATTR: &[u8] = b"url";
pub(crate) const FILTER_ATTR: &[u8] = b"filter";
pub(crate) const RECURSIVE_ATTR: &[u8] = b"recursive";
pub(crate) const SHA256_ATTR: &[u8] = b"sha256";
pub(crate) const REV_ATTR: &[u8] = b"rev";
pub(crate) const REF_ATTR: &[u8] = b"ref";
pub(crate) const SUBMODULES_ATTR: &[u8] = b"submodules";
pub(crate) const SHALLOW_ATTR: &[u8] = b"shallow";
pub(crate) const ALL_REFS_ATTR: &[u8] = b"allRefs";
pub(crate) const EXPORT_IGNORE_ATTR: &[u8] = b"exportIgnore";
pub(crate) const UNPACK_ATTR: &[u8] = b"unpack";
pub(crate) const VERIFY_COMMIT_ATTR: &[u8] = b"verifyCommit";
pub(crate) const KEYTYPE_ATTR: &[u8] = b"keytype";
pub(crate) const PUBLIC_KEY_ATTR: &[u8] = b"publicKey";
pub(crate) const PUBLIC_KEYS_ATTR: &[u8] = b"publicKeys";
pub(crate) const SHORT_REV_ATTR: &[u8] = b"shortRev";
pub(crate) const DIRTY_REV_ATTR: &[u8] = b"dirtyRev";
pub(crate) const DIRTY_SHORT_REV_ATTR: &[u8] = b"dirtyShortRev";
pub(crate) const REV_COUNT_ATTR: &[u8] = b"revCount";
pub(crate) const LAST_MODIFIED_ATTR: &[u8] = b"lastModified";
pub(crate) const LAST_MODIFIED_DATE_ATTR: &[u8] = b"lastModifiedDate";
pub(crate) const NAR_HASH_ATTR: &[u8] = b"narHash";
pub(crate) const PREFIX_ATTR: &[u8] = b"prefix";
pub(crate) const VALUE_ATTR: &[u8] = b"value";
pub(crate) const TOML_TIMESTAMP_TYPE_ATTR: &[u8] = b"_type";
pub(crate) const TOML_TIMESTAMP_TYPE_VALUE: &[u8] = b"timestamp";
pub(crate) const KEY_ATTR: &[u8] = b"key";
pub(crate) const FILE_ATTR: &[u8] = b"file";
pub(crate) const LINE_ATTR: &[u8] = b"line";
pub(crate) const COLUMN_ATTR: &[u8] = b"column";
pub(crate) const CUR_POS_ATTR: &[u8] = b"__curPos";
pub(crate) const NIX_PATH_ATTR: &[u8] = b"__nixPath";
pub(crate) const OPERATOR_ATTR: &[u8] = b"operator";
pub(crate) const START_SET_ATTR: &[u8] = b"startSet";
pub(crate) const HASH_ATTR: &[u8] = b"hash";
pub(crate) const HASH_ALGO_ATTR: &[u8] = b"hashAlgo";
pub(crate) const TO_HASH_FORMAT_ATTR: &[u8] = b"toHashFormat";
pub(crate) const DEFAULT_STORE_DIR: &[u8] = b"/nix/store";
pub(crate) const DEFAULT_MAX_CALL_DEPTH: usize = 10_000;
pub(crate) const MAX_FLAKE_REF_RESOLUTION_DEPTH: usize = 16;
pub(crate) const DEFAULT_FORCE_CACHE_MATERIALIZATION_COSTS: MaterializationCosts =
    MaterializationCosts::new(4, 1, 1, 1);
pub(crate) const PLACEHOLDER_HASH_PREFIX: &[u8] = b"nix-output:";
pub(crate) const UPSTREAM_OUTPUT_PLACEHOLDER_HASH_PREFIX: &[u8] = b"nix-upstream-output:";
pub(crate) const DERIVATION_EXTENSION: &str = ".drv";
pub(crate) const DERIVATION_NAME_MAX_LEN: usize = 211;
pub(crate) const TRACE_PREFIX: &[u8] = b"trace: ";
pub(crate) const WARNING_PREFIX: &[u8] = b"evaluation warning:";
pub(crate) const WARNING_CONTINUATION_INDENT: &[u8] = b"                    ";
pub(crate) const EMPTY_FETCHURL_SHA256_WARNING: &[u8] =
    b"found empty hash, assuming 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='";
pub(crate) const ADD_ERROR_CONTEXT_MESSAGE_CONTEXT: &[u8] =
    b"while evaluating the error message passed to builtins.addErrorContext";
pub(crate) const I64_MAX_EXCLUSIVE_AS_F64: f64 = 9_223_372_036_854_775_808.0;
pub(crate) const NIX_BASE32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";
pub(crate) const DERIVATION_INTERNAL_PATH: &[u8] = b"<nix/derivation-internal.nix>";
pub(crate) static FETCH_TARBALL_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
pub(crate) static FETCH_GIT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
pub(crate) const DERIVATION_INTERNAL_SOURCE: &str = r#"
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
