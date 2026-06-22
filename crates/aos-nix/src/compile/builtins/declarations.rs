//! The builtin inventory: the `define_builtins!` invocation declaring every
//! builtin marker type, its execution strategy, documentation, and name policy.

use super::*;

define_builtins! {
    pub(crate) struct AbortBuiltin;
    impl BuiltinDefinition for AbortBuiltin {
        const NAME: &'static [u8] = b"abort";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Abort);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Aborts evaluation with a non-catchable diagnostic message.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct AddBuiltin;
    impl BuiltinDefinition for AddBuiltin {
        const NAME: &'static [u8] = b"add";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Add);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Adds two numeric values using Nix arithmetic semantics.");
    }

    pub(crate) struct AddDrvOutputDependenciesBuiltin;
    impl BuiltinDefinition for AddDrvOutputDependenciesBuiltin {
        const NAME: &'static [u8] = b"addDrvOutputDependencies";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::AddDrvOutputDependencies);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Marks string context outputs as derivation-output dependencies.");
    }

    pub(crate) struct AddErrorContextBuiltin;
    impl BuiltinDefinition for AddErrorContextBuiltin {
        const NAME: &'static [u8] = b"addErrorContext";
        const EXECUTION: BuiltinExecution = BuiltinExecution::AddErrorContext;
        const DOCS: &'static BuiltinDocs = &ADD_ERROR_CONTEXT_DOCS;
    }

    pub(crate) struct AllBuiltin;
    impl BuiltinDefinition for AllBuiltin {
        const NAME: &'static [u8] = b"all";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::All);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a predicate succeeds for every list element.");
    }

    pub(crate) struct AnyBuiltin;
    impl BuiltinDefinition for AnyBuiltin {
        const NAME: &'static [u8] = b"any";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Any);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a predicate succeeds for any list element.");
    }

    pub(crate) struct AppendContextBuiltin;
    impl BuiltinDefinition for AppendContextBuiltin {
        const NAME: &'static [u8] = b"appendContext";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_binary(StrictBinaryPrimOp::AppendContext);
        const DOCS: &'static BuiltinDocs = &APPEND_CONTEXT_DOCS;
    }

    pub(crate) struct AttrNamesBuiltin;
    impl BuiltinDefinition for AttrNamesBuiltin {
        const NAME: &'static [u8] = b"attrNames";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::AttrNames);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns an attribute set's names in sorted order.");
    }

    pub(crate) struct AttrValuesBuiltin;
    impl BuiltinDefinition for AttrValuesBuiltin {
        const NAME: &'static [u8] = b"attrValues";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::AttrValues);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns an attribute set's values in sorted-name order.");
    }

    pub(crate) struct BaseNameOfBuiltin;
    impl BuiltinDefinition for BaseNameOfBuiltin {
        const NAME: &'static [u8] = b"baseNameOf";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::BaseNameOf);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the final path component of a path-like value.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct BitAndBuiltin;
    impl BuiltinDefinition for BitAndBuiltin {
        const NAME: &'static [u8] = b"bitAnd";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::BitAnd);
        const DOCS: &'static BuiltinDocs = builtin_docs!("Computes bitwise AND for two integers.");
    }

    pub(crate) struct BitOrBuiltin;
    impl BuiltinDefinition for BitOrBuiltin {
        const NAME: &'static [u8] = b"bitOr";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::BitOr);
        const DOCS: &'static BuiltinDocs = builtin_docs!("Computes bitwise OR for two integers.");
    }

    pub(crate) struct BitXorBuiltin;
    impl BuiltinDefinition for BitXorBuiltin {
        const NAME: &'static [u8] = b"bitXor";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::BitXor);
        const DOCS: &'static BuiltinDocs = builtin_docs!("Computes bitwise XOR for two integers.");
    }

    pub(crate) struct BreakBuiltin;
    impl BuiltinDefinition for BreakBuiltin {
        const NAME: &'static [u8] = b"break";
        const EXECUTION: BuiltinExecution = BuiltinExecution::LazyUnary;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns its argument lazily for debugger breakpoints.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct BuiltinsBuiltin;
    impl BuiltinDefinition for BuiltinsBuiltin {
        const NAME: &'static [u8] = b"builtins";
        const EXECUTION: BuiltinExecution = BuiltinExecution::BuiltinsValue;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the recursive attribute set of builtin values.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct CatAttrsBuiltin;
    impl BuiltinDefinition for CatAttrsBuiltin {
        const NAME: &'static [u8] = b"catAttrs";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectBinary(DirectBinaryPrimOp::CatAttrs);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Collects one named attribute from each set in a list.");
    }

    pub(crate) struct CeilBuiltin;
    impl BuiltinDefinition for CeilBuiltin {
        const NAME: &'static [u8] = b"ceil";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Ceil);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Rounds a floating-point value upward to an integer.");
    }

    pub(crate) struct CompareVersionsBuiltin;
    impl BuiltinDefinition for CompareVersionsBuiltin {
        const NAME: &'static [u8] = b"compareVersions";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_binary(StrictBinaryPrimOp::CompareVersions);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Compares two version strings using Nix version ordering.");
    }

    pub(crate) struct ConcatListsBuiltin;
    impl BuiltinDefinition for ConcatListsBuiltin {
        const NAME: &'static [u8] = b"concatLists";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::ConcatLists);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Concatenates a list of lists into one list.");
    }

    pub(crate) struct ConcatMapBuiltin;
    impl BuiltinDefinition for ConcatMapBuiltin {
        const NAME: &'static [u8] = b"concatMap";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_binary(StrictBinaryPrimOp::ConcatMap);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Maps a function over a list and concatenates the resulting lists.");
    }

    pub(crate) struct ConcatStringsSepBuiltin;
    impl BuiltinDefinition for ConcatStringsSepBuiltin {
        const NAME: &'static [u8] = b"concatStringsSep";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectBinary(DirectBinaryPrimOp::ConcatStringsSep);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Concatenates strings with a separator between elements.");
    }

    pub(crate) struct ConvertHashBuiltin;
    impl BuiltinDefinition for ConvertHashBuiltin {
        const NAME: &'static [u8] = b"convertHash";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::ConvertHash);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Converts a hash attribute set between supported encodings.");
    }

    pub(crate) struct CurrentSystemBuiltin;
    impl BuiltinDefinition for CurrentSystemBuiltin {
        const NAME: &'static [u8] = b"currentSystem";
        const EXECUTION: BuiltinExecution = BuiltinExecution::CurrentSystemValue;
        const DOCS: &'static BuiltinDocs = &CURRENT_SYSTEM_DOCS;
    }

    pub(crate) struct CurrentTimeBuiltin;
    impl BuiltinDefinition for CurrentTimeBuiltin {
        const NAME: &'static [u8] = b"currentTime";
        const EXECUTION: BuiltinExecution = BuiltinExecution::CurrentTimeValue;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the configured current time when available.");
    }

    pub(crate) struct DeepSeqBuiltin;
    impl BuiltinDefinition for DeepSeqBuiltin {
        const NAME: &'static [u8] = b"deepSeq";
        const EXECUTION: BuiltinExecution = BuiltinExecution::DeepSeq;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Deeply forces the first argument before returning the second.");
    }

    pub(crate) struct DerivationBuiltin;
    impl BuiltinDefinition for DerivationBuiltin {
        const NAME: &'static [u8] = b"derivation";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Derivation;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Builds Nix's derivation wrapper around derivationStrict.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct DerivationStrictBuiltin;
    impl BuiltinDefinition for DerivationStrictBuiltin {
        const NAME: &'static [u8] = b"derivationStrict";
        const EXECUTION: BuiltinExecution = BuiltinExecution::DerivationStrict;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Converts derivation attributes to a store derivation value.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct DirOfBuiltin;
    impl BuiltinDefinition for DirOfBuiltin {
        const NAME: &'static [u8] = b"dirOf";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::DirOf);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the parent directory of a path-like value.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct DivBuiltin;
    impl BuiltinDefinition for DivBuiltin {
        const NAME: &'static [u8] = b"div";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Div);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Divides two numbers using Nix numeric semantics.");
    }

    pub(crate) struct ElemBuiltin;
    impl BuiltinDefinition for ElemBuiltin {
        const NAME: &'static [u8] = b"elem";
        const EXECUTION: BuiltinExecution = BuiltinExecution::DirectBinary(DirectBinaryPrimOp::Elem);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value occurs in a list.");
    }

    pub(crate) struct ElemAtBuiltin;
    impl BuiltinDefinition for ElemAtBuiltin {
        const NAME: &'static [u8] = b"elemAt";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::ElemAt);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the list element at a zero-based index.");
    }

    pub(crate) struct FalseBuiltin;
    impl BuiltinDefinition for FalseBuiltin {
        const NAME: &'static [u8] = b"false";
        const EXECUTION: BuiltinExecution = BuiltinExecution::FalseValue;
        const DOCS: &'static BuiltinDocs = builtin_docs!("Returns the boolean false value.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct FetchGitBuiltin;
    impl BuiltinDefinition for FetchGitBuiltin {
        const NAME: &'static [u8] = b"fetchGit";
        const EXECUTION: BuiltinExecution = BuiltinExecution::FetchGit;
        const DOCS: &'static BuiltinDocs = &FETCH_GIT_DOCS;
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct FetchMercurialBuiltin;
    impl BuiltinDefinition for FetchMercurialBuiltin {
        const NAME: &'static [u8] = b"fetchMercurial";
        const EXECUTION: BuiltinExecution = BuiltinExecution::FetchMercurial;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Fetches a Mercurial repository as a fixed-output store path.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct FetchTarballBuiltin;
    impl BuiltinDefinition for FetchTarballBuiltin {
        const NAME: &'static [u8] = b"fetchTarball";
        const EXECUTION: BuiltinExecution = BuiltinExecution::FetchTarball;
        const DOCS: &'static BuiltinDocs = &FETCH_TARBALL_DOCS;
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct FetchTreeBuiltin;
    impl BuiltinDefinition for FetchTreeBuiltin {
        const NAME: &'static [u8] = b"fetchTree";
        const EXECUTION: BuiltinExecution = BuiltinExecution::FetchTree;
        const DOCS: &'static BuiltinDocs = &FETCH_TREE_DOCS;
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct FetchurlBuiltin;
    impl BuiltinDefinition for FetchurlBuiltin {
        const NAME: &'static [u8] = b"fetchurl";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Fetchurl;
        const DOCS: &'static BuiltinDocs = &FETCHURL_DOCS;
    }

    pub(crate) struct FilterBuiltin;
    impl BuiltinDefinition for FilterBuiltin {
        const NAME: &'static [u8] = b"filter";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Filter);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the list elements for which a predicate succeeds.");
    }

    pub(crate) struct FilterSourceBuiltin;
    impl BuiltinDefinition for FilterSourceBuiltin {
        const NAME: &'static [u8] = b"filterSource";
        const EXECUTION: BuiltinExecution = BuiltinExecution::FilterSource;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Copies a source tree while retaining paths accepted by a filter.");
    }

    pub(crate) struct FindFileBuiltin;
    impl BuiltinDefinition for FindFileBuiltin {
        const NAME: &'static [u8] = b"findFile";
        const EXECUTION: BuiltinExecution = BuiltinExecution::FindFile;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Resolves a lookup path entry using a Nix search path.");
    }

    pub(crate) struct FlakeRefToStringBuiltin;
    impl BuiltinDefinition for FlakeRefToStringBuiltin {
        const NAME: &'static [u8] = b"flakeRefToString";
        const EXECUTION: BuiltinExecution = BuiltinExecution::FlakeRefToString;
        const DOCS: &'static BuiltinDocs = &FLAKE_REF_TO_STRING_DOCS;
    }

    pub(crate) struct FloorBuiltin;
    impl BuiltinDefinition for FloorBuiltin {
        const NAME: &'static [u8] = b"floor";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Floor);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Rounds a floating-point value downward to an integer.");
    }

    pub(crate) struct FoldlStrictBuiltin;
    impl BuiltinDefinition for FoldlStrictBuiltin {
        const NAME: &'static [u8] = b"foldl'";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectTernary(StrictTernaryPrimOp::FoldlStrict);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Strictly folds a binary function over a list from the left.");
    }

    pub(crate) struct FromJsonBuiltin;
    impl BuiltinDefinition for FromJsonBuiltin {
        const NAME: &'static [u8] = b"fromJSON";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::FromJson);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Parses a JSON string into the corresponding Nix value.");
    }

    pub(crate) struct FromTomlBuiltin;
    impl BuiltinDefinition for FromTomlBuiltin {
        const NAME: &'static [u8] = b"fromTOML";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::FromToml);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Parses a TOML string into the corresponding Nix value.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct FunctionArgsBuiltin;
    impl BuiltinDefinition for FunctionArgsBuiltin {
        const NAME: &'static [u8] = b"functionArgs";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::FunctionArgs);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the formal argument set for an attribute-pattern function.");
    }

    pub(crate) struct GenListBuiltin;
    impl BuiltinDefinition for GenListBuiltin {
        const NAME: &'static [u8] = b"genList";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_binary(StrictBinaryPrimOp::GenList);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Generates a list by calling a function for each index.");
    }

    pub(crate) struct GenericClosureBuiltin;
    impl BuiltinDefinition for GenericClosureBuiltin {
        const NAME: &'static [u8] = b"genericClosure";
        const EXECUTION: BuiltinExecution = BuiltinExecution::GenericClosure;
        const DOCS: &'static BuiltinDocs = &GENERIC_CLOSURE_DOCS;
    }

    pub(crate) struct GetAttrBuiltin;
    impl BuiltinDefinition for GetAttrBuiltin {
        const NAME: &'static [u8] = b"getAttr";
        const EXECUTION: BuiltinExecution = BuiltinExecution::DirectBinary(DirectBinaryPrimOp::GetAttr);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns a named attribute from an attribute set.");
    }

    pub(crate) struct GetContextBuiltin;
    impl BuiltinDefinition for GetContextBuiltin {
        const NAME: &'static [u8] = b"getContext";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::GetContext);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the string context attached to a string.");
    }

    pub(crate) struct GetEnvBuiltin;
    impl BuiltinDefinition for GetEnvBuiltin {
        const NAME: &'static [u8] = b"getEnv";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::effectful_strict_unary(StrictUnaryPrimOp::GetEnv);
        const DOCS: &'static BuiltinDocs = &GET_ENV_DOCS;
    }

    pub(crate) struct GetFlakeBuiltin;
    impl BuiltinDefinition for GetFlakeBuiltin {
        const NAME: &'static [u8] = b"getFlake";
        const EXECUTION: BuiltinExecution = BuiltinExecution::GetFlake;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Fetches and evaluates a flake reference when flakes are enabled.");
    }

    pub(crate) struct GroupByBuiltin;
    impl BuiltinDefinition for GroupByBuiltin {
        const NAME: &'static [u8] = b"groupBy";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_binary(StrictBinaryPrimOp::GroupBy);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Groups list elements by keys returned from a function.");
    }

    pub(crate) struct HasAttrBuiltin;
    impl BuiltinDefinition for HasAttrBuiltin {
        const NAME: &'static [u8] = b"hasAttr";
        const EXECUTION: BuiltinExecution = BuiltinExecution::DirectBinary(DirectBinaryPrimOp::HasAttr);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether an attribute set contains a named attribute.");
    }

    pub(crate) struct HasContextBuiltin;
    impl BuiltinDefinition for HasContextBuiltin {
        const NAME: &'static [u8] = b"hasContext";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::HasContext);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a string carries any string context.");
    }

    pub(crate) struct HashFileBuiltin;
    impl BuiltinDefinition for HashFileBuiltin {
        const NAME: &'static [u8] = b"hashFile";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::effectful_strict_binary(StrictBinaryPrimOp::HashFile);
        const DOCS: &'static BuiltinDocs = &HASH_FILE_DOCS;
    }

    pub(crate) struct HashStringBuiltin;
    impl BuiltinDefinition for HashStringBuiltin {
        const NAME: &'static [u8] = b"hashString";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_binary(StrictBinaryPrimOp::HashString);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the hex digest of a string with a selected hash algorithm.");
    }

    pub(crate) struct HeadBuiltin;
    impl BuiltinDefinition for HeadBuiltin {
        const NAME: &'static [u8] = b"head";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Head);
        const DOCS: &'static BuiltinDocs = builtin_docs!("Returns the first element of a list.");
    }

    pub(crate) struct ImportBuiltin;
    impl BuiltinDefinition for ImportBuiltin {
        const NAME: &'static [u8] = b"import";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Import;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Parses and evaluates another Nix file.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct IntersectAttrsBuiltin;
    impl BuiltinDefinition for IntersectAttrsBuiltin {
        const NAME: &'static [u8] = b"intersectAttrs";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectBinary(DirectBinaryPrimOp::IntersectAttrs);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns attributes from the second set whose names occur in the first.");
    }

    pub(crate) struct IsAttrsBuiltin;
    impl BuiltinDefinition for IsAttrsBuiltin {
        const NAME: &'static [u8] = b"isAttrs";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsAttrs);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is an attribute set.");
    }

    pub(crate) struct IsBoolBuiltin;
    impl BuiltinDefinition for IsBoolBuiltin {
        const NAME: &'static [u8] = b"isBool";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsBool);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is a boolean.");
    }

    pub(crate) struct IsFloatBuiltin;
    impl BuiltinDefinition for IsFloatBuiltin {
        const NAME: &'static [u8] = b"isFloat";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsFloat);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is a floating-point number.");
    }

    pub(crate) struct IsFunctionBuiltin;
    impl BuiltinDefinition for IsFunctionBuiltin {
        const NAME: &'static [u8] = b"isFunction";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsFunction);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is callable as a function.");
    }

    pub(crate) struct IsIntBuiltin;
    impl BuiltinDefinition for IsIntBuiltin {
        const NAME: &'static [u8] = b"isInt";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsInt);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is an integer.");
    }

    pub(crate) struct IsListBuiltin;
    impl BuiltinDefinition for IsListBuiltin {
        const NAME: &'static [u8] = b"isList";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsList);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is a list.");
    }

    pub(crate) struct IsNullBuiltin;
    impl BuiltinDefinition for IsNullBuiltin {
        const NAME: &'static [u8] = b"isNull";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsNull);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is null.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct IsPathBuiltin;
    impl BuiltinDefinition for IsPathBuiltin {
        const NAME: &'static [u8] = b"isPath";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsPath);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is a path.");
    }

    pub(crate) struct IsStringBuiltin;
    impl BuiltinDefinition for IsStringBuiltin {
        const NAME: &'static [u8] = b"isString";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsString);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns whether a value is a string.");
    }

    pub(crate) struct LangVersionBuiltin;
    impl BuiltinDefinition for LangVersionBuiltin {
        const NAME: &'static [u8] = b"langVersion";
        const EXECUTION: BuiltinExecution = BuiltinExecution::LangVersionValue;
        const DOCS: &'static BuiltinDocs = &LANG_VERSION_DOCS;
    }

    pub(crate) struct LengthBuiltin;
    impl BuiltinDefinition for LengthBuiltin {
        const NAME: &'static [u8] = b"length";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Length);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the length of a list.");
    }

    pub(crate) struct LessThanBuiltin;
    impl BuiltinDefinition for LessThanBuiltin {
        const NAME: &'static [u8] = b"lessThan";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_binary(StrictBinaryPrimOp::LessThan);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Compares two values using Nix ordering.");
    }

    pub(crate) struct ListToAttrsBuiltin;
    impl BuiltinDefinition for ListToAttrsBuiltin {
        const NAME: &'static [u8] = b"listToAttrs";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::ListToAttrs);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Converts a list of name-value attribute sets into an attribute set.");
    }

    pub(crate) struct MapBuiltin;
    impl BuiltinDefinition for MapBuiltin {
        const NAME: &'static [u8] = b"map";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Map);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Applies a function to every list element.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct MapAttrsBuiltin;
    impl BuiltinDefinition for MapAttrsBuiltin {
        const NAME: &'static [u8] = b"mapAttrs";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectBinary(DirectBinaryPrimOp::MapAttrs);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Applies a function to every attribute value.");
    }

    pub(crate) struct MatchBuiltin;
    impl BuiltinDefinition for MatchBuiltin {
        const NAME: &'static [u8] = b"match";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Match);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Matches a string against a regular expression.");
    }

    pub(crate) struct MulBuiltin;
    impl BuiltinDefinition for MulBuiltin {
        const NAME: &'static [u8] = b"mul";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Mul);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Multiplies two numbers.");
    }

    pub(crate) struct NixPathBuiltin;
    impl BuiltinDefinition for NixPathBuiltin {
        const NAME: &'static [u8] = b"nixPath";
        const EXECUTION: BuiltinExecution = BuiltinExecution::NixPathValue;
        const DOCS: &'static BuiltinDocs = &NIX_PATH_DOCS;
    }

    pub(crate) struct NixVersionBuiltin;
    impl BuiltinDefinition for NixVersionBuiltin {
        const NAME: &'static [u8] = b"nixVersion";
        const EXECUTION: BuiltinExecution = BuiltinExecution::NixVersionValue;
        const DOCS: &'static BuiltinDocs = &NIX_VERSION_DOCS;
    }

    pub(crate) struct NullBuiltin;
    impl BuiltinDefinition for NullBuiltin {
        const NAME: &'static [u8] = b"null";
        const EXECUTION: BuiltinExecution = BuiltinExecution::NullValue;
        const DOCS: &'static BuiltinDocs = builtin_docs!("Returns the null value.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct ParseDrvNameBuiltin;
    impl BuiltinDefinition for ParseDrvNameBuiltin {
        const NAME: &'static [u8] = b"parseDrvName";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::ParseDrvName);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Splits a derivation-like name into name and version fields.");
    }

    pub(crate) struct ParseFlakeRefBuiltin;
    impl BuiltinDefinition for ParseFlakeRefBuiltin {
        const NAME: &'static [u8] = b"parseFlakeRef";
        const EXECUTION: BuiltinExecution = BuiltinExecution::ParseFlakeRef;
        const DOCS: &'static BuiltinDocs = &PARSE_FLAKE_REF_DOCS;
    }

    pub(crate) struct PartitionBuiltin;
    impl BuiltinDefinition for PartitionBuiltin {
        const NAME: &'static [u8] = b"partition";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_binary(StrictBinaryPrimOp::Partition);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Splits a list into right and wrong lists by predicate result.");
    }

    pub(crate) struct PathBuiltin;
    impl BuiltinDefinition for PathBuiltin {
        const NAME: &'static [u8] = b"path";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Path;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Copies a named source path into the store.");
    }

    pub(crate) struct PathExistsBuiltin;
    impl BuiltinDefinition for PathExistsBuiltin {
        const NAME: &'static [u8] = b"pathExists";
        const EXECUTION: BuiltinExecution = BuiltinExecution::PathExists;
        const DOCS: &'static BuiltinDocs = &PATH_EXISTS_DOCS;
    }

    pub(crate) struct PlaceholderBuiltin;
    impl BuiltinDefinition for PlaceholderBuiltin {
        const NAME: &'static [u8] = b"placeholder";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::Placeholder);
        const DOCS: &'static BuiltinDocs = &PLACEHOLDER_DOCS;
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct ReadDirBuiltin;
    impl BuiltinDefinition for ReadDirBuiltin {
        const NAME: &'static [u8] = b"readDir";
        const EXECUTION: BuiltinExecution = BuiltinExecution::ReadDir;
        const DOCS: &'static BuiltinDocs = &READ_DIR_DOCS;
    }

    pub(crate) struct ReadFileBuiltin;
    impl BuiltinDefinition for ReadFileBuiltin {
        const NAME: &'static [u8] = b"readFile";
        const EXECUTION: BuiltinExecution = BuiltinExecution::ReadFile;
        const DOCS: &'static BuiltinDocs = &READ_FILE_DOCS;
    }

    pub(crate) struct ReadFileTypeBuiltin;
    impl BuiltinDefinition for ReadFileTypeBuiltin {
        const NAME: &'static [u8] = b"readFileType";
        const EXECUTION: BuiltinExecution = BuiltinExecution::ReadFileType;
        const DOCS: &'static BuiltinDocs = &READ_FILE_TYPE_DOCS;
    }

    pub(crate) struct RemoveAttrsBuiltin;
    impl BuiltinDefinition for RemoveAttrsBuiltin {
        const NAME: &'static [u8] = b"removeAttrs";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectBinary(DirectBinaryPrimOp::RemoveAttrs);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns an attribute set with selected names removed.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct ReplaceStringsBuiltin;
    impl BuiltinDefinition for ReplaceStringsBuiltin {
        const NAME: &'static [u8] = b"replaceStrings";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectTernary(StrictTernaryPrimOp::ReplaceStrings);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Replaces occurrences of source strings with target strings.");
    }

    pub(crate) struct ScopedImportBuiltin;
    impl BuiltinDefinition for ScopedImportBuiltin {
        const NAME: &'static [u8] = b"scopedImport";
        const EXECUTION: BuiltinExecution = BuiltinExecution::ScopedImport;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Imports a Nix file with an additional global scope.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct SeqBuiltin;
    impl BuiltinDefinition for SeqBuiltin {
        const NAME: &'static [u8] = b"seq";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Seq;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Forces the first argument before returning the second.");
    }

    pub(crate) struct SortBuiltin;
    impl BuiltinDefinition for SortBuiltin {
        const NAME: &'static [u8] = b"sort";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Sort;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Sorts a list with a comparator function.");
    }

    pub(crate) struct SplitBuiltin;
    impl BuiltinDefinition for SplitBuiltin {
        const NAME: &'static [u8] = b"split";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Split);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Splits a string with a regular expression.");
    }

    pub(crate) struct SplitVersionBuiltin;
    impl BuiltinDefinition for SplitVersionBuiltin {
        const NAME: &'static [u8] = b"splitVersion";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::SplitVersion);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Splits a version string into comparison components.");
    }

    pub(crate) struct StoreDirBuiltin;
    impl BuiltinDefinition for StoreDirBuiltin {
        const NAME: &'static [u8] = b"storeDir";
        const EXECUTION: BuiltinExecution = BuiltinExecution::StoreDirValue;
        const DOCS: &'static BuiltinDocs = &STORE_DIR_DOCS;
    }

    pub(crate) struct StorePathBuiltin;
    impl BuiltinDefinition for StorePathBuiltin {
        const NAME: &'static [u8] = b"storePath";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::effectful_strict_unary(StrictUnaryPrimOp::StorePath);
        const DOCS: &'static BuiltinDocs = &STORE_PATH_DOCS;
    }

    pub(crate) struct StringLengthBuiltin;
    impl BuiltinDefinition for StringLengthBuiltin {
        const NAME: &'static [u8] = b"stringLength";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::StringLength);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the byte length of a string.");
    }

    pub(crate) struct SubBuiltin;
    impl BuiltinDefinition for SubBuiltin {
        const NAME: &'static [u8] = b"sub";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Sub);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Subtracts the second number from the first.");
    }

    pub(crate) struct SubstringBuiltin;
    impl BuiltinDefinition for SubstringBuiltin {
        const NAME: &'static [u8] = b"substring";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectTernary(StrictTernaryPrimOp::Substring);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns a substring selected by start offset and length.");
    }

    pub(crate) struct TailBuiltin;
    impl BuiltinDefinition for TailBuiltin {
        const NAME: &'static [u8] = b"tail";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Tail);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns a list without its first element.");
    }

    pub(crate) struct ThrowBuiltin;
    impl BuiltinDefinition for ThrowBuiltin {
        const NAME: &'static [u8] = b"throw";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Throw);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Throws a catchable evaluation error.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct ToFileBuiltin;
    impl BuiltinDefinition for ToFileBuiltin {
        const NAME: &'static [u8] = b"toFile";
        const EXECUTION: BuiltinExecution = BuiltinExecution::ToFile;
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Writes a string to a named store file.");
    }

    pub(crate) struct ToJsonBuiltin;
    impl BuiltinDefinition for ToJsonBuiltin {
        const NAME: &'static [u8] = b"toJSON";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::ToJson);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Serializes a Nix value to JSON.");
    }

    pub(crate) struct ToPathBuiltin;
    impl BuiltinDefinition for ToPathBuiltin {
        const NAME: &'static [u8] = b"toPath";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::ToPath);
        const DOCS: &'static BuiltinDocs = &TO_PATH_DOCS;
    }

    pub(crate) struct ToStringBuiltin;
    impl BuiltinDefinition for ToStringBuiltin {
        const NAME: &'static [u8] = b"toString";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::ToString);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Coerces a value to a string using Nix coercion rules.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct ToXmlBuiltin;
    impl BuiltinDefinition for ToXmlBuiltin {
        const NAME: &'static [u8] = b"toXML";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::ToXml);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Serializes a Nix value to XML.");
    }

    pub(crate) struct TraceBuiltin;
    impl BuiltinDefinition for TraceBuiltin {
        const NAME: &'static [u8] = b"trace";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Trace {
            mode: TraceMode::Always,
        };
        const DOCS: &'static BuiltinDocs = &TRACE_DOCS;
    }

    pub(crate) struct TraceVerboseBuiltin;
    impl BuiltinDefinition for TraceVerboseBuiltin {
        const NAME: &'static [u8] = b"traceVerbose";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Trace {
            mode: TraceMode::Verbose,
        };
        const DOCS: &'static BuiltinDocs = &TRACE_VERBOSE_DOCS;
    }

    pub(crate) struct TrueBuiltin;
    impl BuiltinDefinition for TrueBuiltin {
        const NAME: &'static [u8] = b"true";
        const EXECUTION: BuiltinExecution = BuiltinExecution::TrueValue;
        const DOCS: &'static BuiltinDocs = builtin_docs!("Returns the boolean true value.");
        const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    }

    pub(crate) struct TryEvalBuiltin;
    impl BuiltinDefinition for TryEvalBuiltin {
        const NAME: &'static [u8] = b"tryEval";
        const EXECUTION: BuiltinExecution = BuiltinExecution::TryEval;
        const DOCS: &'static BuiltinDocs = &TRY_EVAL_DOCS;
    }

    pub(crate) struct TypeOfBuiltin;
    impl BuiltinDefinition for TypeOfBuiltin {
        const NAME: &'static [u8] = b"typeOf";
        const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::TypeOf);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns the user-visible type name of a value.");
    }

    pub(crate) struct UnsafeDiscardOutputDependencyBuiltin;
    impl BuiltinDefinition for UnsafeDiscardOutputDependencyBuiltin {
        const NAME: &'static [u8] = b"unsafeDiscardOutputDependency";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::UnsafeDiscardOutputDependency);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Downgrades output-dependency string context to plain context.");
    }

    pub(crate) struct UnsafeDiscardStringContextBuiltin;
    impl BuiltinDefinition for UnsafeDiscardStringContextBuiltin {
        const NAME: &'static [u8] = b"unsafeDiscardStringContext";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::UnsafeDiscardStringContext);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns a string with all string context removed.");
    }

    pub(crate) struct UnsafeGetAttrPosBuiltin;
    impl BuiltinDefinition for UnsafeGetAttrPosBuiltin {
        const NAME: &'static [u8] = b"unsafeGetAttrPos";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectBinary(DirectBinaryPrimOp::UnsafeGetAttrPos);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Returns source-position metadata for an attribute when available.");
    }

    pub(crate) struct WarnBuiltin;
    impl BuiltinDefinition for WarnBuiltin {
        const NAME: &'static [u8] = b"warn";
        const EXECUTION: BuiltinExecution = BuiltinExecution::Warn;
        const DOCS: &'static BuiltinDocs = &WARN_DOCS;
    }

    pub(crate) struct ZipAttrsWithBuiltin;
    impl BuiltinDefinition for ZipAttrsWithBuiltin {
        const NAME: &'static [u8] = b"zipAttrsWith";
        const EXECUTION: BuiltinExecution =
            BuiltinExecution::DirectBinary(DirectBinaryPrimOp::ZipAttrsWith);
        const DOCS: &'static BuiltinDocs =
            builtin_docs!("Combines attribute values with the same name across a list of sets.");
    }
}
