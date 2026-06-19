//! Builtin declarations shared by scope resolution and runtime dispatch.
//!
//! Each builtin marker type implements [`BuiltinDefinition`] with its static
//! execution strategy, documentation, and top-level name policy. The execution
//! strategy provides default direct-lowering and first-class arity, and
//! custom builtins can override those fields in their definition impl. The
//! declaration macro publishes those typed definitions as both the ordered
//! `builtins` attrset inventory and the generated exact-name lookup used by
//! evaluator dispatch and frontend passes.

macro_rules! builtin_registry {
    (
        $(
            $ty:ident,
        )*
    ) => {
        const BUILTIN_DECLARATIONS: &[Builtin] = &[
            $(
                <$ty as BuiltinDefinition>::DECLARATION,
            )*
        ];
        const BUILTIN_LOOKUP_LEN: usize = BUILTIN_DECLARATIONS.len();
        type BuiltinLookup = BuiltinLookupTable<BUILTIN_LOOKUP_LEN>;
        const BUILTIN_LOOKUP: BuiltinLookup = BuiltinLookupTable::build(BUILTIN_DECLARATIONS);

        /// Builtin declarations recognized by the resolver and evaluator.
        pub(crate) const BUILTINS: BuiltinRegistry =
            BuiltinRegistry::new(BUILTIN_DECLARATIONS, &BUILTIN_LOOKUP);
    };
}

macro_rules! define_builtins {
    (
        $(
            pub(crate) struct $ty:ident;
            impl BuiltinDefinition for $impl_ty:ident {
                $($body:item)*
            }
        )*
    ) => {
        $(
            pub(crate) struct $ty;
            impl BuiltinDefinition for $impl_ty {
                $($body)*
            }
        )*

        builtin_registry! {
            $(
                $ty,
            )*
        }
    };
}

macro_rules! builtin_docs {
    ($summary:literal) => {
        &BuiltinDocs { summary: $summary }
    };
}

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

/// The C++ Nix version whose observable builtin surface this evaluator targets.
pub(crate) const PINNED_NIX_VERSION: &[u8] = b"2.24.12";

/// The Nix language version reported by the pinned C++ Nix evaluator.
pub(crate) const PINNED_NIX_LANG_VERSION: i64 = 6;

/// The observable effect class for a direct builtin boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinEffect {
    /// The builtin is pure for IR speculation and caching.
    Pure,
    /// The builtin can observe the filesystem, environment, or evaluator state.
    Effectful,
}

/// Direct lowering behavior for a builtin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinDirect {
    /// The builtin lowers to the derivation boundary IR node.
    DerivationStrict,
    /// The builtin lowers after one strict argument.
    StrictUnary { effect: BuiltinEffect },
    /// The builtin lowers after one lazy argument.
    LazyUnary { effect: BuiltinEffect },
    /// The builtin lowers after two strict arguments.
    StrictBinary { effect: BuiltinEffect },
    /// The builtin lowers after a strict first argument and lazy second argument.
    StrictLazyBinary { effect: BuiltinEffect },
    /// The builtin lowers after a lazy first argument and strict second argument.
    LazyStrictBinary { effect: BuiltinEffect },
    /// The builtin lowers as a two-argument sort boundary with Nix-specific forcing.
    Sort { effect: BuiltinEffect },
    /// The builtin lowers after three strict arguments.
    StrictTernary { effect: BuiltinEffect },
}

/// Runtime execution strategy attached to a concrete builtin declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinExecution {
    /// The builtin parses and evaluates another Nix file.
    Import,
    /// The builtin parses another Nix file with an injected global scope.
    ScopedImport,
    /// The builtin evaluates Nix's derivation wrapper around `derivationStrict`.
    Derivation,
    /// The builtin lowers to the derivation boundary and is not first-class.
    DerivationStrict,
    /// The builtin evaluates to the recursive builtin attribute set.
    BuiltinsValue,
    /// The builtin evaluates to the constant `true` value.
    TrueValue,
    /// The builtin evaluates to the constant `false` value.
    FalseValue,
    /// The builtin evaluates to the constant `null` value.
    NullValue,
    /// The builtin evaluates to the configured current system string when available.
    CurrentSystemValue,
    /// The builtin evaluates to the configured current time integer when available.
    CurrentTimeValue,
    /// The builtin evaluates to the configured store directory string.
    StoreDirValue,
    /// The builtin evaluates to the pinned Nix version string.
    NixVersionValue,
    /// The builtin evaluates to the pinned Nix language version integer.
    LangVersionValue,
    /// The builtin evaluates to the configured Nix search path list.
    NixPathValue,
    /// The builtin is a strict unary primitive operation.
    StrictUnary {
        /// The primitive operation executed by the tree-walk evaluator.
        primop: StrictUnaryPrimOp,
        /// The direct-lowering effect class for the operation.
        effect: BuiltinEffect,
    },
    /// The builtin returns its single argument lazily.
    LazyUnary,
    /// The builtin is a strict binary primitive operation.
    StrictBinary {
        /// The primitive operation executed by the tree-walk evaluator.
        primop: StrictBinaryPrimOp,
        /// The direct-lowering effect class for the operation.
        effect: BuiltinEffect,
    },
    /// The builtin has direct-only binary execution.
    DirectBinary(DirectBinaryPrimOp),
    /// The builtin has direct-only ternary execution.
    DirectTernary(StrictTernaryPrimOp),
    /// The builtin evaluates `sort`.
    Sort,
    /// The builtin evaluates `tryEval`.
    TryEval,
    /// The builtin evaluates `addErrorContext`.
    AddErrorContext,
    /// The builtin evaluates `pathExists`.
    PathExists,
    /// The builtin evaluates `path`.
    Path,
    /// The builtin evaluates `filterSource`.
    FilterSource,
    /// The builtin evaluates `fetchurl`.
    Fetchurl,
    /// The builtin evaluates `fetchGit`.
    FetchGit,
    /// The builtin preflights `fetchMercurial` before deferring execution.
    FetchMercurial,
    /// The builtin evaluates `fetchTarball`.
    FetchTarball,
    /// The builtin evaluates `fetchTree`.
    FetchTree,
    /// The builtin preflights `getFlake` before deferring execution.
    GetFlake,
    /// The builtin converts flake-reference attrs to URL syntax.
    FlakeRefToString,
    /// The builtin parses flake-reference URL syntax into attrs.
    ParseFlakeRef,
    /// The builtin evaluates `readDir`.
    ReadDir,
    /// The builtin evaluates `readFile`.
    ReadFile,
    /// The builtin evaluates `readFileType`.
    ReadFileType,
    /// The builtin evaluates `toFile`.
    ToFile,
    /// The builtin evaluates `seq`.
    Seq,
    /// The builtin evaluates `deepSeq`.
    DeepSeq,
    /// The builtin evaluates `findFile`.
    FindFile,
    /// The builtin evaluates `genericClosure`.
    GenericClosure,
    /// The builtin evaluates `trace` or `traceVerbose`.
    Trace {
        /// The verbosity mode controlling whether output is emitted.
        mode: TraceMode,
    },
    /// The builtin evaluates `warn`.
    Warn,
}

impl BuiltinExecution {
    /// Creates a pure strict unary builtin execution record.
    pub(crate) const fn strict_unary(primop: StrictUnaryPrimOp) -> Self {
        Self::StrictUnary {
            primop,
            effect: BuiltinEffect::Pure,
        }
    }

    /// Creates an effectful strict unary builtin execution record.
    pub(crate) const fn effectful_strict_unary(primop: StrictUnaryPrimOp) -> Self {
        Self::StrictUnary {
            primop,
            effect: BuiltinEffect::Effectful,
        }
    }

    /// Creates a pure strict binary builtin execution record.
    pub(crate) const fn strict_binary(primop: StrictBinaryPrimOp) -> Self {
        Self::StrictBinary {
            primop,
            effect: BuiltinEffect::Pure,
        }
    }

    /// Creates an effectful strict binary builtin execution record.
    pub(crate) const fn effectful_strict_binary(primop: StrictBinaryPrimOp) -> Self {
        Self::StrictBinary {
            primop,
            effect: BuiltinEffect::Effectful,
        }
    }

    /// Returns direct-lowering behavior implied by this execution strategy.
    pub(crate) const fn direct(self) -> Option<BuiltinDirect> {
        match self {
            Self::DerivationStrict => Some(BuiltinDirect::DerivationStrict),
            Self::StrictUnary { effect, .. } => Some(BuiltinDirect::StrictUnary { effect }),
            Self::LazyUnary => Some(BuiltinDirect::LazyUnary {
                effect: BuiltinEffect::Pure,
            }),
            Self::StrictBinary { effect, .. } => Some(BuiltinDirect::StrictBinary { effect }),
            Self::Derivation => Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful,
            }),
            Self::ScopedImport => Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful,
            }),
            Self::FindFile => Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful,
            }),
            Self::GenericClosure => Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure,
            }),
            Self::DirectBinary(_) => Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure,
            }),
            Self::Sort => Some(BuiltinDirect::Sort {
                effect: BuiltinEffect::Pure,
            }),
            Self::DirectTernary(_) => Some(BuiltinDirect::StrictTernary {
                effect: BuiltinEffect::Pure,
            }),
            Self::Import
            | Self::Path
            | Self::PathExists
            | Self::ReadDir
            | Self::ReadFile
            | Self::ReadFileType
            | Self::FetchGit
            | Self::FetchMercurial
            | Self::FetchTarball
            | Self::FetchTree
            | Self::Fetchurl => Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful,
            }),
            Self::FlakeRefToString | Self::ParseFlakeRef => Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure,
            }),
            Self::FilterSource => Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful,
            }),
            Self::ToFile => Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful,
            }),
            Self::TryEval => Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure,
            }),
            Self::Seq | Self::DeepSeq => Some(BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Pure,
            }),
            Self::AddErrorContext => Some(BuiltinDirect::LazyStrictBinary {
                effect: BuiltinEffect::Pure,
            }),
            Self::Trace { .. } | Self::Warn => Some(BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Effectful,
            }),
            Self::TrueValue
            | Self::FalseValue
            | Self::NullValue
            | Self::BuiltinsValue
            | Self::CurrentSystemValue
            | Self::CurrentTimeValue
            | Self::StoreDirValue
            | Self::NixVersionValue
            | Self::LangVersionValue
            | Self::NixPathValue
            | Self::GetFlake => None,
        }
    }

    /// Returns the arity exposed when this builtin is selected as a value.
    pub(crate) const fn first_class_arity(self) -> Option<usize> {
        match self {
            Self::StrictUnary { .. }
            | Self::LazyUnary
            | Self::Derivation
            | Self::DerivationStrict
            | Self::Import
            | Self::GenericClosure
            | Self::TryEval
            | Self::Path
            | Self::PathExists
            | Self::ReadDir
            | Self::ReadFile
            | Self::ReadFileType
            | Self::FetchGit
            | Self::FetchTarball
            | Self::FetchTree
            | Self::GetFlake
            | Self::Fetchurl
            | Self::FlakeRefToString
            | Self::ParseFlakeRef
            | Self::FetchMercurial => Some(1),
            Self::StrictBinary { .. }
            | Self::ScopedImport
            | Self::AddErrorContext
            | Self::FindFile
            | Self::FilterSource
            | Self::DirectBinary(_)
            | Self::ToFile
            | Self::Sort
            | Self::Seq
            | Self::DeepSeq
            | Self::Trace { .. }
            | Self::Warn => Some(2),
            Self::DirectTernary(_) => Some(3),
            Self::BuiltinsValue
            | Self::TrueValue
            | Self::FalseValue
            | Self::NullValue
            | Self::CurrentSystemValue
            | Self::CurrentTimeValue
            | Self::StoreDirValue
            | Self::NixVersionValue
            | Self::LangVersionValue
            | Self::NixPathValue => None,
        }
    }

    /// Returns when this builtin is present in the reified `builtins` set.
    const fn availability(self) -> BuiltinAvailability {
        match self {
            Self::CurrentSystemValue => BuiltinAvailability::ImpureCurrentSystem,
            Self::CurrentTimeValue => BuiltinAvailability::ImpureCurrentTime,
            _ => BuiltinAvailability::Always,
        }
    }

    /// Returns the native JSON fallback class implied by this execution strategy.
    const fn native_cli_fallback_feature(self) -> Option<NativeCliFallbackFeature> {
        match self {
            Self::Derivation
            | Self::Import
            | Self::ScopedImport
            | Self::DerivationStrict
            | Self::CurrentSystemValue
            | Self::CurrentTimeValue
            | Self::StoreDirValue
            | Self::NixPathValue
            | Self::Path
            | Self::PathExists
            | Self::FilterSource
            | Self::ReadDir
            | Self::ReadFile
            | Self::ReadFileType
            | Self::ToFile
            | Self::FindFile
            | Self::FetchGit
            | Self::FetchMercurial
            | Self::FetchTarball
            | Self::FetchTree
            | Self::Fetchurl
            | Self::Trace { .. }
            | Self::Warn => Some(NativeCliFallbackFeature::CliSensitiveBuiltinEvaluation),
            Self::GetFlake => Some(NativeCliFallbackFeature::Flakes),
            Self::StrictUnary { effect, .. } | Self::StrictBinary { effect, .. } => match effect {
                BuiltinEffect::Pure => None,
                BuiltinEffect::Effectful => {
                    Some(NativeCliFallbackFeature::CliSensitiveBuiltinEvaluation)
                }
            },
            Self::LazyUnary
            | Self::FlakeRefToString
            | Self::ParseFlakeRef
            | Self::DirectBinary(_)
            | Self::DirectTernary(_)
            | Self::Sort
            | Self::TryEval
            | Self::AddErrorContext
            | Self::GenericClosure
            | Self::Seq
            | Self::DeepSeq
            | Self::TrueValue
            | Self::FalseValue
            | Self::NullValue
            | Self::BuiltinsValue
            | Self::NixVersionValue
            | Self::LangVersionValue => None,
        }
    }
}

/// User-facing native evaluator fallback classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCliFallbackFeature {
    /// Evaluation must defer because the builtin can observe CLI/runtime state.
    CliSensitiveBuiltinEvaluation,
    /// Evaluation must defer because the builtin belongs to flake evaluation.
    Flakes,
}

impl NativeCliFallbackFeature {
    /// Returns the diagnostic feature label for this fallback class.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::CliSensitiveBuiltinEvaluation => "CLI-sensitive builtin evaluation",
            Self::Flakes => "flakes",
        }
    }
}

/// Contextual availability of a builtin in the reified `builtins` attrset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinAvailability {
    /// The builtin is always present.
    Always,
    /// The builtin is present only in impure mode when `currentSystem` is set.
    ImpureCurrentSystem,
    /// The builtin is present only in impure mode when `currentTime` is set.
    ImpureCurrentTime,
}

/// Output mode for trace-like builtins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceMode {
    /// `builtins.trace` always emits its message.
    Always,
    /// `builtins.traceVerbose` emits only when verbose tracing is enabled.
    Verbose,
}

/// Strict unary primitive operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StrictUnaryPrimOp {
    Abort,
    IsAttrs,
    IsList,
    IsFunction,
    IsString,
    IsInt,
    IsFloat,
    IsBool,
    IsNull,
    IsPath,
    TypeOf,
    Length,
    AttrNames,
    AttrValues,
    Tail,
    FunctionArgs,
    Head,
    Ceil,
    Floor,
    HasContext,
    GetContext,
    GetEnv,
    AddDrvOutputDependencies,
    UnsafeDiscardOutputDependency,
    UnsafeDiscardStringContext,
    Placeholder,
    StorePath,
    StringLength,
    BaseNameOf,
    DirOf,
    ParseDrvName,
    SplitVersion,
    FromJson,
    FromToml,
    ToPath,
    ToString,
    ToJson,
    ToXml,
    ConvertHash,
    ListToAttrs,
    ConcatLists,
    Throw,
}

/// Strict ternary primitive operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StrictTernaryPrimOp {
    FoldlStrict,
    ReplaceStrings,
    Substring,
}

/// Strict binary primitive operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StrictBinaryPrimOp {
    AppendContext,
    Add,
    Sub,
    Mul,
    Div,
    BitAnd,
    BitOr,
    BitXor,
    CompareVersions,
    ElemAt,
    LessThan,
    HashString,
    HashFile,
    All,
    Any,
    ConcatMap,
    Filter,
    GenList,
    GroupBy,
    Match,
    Map,
    Partition,
    Split,
}

/// Direct-only binary primitive operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectBinaryPrimOp {
    GetAttr,
    HasAttr,
    UnsafeGetAttrPos,
    RemoveAttrs,
    IntersectAttrs,
    CatAttrs,
    Elem,
    ConcatStringsSep,
    MapAttrs,
    ZipAttrsWith,
}

/// Short user-facing documentation for a builtin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BuiltinDocs {
    summary: &'static str,
}

impl BuiltinDocs {
    /// Returns the one-line summary for the builtin.
    #[allow(dead_code)]
    pub(crate) const fn summary(&self) -> &'static str {
        self.summary
    }
}

static APPEND_CONTEXT_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns a string with reflected string context appended.",
};

static ADD_ERROR_CONTEXT_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Adds a diagnostic context message to errors from an expression.",
};

static CURRENT_SYSTEM_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the configured target system when available.",
};

static HASH_FILE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the hex digest of a file's contents.",
};

static GET_ENV_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns a configured environment variable or an empty string.",
};

static GENERIC_CLOSURE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Computes the transitive closure of keyed attribute sets.",
};

static FETCHURL_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Fetches a URL as a fixed-output store path.",
};

static FETCH_GIT_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Fetches a pinned Git repository as a recursive fixed-output store path.",
};

static FETCH_TARBALL_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Fetches and unpacks a tarball as a recursive fixed-output store path.",
};

static FETCH_TREE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Fetches supported typed tree inputs as fixed-output store paths.",
};

static FLAKE_REF_TO_STRING_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Converts flake-reference attrs to URL syntax.",
};

static PARSE_FLAKE_REF_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Parses flake-reference URL syntax into attrs.",
};

static LANG_VERSION_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the pinned Nix language version.",
};

static NIX_VERSION_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the pinned C++ Nix version string.",
};

static NIX_PATH_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the configured Nix search path entries.",
};

static PATH_EXISTS_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns whether a path exists at evaluation time.",
};

static PLACEHOLDER_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the Nix placeholder string for a derivation output.",
};

static READ_DIR_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns an attribute set describing a directory's entries.",
};

static READ_FILE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the contents of a file as a string.",
};

static READ_FILE_TYPE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the filesystem type of a path.",
};

static STORE_DIR_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the configured Nix store directory.",
};

static STORE_PATH_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns a store path as a context-carrying string.",
};

static TO_PATH_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Coerces an absolute path-like value to a normalized string.",
};

static TRY_EVAL_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Evaluates an expression to WHNF and reports catchable failures.",
};

static TRACE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Prints a value to stderr and returns the second argument.",
};

static TRACE_VERBOSE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Conditionally prints a value to stderr and returns the second argument.",
};

static WARN_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Prints a warning to stderr and returns the second argument.",
};

/// How a builtin's spelling participates in top-level name resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinNameScope {
    /// The builtin is reachable through the `builtins` attribute set.
    BuiltinsAttrOnly,
    /// The builtin is also a top-level name that active `with` scopes cannot shadow.
    UnshadowableGlobal,
}

/// A builtin declaration shared by resolution, lowering, and execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Builtin {
    name: &'static [u8],
    execution: BuiltinExecution,
    name_scope: BuiltinNameScope,
    native_cli_fallback_feature_override: Option<NativeCliFallbackFeature>,
    docs: &'static BuiltinDocs,
}

impl Builtin {
    /// Creates a builtin declaration.
    const fn new(
        name: &'static [u8],
        execution: BuiltinExecution,
        name_scope: BuiltinNameScope,
        native_cli_fallback_feature_override: Option<NativeCliFallbackFeature>,
        docs: &'static BuiltinDocs,
    ) -> Self {
        Self {
            name,
            execution,
            name_scope,
            native_cli_fallback_feature_override,
            docs,
        }
    }

    /// Returns the byte-oriented builtin attribute name.
    pub(crate) const fn name(&self) -> &'static [u8] {
        self.name
    }

    /// Returns the runtime execution strategy for the builtin.
    pub(crate) const fn execution(&self) -> BuiltinExecution {
        self.execution
    }

    /// Returns direct-lowering behavior for the builtin, if any.
    pub(crate) const fn direct(&self) -> Option<BuiltinDirect> {
        self.execution.direct()
    }

    /// Returns the arity exposed when the builtin is selected as a first-class value.
    pub(crate) const fn first_class_arity(&self) -> Option<usize> {
        self.execution.first_class_arity()
    }

    /// Returns how this builtin's spelling participates in top-level name resolution.
    #[cfg(test)]
    pub(crate) const fn name_scope(&self) -> BuiltinNameScope {
        self.name_scope
    }

    /// Returns whether active `with` scopes cannot shadow this builtin's spelling.
    pub(crate) const fn is_unshadowable_global(&self) -> bool {
        match self.name_scope {
            BuiltinNameScope::BuiltinsAttrOnly => false,
            BuiltinNameScope::UnshadowableGlobal => true,
        }
    }

    /// Returns when this builtin is visible through the reified `builtins` attrset.
    pub(crate) const fn availability(&self) -> BuiltinAvailability {
        self.execution.availability()
    }

    /// Returns the diagnostic feature label when native JSON evaluation must fall back.
    pub(crate) const fn native_cli_fallback_feature(&self) -> Option<&'static str> {
        match self.native_cli_fallback_feature_kind() {
            Some(feature) => Some(feature.label()),
            None => None,
        }
    }

    /// Returns the native JSON fallback class for this builtin.
    const fn native_cli_fallback_feature_kind(&self) -> Option<NativeCliFallbackFeature> {
        match self.native_cli_fallback_feature_override {
            Some(feature) => Some(feature),
            None => self.execution.native_cli_fallback_feature(),
        }
    }

    /// Returns the static documentation attached to the builtin.
    #[allow(dead_code)]
    pub(crate) const fn docs(&self) -> &'static BuiltinDocs {
        self.docs
    }
}

/// Registry of builtin declarations known to the evaluator.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BuiltinRegistry {
    declarations: &'static [Builtin],
    lookup: &'static BuiltinLookup,
}

impl BuiltinRegistry {
    /// Creates a builtin registry from trait-generated declarations.
    const fn new(declarations: &'static [Builtin], lookup: &'static BuiltinLookup) -> Self {
        Self {
            declarations,
            lookup,
        }
    }

    /// Returns the number of builtin declarations.
    pub(crate) const fn len(&self) -> usize {
        self.declarations.len()
    }

    /// Returns an iterator over builtin declarations.
    pub(crate) fn iter(&self) -> std::slice::Iter<'static, Builtin> {
        self.declarations.iter()
    }

    /// Returns the declaration for a builtin name.
    pub(crate) fn lookup(&self, name: &[u8]) -> Option<Builtin> {
        let index = self.lookup.candidate_index(name)?;
        let builtin = self.declarations.get(index).copied()?;
        (builtin.name() == name).then_some(builtin)
    }

    /// Returns direct lowering behavior for a builtin name.
    pub(crate) fn direct(&self, name: &[u8]) -> Option<BuiltinDirect> {
        self.lookup(name).and_then(|builtin| builtin.direct())
    }

    /// Returns whether `name` is a builtin attribute known to this evaluator.
    pub(crate) fn is_known_attr(&self, name: &[u8]) -> bool {
        self.lookup(name).is_some()
    }

    /// Returns whether `name` is a top-level Nix name that active `with` scopes cannot shadow.
    pub(crate) fn is_unshadowable_global_name(&self, name: &[u8]) -> bool {
        self.lookup(name)
            .is_some_and(|builtin| builtin.is_unshadowable_global())
    }
}

const BUILTIN_LOOKUP_PRIMARY_SEED: u32 = 0x811c_9dc5;
const BUILTIN_LOOKUP_SECONDARY_SEED: u32 = 0x9e37_79b9;
const BUILTIN_LOOKUP_EMPTY_SLOT: u16 = u16::MAX;

#[derive(Clone, Copy, Debug)]
struct BuiltinLookupTable<const N: usize> {
    displacements: [u16; N],
    slots: [u16; N],
}

#[derive(Clone, Copy, Debug)]
struct BuiltinLookupBuckets<const N: usize> {
    sizes: [usize; N],
    members: [[u16; N]; N],
    order: [usize; N],
}

impl<const N: usize> BuiltinLookupTable<N> {
    const fn build(declarations: &[Builtin]) -> Self {
        assert!(declarations.len() == N);

        let mut lookup = Self {
            displacements: [0; N],
            slots: [BUILTIN_LOOKUP_EMPTY_SLOT; N],
        };
        let buckets = BuiltinLookupBuckets::build(declarations);
        let mut order_index = 0;
        while order_index < N {
            let bucket = buckets.order[order_index];
            if buckets.sizes[bucket] > 0 {
                let displacement = lookup.find_displacement(declarations, &buckets, bucket);
                lookup.displacements[bucket] = displacement;
                lookup.place_bucket(declarations, &buckets, bucket, displacement);
            }
            order_index += 1;
        }
        lookup.assert_complete();
        lookup
    }

    fn candidate_index(&self, name: &[u8]) -> Option<usize> {
        if name.is_empty() || N == 0 {
            return None;
        }
        let bucket = builtin_lookup_primary_bucket::<N>(name);
        let displacement = self.displacements[bucket];
        let slot = builtin_lookup_secondary_slot::<N>(name, displacement);
        let index = self.slots[slot];
        (index != BUILTIN_LOOKUP_EMPTY_SLOT).then_some(usize::from(index))
    }

    const fn find_displacement(
        &self,
        declarations: &[Builtin],
        buckets: &BuiltinLookupBuckets<N>,
        bucket: usize,
    ) -> u16 {
        let mut displacement = 0;
        while displacement < BUILTIN_LOOKUP_EMPTY_SLOT {
            if self.displacement_fits(declarations, buckets, bucket, displacement) {
                return displacement;
            }
            displacement += 1;
        }
        panic!("unable to build builtin lookup table");
    }

    const fn displacement_fits(
        &self,
        declarations: &[Builtin],
        buckets: &BuiltinLookupBuckets<N>,
        bucket: usize,
        displacement: u16,
    ) -> bool {
        let mut member_offset = 0;
        while member_offset < buckets.sizes[bucket] {
            let declaration_index = buckets.members[bucket][member_offset] as usize;
            let name = declarations[declaration_index].name();
            let slot = builtin_lookup_secondary_slot::<N>(name, displacement);
            if self.slots[slot] != BUILTIN_LOOKUP_EMPTY_SLOT {
                return false;
            }

            let mut previous_member_offset = 0;
            while previous_member_offset < member_offset {
                let previous_declaration_index =
                    buckets.members[bucket][previous_member_offset] as usize;
                let previous_name = declarations[previous_declaration_index].name();
                let previous_slot = builtin_lookup_secondary_slot::<N>(previous_name, displacement);
                if previous_slot == slot {
                    return false;
                }
                previous_member_offset += 1;
            }
            member_offset += 1;
        }
        true
    }

    const fn place_bucket(
        &mut self,
        declarations: &[Builtin],
        buckets: &BuiltinLookupBuckets<N>,
        bucket: usize,
        displacement: u16,
    ) {
        let mut member_offset = 0;
        while member_offset < buckets.sizes[bucket] {
            let declaration_index = buckets.members[bucket][member_offset] as usize;
            let name = declarations[declaration_index].name();
            let slot = builtin_lookup_secondary_slot::<N>(name, displacement);
            self.slots[slot] = declaration_index as u16;
            member_offset += 1;
        }
    }

    const fn assert_complete(&self) {
        let mut seen = [false; N];
        let mut slot = 0;
        while slot < N {
            let index = self.slots[slot];
            assert!(index != BUILTIN_LOOKUP_EMPTY_SLOT);
            let index = index as usize;
            assert!(index < N);
            assert!(!seen[index]);
            seen[index] = true;
            slot += 1;
        }

        let mut index = 0;
        while index < N {
            assert!(seen[index]);
            index += 1;
        }
    }
}

impl<const N: usize> BuiltinLookupBuckets<N> {
    const fn build(declarations: &[Builtin]) -> Self {
        assert!(declarations.len() == N);
        assert!(declarations.len() <= BUILTIN_LOOKUP_EMPTY_SLOT as usize);

        let mut sizes = [0; N];
        let mut members = [[BUILTIN_LOOKUP_EMPTY_SLOT; N]; N];
        let mut declaration_index = 0;
        while declaration_index < declarations.len() {
            let bucket = builtin_lookup_primary_bucket::<N>(declarations[declaration_index].name());
            let member_offset = sizes[bucket];
            members[bucket][member_offset] = declaration_index as u16;
            sizes[bucket] += 1;
            declaration_index += 1;
        }

        let order = builtin_lookup_bucket_order::<N>(sizes);
        Self {
            sizes,
            members,
            order,
        }
    }
}

const fn builtin_lookup_bucket_order<const N: usize>(bucket_sizes: [usize; N]) -> [usize; N] {
    let mut order = [0; N];
    let mut index = 0;
    while index < N {
        order[index] = index;
        index += 1;
    }

    let mut pass = 0;
    while pass < N {
        let mut index = 1;
        while index < N - pass {
            let left = order[index - 1];
            let right = order[index];
            if bucket_sizes[left] < bucket_sizes[right] {
                order[index - 1] = right;
                order[index] = left;
            }
            index += 1;
        }
        pass += 1;
    }

    order
}

const fn builtin_lookup_primary_bucket<const N: usize>(name: &[u8]) -> usize {
    builtin_lookup_hash(name, BUILTIN_LOOKUP_PRIMARY_SEED) % N
}

const fn builtin_lookup_secondary_slot<const N: usize>(name: &[u8], displacement: u16) -> usize {
    builtin_lookup_hash(name, BUILTIN_LOOKUP_SECONDARY_SEED ^ displacement as u32) % N
}

const fn builtin_lookup_hash(name: &[u8], seed: u32) -> usize {
    let mut hash = seed;
    let mut index = 0;
    while index < name.len() {
        hash ^= name[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    hash as usize
}

/// Provides the single static declaration for a concrete builtin marker type.
trait BuiltinDefinition {
    /// Byte-oriented builtin attribute name.
    const NAME: &'static [u8];

    /// Runtime execution strategy for this builtin.
    const EXECUTION: BuiltinExecution;

    /// Static documentation attached to this builtin.
    const DOCS: &'static BuiltinDocs;

    /// Scope behavior for this builtin's spelling.
    const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::BuiltinsAttrOnly;

    /// Override for the execution-derived native JSON fallback class.
    const NATIVE_CLI_FALLBACK_FEATURE_OVERRIDE: Option<NativeCliFallbackFeature> = None;

    /// Declaration shared by all evaluator tiers for this builtin.
    const DECLARATION: Builtin = Builtin::new(
        Self::NAME,
        Self::EXECUTION,
        Self::NAME_SCOPE,
        Self::NATIVE_CLI_FALLBACK_FEATURE_OVERRIDE,
        Self::DOCS,
    );
}

/// Returns direct lowering behavior for a builtin name.
pub(crate) fn direct_builtin(name: &[u8]) -> Option<BuiltinDirect> {
    BUILTINS.direct(name)
}

/// Returns the declaration for a builtin name.
pub(crate) fn lookup_builtin(name: &[u8]) -> Option<Builtin> {
    BUILTINS.lookup(name)
}

/// Returns whether `name` is a builtin attribute known to this evaluator.
pub(crate) fn is_known_builtin_attr(name: &[u8]) -> bool {
    BUILTINS.is_known_attr(name)
}

/// Returns whether `name` is a top-level Nix name that active `with` scopes cannot shadow.
pub(crate) fn is_unshadowable_global_name(name: &[u8]) -> bool {
    BUILTINS.is_unshadowable_global_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn builtin_names_are_unique() {
        let names = BUILTINS.iter().map(Builtin::name).collect::<BTreeSet<_>>();

        assert_eq!(names.len(), BUILTINS.len());
    }

    #[test]
    fn builtin_declarations_are_sorted_for_deterministic_iteration() {
        let mut previous = None;
        for builtin in BUILTINS.iter() {
            if let Some(previous) = previous {
                assert!(
                    previous < builtin.name(),
                    "{} must sort before {}",
                    String::from_utf8_lossy(previous),
                    String::from_utf8_lossy(builtin.name())
                );
            }
            previous = Some(builtin.name());
        }
    }

    #[test]
    fn generated_builtin_lookup_table_is_perfect_for_declared_builtins() {
        assert_eq!(BUILTINS.len(), BUILTIN_LOOKUP_LEN);
        assert_eq!(BUILTIN_LOOKUP.displacements.len(), BUILTIN_LOOKUP_LEN);
        assert_eq!(BUILTIN_LOOKUP.slots.len(), BUILTIN_LOOKUP_LEN);

        let mut seen = vec![false; BUILTIN_LOOKUP_LEN];
        for slot in BUILTIN_LOOKUP.slots {
            assert_ne!(slot, BUILTIN_LOOKUP_EMPTY_SLOT);
            let index = usize::from(slot);
            assert!(index < BUILTIN_LOOKUP_LEN, "{index}");
            assert!(!seen[index], "{index} appears more than once");
            seen[index] = true;
        }
        assert!(seen.into_iter().all(|slot| slot));

        for (expected, builtin) in BUILTINS.iter().copied().enumerate() {
            assert_eq!(
                BUILTIN_LOOKUP.candidate_index(builtin.name()),
                Some(expected)
            );
            assert_eq!(BUILTINS.lookup(builtin.name()), Some(builtin));
        }
    }

    #[test]
    fn generated_builtin_lookup_covers_declared_builtins() {
        for builtin in BUILTINS.iter().copied() {
            assert_eq!(BUILTINS.lookup(builtin.name()), Some(builtin));
        }
        assert_eq!(BUILTINS.lookup(b""), None);
        assert_eq!(BUILTINS.lookup(b"abort\0"), None);
        assert_eq!(BUILTINS.lookup(b"toXML\0"), None);
        assert_eq!(BUILTINS.lookup(b"foldl"), None);
        assert_eq!(BUILTINS.lookup(b"zzzz"), None);
    }

    #[test]
    fn builtin_lookup_helpers_delegate_to_registry() {
        assert!(BUILTINS.is_known_attr(b"length"));
        assert!(is_known_builtin_attr(b"length"));
        assert!(!BUILTINS.is_known_attr(b"__missing"));
        assert!(!is_known_builtin_attr(b"__missing"));
        assert_eq!(lookup_builtin(b"length"), BUILTINS.lookup(b"length"));
        assert_eq!(lookup_builtin(b"__missing"), None);
        assert_eq!(direct_builtin(b"length"), BUILTINS.direct(b"length"));
    }

    #[test]
    fn builtin_lookup_distinguishes_top_level_names_from_attrs() {
        for name in [
            b"true".as_slice(),
            b"builtins".as_slice(),
            b"map".as_slice(),
            b"toString".as_slice(),
            b"derivationStrict".as_slice(),
        ] {
            assert!(is_unshadowable_global_name(name), "{name:?}");
            let builtin = lookup_builtin(name).expect("top-level builtin is registered");
            assert_eq!(builtin.name_scope(), BuiltinNameScope::UnshadowableGlobal);
            assert!(builtin.is_unshadowable_global());
        }
        for name in [
            b"length".as_slice(),
            b"concatMap".as_slice(),
            b"currentTime".as_slice(),
            b"storeDir".as_slice(),
        ] {
            assert!(!is_unshadowable_global_name(name), "{name:?}");
            assert!(is_known_builtin_attr(name), "{name:?}");
            let builtin = lookup_builtin(name).expect("builtin attr is registered");
            assert_eq!(builtin.name_scope(), BuiltinNameScope::BuiltinsAttrOnly);
            assert!(!builtin.is_unshadowable_global());
        }
    }

    #[test]
    fn pinned_nix_version_matches_packaged_cpp_nix() {
        let package = include_str!("../../../../pkgs/tools/nix.nix");
        let version = package
            .lines()
            .find_map(|line| {
                let line = line.trim();
                let version = line.strip_prefix("version = \"")?;
                version.strip_suffix("\";")
            })
            .expect("pkgs/tools/nix.nix declares a version");

        let expected_lang_version = match version {
            "2.24.12" => 6,
            other => panic!("re-check builtins.langVersion for pinned Nix {other}"),
        };

        assert_eq!(PINNED_NIX_VERSION, version.as_bytes());
        assert_eq!(PINNED_NIX_LANG_VERSION, expected_lang_version);
    }

    #[test]
    fn direct_builtin_declarations_mark_effectful_boundaries() {
        assert_eq!(
            direct_builtin(b"derivation"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"derivationStrict"),
            Some(BuiltinDirect::DerivationStrict)
        );
        assert_eq!(
            direct_builtin(b"getEnv"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"break"),
            Some(BuiltinDirect::LazyUnary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"hashFile"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"map"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"appendContext"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"addErrorContext"),
            Some(BuiltinDirect::LazyStrictBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"match"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"split"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"zipAttrsWith"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"genList"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"sort"),
            Some(BuiltinDirect::Sort {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"pathExists"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"path"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"fetchurl"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"readDir"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"readFile"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"readFileType"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"filterSource"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"storePath"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"tryEval"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"seq"),
            Some(BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"trace"),
            Some(BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"traceVerbose"),
            Some(BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"warn"),
            Some(BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"substring"),
            Some(BuiltinDirect::StrictTernary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"fromTOML"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"toPath"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure
            })
        );
    }

    #[test]
    fn builtin_declarations_record_first_class_arity_by_category() {
        for name in [
            b"fetchGit".as_slice(),
            b"fetchMercurial".as_slice(),
            b"fetchTree".as_slice(),
            b"getFlake".as_slice(),
        ] {
            assert_eq!(
                BUILTINS.lookup(name).unwrap().first_class_arity(),
                Some(1),
                "{} should expose a unary first-class builtin",
                String::from_utf8_lossy(name),
            );
        }
        for name in [b"flakeRefToString".as_slice(), b"parseFlakeRef".as_slice()] {
            let builtin = BUILTINS.lookup(name).unwrap();
            assert_eq!(
                builtin.first_class_arity(),
                Some(1),
                "{} should expose a unary first-class builtin",
                String::from_utf8_lossy(name),
            );
            assert_eq!(
                builtin.direct(),
                Some(BuiltinDirect::StrictUnary {
                    effect: BuiltinEffect::Pure,
                }),
                "{} should lower as a pure strict unary builtin",
                String::from_utf8_lossy(name),
            );
        }
        assert_eq!(
            BUILTINS.lookup(b"path").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS.lookup(b"fetchurl").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"filterSource")
                .unwrap()
                .first_class_arity(),
            Some(2),
        );
        assert_eq!(
            BUILTINS.lookup(b"attrNames").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS.lookup(b"getEnv").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS.lookup(b"break").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS.lookup(b"pathExists").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS.lookup(b"readFile").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS.lookup(b"tryEval").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"genericClosure")
                .unwrap()
                .first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS.lookup(b"import").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"scopedImport")
                .unwrap()
                .first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"add").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"appendContext")
                .unwrap()
                .first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"addErrorContext")
                .unwrap()
                .first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"hashFile").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"elemAt").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"elem").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"map").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"match").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"split").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"genList").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"filter").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"partition").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"concatMap").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"groupBy").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"zipAttrsWith")
                .unwrap()
                .first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"all").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"any").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"sort").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"seq").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"trace").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"traceVerbose")
                .unwrap()
                .first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"warn").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            BUILTINS.lookup(b"foldl'").unwrap().first_class_arity(),
            Some(3)
        );
        assert_eq!(
            BUILTINS.lookup(b"substring").unwrap().first_class_arity(),
            Some(3)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"replaceStrings")
                .unwrap()
                .first_class_arity(),
            Some(3)
        );
        assert_eq!(
            BUILTINS.lookup(b"derivation").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            BUILTINS
                .lookup(b"derivationStrict")
                .unwrap()
                .first_class_arity(),
            Some(1)
        );
        assert_eq!(BUILTINS.lookup(b"true").unwrap().first_class_arity(), None);
        assert_eq!(
            BUILTINS.lookup(b"fromTOML").unwrap().first_class_arity(),
            Some(1)
        );
    }

    #[test]
    fn builtin_declarations_record_contextual_availability() {
        assert_eq!(
            BUILTINS.lookup(b"length").unwrap().availability(),
            BuiltinAvailability::Always
        );
        assert_eq!(
            BUILTINS.lookup(b"currentSystem").unwrap().availability(),
            BuiltinAvailability::ImpureCurrentSystem
        );
        assert_eq!(
            BUILTINS.lookup(b"currentTime").unwrap().availability(),
            BuiltinAvailability::ImpureCurrentTime
        );
    }

    #[test]
    fn builtin_declarations_record_native_fallback_policy() {
        for name in [
            b"derivation".as_slice(),
            b"derivationStrict".as_slice(),
            b"fetchMercurial".as_slice(),
            b"fetchTree".as_slice(),
            b"fetchurl".as_slice(),
            b"getEnv".as_slice(),
            b"hashFile".as_slice(),
            b"readFile".as_slice(),
            b"trace".as_slice(),
        ] {
            assert!(
                BUILTINS
                    .lookup(name)
                    .unwrap()
                    .native_cli_fallback_feature()
                    .is_some(),
                "{} should require CLI fallback",
                String::from_utf8_lossy(name),
            );
        }

        for name in [
            b"length".as_slice(),
            b"lessThan".as_slice(),
            b"nixVersion".as_slice(),
            b"langVersion".as_slice(),
            b"parseFlakeRef".as_slice(),
            b"flakeRefToString".as_slice(),
        ] {
            assert!(
                !BUILTINS
                    .lookup(name)
                    .unwrap()
                    .native_cli_fallback_feature()
                    .is_some(),
                "{} should stay native-evaluable",
                String::from_utf8_lossy(name),
            );
        }

        for name in [b"getFlake".as_slice()] {
            assert_eq!(
                BUILTINS.lookup(name).unwrap().native_cli_fallback_feature(),
                Some("flakes"),
                "{} should report flakes as the fallback feature",
                String::from_utf8_lossy(name),
            );
        }

        assert_eq!(
            BUILTINS
                .lookup(b"fetchurl")
                .unwrap()
                .native_cli_fallback_feature(),
            Some("CLI-sensitive builtin evaluation")
        );
        assert_eq!(
            BUILTINS
                .lookup(b"length")
                .unwrap()
                .native_cli_fallback_feature(),
            None
        );
    }

    #[test]
    fn default_builtin_declarations_stay_derived_from_execution_strategy() {
        for builtin in BUILTINS.iter() {
            let execution = builtin.execution();
            assert_eq!(builtin.direct(), execution.direct(), "{builtin:?}");
            assert_eq!(
                builtin.first_class_arity(),
                execution.first_class_arity(),
                "{builtin:?}",
            );
            assert_eq!(
                builtin.availability(),
                execution.availability(),
                "{builtin:?}",
            );
            assert_eq!(
                builtin.native_cli_fallback_feature_override, None,
                "{builtin:?}"
            );
            assert_eq!(
                builtin.native_cli_fallback_feature(),
                execution
                    .native_cli_fallback_feature()
                    .map(NativeCliFallbackFeature::label),
                "{builtin:?}",
            );
        }
    }

    #[test]
    fn custom_builtin_declaration_stays_attached_to_definition() {
        let fetchurl = BUILTINS
            .lookup(b"fetchurl")
            .expect("fetchurl builtin is registered");

        assert_eq!(fetchurl.execution(), BuiltinExecution::Fetchurl);
        assert_eq!(
            fetchurl.direct(),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(fetchurl.first_class_arity(), Some(1));
        assert_eq!(
            fetchurl.native_cli_fallback_feature(),
            Some("CLI-sensitive builtin evaluation")
        );
        assert_eq!(
            fetchurl.docs().summary(),
            "Fetches a URL as a fixed-output store path."
        );

        let fetch_git = BUILTINS
            .lookup(b"fetchGit")
            .expect("fetchGit builtin is registered");

        assert_eq!(fetch_git.execution(), BuiltinExecution::FetchGit);
        assert_eq!(
            fetch_git.direct(),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(fetch_git.first_class_arity(), Some(1));
        assert_eq!(
            fetch_git.native_cli_fallback_feature(),
            Some("CLI-sensitive builtin evaluation")
        );
        assert_eq!(
            fetch_git.docs().summary(),
            "Fetches a pinned Git repository as a recursive fixed-output store path."
        );

        let fetch_tarball = BUILTINS
            .lookup(b"fetchTarball")
            .expect("fetchTarball builtin is registered");

        assert_eq!(fetch_tarball.execution(), BuiltinExecution::FetchTarball);
        assert_eq!(
            fetch_tarball.direct(),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(fetch_tarball.first_class_arity(), Some(1));
        assert_eq!(
            fetch_tarball.native_cli_fallback_feature(),
            Some("CLI-sensitive builtin evaluation")
        );
        assert_eq!(
            fetch_tarball.docs().summary(),
            "Fetches and unpacks a tarball as a recursive fixed-output store path."
        );

        let fetch_tree = BUILTINS
            .lookup(b"fetchTree")
            .expect("fetchTree builtin is registered");

        assert_eq!(fetch_tree.execution(), BuiltinExecution::FetchTree);
        assert_eq!(
            fetch_tree.direct(),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(fetch_tree.first_class_arity(), Some(1));
        assert_eq!(
            fetch_tree.native_cli_fallback_feature(),
            Some("CLI-sensitive builtin evaluation")
        );
        assert_eq!(
            fetch_tree.docs().summary(),
            "Fetches supported typed tree inputs as fixed-output store paths."
        );

        let get_flake = BUILTINS
            .lookup(b"getFlake")
            .expect("getFlake builtin is registered");
        assert_eq!(get_flake.execution(), BuiltinExecution::GetFlake);
        assert_eq!(get_flake.direct(), None);
        assert_eq!(get_flake.first_class_arity(), Some(1));
        assert_eq!(get_flake.native_cli_fallback_feature(), Some("flakes"));
        assert_eq!(
            get_flake.docs().summary(),
            "Fetches and evaluates a flake reference when flakes are enabled."
        );

        let parse_flake_ref = BUILTINS
            .lookup(b"parseFlakeRef")
            .expect("parseFlakeRef builtin is registered");
        assert_eq!(parse_flake_ref.execution(), BuiltinExecution::ParseFlakeRef);
        assert_eq!(
            parse_flake_ref.direct(),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(parse_flake_ref.first_class_arity(), Some(1));
        assert_eq!(parse_flake_ref.native_cli_fallback_feature(), None);
        assert_eq!(
            parse_flake_ref.docs().summary(),
            "Parses flake-reference URL syntax into attrs."
        );

        let flake_ref_to_string = BUILTINS
            .lookup(b"flakeRefToString")
            .expect("flakeRefToString builtin is registered");
        assert_eq!(
            flake_ref_to_string.execution(),
            BuiltinExecution::FlakeRefToString
        );
        assert_eq!(
            flake_ref_to_string.direct(),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(flake_ref_to_string.first_class_arity(), Some(1));
        assert_eq!(flake_ref_to_string.native_cli_fallback_feature(), None);
        assert_eq!(
            flake_ref_to_string.docs().summary(),
            "Converts flake-reference attrs to URL syntax."
        );
    }

    #[test]
    fn custom_builtin_docs_stay_attached_to_declaration() {
        assert_eq!(
            BUILTINS.lookup(b"appendContext").unwrap().docs().summary(),
            "Returns a string with reflected string context appended."
        );
        assert_eq!(
            BUILTINS
                .lookup(b"addErrorContext")
                .unwrap()
                .docs()
                .summary(),
            "Adds a diagnostic context message to errors from an expression."
        );
        assert_eq!(
            BUILTINS.lookup(b"currentSystem").unwrap().docs().summary(),
            "Returns the configured target system when available."
        );
        assert_eq!(
            BUILTINS.lookup(b"genericClosure").unwrap().docs().summary(),
            "Computes the transitive closure of keyed attribute sets."
        );
        assert_eq!(
            BUILTINS.lookup(b"hashFile").unwrap().docs().summary(),
            "Returns the hex digest of a file's contents."
        );
        assert_eq!(
            BUILTINS.lookup(b"getEnv").unwrap().docs().summary(),
            "Returns a configured environment variable or an empty string."
        );
        assert_eq!(
            BUILTINS.lookup(b"fetchurl").unwrap().docs().summary(),
            "Fetches a URL as a fixed-output store path."
        );
        assert_eq!(
            BUILTINS.lookup(b"fetchTarball").unwrap().docs().summary(),
            "Fetches and unpacks a tarball as a recursive fixed-output store path."
        );
        assert_eq!(
            BUILTINS.lookup(b"fetchTree").unwrap().docs().summary(),
            "Fetches supported typed tree inputs as fixed-output store paths."
        );
        assert_eq!(
            BUILTINS.lookup(b"langVersion").unwrap().docs().summary(),
            "Returns the pinned Nix language version."
        );
        assert_eq!(
            BUILTINS.lookup(b"nixVersion").unwrap().docs().summary(),
            "Returns the pinned C++ Nix version string."
        );
        assert_eq!(
            BUILTINS.lookup(b"nixPath").unwrap().docs().summary(),
            "Returns the configured Nix search path entries."
        );
        assert_eq!(
            BUILTINS.lookup(b"pathExists").unwrap().docs().summary(),
            "Returns whether a path exists at evaluation time."
        );
        assert_eq!(
            BUILTINS.lookup(b"placeholder").unwrap().docs().summary(),
            "Returns the Nix placeholder string for a derivation output."
        );
        assert_eq!(
            BUILTINS.lookup(b"readDir").unwrap().docs().summary(),
            "Returns an attribute set describing a directory's entries."
        );
        assert_eq!(
            BUILTINS.lookup(b"readFile").unwrap().docs().summary(),
            "Returns the contents of a file as a string."
        );
        assert_eq!(
            BUILTINS.lookup(b"readFileType").unwrap().docs().summary(),
            "Returns the filesystem type of a path."
        );
        assert_eq!(
            BUILTINS.lookup(b"storeDir").unwrap().docs().summary(),
            "Returns the configured Nix store directory."
        );
        assert_eq!(
            BUILTINS.lookup(b"storePath").unwrap().docs().summary(),
            "Returns a store path as a context-carrying string."
        );
        assert_eq!(
            BUILTINS.lookup(b"toPath").unwrap().docs().summary(),
            "Coerces an absolute path-like value to a normalized string."
        );
        assert_eq!(
            BUILTINS.lookup(b"tryEval").unwrap().docs().summary(),
            "Evaluates an expression to WHNF and reports catchable failures."
        );
        assert_eq!(
            BUILTINS.lookup(b"trace").unwrap().docs().summary(),
            "Prints a value to stderr and returns the second argument."
        );
        assert_eq!(
            BUILTINS.lookup(b"traceVerbose").unwrap().docs().summary(),
            "Conditionally prints a value to stderr and returns the second argument."
        );
        assert_eq!(
            BUILTINS.lookup(b"warn").unwrap().docs().summary(),
            "Prints a warning to stderr and returns the second argument."
        );
    }

    #[test]
    fn builtin_declarations_all_have_explicit_docs() {
        for builtin in BUILTINS.iter() {
            let summary = builtin.docs().summary();
            assert!(
                !summary.is_empty(),
                "{} should have builtin docs",
                String::from_utf8_lossy(builtin.name())
            );
            assert!(
                !summary.contains("not been imported"),
                "{} should not use placeholder builtin docs",
                String::from_utf8_lossy(builtin.name())
            );
            assert!(
                summary.ends_with('.'),
                "{} docs should be a complete sentence",
                String::from_utf8_lossy(builtin.name())
            );
        }
    }
}
