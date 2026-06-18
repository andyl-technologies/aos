//! Builtin declarations shared by scope resolution and runtime dispatch.
//!
//! Each builtin marker type implements [`BuiltinDefinition`] with its static
//! execution strategy and documentation. The execution strategy derives
//! direct-lowering and first-class arity metadata, and the registry macro
//! publishes those typed definitions as both the ordered `builtins` attrset
//! inventory and the exact-name lookup used by evaluator dispatch and frontend
//! passes.

macro_rules! builtin_registry {
    (
        $(
            $ty:ident,
        )*
    ) => {
        const BUILTIN_METADATA: &[BuiltinMetadata] = &[
            $(
                <$ty as BuiltinDefinition>::METADATA,
            )*
        ];

        #[cfg(test)]
        const REGISTERED_BUILTIN_TYPES: &[&str] = &[
            $(
                stringify!($ty),
            )*
        ];

        fn lookup_builtin_metadata(name: &[u8]) -> Option<BuiltinMetadata> {
            $(
                if name == <$ty as BuiltinDefinition>::NAME {
                    return Some(<$ty as BuiltinDefinition>::METADATA);
                }
            )*

            None
        }

        /// Builtin declarations recognized by the resolver and evaluator.
        pub(crate) const BUILTINS: BuiltinRegistry =
            BuiltinRegistry::new(BUILTIN_METADATA, lookup_builtin_metadata);
    };
}

pub(crate) struct AbortBuiltin;
impl BuiltinDefinition for AbortBuiltin {
    const NAME: &'static [u8] = b"abort";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Abort);
}

pub(crate) struct AddBuiltin;
impl BuiltinDefinition for AddBuiltin {
    const NAME: &'static [u8] = b"add";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Add);
}

pub(crate) struct AddDrvOutputDependenciesBuiltin;
impl BuiltinDefinition for AddDrvOutputDependenciesBuiltin {
    const NAME: &'static [u8] = b"addDrvOutputDependencies";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::AddDrvOutputDependencies);
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
}

pub(crate) struct AnyBuiltin;
impl BuiltinDefinition for AnyBuiltin {
    const NAME: &'static [u8] = b"any";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Any);
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
}

pub(crate) struct AttrValuesBuiltin;
impl BuiltinDefinition for AttrValuesBuiltin {
    const NAME: &'static [u8] = b"attrValues";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::AttrValues);
}

pub(crate) struct BaseNameOfBuiltin;
impl BuiltinDefinition for BaseNameOfBuiltin {
    const NAME: &'static [u8] = b"baseNameOf";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::BaseNameOf);
}

pub(crate) struct BitAndBuiltin;
impl BuiltinDefinition for BitAndBuiltin {
    const NAME: &'static [u8] = b"bitAnd";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::BitAnd);
}

pub(crate) struct BitOrBuiltin;
impl BuiltinDefinition for BitOrBuiltin {
    const NAME: &'static [u8] = b"bitOr";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::BitOr);
}

pub(crate) struct BitXorBuiltin;
impl BuiltinDefinition for BitXorBuiltin {
    const NAME: &'static [u8] = b"bitXor";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::BitXor);
}

pub(crate) struct BreakBuiltin;
impl BuiltinDefinition for BreakBuiltin {
    const NAME: &'static [u8] = b"break";
    const EXECUTION: BuiltinExecution = BuiltinExecution::LazyUnary;
}

pub(crate) struct BuiltinsBuiltin;
impl BuiltinDefinition for BuiltinsBuiltin {
    const NAME: &'static [u8] = b"builtins";
    const EXECUTION: BuiltinExecution = BuiltinExecution::BuiltinsValue;
}

pub(crate) struct CatAttrsBuiltin;
impl BuiltinDefinition for CatAttrsBuiltin {
    const NAME: &'static [u8] = b"catAttrs";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::DirectBinary(DirectBinaryPrimOp::CatAttrs);
}

pub(crate) struct CeilBuiltin;
impl BuiltinDefinition for CeilBuiltin {
    const NAME: &'static [u8] = b"ceil";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Ceil);
}

pub(crate) struct CompareVersionsBuiltin;
impl BuiltinDefinition for CompareVersionsBuiltin {
    const NAME: &'static [u8] = b"compareVersions";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_binary(StrictBinaryPrimOp::CompareVersions);
}

pub(crate) struct ConcatListsBuiltin;
impl BuiltinDefinition for ConcatListsBuiltin {
    const NAME: &'static [u8] = b"concatLists";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::ConcatLists);
}

pub(crate) struct ConcatMapBuiltin;
impl BuiltinDefinition for ConcatMapBuiltin {
    const NAME: &'static [u8] = b"concatMap";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_binary(StrictBinaryPrimOp::ConcatMap);
}

pub(crate) struct ConcatStringsSepBuiltin;
impl BuiltinDefinition for ConcatStringsSepBuiltin {
    const NAME: &'static [u8] = b"concatStringsSep";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::DirectBinary(DirectBinaryPrimOp::ConcatStringsSep);
}

pub(crate) struct ConvertHashBuiltin;
impl BuiltinDefinition for ConvertHashBuiltin {
    const NAME: &'static [u8] = b"convertHash";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::ConvertHash);
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
}

pub(crate) struct DeepSeqBuiltin;
impl BuiltinDefinition for DeepSeqBuiltin {
    const NAME: &'static [u8] = b"deepSeq";
    const EXECUTION: BuiltinExecution = BuiltinExecution::DeepSeq;
}

pub(crate) struct DerivationBuiltin;
impl BuiltinDefinition for DerivationBuiltin {
    const NAME: &'static [u8] = b"derivation";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct DerivationStrictBuiltin;
impl BuiltinDefinition for DerivationStrictBuiltin {
    const NAME: &'static [u8] = b"derivationStrict";
    const EXECUTION: BuiltinExecution = BuiltinExecution::DerivationStrict;
}

pub(crate) struct DirOfBuiltin;
impl BuiltinDefinition for DirOfBuiltin {
    const NAME: &'static [u8] = b"dirOf";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::DirOf);
}

pub(crate) struct DivBuiltin;
impl BuiltinDefinition for DivBuiltin {
    const NAME: &'static [u8] = b"div";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Div);
}

pub(crate) struct ElemBuiltin;
impl BuiltinDefinition for ElemBuiltin {
    const NAME: &'static [u8] = b"elem";
    const EXECUTION: BuiltinExecution = BuiltinExecution::DirectBinary(DirectBinaryPrimOp::Elem);
}

pub(crate) struct ElemAtBuiltin;
impl BuiltinDefinition for ElemAtBuiltin {
    const NAME: &'static [u8] = b"elemAt";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::ElemAt);
}

pub(crate) struct FalseBuiltin;
impl BuiltinDefinition for FalseBuiltin {
    const NAME: &'static [u8] = b"false";
    const EXECUTION: BuiltinExecution = BuiltinExecution::FalseValue;
}

pub(crate) struct FetchGitBuiltin;
impl BuiltinDefinition for FetchGitBuiltin {
    const NAME: &'static [u8] = b"fetchGit";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct FetchMercurialBuiltin;
impl BuiltinDefinition for FetchMercurialBuiltin {
    const NAME: &'static [u8] = b"fetchMercurial";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct FetchTarballBuiltin;
impl BuiltinDefinition for FetchTarballBuiltin {
    const NAME: &'static [u8] = b"fetchTarball";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct FetchTreeBuiltin;
impl BuiltinDefinition for FetchTreeBuiltin {
    const NAME: &'static [u8] = b"fetchTree";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct FetchurlBuiltin;
impl BuiltinDefinition for FetchurlBuiltin {
    const NAME: &'static [u8] = b"fetchurl";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct FilterBuiltin;
impl BuiltinDefinition for FilterBuiltin {
    const NAME: &'static [u8] = b"filter";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Filter);
}

pub(crate) struct FilterSourceBuiltin;
impl BuiltinDefinition for FilterSourceBuiltin {
    const NAME: &'static [u8] = b"filterSource";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct FindFileBuiltin;
impl BuiltinDefinition for FindFileBuiltin {
    const NAME: &'static [u8] = b"findFile";
    const EXECUTION: BuiltinExecution = BuiltinExecution::FindFile;
}

pub(crate) struct FlakeRefToStringBuiltin;
impl BuiltinDefinition for FlakeRefToStringBuiltin {
    const NAME: &'static [u8] = b"flakeRefToString";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct FloorBuiltin;
impl BuiltinDefinition for FloorBuiltin {
    const NAME: &'static [u8] = b"floor";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Floor);
}

pub(crate) struct FoldlStrictBuiltin;
impl BuiltinDefinition for FoldlStrictBuiltin {
    const NAME: &'static [u8] = b"foldl'";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::DirectTernary(StrictTernaryPrimOp::FoldlStrict);
}

pub(crate) struct FromJsonBuiltin;
impl BuiltinDefinition for FromJsonBuiltin {
    const NAME: &'static [u8] = b"fromJSON";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::FromJson);
}

pub(crate) struct FromTomlBuiltin;
impl BuiltinDefinition for FromTomlBuiltin {
    const NAME: &'static [u8] = b"fromTOML";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::FromToml);
}

pub(crate) struct FunctionArgsBuiltin;
impl BuiltinDefinition for FunctionArgsBuiltin {
    const NAME: &'static [u8] = b"functionArgs";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::FunctionArgs);
}

pub(crate) struct GenListBuiltin;
impl BuiltinDefinition for GenListBuiltin {
    const NAME: &'static [u8] = b"genList";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_binary(StrictBinaryPrimOp::GenList);
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
}

pub(crate) struct GetContextBuiltin;
impl BuiltinDefinition for GetContextBuiltin {
    const NAME: &'static [u8] = b"getContext";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::GetContext);
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
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct GroupByBuiltin;
impl BuiltinDefinition for GroupByBuiltin {
    const NAME: &'static [u8] = b"groupBy";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_binary(StrictBinaryPrimOp::GroupBy);
}

pub(crate) struct HasAttrBuiltin;
impl BuiltinDefinition for HasAttrBuiltin {
    const NAME: &'static [u8] = b"hasAttr";
    const EXECUTION: BuiltinExecution = BuiltinExecution::DirectBinary(DirectBinaryPrimOp::HasAttr);
}

pub(crate) struct HasContextBuiltin;
impl BuiltinDefinition for HasContextBuiltin {
    const NAME: &'static [u8] = b"hasContext";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::HasContext);
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
}

pub(crate) struct HeadBuiltin;
impl BuiltinDefinition for HeadBuiltin {
    const NAME: &'static [u8] = b"head";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Head);
}

pub(crate) struct ImportBuiltin;
impl BuiltinDefinition for ImportBuiltin {
    const NAME: &'static [u8] = b"import";
    const EXECUTION: BuiltinExecution = BuiltinExecution::EffectfulUnaryUnsupported;
}

pub(crate) struct IntersectAttrsBuiltin;
impl BuiltinDefinition for IntersectAttrsBuiltin {
    const NAME: &'static [u8] = b"intersectAttrs";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::DirectBinary(DirectBinaryPrimOp::IntersectAttrs);
}

pub(crate) struct IsAttrsBuiltin;
impl BuiltinDefinition for IsAttrsBuiltin {
    const NAME: &'static [u8] = b"isAttrs";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsAttrs);
}

pub(crate) struct IsBoolBuiltin;
impl BuiltinDefinition for IsBoolBuiltin {
    const NAME: &'static [u8] = b"isBool";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsBool);
}

pub(crate) struct IsFloatBuiltin;
impl BuiltinDefinition for IsFloatBuiltin {
    const NAME: &'static [u8] = b"isFloat";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsFloat);
}

pub(crate) struct IsFunctionBuiltin;
impl BuiltinDefinition for IsFunctionBuiltin {
    const NAME: &'static [u8] = b"isFunction";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsFunction);
}

pub(crate) struct IsIntBuiltin;
impl BuiltinDefinition for IsIntBuiltin {
    const NAME: &'static [u8] = b"isInt";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsInt);
}

pub(crate) struct IsListBuiltin;
impl BuiltinDefinition for IsListBuiltin {
    const NAME: &'static [u8] = b"isList";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsList);
}

pub(crate) struct IsNullBuiltin;
impl BuiltinDefinition for IsNullBuiltin {
    const NAME: &'static [u8] = b"isNull";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsNull);
}

pub(crate) struct IsPathBuiltin;
impl BuiltinDefinition for IsPathBuiltin {
    const NAME: &'static [u8] = b"isPath";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsPath);
}

pub(crate) struct IsStringBuiltin;
impl BuiltinDefinition for IsStringBuiltin {
    const NAME: &'static [u8] = b"isString";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::IsString);
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
}

pub(crate) struct LessThanBuiltin;
impl BuiltinDefinition for LessThanBuiltin {
    const NAME: &'static [u8] = b"lessThan";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_binary(StrictBinaryPrimOp::LessThan);
}

pub(crate) struct ListToAttrsBuiltin;
impl BuiltinDefinition for ListToAttrsBuiltin {
    const NAME: &'static [u8] = b"listToAttrs";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::ListToAttrs);
}

pub(crate) struct MapBuiltin;
impl BuiltinDefinition for MapBuiltin {
    const NAME: &'static [u8] = b"map";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Map);
}

pub(crate) struct MapAttrsBuiltin;
impl BuiltinDefinition for MapAttrsBuiltin {
    const NAME: &'static [u8] = b"mapAttrs";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::DirectBinary(DirectBinaryPrimOp::MapAttrs);
}

pub(crate) struct MatchBuiltin;
impl BuiltinDefinition for MatchBuiltin {
    const NAME: &'static [u8] = b"match";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Match);
}

pub(crate) struct MulBuiltin;
impl BuiltinDefinition for MulBuiltin {
    const NAME: &'static [u8] = b"mul";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Mul);
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
}

pub(crate) struct ParseDrvNameBuiltin;
impl BuiltinDefinition for ParseDrvNameBuiltin {
    const NAME: &'static [u8] = b"parseDrvName";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::ParseDrvName);
}

pub(crate) struct ParseFlakeRefBuiltin;
impl BuiltinDefinition for ParseFlakeRefBuiltin {
    const NAME: &'static [u8] = b"parseFlakeRef";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct PartitionBuiltin;
impl BuiltinDefinition for PartitionBuiltin {
    const NAME: &'static [u8] = b"partition";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_binary(StrictBinaryPrimOp::Partition);
}

pub(crate) struct PathBuiltin;
impl BuiltinDefinition for PathBuiltin {
    const NAME: &'static [u8] = b"path";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
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
}

pub(crate) struct ReplaceStringsBuiltin;
impl BuiltinDefinition for ReplaceStringsBuiltin {
    const NAME: &'static [u8] = b"replaceStrings";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::DirectTernary(StrictTernaryPrimOp::ReplaceStrings);
}

pub(crate) struct ScopedImportBuiltin;
impl BuiltinDefinition for ScopedImportBuiltin {
    const NAME: &'static [u8] = b"scopedImport";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct SeqBuiltin;
impl BuiltinDefinition for SeqBuiltin {
    const NAME: &'static [u8] = b"seq";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Seq;
}

pub(crate) struct SortBuiltin;
impl BuiltinDefinition for SortBuiltin {
    const NAME: &'static [u8] = b"sort";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Sort;
}

pub(crate) struct SplitBuiltin;
impl BuiltinDefinition for SplitBuiltin {
    const NAME: &'static [u8] = b"split";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Split);
}

pub(crate) struct SplitVersionBuiltin;
impl BuiltinDefinition for SplitVersionBuiltin {
    const NAME: &'static [u8] = b"splitVersion";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::SplitVersion);
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
}

pub(crate) struct SubBuiltin;
impl BuiltinDefinition for SubBuiltin {
    const NAME: &'static [u8] = b"sub";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_binary(StrictBinaryPrimOp::Sub);
}

pub(crate) struct SubstringBuiltin;
impl BuiltinDefinition for SubstringBuiltin {
    const NAME: &'static [u8] = b"substring";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::DirectTernary(StrictTernaryPrimOp::Substring);
}

pub(crate) struct TailBuiltin;
impl BuiltinDefinition for TailBuiltin {
    const NAME: &'static [u8] = b"tail";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Tail);
}

pub(crate) struct ThrowBuiltin;
impl BuiltinDefinition for ThrowBuiltin {
    const NAME: &'static [u8] = b"throw";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Throw);
}

pub(crate) struct ToFileBuiltin;
impl BuiltinDefinition for ToFileBuiltin {
    const NAME: &'static [u8] = b"toFile";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
}

pub(crate) struct ToJsonBuiltin;
impl BuiltinDefinition for ToJsonBuiltin {
    const NAME: &'static [u8] = b"toJSON";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::ToJson);
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
}

pub(crate) struct ToXmlBuiltin;
impl BuiltinDefinition for ToXmlBuiltin {
    const NAME: &'static [u8] = b"toXML";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::ToXml);
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
}

pub(crate) struct UnsafeDiscardOutputDependencyBuiltin;
impl BuiltinDefinition for UnsafeDiscardOutputDependencyBuiltin {
    const NAME: &'static [u8] = b"unsafeDiscardOutputDependency";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::UnsafeDiscardOutputDependency);
}

pub(crate) struct UnsafeDiscardStringContextBuiltin;
impl BuiltinDefinition for UnsafeDiscardStringContextBuiltin {
    const NAME: &'static [u8] = b"unsafeDiscardStringContext";
    const EXECUTION: BuiltinExecution =
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::UnsafeDiscardStringContext);
}

pub(crate) struct UnsafeGetAttrPosBuiltin;
impl BuiltinDefinition for UnsafeGetAttrPosBuiltin {
    const NAME: &'static [u8] = b"unsafeGetAttrPos";
    const EXECUTION: BuiltinExecution = BuiltinExecution::Unsupported;
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
}

builtin_registry! {
    AbortBuiltin,
    AddBuiltin,
    AddDrvOutputDependenciesBuiltin,
    AddErrorContextBuiltin,
    AllBuiltin,
    AnyBuiltin,
    AppendContextBuiltin,
    AttrNamesBuiltin,
    AttrValuesBuiltin,
    BaseNameOfBuiltin,
    BitAndBuiltin,
    BitOrBuiltin,
    BitXorBuiltin,
    BreakBuiltin,
    BuiltinsBuiltin,
    CatAttrsBuiltin,
    CeilBuiltin,
    CompareVersionsBuiltin,
    ConcatListsBuiltin,
    ConcatMapBuiltin,
    ConcatStringsSepBuiltin,
    ConvertHashBuiltin,
    CurrentSystemBuiltin,
    CurrentTimeBuiltin,
    DeepSeqBuiltin,
    DerivationBuiltin,
    DerivationStrictBuiltin,
    DirOfBuiltin,
    DivBuiltin,
    ElemBuiltin,
    ElemAtBuiltin,
    FalseBuiltin,
    FetchGitBuiltin,
    FetchMercurialBuiltin,
    FetchTarballBuiltin,
    FetchTreeBuiltin,
    FetchurlBuiltin,
    FilterBuiltin,
    FilterSourceBuiltin,
    FindFileBuiltin,
    FlakeRefToStringBuiltin,
    FloorBuiltin,
    FoldlStrictBuiltin,
    FromJsonBuiltin,
    FromTomlBuiltin,
    FunctionArgsBuiltin,
    GenListBuiltin,
    GenericClosureBuiltin,
    GetAttrBuiltin,
    GetContextBuiltin,
    GetEnvBuiltin,
    GetFlakeBuiltin,
    GroupByBuiltin,
    HasAttrBuiltin,
    HasContextBuiltin,
    HashFileBuiltin,
    HashStringBuiltin,
    HeadBuiltin,
    ImportBuiltin,
    IntersectAttrsBuiltin,
    IsAttrsBuiltin,
    IsBoolBuiltin,
    IsFloatBuiltin,
    IsFunctionBuiltin,
    IsIntBuiltin,
    IsListBuiltin,
    IsNullBuiltin,
    IsPathBuiltin,
    IsStringBuiltin,
    LangVersionBuiltin,
    LengthBuiltin,
    LessThanBuiltin,
    ListToAttrsBuiltin,
    MapBuiltin,
    MapAttrsBuiltin,
    MatchBuiltin,
    MulBuiltin,
    NixPathBuiltin,
    NixVersionBuiltin,
    NullBuiltin,
    ParseDrvNameBuiltin,
    ParseFlakeRefBuiltin,
    PartitionBuiltin,
    PathBuiltin,
    PathExistsBuiltin,
    PlaceholderBuiltin,
    ReadDirBuiltin,
    ReadFileBuiltin,
    ReadFileTypeBuiltin,
    RemoveAttrsBuiltin,
    ReplaceStringsBuiltin,
    ScopedImportBuiltin,
    SeqBuiltin,
    SortBuiltin,
    SplitBuiltin,
    SplitVersionBuiltin,
    StoreDirBuiltin,
    StorePathBuiltin,
    StringLengthBuiltin,
    SubBuiltin,
    SubstringBuiltin,
    TailBuiltin,
    ThrowBuiltin,
    ToFileBuiltin,
    ToJsonBuiltin,
    ToPathBuiltin,
    ToStringBuiltin,
    ToXmlBuiltin,
    TraceBuiltin,
    TraceVerboseBuiltin,
    TrueBuiltin,
    TryEvalBuiltin,
    TypeOfBuiltin,
    UnsafeDiscardOutputDependencyBuiltin,
    UnsafeDiscardStringContextBuiltin,
    UnsafeGetAttrPosBuiltin,
    WarnBuiltin,
    ZipAttrsWithBuiltin,
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

/// Direct lowering metadata for a builtin.
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
    /// The builtin is known but not implemented by the tree-walk evaluator.
    Unsupported,
    /// The builtin lowers as effectful strict unary but reports unsupported at runtime.
    EffectfulUnaryUnsupported,
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
    /// The builtin evaluates `readDir`.
    ReadDir,
    /// The builtin evaluates `readFile`.
    ReadFile,
    /// The builtin evaluates `readFileType`.
    ReadFileType,
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

    /// Returns direct-lowering metadata implied by this execution strategy.
    pub(crate) const fn direct(self) -> Option<BuiltinDirect> {
        match self {
            Self::DerivationStrict => Some(BuiltinDirect::DerivationStrict),
            Self::StrictUnary { effect, .. } => Some(BuiltinDirect::StrictUnary { effect }),
            Self::LazyUnary => Some(BuiltinDirect::LazyUnary {
                effect: BuiltinEffect::Pure,
            }),
            Self::StrictBinary { effect, .. } => Some(BuiltinDirect::StrictBinary { effect }),
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
            Self::EffectfulUnaryUnsupported
            | Self::PathExists
            | Self::ReadDir
            | Self::ReadFile
            | Self::ReadFileType => Some(BuiltinDirect::StrictUnary {
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
            Self::Unsupported
            | Self::TrueValue
            | Self::FalseValue
            | Self::NullValue
            | Self::BuiltinsValue
            | Self::CurrentSystemValue
            | Self::CurrentTimeValue
            | Self::StoreDirValue
            | Self::NixVersionValue
            | Self::LangVersionValue
            | Self::NixPathValue => None,
        }
    }

    /// Returns the arity exposed when this builtin is selected as a value.
    pub(crate) const fn first_class_arity(self) -> Option<usize> {
        match self {
            Self::StrictUnary { .. }
            | Self::LazyUnary
            | Self::GenericClosure
            | Self::TryEval
            | Self::PathExists
            | Self::ReadDir
            | Self::ReadFile
            | Self::ReadFileType => Some(1),
            Self::StrictBinary { .. }
            | Self::AddErrorContext
            | Self::FindFile
            | Self::DirectBinary(_)
            | Self::Sort
            | Self::Seq
            | Self::DeepSeq
            | Self::Trace { .. }
            | Self::Warn => Some(2),
            Self::DirectTernary(_) => Some(3),
            Self::Unsupported
            | Self::EffectfulUnaryUnsupported
            | Self::DerivationStrict
            | Self::BuiltinsValue
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

static TODO_BUILTIN_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Builtin documentation has not been imported yet.",
};

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

/// Static metadata shared by builtin resolution, lowering, and execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BuiltinMetadata {
    name: &'static [u8],
    execution: BuiltinExecution,
    direct: Option<BuiltinDirect>,
    first_class_arity: Option<usize>,
    docs: &'static BuiltinDocs,
}

impl BuiltinMetadata {
    /// Creates builtin metadata.
    const fn new(
        name: &'static [u8],
        execution: BuiltinExecution,
        docs: &'static BuiltinDocs,
    ) -> Self {
        Self {
            name,
            execution,
            direct: execution.direct(),
            first_class_arity: execution.first_class_arity(),
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

    /// Returns direct-lowering metadata for the builtin, if any.
    pub(crate) const fn direct(&self) -> Option<BuiltinDirect> {
        self.direct
    }

    /// Returns the arity exposed when the builtin is selected as a first-class value.
    pub(crate) const fn first_class_arity(&self) -> Option<usize> {
        self.first_class_arity
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
    metadata: &'static [BuiltinMetadata],
    lookup: fn(&[u8]) -> Option<BuiltinMetadata>,
}

impl BuiltinRegistry {
    /// Creates a builtin registry from static metadata.
    const fn new(
        metadata: &'static [BuiltinMetadata],
        lookup: fn(&[u8]) -> Option<BuiltinMetadata>,
    ) -> Self {
        Self { metadata, lookup }
    }

    /// Returns the number of builtin declarations.
    pub(crate) const fn len(&self) -> usize {
        self.metadata.len()
    }

    /// Returns an iterator over builtin metadata.
    pub(crate) fn iter(&self) -> std::slice::Iter<'static, BuiltinMetadata> {
        self.metadata.iter()
    }

    /// Returns shared metadata for a builtin name.
    pub(crate) fn lookup(&self, name: &[u8]) -> Option<BuiltinMetadata> {
        (self.lookup)(name)
    }

    /// Returns direct lowering metadata for a builtin name.
    pub(crate) fn direct(&self, name: &[u8]) -> Option<BuiltinDirect> {
        self.lookup(name).and_then(|metadata| metadata.direct())
    }

    /// Returns whether `name` is a builtin attribute known to this evaluator.
    pub(crate) fn is_known_attr(&self, name: &[u8]) -> bool {
        self.lookup(name).is_some()
    }
}

/// Provides static metadata for a concrete builtin marker type.
trait BuiltinDefinition {
    /// Byte-oriented builtin attribute name.
    const NAME: &'static [u8];

    /// Runtime execution strategy for this builtin.
    const EXECUTION: BuiltinExecution;

    /// Static documentation attached to this builtin.
    const DOCS: &'static BuiltinDocs = &TODO_BUILTIN_DOCS;

    /// Metadata shared by all evaluator tiers for this builtin.
    const METADATA: BuiltinMetadata = BuiltinMetadata::new(Self::NAME, Self::EXECUTION, Self::DOCS);
}

/// Returns direct lowering metadata for a builtin name.
pub(crate) fn direct_builtin(name: &[u8]) -> Option<BuiltinDirect> {
    BUILTINS.direct(name)
}

/// Returns whether `name` is a builtin attribute known to this evaluator.
pub(crate) fn is_known_builtin_attr(name: &[u8]) -> bool {
    BUILTINS.is_known_attr(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn builtin_names_are_unique() {
        let names = BUILTINS
            .iter()
            .map(BuiltinMetadata::name)
            .collect::<BTreeSet<_>>();

        assert_eq!(names.len(), BUILTINS.len());
    }

    #[test]
    fn generated_builtin_lookup_covers_declared_metadata() {
        for metadata in BUILTINS.iter().copied() {
            assert_eq!(BUILTINS.lookup(metadata.name()), Some(metadata));
        }
        assert_eq!(BUILTINS.lookup(b"toXML\0"), None);
        assert_eq!(BUILTINS.lookup(b"foldl"), None);
    }

    #[test]
    fn registry_lists_every_builtin_definition_type() {
        let declared = include_str!("builtins.rs")
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                line.strip_prefix("impl BuiltinDefinition for ")
                    .and_then(|name| name.strip_suffix(" {"))
            })
            .collect::<BTreeSet<_>>();
        let registered = REGISTERED_BUILTIN_TYPES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();

        assert_eq!(declared, registered);
    }

    #[test]
    fn builtin_lookup_helpers_delegate_to_registry() {
        assert!(BUILTINS.is_known_attr(b"length"));
        assert!(is_known_builtin_attr(b"length"));
        assert!(!BUILTINS.is_known_attr(b"__missing"));
        assert!(!is_known_builtin_attr(b"__missing"));
        assert_eq!(direct_builtin(b"length"), BUILTINS.direct(b"length"));
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
    fn direct_builtin_metadata_marks_effectful_boundaries() {
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
    fn builtin_metadata_records_first_class_arity_by_category() {
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
            None
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
            BUILTINS
                .lookup(b"derivationStrict")
                .unwrap()
                .first_class_arity(),
            None
        );
        assert_eq!(BUILTINS.lookup(b"true").unwrap().first_class_arity(), None);
        assert_eq!(
            BUILTINS.lookup(b"fromTOML").unwrap().first_class_arity(),
            Some(1)
        );
    }

    #[test]
    fn custom_builtin_docs_stay_attached_to_metadata() {
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
}
