//! Builtin declarations shared by scope resolution and runtime dispatch.
//!
//! Each entry names a builtin once. The tree-walk evaluator expands the list
//! into trait-backed execution records, and frontend passes expand the same list
//! into known global names and direct-primop lowering metadata.

macro_rules! builtin_definitions {
    ($registry:ident) => {
        $registry! {
            unsupported AbortBuiltin, b"abort";
            strict_binary AddBuiltin, b"add", StrictBinaryPrimOp::Add;
            strict_unary AddDrvOutputDependenciesBuiltin, b"addDrvOutputDependencies", StrictUnaryPrimOp::AddDrvOutputDependencies;
            unsupported AddErrorContextBuiltin, b"addErrorContext";
            direct_binary AllBuiltin, b"all", StrictBinaryPrimOp::All;
            direct_binary AnyBuiltin, b"any", StrictBinaryPrimOp::Any;
            unsupported AppendContextBuiltin, b"appendContext";
            strict_unary AttrNamesBuiltin, b"attrNames", StrictUnaryPrimOp::AttrNames;
            strict_unary AttrValuesBuiltin, b"attrValues", StrictUnaryPrimOp::AttrValues;
            strict_unary BaseNameOfBuiltin, b"baseNameOf", StrictUnaryPrimOp::BaseNameOf;
            strict_binary BitAndBuiltin, b"bitAnd", StrictBinaryPrimOp::BitAnd;
            strict_binary BitOrBuiltin, b"bitOr", StrictBinaryPrimOp::BitOr;
            strict_binary BitXorBuiltin, b"bitXor", StrictBinaryPrimOp::BitXor;
            unsupported BreakBuiltin, b"break";
            unsupported BuiltinsBuiltin, b"builtins";
            direct_binary CatAttrsBuiltin, b"catAttrs", StrictBinaryPrimOp::CatAttrs;
            strict_unary CeilBuiltin, b"ceil", StrictUnaryPrimOp::Ceil;
            strict_binary CompareVersionsBuiltin, b"compareVersions", StrictBinaryPrimOp::CompareVersions;
            strict_unary ConcatListsBuiltin, b"concatLists", StrictUnaryPrimOp::ConcatLists;
            direct_binary ConcatMapBuiltin, b"concatMap", StrictBinaryPrimOp::ConcatMap;
            direct_binary ConcatStringsSepBuiltin, b"concatStringsSep", StrictBinaryPrimOp::ConcatStringsSep;
            strict_unary ConvertHashBuiltin, b"convertHash", StrictUnaryPrimOp::ConvertHash;
            custom_value CurrentSystemBuiltin, b"currentSystem";
            unsupported CurrentTimeBuiltin, b"currentTime";
            strict_lazy_binary DeepSeqBuiltin, b"deepSeq";
            unsupported DerivationBuiltin, b"derivation";
            derivation_strict DerivationStrictBuiltin, b"derivationStrict";
            strict_unary DirOfBuiltin, b"dirOf", StrictUnaryPrimOp::DirOf;
            strict_binary DivBuiltin, b"div", StrictBinaryPrimOp::Div;
            direct_binary ElemBuiltin, b"elem", StrictBinaryPrimOp::Elem;
            direct_binary ElemAtBuiltin, b"elemAt", StrictBinaryPrimOp::ElemAt;
            unsupported ExecBuiltin, b"exec";
            custom_value FalseBuiltin, b"false";
            unsupported FetchClosureBuiltin, b"fetchClosure";
            unsupported FetchGitBuiltin, b"fetchGit";
            unsupported FetchMercurialBuiltin, b"fetchMercurial";
            unsupported FetchTarballBuiltin, b"fetchTarball";
            unsupported FetchTreeBuiltin, b"fetchTree";
            unsupported FetchurlBuiltin, b"fetchurl";
            direct_binary FilterBuiltin, b"filter", StrictBinaryPrimOp::Filter;
            unsupported FilterSourceBuiltin, b"filterSource";
            unsupported FindFileBuiltin, b"findFile";
            unsupported FlakeRefToStringBuiltin, b"flakeRefToString";
            strict_unary FloorBuiltin, b"floor", StrictUnaryPrimOp::Floor;
            direct_ternary FoldlStrictBuiltin, b"foldl'", StrictTernaryPrimOp::FoldlStrict;
            strict_unary FromJsonBuiltin, b"fromJSON", StrictUnaryPrimOp::FromJson;
            unsupported FromTomlBuiltin, b"fromTOML";
            strict_unary FunctionArgsBuiltin, b"functionArgs", StrictUnaryPrimOp::FunctionArgs;
            unsupported GenListBuiltin, b"genList";
            unsupported GenericClosureBuiltin, b"genericClosure";
            direct_binary GetAttrBuiltin, b"getAttr", StrictBinaryPrimOp::GetAttr;
            strict_unary GetContextBuiltin, b"getContext", StrictUnaryPrimOp::GetContext;
            effectful_strict_unary GetEnvBuiltin, b"getEnv", StrictUnaryPrimOp::GetEnv;
            unsupported GetFlakeBuiltin, b"getFlake";
            direct_binary GroupByBuiltin, b"groupBy", StrictBinaryPrimOp::GroupBy;
            direct_binary HasAttrBuiltin, b"hasAttr", StrictBinaryPrimOp::HasAttr;
            strict_unary HasContextBuiltin, b"hasContext", StrictUnaryPrimOp::HasContext;
            effectful_strict_binary HashFileBuiltin, b"hashFile", StrictBinaryPrimOp::HashFile;
            strict_binary HashStringBuiltin, b"hashString", StrictBinaryPrimOp::HashString;
            strict_unary HeadBuiltin, b"head", StrictUnaryPrimOp::Head;
            effectful_unary_unsupported ImportBuiltin, b"import";
            direct_binary IntersectAttrsBuiltin, b"intersectAttrs", StrictBinaryPrimOp::IntersectAttrs;
            strict_unary IsAttrsBuiltin, b"isAttrs", StrictUnaryPrimOp::IsAttrs;
            strict_unary IsBoolBuiltin, b"isBool", StrictUnaryPrimOp::IsBool;
            strict_unary IsFloatBuiltin, b"isFloat", StrictUnaryPrimOp::IsFloat;
            strict_unary IsFunctionBuiltin, b"isFunction", StrictUnaryPrimOp::IsFunction;
            strict_unary IsIntBuiltin, b"isInt", StrictUnaryPrimOp::IsInt;
            strict_unary IsListBuiltin, b"isList", StrictUnaryPrimOp::IsList;
            strict_unary IsNullBuiltin, b"isNull", StrictUnaryPrimOp::IsNull;
            strict_unary IsPathBuiltin, b"isPath", StrictUnaryPrimOp::IsPath;
            strict_unary IsStringBuiltin, b"isString", StrictUnaryPrimOp::IsString;
            unsupported LangVersionBuiltin, b"langVersion";
            strict_unary LengthBuiltin, b"length", StrictUnaryPrimOp::Length;
            strict_binary LessThanBuiltin, b"lessThan", StrictBinaryPrimOp::LessThan;
            strict_unary ListToAttrsBuiltin, b"listToAttrs", StrictUnaryPrimOp::ListToAttrs;
            unsupported MapBuiltin, b"map";
            unsupported MapAttrsBuiltin, b"mapAttrs";
            unsupported MatchBuiltin, b"match";
            strict_binary MulBuiltin, b"mul", StrictBinaryPrimOp::Mul;
            unsupported NixPathBuiltin, b"nixPath";
            unsupported NixVersionBuiltin, b"nixVersion";
            custom_value NullBuiltin, b"null";
            unsupported OutputOfBuiltin, b"outputOf";
            strict_unary ParseDrvNameBuiltin, b"parseDrvName", StrictUnaryPrimOp::ParseDrvName;
            unsupported ParseFlakeRefBuiltin, b"parseFlakeRef";
            direct_binary PartitionBuiltin, b"partition", StrictBinaryPrimOp::Partition;
            unsupported PathBuiltin, b"path";
            custom_effectful_strict_unary PathExistsBuiltin, b"pathExists";
            unsupported PlaceholderBuiltin, b"placeholder";
            custom_effectful_strict_unary ReadDirBuiltin, b"readDir";
            effectful_unary_unsupported ReadFileBuiltin, b"readFile";
            custom_effectful_strict_unary ReadFileTypeBuiltin, b"readFileType";
            direct_binary RemoveAttrsBuiltin, b"removeAttrs", StrictBinaryPrimOp::RemoveAttrs;
            direct_ternary ReplaceStringsBuiltin, b"replaceStrings", StrictTernaryPrimOp::ReplaceStrings;
            unsupported ScopedImportBuiltin, b"scopedImport";
            strict_lazy_binary SeqBuiltin, b"seq";
            unsupported SortBuiltin, b"sort";
            unsupported SplitBuiltin, b"split";
            strict_unary SplitVersionBuiltin, b"splitVersion", StrictUnaryPrimOp::SplitVersion;
            custom_value StoreDirBuiltin, b"storeDir";
            unsupported StorePathBuiltin, b"storePath";
            strict_unary StringLengthBuiltin, b"stringLength", StrictUnaryPrimOp::StringLength;
            strict_binary SubBuiltin, b"sub", StrictBinaryPrimOp::Sub;
            direct_ternary SubstringBuiltin, b"substring", StrictTernaryPrimOp::Substring;
            strict_unary TailBuiltin, b"tail", StrictUnaryPrimOp::Tail;
            unsupported ThrowBuiltin, b"throw";
            unsupported ToFileBuiltin, b"toFile";
            unsupported ToHashFormatBuiltin, b"toHashFormat";
            strict_unary ToJsonBuiltin, b"toJSON", StrictUnaryPrimOp::ToJson;
            unsupported ToPathBuiltin, b"toPath";
            strict_unary ToStringBuiltin, b"toString", StrictUnaryPrimOp::ToString;
            unsupported ToXmlBuiltin, b"toXML";
            unsupported TraceBuiltin, b"trace";
            unsupported TraceVerboseBuiltin, b"traceVerbose";
            custom_value TrueBuiltin, b"true";
            unsupported TryEvalBuiltin, b"tryEval";
            strict_unary TypeOfBuiltin, b"typeOf", StrictUnaryPrimOp::TypeOf;
            strict_unary UnsafeDiscardOutputDependencyBuiltin, b"unsafeDiscardOutputDependency", StrictUnaryPrimOp::UnsafeDiscardOutputDependency;
            strict_unary UnsafeDiscardStringContextBuiltin, b"unsafeDiscardStringContext", StrictUnaryPrimOp::UnsafeDiscardStringContext;
            unsupported UnsafeGetAttrPosBuiltin, b"unsafeGetAttrPos";
            unsupported WarnBuiltin, b"warn";
            unsupported ZipAttrsWithBuiltin, b"zipAttrsWith";
        }
    };
}

pub(crate) use builtin_definitions;

macro_rules! builtin_names {
    ($($kind:ident $ty:ident, $name:expr $(, $primop:expr)?;)*) => {
        &[
            $($name,)*
        ]
    };
}

/// Builtin names recognized by the resolver and evaluator.
pub(crate) const BUILTIN_NAMES: &[&[u8]] = builtin_definitions!(builtin_names);

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
    /// The builtin lowers after two strict arguments.
    StrictBinary { effect: BuiltinEffect },
    /// The builtin lowers after a strict first argument and lazy second argument.
    StrictLazyBinary { effect: BuiltinEffect },
    /// The builtin lowers after three strict arguments.
    StrictTernary { effect: BuiltinEffect },
}

macro_rules! builtin_direct_metadata {
    ($($kind:ident $ty:ident, $name:expr $(, $primop:expr)?;)*) => {
        &[
            $(
                builtin_direct_metadata!(@record $kind, $name $(, $primop)?),
            )*
        ]
    };

    (@record strict_unary, $name:expr, $primop:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure,
            },
        ))
    };

    (@record effectful_unary_unsupported, $name:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful,
            },
        ))
    };

    (@record effectful_strict_unary, $name:expr, $primop:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful,
            },
        ))
    };

    (@record custom_effectful_strict_unary, $name:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful,
            },
        ))
    };

    (@record strict_binary, $name:expr, $primop:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure,
            },
        ))
    };

    (@record effectful_strict_binary, $name:expr, $primop:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful,
            },
        ))
    };

    (@record direct_binary, $name:expr, $primop:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure,
            },
        ))
    };

    (@record strict_lazy_binary, $name:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Pure,
            },
        ))
    };

    (@record direct_ternary, $name:expr, $primop:expr) => {
        Some((
            $name,
            BuiltinDirect::StrictTernary {
                effect: BuiltinEffect::Pure,
            },
        ))
    };

    (@record derivation_strict, $name:expr) => {
        Some(($name, BuiltinDirect::DerivationStrict))
    };

    (@record unsupported, $name:expr) => {
        None
    };

    (@record custom_value, $name:expr) => {
        None
    };
}

const BUILTIN_DIRECT_METADATA: &[Option<(&[u8], BuiltinDirect)>] =
    builtin_definitions!(builtin_direct_metadata);

/// Returns direct lowering metadata for a builtin name.
pub(crate) fn direct_builtin(name: &[u8]) -> Option<BuiltinDirect> {
    BUILTIN_DIRECT_METADATA
        .iter()
        .flatten()
        .find_map(|(builtin_name, direct)| (*builtin_name == name).then_some(*direct))
}

/// Returns whether `name` is a builtin attribute known to this evaluator.
pub(crate) fn is_known_builtin_attr(name: &[u8]) -> bool {
    BUILTIN_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn builtin_names_are_unique() {
        let names = BUILTIN_NAMES.iter().copied().collect::<BTreeSet<_>>();

        assert_eq!(names.len(), BUILTIN_NAMES.len());
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
            direct_builtin(b"hashFile"),
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful
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
            direct_builtin(b"readFileType"),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        assert_eq!(
            direct_builtin(b"seq"),
            Some(BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(
            direct_builtin(b"substring"),
            Some(BuiltinDirect::StrictTernary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(direct_builtin(b"fromTOML"), None);
    }
}
