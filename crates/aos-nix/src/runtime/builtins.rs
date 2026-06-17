//! Builtin declarations shared by scope resolution and runtime dispatch.
//!
//! Each entry names a builtin once. The tree-walk evaluator expands the list
//! into trait-backed execution records, and frontend passes expand the same list
//! into known global names and direct-primop lowering metadata.

macro_rules! builtin_definitions {
    ($registry:ident) => {
        $registry! {
            strict_unary AbortBuiltin, b"abort", StrictUnaryPrimOp::Abort;
            strict_binary AddBuiltin, b"add", StrictBinaryPrimOp::Add;
            strict_unary AddDrvOutputDependenciesBuiltin, b"addDrvOutputDependencies", StrictUnaryPrimOp::AddDrvOutputDependencies;
            unsupported AddErrorContextBuiltin, b"addErrorContext";
            strict_binary AllBuiltin, b"all", StrictBinaryPrimOp::All;
            strict_binary AnyBuiltin, b"any", StrictBinaryPrimOp::Any;
            unsupported AppendContextBuiltin, b"appendContext";
            strict_unary AttrNamesBuiltin, b"attrNames", StrictUnaryPrimOp::AttrNames;
            strict_unary AttrValuesBuiltin, b"attrValues", StrictUnaryPrimOp::AttrValues;
            strict_unary BaseNameOfBuiltin, b"baseNameOf", StrictUnaryPrimOp::BaseNameOf;
            strict_binary BitAndBuiltin, b"bitAnd", StrictBinaryPrimOp::BitAnd;
            strict_binary BitOrBuiltin, b"bitOr", StrictBinaryPrimOp::BitOr;
            strict_binary BitXorBuiltin, b"bitXor", StrictBinaryPrimOp::BitXor;
            lazy_unary BreakBuiltin, b"break";
            unsupported BuiltinsBuiltin, b"builtins";
            direct_binary CatAttrsBuiltin, b"catAttrs", DirectBinaryPrimOp::CatAttrs;
            strict_unary CeilBuiltin, b"ceil", StrictUnaryPrimOp::Ceil;
            strict_binary CompareVersionsBuiltin, b"compareVersions", StrictBinaryPrimOp::CompareVersions;
            strict_unary ConcatListsBuiltin, b"concatLists", StrictUnaryPrimOp::ConcatLists;
            strict_binary ConcatMapBuiltin, b"concatMap", StrictBinaryPrimOp::ConcatMap;
            direct_binary ConcatStringsSepBuiltin, b"concatStringsSep", DirectBinaryPrimOp::ConcatStringsSep;
            strict_unary ConvertHashBuiltin, b"convertHash", StrictUnaryPrimOp::ConvertHash;
            custom_value CurrentSystemBuiltin, b"currentSystem";
            custom_value CurrentTimeBuiltin, b"currentTime";
            strict_lazy_binary DeepSeqBuiltin, b"deepSeq";
            unsupported DerivationBuiltin, b"derivation";
            derivation_strict DerivationStrictBuiltin, b"derivationStrict";
            strict_unary DirOfBuiltin, b"dirOf", StrictUnaryPrimOp::DirOf;
            strict_binary DivBuiltin, b"div", StrictBinaryPrimOp::Div;
            direct_binary ElemBuiltin, b"elem", DirectBinaryPrimOp::Elem;
            strict_binary ElemAtBuiltin, b"elemAt", StrictBinaryPrimOp::ElemAt;
            unsupported ExecBuiltin, b"exec";
            custom_value FalseBuiltin, b"false";
            unsupported FetchClosureBuiltin, b"fetchClosure";
            unsupported FetchGitBuiltin, b"fetchGit";
            unsupported FetchMercurialBuiltin, b"fetchMercurial";
            unsupported FetchTarballBuiltin, b"fetchTarball";
            unsupported FetchTreeBuiltin, b"fetchTree";
            unsupported FetchurlBuiltin, b"fetchurl";
            strict_binary FilterBuiltin, b"filter", StrictBinaryPrimOp::Filter;
            unsupported FilterSourceBuiltin, b"filterSource";
            unsupported FindFileBuiltin, b"findFile";
            unsupported FlakeRefToStringBuiltin, b"flakeRefToString";
            strict_unary FloorBuiltin, b"floor", StrictUnaryPrimOp::Floor;
            direct_ternary FoldlStrictBuiltin, b"foldl'", StrictTernaryPrimOp::FoldlStrict;
            strict_unary FromJsonBuiltin, b"fromJSON", StrictUnaryPrimOp::FromJson;
            unsupported FromTomlBuiltin, b"fromTOML";
            strict_unary FunctionArgsBuiltin, b"functionArgs", StrictUnaryPrimOp::FunctionArgs;
            strict_binary GenListBuiltin, b"genList", StrictBinaryPrimOp::GenList;
            unsupported GenericClosureBuiltin, b"genericClosure";
            direct_binary GetAttrBuiltin, b"getAttr", DirectBinaryPrimOp::GetAttr;
            strict_unary GetContextBuiltin, b"getContext", StrictUnaryPrimOp::GetContext;
            effectful_strict_unary GetEnvBuiltin, b"getEnv", StrictUnaryPrimOp::GetEnv;
            unsupported GetFlakeBuiltin, b"getFlake";
            strict_binary GroupByBuiltin, b"groupBy", StrictBinaryPrimOp::GroupBy;
            direct_binary HasAttrBuiltin, b"hasAttr", DirectBinaryPrimOp::HasAttr;
            strict_unary HasContextBuiltin, b"hasContext", StrictUnaryPrimOp::HasContext;
            effectful_strict_binary HashFileBuiltin, b"hashFile", StrictBinaryPrimOp::HashFile;
            strict_binary HashStringBuiltin, b"hashString", StrictBinaryPrimOp::HashString;
            strict_unary HeadBuiltin, b"head", StrictUnaryPrimOp::Head;
            effectful_unary_unsupported ImportBuiltin, b"import";
            direct_binary IntersectAttrsBuiltin, b"intersectAttrs", DirectBinaryPrimOp::IntersectAttrs;
            strict_unary IsAttrsBuiltin, b"isAttrs", StrictUnaryPrimOp::IsAttrs;
            strict_unary IsBoolBuiltin, b"isBool", StrictUnaryPrimOp::IsBool;
            strict_unary IsFloatBuiltin, b"isFloat", StrictUnaryPrimOp::IsFloat;
            strict_unary IsFunctionBuiltin, b"isFunction", StrictUnaryPrimOp::IsFunction;
            strict_unary IsIntBuiltin, b"isInt", StrictUnaryPrimOp::IsInt;
            strict_unary IsListBuiltin, b"isList", StrictUnaryPrimOp::IsList;
            strict_unary IsNullBuiltin, b"isNull", StrictUnaryPrimOp::IsNull;
            strict_unary IsPathBuiltin, b"isPath", StrictUnaryPrimOp::IsPath;
            strict_unary IsStringBuiltin, b"isString", StrictUnaryPrimOp::IsString;
            custom_value LangVersionBuiltin, b"langVersion";
            strict_unary LengthBuiltin, b"length", StrictUnaryPrimOp::Length;
            strict_binary LessThanBuiltin, b"lessThan", StrictBinaryPrimOp::LessThan;
            strict_unary ListToAttrsBuiltin, b"listToAttrs", StrictUnaryPrimOp::ListToAttrs;
            strict_binary MapBuiltin, b"map", StrictBinaryPrimOp::Map;
            unsupported MapAttrsBuiltin, b"mapAttrs";
            unsupported MatchBuiltin, b"match";
            strict_binary MulBuiltin, b"mul", StrictBinaryPrimOp::Mul;
            unsupported NixPathBuiltin, b"nixPath";
            custom_value NixVersionBuiltin, b"nixVersion";
            custom_value NullBuiltin, b"null";
            unsupported OutputOfBuiltin, b"outputOf";
            strict_unary ParseDrvNameBuiltin, b"parseDrvName", StrictUnaryPrimOp::ParseDrvName;
            unsupported ParseFlakeRefBuiltin, b"parseFlakeRef";
            strict_binary PartitionBuiltin, b"partition", StrictBinaryPrimOp::Partition;
            unsupported PathBuiltin, b"path";
            custom_effectful_strict_unary PathExistsBuiltin, b"pathExists";
            unsupported PlaceholderBuiltin, b"placeholder";
            custom_effectful_strict_unary ReadDirBuiltin, b"readDir";
            custom_effectful_strict_unary ReadFileBuiltin, b"readFile";
            custom_effectful_strict_unary ReadFileTypeBuiltin, b"readFileType";
            direct_binary RemoveAttrsBuiltin, b"removeAttrs", DirectBinaryPrimOp::RemoveAttrs;
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
            strict_unary ThrowBuiltin, b"throw", StrictUnaryPrimOp::Throw;
            unsupported ToFileBuiltin, b"toFile";
            unsupported ToHashFormatBuiltin, b"toHashFormat";
            strict_unary ToJsonBuiltin, b"toJSON", StrictUnaryPrimOp::ToJson;
            unsupported ToPathBuiltin, b"toPath";
            strict_unary ToStringBuiltin, b"toString", StrictUnaryPrimOp::ToString;
            unsupported ToXmlBuiltin, b"toXML";
            unsupported TraceBuiltin, b"trace";
            unsupported TraceVerboseBuiltin, b"traceVerbose";
            custom_value TrueBuiltin, b"true";
            custom_strict_unary TryEvalBuiltin, b"tryEval";
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
    /// The builtin lowers after three strict arguments.
    StrictTernary { effect: BuiltinEffect },
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

static PATH_EXISTS_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns whether a path exists at evaluation time.",
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

static TRY_EVAL_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Evaluates an expression to WHNF and reports catchable failures.",
};

/// Static metadata shared by builtin resolution, lowering, and execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BuiltinMetadata {
    name: &'static [u8],
    direct: Option<BuiltinDirect>,
    first_class_arity: Option<usize>,
    docs: &'static BuiltinDocs,
}

impl BuiltinMetadata {
    /// Creates builtin metadata.
    const fn new(
        name: &'static [u8],
        direct: Option<BuiltinDirect>,
        first_class_arity: Option<usize>,
        docs: &'static BuiltinDocs,
    ) -> Self {
        Self {
            name,
            direct,
            first_class_arity,
            docs,
        }
    }

    /// Returns the byte-oriented builtin attribute name.
    pub(crate) const fn name(&self) -> &'static [u8] {
        self.name
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
    pub(crate) const fn docs(&self) -> &'static BuiltinDocs {
        self.docs
    }
}

/// Provides static metadata for a concrete builtin marker type.
pub(crate) trait BuiltinInfo {
    /// Metadata shared by all evaluator tiers for this builtin.
    const METADATA: BuiltinMetadata;
}

macro_rules! builtin_metadata {
    ($($kind:ident $ty:ident, $name:expr $(, $primop:expr)?;)*) => {
        &[
            $(
                <$ty as BuiltinInfo>::METADATA,
            )*
        ]
    };

    (@record strict_unary, $ty:ident, $name:expr, $primop:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure,
            }),
            Some(1),
            builtin_metadata!(@docs $ty),
        )
    };

    (@record custom_strict_unary, $ty:ident, $name:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Pure,
            }),
            Some(1),
            builtin_metadata!(@docs $ty),
        )
    };

    (@record lazy_unary, $ty:ident, $name:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::LazyUnary {
                effect: BuiltinEffect::Pure,
            }),
            Some(1),
            builtin_metadata!(@docs $ty),
        )
    };

    (@record effectful_unary_unsupported, $ty:ident, $name:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful,
            }),
            None,
            builtin_metadata!(@docs $ty),
        )
    };

    (@record effectful_strict_unary, $ty:ident, $name:expr, $primop:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful,
            }),
            Some(1),
            builtin_metadata!(@docs $ty),
        )
    };

    (@record custom_effectful_strict_unary, $ty:ident, $name:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful,
            }),
            Some(1),
            builtin_metadata!(@docs $ty),
        )
    };

    (@record strict_binary, $ty:ident, $name:expr, $primop:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure,
            }),
            Some(2),
            builtin_metadata!(@docs $ty),
        )
    };

    (@record effectful_strict_binary, $ty:ident, $name:expr, $primop:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Effectful,
            }),
            Some(2),
            builtin_metadata!(@docs $ty),
        )
    };

    (@record direct_binary, $ty:ident, $name:expr, $primop:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictBinary {
                effect: BuiltinEffect::Pure,
            }),
            None,
            builtin_metadata!(@docs $ty),
        )
    };

    (@record strict_lazy_binary, $ty:ident, $name:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictLazyBinary {
                effect: BuiltinEffect::Pure,
            }),
            Some(2),
            builtin_metadata!(@docs $ty),
        )
    };

    (@record direct_ternary, $ty:ident, $name:expr, $primop:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::StrictTernary {
                effect: BuiltinEffect::Pure,
            }),
            None,
            builtin_metadata!(@docs $ty),
        )
    };

    (@record derivation_strict, $ty:ident, $name:expr) => {
        BuiltinMetadata::new(
            $name,
            Some(BuiltinDirect::DerivationStrict),
            None,
            builtin_metadata!(@docs $ty),
        )
    };

    (@record unsupported, $ty:ident, $name:expr) => {
        BuiltinMetadata::new($name, None, None, builtin_metadata!(@docs $ty))
    };

    (@record custom_value, $ty:ident, $name:expr) => {
        BuiltinMetadata::new($name, None, None, builtin_metadata!(@docs $ty))
    };

    (@docs PathExistsBuiltin) => {
        &PATH_EXISTS_DOCS
    };

    (@docs ReadDirBuiltin) => {
        &READ_DIR_DOCS
    };

    (@docs ReadFileBuiltin) => {
        &READ_FILE_DOCS
    };

    (@docs ReadFileTypeBuiltin) => {
        &READ_FILE_TYPE_DOCS
    };

    (@docs TryEvalBuiltin) => {
        &TRY_EVAL_DOCS
    };

    (@docs $ty:ident) => {
        &TODO_BUILTIN_DOCS
    };
}

macro_rules! builtin_marker_types {
    ($($kind:ident $ty:ident, $name:expr $(, $primop:expr)?;)*) => {
        $(
            pub(crate) struct $ty;

            impl BuiltinInfo for $ty {
                const METADATA: BuiltinMetadata =
                    builtin_metadata!(@record $kind, $ty, $name $(, $primop)?);
            }
        )*
    };
}

builtin_definitions!(builtin_marker_types);

/// Builtin metadata recognized by the resolver and evaluator.
pub(crate) const BUILTIN_METADATA: &[BuiltinMetadata] = builtin_definitions!(builtin_metadata);

/// Returns shared metadata for a builtin name.
pub(crate) fn builtin_metadata(name: &[u8]) -> Option<BuiltinMetadata> {
    BUILTIN_METADATA
        .iter()
        .copied()
        .find(|metadata| metadata.name() == name)
}

/// Returns direct lowering metadata for a builtin name.
pub(crate) fn direct_builtin(name: &[u8]) -> Option<BuiltinDirect> {
    builtin_metadata(name).and_then(|metadata| metadata.direct())
}

/// Returns whether `name` is a builtin attribute known to this evaluator.
pub(crate) fn is_known_builtin_attr(name: &[u8]) -> bool {
    builtin_metadata(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn builtin_names_are_unique() {
        let names = BUILTIN_METADATA
            .iter()
            .map(BuiltinMetadata::name)
            .collect::<BTreeSet<_>>();

        assert_eq!(names.len(), BUILTIN_METADATA.len());
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
            direct_builtin(b"genList"),
            Some(BuiltinDirect::StrictBinary {
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
            direct_builtin(b"substring"),
            Some(BuiltinDirect::StrictTernary {
                effect: BuiltinEffect::Pure
            })
        );
        assert_eq!(direct_builtin(b"fromTOML"), None);
    }

    #[test]
    fn builtin_metadata_records_first_class_arity_by_category() {
        assert_eq!(
            builtin_metadata(b"attrNames").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            builtin_metadata(b"getEnv").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            builtin_metadata(b"break").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            builtin_metadata(b"pathExists").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            builtin_metadata(b"readFile").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            builtin_metadata(b"tryEval").unwrap().first_class_arity(),
            Some(1)
        );
        assert_eq!(
            builtin_metadata(b"import").unwrap().first_class_arity(),
            None
        );
        assert_eq!(
            builtin_metadata(b"add").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"hashFile").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"elemAt").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"map").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"genList").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"filter").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"partition").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"concatMap").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"groupBy").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"all").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"any").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"seq").unwrap().first_class_arity(),
            Some(2)
        );
        assert_eq!(
            builtin_metadata(b"foldl'").unwrap().first_class_arity(),
            None
        );
        assert_eq!(
            builtin_metadata(b"derivationStrict")
                .unwrap()
                .first_class_arity(),
            None
        );
        assert_eq!(builtin_metadata(b"true").unwrap().first_class_arity(), None);
        assert_eq!(
            builtin_metadata(b"fromTOML").unwrap().first_class_arity(),
            None
        );
    }

    #[test]
    fn custom_builtin_docs_stay_attached_to_metadata() {
        assert_eq!(
            builtin_metadata(b"pathExists").unwrap().docs().summary(),
            "Returns whether a path exists at evaluation time."
        );
        assert_eq!(
            builtin_metadata(b"readDir").unwrap().docs().summary(),
            "Returns an attribute set describing a directory's entries."
        );
        assert_eq!(
            builtin_metadata(b"readFile").unwrap().docs().summary(),
            "Returns the contents of a file as a string."
        );
        assert_eq!(
            builtin_metadata(b"readFileType").unwrap().docs().summary(),
            "Returns the filesystem type of a path."
        );
        assert_eq!(
            builtin_metadata(b"tryEval").unwrap().docs().summary(),
            "Evaluates an expression to WHNF and reports catchable failures."
        );
    }
}
