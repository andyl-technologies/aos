//! Builtin declaration types: execution strategy, effect classes, the shared
//! [`Builtin`] record, the [`BuiltinExecutor`] dispatch trait, the
//! [`BuiltinRegistry`], and the `BuiltinDefinition` declaration trait.

use super::*;
use crate::runtime_abi::BuiltinRuntimeSymbol;

/// The observable effect class for a direct builtin boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinEffect {
    /// The builtin is pure for IR speculation and caching.
    Pure,
    /// The builtin can observe the filesystem, environment, or evaluator state.
    Effectful,
}

/// Direct lowering behavior for a builtin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinDirect {
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

impl BuiltinDirect {
    /// Returns the number of arguments consumed by a direct-lowered call.
    pub const fn arity(self) -> usize {
        match self {
            Self::DerivationStrict | Self::StrictUnary { .. } | Self::LazyUnary { .. } => 1,
            Self::StrictBinary { .. }
            | Self::StrictLazyBinary { .. }
            | Self::LazyStrictBinary { .. }
            | Self::Sort { .. } => 2,
            Self::StrictTernary { .. } => 3,
        }
    }
}

/// Runtime execution strategy attached to a concrete builtin declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinExecution {
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
            | Self::GetFlake
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
            | Self::NixPathValue => None,
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
pub enum NativeCliFallbackFeature {
    /// Evaluation must defer because the builtin can observe CLI/runtime state.
    CliSensitiveBuiltinEvaluation,
    /// Evaluation must defer because the builtin belongs to flake evaluation.
    Flakes,
}

impl NativeCliFallbackFeature {
    /// Returns the diagnostic feature label for this fallback class.
    pub const fn label(self) -> &'static str {
        match self {
            Self::CliSensitiveBuiltinEvaluation => "CLI-sensitive builtin evaluation",
            Self::Flakes => "flakes",
        }
    }
}

/// Contextual availability of a builtin in the reified `builtins` attrset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinAvailability {
    /// The builtin is always present.
    Always,
    /// The builtin is present only in impure mode when `currentSystem` is set.
    ImpureCurrentSystem,
    /// The builtin is present only in impure mode when `currentTime` is set.
    ImpureCurrentTime,
}

/// Output mode for trace-like builtins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceMode {
    /// `builtins.trace` always emits its message.
    Always,
    /// `builtins.traceVerbose` emits only when verbose tracing is enabled.
    Verbose,
}

/// Strict unary primitive operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictUnaryPrimOp {
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
pub enum StrictTernaryPrimOp {
    FoldlStrict,
    ReplaceStrings,
    Substring,
}

/// Strict binary primitive operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictBinaryPrimOp {
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
pub enum DirectBinaryPrimOp {
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

/// How a builtin's spelling participates in top-level name resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinNameScope {
    /// The builtin is reachable through the `builtins` attribute set.
    BuiltinsAttrOnly,
    /// The builtin is also a top-level name that active `with` scopes cannot shadow.
    UnshadowableGlobal,
}

/// Source location and symbol metadata for one builtin call site.
#[derive(Clone, Copy, Debug)]
pub struct BuiltinCall {
    /// The IR node that performs the call.
    pub id: IrId,
    /// The source span reported for call-level diagnostics.
    pub span: Span,
    /// The source symbol used for builtin diagnostics.
    pub symbol: Symbol,
}

impl BuiltinCall {
    /// Creates builtin call metadata from a lowered call site.
    pub const fn new(id: IrId, span: Span, symbol: Symbol) -> Self {
        Self { id, span, symbol }
    }
}

/// A builtin declaration shared by resolution, lowering, and execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Builtin {
    pub(crate) kind: BuiltinKind,
    name: &'static [u8],
    execution: BuiltinExecution,
    pub(super) direct: Option<BuiltinDirect>,
    pub(super) first_class_arity: Option<usize>,
    pub(super) availability: BuiltinAvailability,
    name_scope: BuiltinNameScope,
    pub(super) native_cli_fallback_feature: Option<NativeCliFallbackFeature>,
    docs: &'static BuiltinDocs,
}

impl Builtin {
    /// Creates a builtin declaration.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        kind: BuiltinKind,
        name: &'static [u8],
        execution: BuiltinExecution,
        direct: Option<BuiltinDirect>,
        first_class_arity: Option<usize>,
        availability: BuiltinAvailability,
        name_scope: BuiltinNameScope,
        native_cli_fallback_feature: Option<NativeCliFallbackFeature>,
        docs: &'static BuiltinDocs,
    ) -> Self {
        Self {
            kind,
            name,
            execution,
            direct,
            first_class_arity,
            availability,
            name_scope,
            native_cli_fallback_feature,
            docs,
        }
    }

    /// Returns the byte-oriented builtin attribute name.
    pub const fn name(&self) -> &'static [u8] {
        self.name
    }

    /// Returns the discriminant identifying this builtin declaration.
    ///
    /// The kind is a stable, `Copy` handle to the declaration: every field of a
    /// [`Builtin`] is a compile-time constant of its kind, so [`Builtin::from_kind`]
    /// reconstructs the identical declaration. Call-site resolution caches store
    /// the kind rather than the wider record.
    pub const fn kind(&self) -> BuiltinKind {
        self.kind
    }

    /// Returns the stable runtime/JIT symbol name view for this builtin.
    pub const fn runtime_symbol(&self) -> BuiltinRuntimeSymbol {
        BuiltinRuntimeSymbol::new(self.name)
    }

    /// Returns the runtime execution strategy for the builtin.
    pub const fn execution(&self) -> BuiltinExecution {
        self.execution
    }

    /// Returns direct-lowering behavior for the builtin, if any.
    pub const fn direct(&self) -> Option<BuiltinDirect> {
        self.direct
    }

    /// Returns the arity exposed when the builtin is selected as a first-class value.
    pub const fn first_class_arity(&self) -> Option<usize> {
        self.first_class_arity
    }

    /// Creates a test-only builtin with explicit direct and first-class arity metadata.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn test_with_call_arities(
        direct: Option<BuiltinDirect>,
        first_class_arity: Option<usize>,
    ) -> Self {
        Self::new(
            BuiltinKind::LengthBuiltin,
            b"__testBuiltin",
            BuiltinExecution::strict_unary(StrictUnaryPrimOp::Length),
            direct,
            first_class_arity,
            BuiltinAvailability::Always,
            BuiltinNameScope::BuiltinsAttrOnly,
            None,
            &TEST_BUILTIN_DOCS,
        )
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
    pub const fn availability(&self) -> BuiltinAvailability {
        self.availability
    }

    /// Returns the diagnostic feature label when native JSON evaluation must fall back.
    pub const fn native_cli_fallback_feature(&self) -> Option<&'static str> {
        match self.native_cli_fallback_feature_kind() {
            Some(feature) => Some(feature.label()),
            None => None,
        }
    }

    /// Returns the native JSON fallback class for this builtin.
    const fn native_cli_fallback_feature_kind(&self) -> Option<NativeCliFallbackFeature> {
        self.native_cli_fallback_feature
    }

    /// Returns the static documentation attached to the builtin.
    #[allow(dead_code)]
    pub const fn docs(&self) -> &'static BuiltinDocs {
        self.docs
    }
}

/// Adapter implemented by concrete evaluators that execute builtin strategies.
pub trait BuiltinExecutor {
    /// Value type returned by the executor.
    type Value;

    /// Error type returned by the executor.
    type Error;

    /// First-class argument record forced before a builtin is applied as a value.
    ///
    /// The metadata layer is agnostic to the concrete primop argument type; each
    /// evaluator tier supplies its own (the tree-walk oracle uses
    /// `crate::eval::heap::EvalPrimOpArg`).
    type Arg;

    /// Returns whether `builtin` is visible in the current evaluator options.
    fn builtin_is_available(&self, builtin: Builtin) -> bool;

    /// Selects `builtin` as an attribute or top-level global value.
    ///
    /// # Errors
    ///
    /// Returns an evaluator error when selecting the builtin requires unsupported
    /// ambient state or heap allocation fails.
    fn select_builtin(
        &mut self,
        builtin: Builtin,
        id: IrId,
        span: Span,
        symbol: Symbol,
    ) -> Result<Self::Value, Self::Error>;

    /// Applies `builtin` at a direct lowered IR call site.
    ///
    /// # Errors
    ///
    /// Returns an evaluator error when arity validation fails, argument forcing
    /// fails, or the builtin implementation reports a runtime diagnostic.
    fn apply_builtin_direct(
        &mut self,
        builtin: Builtin,
        call: BuiltinCall,
        node: &IrNode,
        args: &[IrId],
    ) -> Result<Self::Value, Self::Error>;

    /// Applies `builtin` after it has been selected as a first-class value.
    ///
    /// # Errors
    ///
    /// Returns an evaluator error when arity validation fails, argument forcing
    /// fails, or the builtin implementation reports a runtime diagnostic.
    fn apply_builtin(
        &mut self,
        builtin: Builtin,
        call: BuiltinCall,
        args: &[Self::Arg],
    ) -> Result<Self::Value, Self::Error>;
}

/// Registry of builtin declarations known to the evaluator.
#[derive(Clone, Copy, Debug)]
pub struct BuiltinRegistry {
    declarations: &'static [Builtin],
    lookup: &'static BuiltinLookup,
}

impl BuiltinRegistry {
    /// Creates a builtin registry from trait-generated declarations.
    pub(crate) const fn new(
        declarations: &'static [Builtin],
        lookup: &'static BuiltinLookup,
    ) -> Self {
        Self {
            declarations,
            lookup,
        }
    }

    /// Returns the number of builtin declarations.
    pub const fn len(&self) -> usize {
        self.declarations.len()
    }

    /// Returns whether the registry has no builtin declarations.
    pub const fn is_empty(&self) -> bool {
        self.declarations.is_empty()
    }

    /// Returns an iterator over builtin declarations.
    pub fn iter(&self) -> std::slice::Iter<'static, Builtin> {
        self.declarations.iter()
    }

    /// Returns the declaration for a builtin name.
    pub fn lookup(&self, name: &[u8]) -> Option<Builtin> {
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

/// Provides the single static declaration for a concrete builtin marker type.
pub trait BuiltinDefinition {
    /// Generated kind tag tying runtime dispatch to this marker type.
    const KIND: BuiltinKind;

    /// Byte-oriented builtin attribute name.
    const NAME: &'static [u8];

    /// Runtime execution strategy for this builtin.
    const EXECUTION: BuiltinExecution;

    /// Direct-lowering behavior for this builtin, if any.
    const DIRECT: Option<BuiltinDirect> = Self::EXECUTION.direct();

    /// Arity exposed when this builtin is selected as a first-class value.
    const FIRST_CLASS_ARITY: Option<usize> = Self::EXECUTION.first_class_arity();

    /// Availability policy for the reified `builtins` attrset.
    const AVAILABILITY: BuiltinAvailability = Self::EXECUTION.availability();

    /// Static documentation attached to this builtin.
    const DOCS: &'static BuiltinDocs;

    /// Scope behavior for this builtin's spelling.
    const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::BuiltinsAttrOnly;

    /// Native JSON fallback class for this builtin.
    const NATIVE_CLI_FALLBACK_FEATURE: Option<NativeCliFallbackFeature> =
        Self::EXECUTION.native_cli_fallback_feature();

    /// Declaration shared by all evaluator tiers for this builtin.
    const DECLARATION: Builtin = Builtin::new(
        Self::KIND,
        Self::NAME,
        Self::EXECUTION,
        Self::DIRECT,
        Self::FIRST_CLASS_ARITY,
        Self::AVAILABILITY,
        Self::NAME_SCOPE,
        Self::NATIVE_CLI_FALLBACK_FEATURE,
        Self::DOCS,
    );

    /// Returns whether this builtin is visible in the current evaluator options.
    fn is_available<E>(eval: &E) -> bool
    where
        E: BuiltinExecutor,
    {
        eval.builtin_is_available(Self::DECLARATION)
    }

    /// Selects this builtin as an attribute or top-level global value.
    fn select<E>(eval: &mut E, id: IrId, span: Span, symbol: Symbol) -> Result<E::Value, E::Error>
    where
        E: BuiltinExecutor,
    {
        eval.select_builtin(Self::DECLARATION, id, span, symbol)
    }

    /// Applies this builtin at a direct lowered IR call site.
    fn apply_direct<E>(
        eval: &mut E,
        call: BuiltinCall,
        node: &IrNode,
        args: &[IrId],
    ) -> Result<E::Value, E::Error>
    where
        E: BuiltinExecutor,
    {
        eval.apply_builtin_direct(Self::DECLARATION, call, node, args)
    }

    /// Applies this builtin after it has been selected as a first-class value.
    fn apply<E>(eval: &mut E, call: BuiltinCall, args: &[E::Arg]) -> Result<E::Value, E::Error>
    where
        E: BuiltinExecutor,
    {
        eval.apply_builtin(Self::DECLARATION, call, args)
    }
}
