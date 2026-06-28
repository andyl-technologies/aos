//! `ratchet-core` — the core IR, scope resolver, and builtin metadata for the
//! AOS Nix evaluator (RFC-0007 §1.1 Phase 1b).
//!
//! Compilation passes from parsed AST to evaluator IR.
//!
//! The compile layer starts with scope resolution: it rewrites expression
//! identifiers into de Bruijn-style variable accesses and records the frame side
//! tables that later lowering, interpretation, and serialization consume.
//!
//! The `builtins` submodule owns the builtin *metadata* layer — the declaration
//! inventory, name lookup, direct-lowering classification, and the abstract
//! [`builtins::BuiltinExecutor`] adapter trait. Lowering and scope resolution
//! consume this metadata without depending on any concrete evaluator. Runtime
//! tiers (the tree-walk oracle) implement the executor trait and supply the
//! builtin *execution* behavior, so the dependency runs runtime -> compile.

#![forbid(unsafe_code)]

/// Re-export of the parser/AST crate so the moved compile sources can keep
/// resolving their `crate::syntax::…` paths after the crate split.
pub use aos_nix_syntax as syntax;

pub mod builtins;
pub mod ir;
pub mod scope;

pub use ir::{
    Cardinality, Effect, EffectClass, Escape, ExprFacts, Ir, IrArena, IrAttrPathId,
    IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData, IrDialectOp, IrError,
    IrErrorKind, IrFacts, IrId, IrInlineCacheSiteId, IrKind, IrLowerOptions, IrNode, IrShape,
    IrShapeId, IrWithChain, Strictness, all_pure, all_pure_builtin, lower, lower_with_options,
};
pub use scope::{
    FrameId, FrameInfo, InheritGroupId, InheritResolution, InheritSource, ResolvedAst,
    ResolverOptions, ScopeError, ScopeErrorKind, ScopeResolver, ScopeTables, Upvalue, WithChain,
    WithChainId, resolve,
};
