//! Compilation passes from parsed AST to evaluator IR.
//!
//! The compile layer starts with scope resolution: it rewrites expression
//! identifiers into de Bruijn-style variable accesses and records the frame side
//! tables that later lowering, interpretation, and serialization consume.

pub mod ir;
pub mod scope;

pub use ir::{
    EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrBinding, IrBindingSlice,
    IrChildSlice, IrData, IrError, IrErrorKind, IrId, IrInlineCacheSiteId, IrKind, IrNode, IrShape,
    IrShapeId, lower,
};
pub use scope::{
    FrameId, FrameInfo, InheritGroupId, InheritResolution, InheritSource, ResolvedAst,
    ResolverOptions, ScopeError, ScopeErrorKind, ScopeResolver, ScopeTables, Upvalue, WithChain,
    WithChainId, resolve,
};
