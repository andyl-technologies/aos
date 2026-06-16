//! Compilation passes from parsed AST to evaluator IR.
//!
//! The compile layer starts with scope resolution: it rewrites expression
//! identifiers into de Bruijn-style variable accesses and records the frame side
//! tables that later lowering, interpretation, and serialization consume.

pub mod scope;

pub use scope::{
    FrameId, FrameInfo, InheritGroupId, InheritResolution, InheritSource, ResolvedAst,
    ResolverOptions, ScopeError, ScopeErrorKind, ScopeResolver, ScopeTables, Upvalue, WithChain,
    WithChainId, resolve,
};
