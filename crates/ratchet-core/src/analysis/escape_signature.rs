//! Escape signatures for direct primitive operations.
//!
//! Direct primitive operations need a separate escape table because their IR
//! node kind is too coarse: one [`crate::ir::IrKind::PrimOp`] may return an
//! immediate boolean, a number, an aggregate, a string, or one of its operands.
//! This precursor names only the scalar-returning operations whose result value
//! cannot be a heap object.

use crate::builtins::{
    BuiltinExecution, DirectBinaryPrimOp, StrictBinaryPrimOp, StrictUnaryPrimOp, lookup_builtin,
};
use crate::ir::Escape;

/// Returns the escape signature for a direct primitive operation name.
///
/// Unknown names and builtins whose result may allocate remain
/// [`PrimOpEscapeSignature::Conservative`]. The table is intentionally
/// name/execution-driven rather than keyed only by arity because Nix builtins
/// with the same direct-lowering shape can return very different value classes.
pub fn primop_escape_signature(name: &[u8]) -> PrimOpEscapeSignature {
    let Some(builtin) = lookup_builtin(name) else {
        return PrimOpEscapeSignature::Conservative;
    };
    match builtin.execution() {
        BuiltinExecution::StrictUnary { primop, .. } => strict_unary_signature(primop),
        BuiltinExecution::StrictBinary { primop, .. } => strict_binary_signature(primop),
        BuiltinExecution::DirectBinary(primop) => direct_binary_signature(primop),
        _ => PrimOpEscapeSignature::Conservative,
    }
}

fn strict_unary_signature(primop: StrictUnaryPrimOp) -> PrimOpEscapeSignature {
    match primop {
        StrictUnaryPrimOp::IsAttrs
        | StrictUnaryPrimOp::IsList
        | StrictUnaryPrimOp::IsFunction
        | StrictUnaryPrimOp::IsString
        | StrictUnaryPrimOp::IsInt
        | StrictUnaryPrimOp::IsFloat
        | StrictUnaryPrimOp::IsBool
        | StrictUnaryPrimOp::IsNull
        | StrictUnaryPrimOp::IsPath
        | StrictUnaryPrimOp::Length
        | StrictUnaryPrimOp::Ceil
        | StrictUnaryPrimOp::Floor
        | StrictUnaryPrimOp::HasContext
        | StrictUnaryPrimOp::StringLength => PrimOpEscapeSignature::ImmediateScalar,
        StrictUnaryPrimOp::Abort
        | StrictUnaryPrimOp::TypeOf
        | StrictUnaryPrimOp::AttrNames
        | StrictUnaryPrimOp::AttrValues
        | StrictUnaryPrimOp::Tail
        | StrictUnaryPrimOp::FunctionArgs
        | StrictUnaryPrimOp::Head
        | StrictUnaryPrimOp::GetContext
        | StrictUnaryPrimOp::GetEnv
        | StrictUnaryPrimOp::AddDrvOutputDependencies
        | StrictUnaryPrimOp::UnsafeDiscardOutputDependency
        | StrictUnaryPrimOp::UnsafeDiscardStringContext
        | StrictUnaryPrimOp::Placeholder
        | StrictUnaryPrimOp::StorePath
        | StrictUnaryPrimOp::BaseNameOf
        | StrictUnaryPrimOp::DirOf
        | StrictUnaryPrimOp::ParseDrvName
        | StrictUnaryPrimOp::SplitVersion
        | StrictUnaryPrimOp::FromJson
        | StrictUnaryPrimOp::FromToml
        | StrictUnaryPrimOp::ToPath
        | StrictUnaryPrimOp::ToString
        | StrictUnaryPrimOp::ToJson
        | StrictUnaryPrimOp::ToXml
        | StrictUnaryPrimOp::ConvertHash
        | StrictUnaryPrimOp::ListToAttrs
        | StrictUnaryPrimOp::ConcatLists
        | StrictUnaryPrimOp::Throw => PrimOpEscapeSignature::Conservative,
    }
}

fn strict_binary_signature(primop: StrictBinaryPrimOp) -> PrimOpEscapeSignature {
    match primop {
        StrictBinaryPrimOp::Sub
        | StrictBinaryPrimOp::Mul
        | StrictBinaryPrimOp::Div
        | StrictBinaryPrimOp::BitAnd
        | StrictBinaryPrimOp::BitOr
        | StrictBinaryPrimOp::BitXor
        | StrictBinaryPrimOp::CompareVersions
        | StrictBinaryPrimOp::LessThan
        | StrictBinaryPrimOp::All
        | StrictBinaryPrimOp::Any => PrimOpEscapeSignature::ImmediateScalar,
        StrictBinaryPrimOp::AppendContext
        | StrictBinaryPrimOp::Add
        | StrictBinaryPrimOp::ElemAt
        | StrictBinaryPrimOp::HashString
        | StrictBinaryPrimOp::HashFile
        | StrictBinaryPrimOp::ConcatMap
        | StrictBinaryPrimOp::Filter
        | StrictBinaryPrimOp::GenList
        | StrictBinaryPrimOp::GroupBy
        | StrictBinaryPrimOp::Match
        | StrictBinaryPrimOp::Map
        | StrictBinaryPrimOp::Partition
        | StrictBinaryPrimOp::Split => PrimOpEscapeSignature::Conservative,
    }
}

fn direct_binary_signature(primop: DirectBinaryPrimOp) -> PrimOpEscapeSignature {
    match primop {
        DirectBinaryPrimOp::HasAttr | DirectBinaryPrimOp::Elem => {
            PrimOpEscapeSignature::ImmediateScalar
        }
        DirectBinaryPrimOp::GetAttr
        | DirectBinaryPrimOp::UnsafeGetAttrPos
        | DirectBinaryPrimOp::RemoveAttrs
        | DirectBinaryPrimOp::IntersectAttrs
        | DirectBinaryPrimOp::CatAttrs
        | DirectBinaryPrimOp::ConcatStringsSep
        | DirectBinaryPrimOp::MapAttrs
        | DirectBinaryPrimOp::ZipAttrsWith => PrimOpEscapeSignature::Conservative,
    }
}

/// Escape behavior of a primitive operation result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimOpEscapeSignature {
    /// The primop returns an immediate scalar value rather than a heap object.
    ImmediateScalar,
    /// The primop may allocate or return an existing heap object.
    Conservative,
}

impl PrimOpEscapeSignature {
    /// Returns the fact licensed by this signature.
    pub const fn escape(self) -> Escape {
        match self {
            Self::ImmediateScalar => Escape::NoEscape,
            Self::Conservative => Escape::Escapes,
        }
    }
}

/// Escape behavior of one primitive-operation argument position.
///
/// Signatures answer the S9 primop clause of the per-frame escape analysis:
/// a value flowing only into [`PrimOpArgumentEscape::Consumed`] positions is
/// forced at most once by the operation and is not retained in, or returned
/// as part of, its result — so the reference does not publish the value
/// outside the calling frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimOpArgumentEscape {
    /// The operation forces the argument (at most once) without retaining it.
    Consumed,
    /// The operation may retain, return, or intern the argument.
    Retained,
}

/// Returns the per-argument escape signature for a builtin name, if enabled.
///
/// The table is deliberately allowlist-shaped (R-9): a signature ships only
/// once its property-fuzz harness is green, and every unlisted builtin —
/// including the whole allocating/overloaded surface — returns `None`, which
/// consumers must treat as every argument escaping. The enabled set is the
/// scalar-result surface: those operations return immediate scalars, so
/// nothing can be retained through the result, and none of them interns an
/// argument — except `hasAttr`, whose attribute-name argument crosses the
/// symbol-interning boundary and is therefore [`PrimOpArgumentEscape::Retained`]
/// (the RFC treats to-be-interned values as escapes, §7.3).
pub fn primop_argument_escape_signature(name: &[u8]) -> Option<&'static [PrimOpArgumentEscape]> {
    use PrimOpArgumentEscape::{Consumed, Retained};
    const CONSUMED_1: &[PrimOpArgumentEscape] = &[Consumed];
    const CONSUMED_2: &[PrimOpArgumentEscape] = &[Consumed, Consumed];
    const HAS_ATTR: &[PrimOpArgumentEscape] = &[Retained, Consumed];
    let builtin = lookup_builtin(name)?;
    match builtin.execution() {
        BuiltinExecution::StrictUnary { primop, .. } => match primop {
            StrictUnaryPrimOp::IsAttrs
            | StrictUnaryPrimOp::IsList
            | StrictUnaryPrimOp::IsFunction
            | StrictUnaryPrimOp::IsString
            | StrictUnaryPrimOp::IsInt
            | StrictUnaryPrimOp::IsFloat
            | StrictUnaryPrimOp::IsBool
            | StrictUnaryPrimOp::IsNull
            | StrictUnaryPrimOp::IsPath
            | StrictUnaryPrimOp::Length
            | StrictUnaryPrimOp::Ceil
            | StrictUnaryPrimOp::Floor
            | StrictUnaryPrimOp::HasContext
            | StrictUnaryPrimOp::StringLength => Some(CONSUMED_1),
            _ => None,
        },
        BuiltinExecution::StrictBinary { primop, .. } => match primop {
            StrictBinaryPrimOp::Sub
            | StrictBinaryPrimOp::Mul
            | StrictBinaryPrimOp::Div
            | StrictBinaryPrimOp::BitAnd
            | StrictBinaryPrimOp::BitOr
            | StrictBinaryPrimOp::BitXor
            | StrictBinaryPrimOp::CompareVersions
            | StrictBinaryPrimOp::LessThan
            | StrictBinaryPrimOp::All
            | StrictBinaryPrimOp::Any => Some(CONSUMED_2),
            _ => None,
        },
        BuiltinExecution::DirectBinary(primop) => match primop {
            DirectBinaryPrimOp::HasAttr => Some(HAS_ATTR),
            DirectBinaryPrimOp::Elem => Some(CONSUMED_2),
            _ => None,
        },
        _ => None,
    }
}
