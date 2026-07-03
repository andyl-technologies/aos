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
