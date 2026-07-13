//! The [`JitLowerError`] type for the tier-1 CLIF lowerer (moved from `lower.rs`).
//!
//! This enumerates every way the shape-directed lowerer can reject an IR body or
//! fail to build a verified Cranelift function, from unsupported node kinds to
//! malformed payloads and verifier failures.

use std::{error::Error, fmt};

use cranelift_codegen::verifier::VerifierErrors;
use ratchet_core::{IrAttrPathId, IrAttrPathSegment, IrData, IrId, IrKind, syntax::BinOpKind};
use ratchet_value::value::{Value, ValueTag};

use crate::abi::JitClifSignatureError;

/// A failure while lowering safe metadata into CLIF.
#[derive(Debug)]
pub enum JitLowerError {
    /// Runtime ABI metadata could not be converted to a CLIF signature.
    Abi(JitClifSignatureError),
    /// Core no longer exposes the runtime helper signature required by lowering.
    MissingRuntimeHelperSignature {
        /// The helper symbol whose frozen runtime-call signature was missing.
        symbol_name: &'static str,
    },
    /// Cranelift rejected the generated CLIF function body.
    Verifier(VerifierErrors),
    /// A compiled constant would embed a relocatable heap address.
    UnsupportedHeapConstant {
        /// The heap-backed value tag rejected before constant-word emission.
        tag: ValueTag,
    },
    /// A constant needs evaluator-owned arena storage on the one-word carrier.
    ArenaBackedConstant {
        /// The value tag whose compressed word cannot be embedded in code.
        tag: ValueTag,
    },
    /// The generated thunk function did not have the expected entry parameter.
    MissingEntryBlockParameter {
        /// The expected entry-block parameter index.
        index: usize,
    },
    /// A generated runtime call did not return the expected number of values.
    InvalidRuntimeCallResultArity {
        /// The helper symbol that was called.
        symbol_name: &'static str,
        /// The expected number of CLIF result values.
        expected: usize,
        /// The actual number of CLIF result values.
        actual: usize,
    },
    /// Generated force safepoint metadata could not be renumbered safely.
    MalformedForceSafepoint {
        /// The failed generated-code invariant.
        reason: &'static str,
    },
    /// The requested IR root was not present in the arena.
    MissingIrNode {
        /// The missing IR root id.
        root: IrId,
    },
    /// The direct thunk-allocation body was not present in the arena.
    MissingIrBody {
        /// The missing IR body id.
        body: IrId,
    },
    /// The requested IR root is outside this precursor's supported subset.
    UnsupportedIrRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is outside this precursor's supported subset.
    UnsupportedIrBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// The requested IR root is not a local-slot read this precursor can lower.
    UnsupportedEnvRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not a local-slot read this precursor can lower.
    UnsupportedEnvBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// The requested IR root is not a local-slot application this precursor can lower.
    UnsupportedApplyRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not a local-slot application this precursor can lower.
    UnsupportedApplyBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// A direct application child was not present in the arena.
    MissingApplyChild {
        /// The missing application child id.
        child: IrId,
    },
    /// A direct application child is not a local-slot read this precursor can lower.
    UnsupportedApplyChild {
        /// The unsupported application child id.
        child: IrId,
        /// The unsupported child node kind.
        kind: IrKind,
    },
    /// The requested IR root is not an attr update this precursor can lower.
    UnsupportedUpdateRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not an attr update this precursor can lower.
    UnsupportedUpdateBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// A binary operator root was not the attr update operator.
    UnsupportedUpdateOp {
        /// The unsupported binary operator.
        op: BinOpKind,
    },
    /// A direct attr update operand was not present in the arena.
    MissingUpdateOperand {
        /// The missing update operand id.
        operand: IrId,
    },
    /// A direct attr update operand is not a local-slot read this precursor can lower.
    UnsupportedUpdateOperand {
        /// The unsupported update operand id.
        operand: IrId,
        /// The unsupported operand node kind.
        kind: IrKind,
    },
    /// The requested IR root is not an attr lookup this precursor can lower.
    UnsupportedAttrRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not an attr lookup this precursor can lower.
    UnsupportedAttrBody {
        /// The unsupported body node kind.
        kind: IrKind,
    },
    /// The attr lookup receiver was not present in the arena.
    MissingAttrReceiver {
        /// The missing receiver node id.
        receiver: IrId,
    },
    /// The attr lookup receiver is not a local-slot read this precursor can lower.
    UnsupportedAttrReceiver {
        /// The unsupported receiver node id.
        receiver: IrId,
        /// The unsupported receiver node kind.
        kind: IrKind,
    },
    /// The attr lookup path was not present in the IR side table.
    MissingAttrPath {
        /// The missing attr-path id.
        path: IrAttrPathId,
    },
    /// The attr lookup path was outside the current single-segment subset.
    UnsupportedAttrPathLength {
        /// The unsupported attr-path id.
        path: IrAttrPathId,
        /// The number of segments found in the attr path.
        len: usize,
    },
    /// The attr lookup path contained a dynamic segment.
    UnsupportedAttrPathSegment {
        /// The unsupported attr-path id.
        path: IrAttrPathId,
        /// The unsupported segment index.
        index: usize,
        /// The unsupported segment.
        segment: IrAttrPathSegment,
    },
    /// Static attr selection with an `or` default is not lowered yet.
    UnsupportedSelectDefault {
        /// The lowered default thunk node.
        default: IrId,
    },
    /// The requested node is not a thunk allocation fact planning can consume.
    UnsupportedThunkFactNode {
        /// The requested node id.
        id: IrId,
        /// The unsupported node kind.
        kind: IrKind,
    },
    /// The IR fact table does not match the arena node count.
    MismatchedIrFactTable {
        /// The number of nodes in the arena.
        node_count: usize,
        /// The number of fact records attached to the IR.
        fact_count: usize,
    },
    /// A thunk allocation points at itself as its body.
    SelfReferentialThunkBody {
        /// The self-referential thunk-allocation node.
        thunk: IrId,
    },
    /// A literal IR node carried payload data that did not match its kind.
    MismatchedConstantData {
        /// The literal node kind.
        kind: IrKind,
        /// The unexpected payload data.
        data: IrData,
    },
    /// A direct thunk-allocation body carried payload data that did not match its kind.
    MismatchedBodyConstantData {
        /// The literal body node kind.
        kind: IrKind,
        /// The unexpected payload data.
        data: IrData,
    },
    /// A supported IR wrapper node carried payload data with the wrong shape.
    MismatchedIrNodeData {
        /// The wrapper node kind.
        kind: IrKind,
        /// The unexpected payload data.
        data: IrData,
        /// The expected payload shape.
        expected: &'static str,
    },
    /// A binary operator is not one the scalar arithmetic tree lowerer handles.
    UnsupportedArithOp {
        /// The unsupported binary operator.
        op: BinOpKind,
    },
    /// A scalar arithmetic tree operand was not present in the arena.
    MissingArithOperand {
        /// The missing operand id.
        operand: IrId,
    },
    /// A scalar arithmetic tree operand shape is not lowerable inline.
    UnsupportedArithOperand {
        /// The unsupported operand id.
        operand: IrId,
        /// The unsupported operand node kind.
        kind: IrKind,
    },
}

impl fmt::Display for JitLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abi(error) => write!(formatter, "{error}"),
            Self::MissingRuntimeHelperSignature { symbol_name } => write!(
                formatter,
                "runtime helper {symbol_name:?} does not have a frozen call signature"
            ),
            Self::Verifier(error) => {
                write!(formatter, "generated CLIF failed verification: {error}")
            }
            Self::UnsupportedHeapConstant { tag } => write!(
                formatter,
                "heap-backed {tag:?} values cannot be embedded as JIT constants"
            ),
            Self::ArenaBackedConstant { tag } => write!(
                formatter,
                "{tag:?} constants require evaluator-owned arena storage on the one-word carrier"
            ),
            Self::MissingEntryBlockParameter { index } => write!(
                formatter,
                "generated thunk function is missing entry-block parameter {index}"
            ),
            Self::InvalidRuntimeCallResultArity {
                symbol_name,
                expected,
                actual,
            } => write!(
                formatter,
                "runtime helper {symbol_name:?} produced {actual} CLIF results, expected {expected}"
            ),
            Self::MalformedForceSafepoint { reason } => {
                write!(formatter, "generated force safepoint is malformed: {reason}")
            }
            Self::MissingIrNode { root } => {
                write!(formatter, "IR root {root:?} is not present in the arena")
            }
            Self::MissingIrBody { body } => {
                write!(
                    formatter,
                    "IR thunk body {body:?} is not present in the arena"
                )
            }
            Self::UnsupportedIrRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by this lowerer"
                )
            }
            Self::UnsupportedIrBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by this lowerer"
                )
            }
            Self::UnsupportedEnvRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by the environment-access lowerer"
                )
            }
            Self::UnsupportedEnvBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the environment-access lowerer"
                )
            }
            Self::UnsupportedApplyRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by the direct-apply lowerer"
                )
            }
            Self::UnsupportedApplyBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the direct-apply lowerer"
                )
            }
            Self::MissingApplyChild { child } => {
                write!(
                    formatter,
                    "IR apply child {child:?} is not present in the arena"
                )
            }
            Self::UnsupportedApplyChild { child, kind } => {
                write!(
                    formatter,
                    "IR apply child {child:?} with kind {kind:?} is not a local-slot read this lowerer can consume"
                )
            }
            Self::UnsupportedUpdateRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by the local-slot attr-update lowerer"
                )
            }
            Self::UnsupportedUpdateBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the local-slot attr-update lowerer"
                )
            }
            Self::UnsupportedUpdateOp { op } => {
                write!(
                    formatter,
                    "IR binary operator {op:?} is not supported by the local-slot attr-update lowerer"
                )
            }
            Self::MissingUpdateOperand { operand } => {
                write!(
                    formatter,
                    "IR attr-update operand {operand:?} is not present in the arena"
                )
            }
            Self::UnsupportedUpdateOperand { operand, kind } => {
                write!(
                    formatter,
                    "IR attr-update operand {operand:?} with kind {kind:?} is not a local-slot read this lowerer can consume"
                )
            }
            Self::UnsupportedAttrRoot { kind } => {
                write!(
                    formatter,
                    "IR root kind {kind:?} is not supported by the static attr-access lowerer"
                )
            }
            Self::UnsupportedAttrBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the static attr-access lowerer"
                )
            }
            Self::MissingAttrReceiver { receiver } => {
                write!(
                    formatter,
                    "IR attr receiver {receiver:?} is not present in the arena"
                )
            }
            Self::UnsupportedAttrReceiver { receiver, kind } => {
                write!(
                    formatter,
                    "IR attr receiver {receiver:?} with kind {kind:?} is not a local-slot read this lowerer can consume"
                )
            }
            Self::MissingAttrPath { path } => {
                write!(formatter, "IR attr path {path:?} is not present")
            }
            Self::UnsupportedAttrPathLength { path, len } => {
                write!(
                    formatter,
                    "IR attr path {path:?} has {len} segments, expected exactly one static segment"
                )
            }
            Self::UnsupportedAttrPathSegment {
                path,
                index,
                segment,
            } => {
                write!(
                    formatter,
                    "IR attr path {path:?} segment {index} is unsupported by the static attr-access lowerer: {segment:?}"
                )
            }
            Self::UnsupportedSelectDefault { default } => {
                write!(
                    formatter,
                    "IR select default {default:?} is not supported by the static attr-access lowerer"
                )
            }
            Self::UnsupportedThunkFactNode { id, kind } => {
                write!(
                    formatter,
                    "IR node {id:?} with kind {kind:?} is not a thunk allocation fact planning can consume"
                )
            }
            Self::MismatchedIrFactTable {
                node_count,
                fact_count,
            } => {
                write!(
                    formatter,
                    "IR fact table has {fact_count} records for {node_count} arena nodes"
                )
            }
            Self::SelfReferentialThunkBody { thunk } => {
                write!(formatter, "IR thunk allocation {thunk:?} points at itself")
            }
            Self::MismatchedConstantData { kind, data } => write!(
                formatter,
                "IR root kind {kind:?} carried incompatible constant payload {data:?}"
            ),
            Self::MismatchedBodyConstantData { kind, data } => write!(
                formatter,
                "IR thunk body kind {kind:?} carried incompatible constant payload {data:?}"
            ),
            Self::MismatchedIrNodeData {
                kind,
                data,
                expected,
            } => write!(
                formatter,
                "IR root kind {kind:?} carried incompatible payload {data:?}, expected {expected}"
            ),
            Self::UnsupportedArithOp { op } => write!(
                formatter,
                "IR binary operator {op:?} is not supported by the scalar arithmetic tree lowerer"
            ),
            Self::MissingArithOperand { operand } => write!(
                formatter,
                "IR arithmetic operand {operand:?} is not present in the arena"
            ),
            Self::UnsupportedArithOperand { operand, kind } => write!(
                formatter,
                "IR arithmetic operand {operand:?} with kind {kind:?} is not lowerable inline"
            ),
        }
    }
}

impl Error for JitLowerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Abi(error) => Some(error),
            Self::Verifier(error) => Some(error),
            Self::UnsupportedHeapConstant { .. }
            | Self::ArenaBackedConstant { .. }
            | Self::MissingRuntimeHelperSignature { .. }
            | Self::MissingEntryBlockParameter { .. }
            | Self::InvalidRuntimeCallResultArity { .. }
            | Self::MalformedForceSafepoint { .. }
            | Self::MissingIrNode { .. }
            | Self::MissingIrBody { .. }
            | Self::UnsupportedIrRoot { .. }
            | Self::UnsupportedIrBody { .. }
            | Self::UnsupportedEnvRoot { .. }
            | Self::UnsupportedEnvBody { .. }
            | Self::UnsupportedApplyRoot { .. }
            | Self::UnsupportedApplyBody { .. }
            | Self::MissingApplyChild { .. }
            | Self::UnsupportedApplyChild { .. }
            | Self::UnsupportedUpdateRoot { .. }
            | Self::UnsupportedUpdateBody { .. }
            | Self::UnsupportedUpdateOp { .. }
            | Self::MissingUpdateOperand { .. }
            | Self::UnsupportedUpdateOperand { .. }
            | Self::UnsupportedAttrRoot { .. }
            | Self::UnsupportedAttrBody { .. }
            | Self::MissingAttrReceiver { .. }
            | Self::UnsupportedAttrReceiver { .. }
            | Self::MissingAttrPath { .. }
            | Self::UnsupportedAttrPathLength { .. }
            | Self::UnsupportedAttrPathSegment { .. }
            | Self::UnsupportedSelectDefault { .. }
            | Self::UnsupportedThunkFactNode { .. }
            | Self::MismatchedIrFactTable { .. }
            | Self::SelfReferentialThunkBody { .. }
            | Self::MismatchedConstantData { .. }
            | Self::MismatchedBodyConstantData { .. }
            | Self::MismatchedIrNodeData { .. }
            | Self::UnsupportedArithOp { .. }
            | Self::MissingArithOperand { .. }
            | Self::UnsupportedArithOperand { .. } => None,
        }
    }
}

/// Rejects values whose embedded payload word could move after compilation.
///
/// # Errors
///
/// Returns [`JitLowerError::UnsupportedHeapConstant`] for every heap-backed
/// value. Inline scalars are safe to embed directly in CLIF.
pub(super) fn validate_embedded_constant(value: Value) -> Result<(), JitLowerError> {
    let tag = value.tag();
    if tag.is_heap() {
        return Err(JitLowerError::UnsupportedHeapConstant { tag });
    }
    Ok(())
}

impl From<JitClifSignatureError> for JitLowerError {
    fn from(error: JitClifSignatureError) -> Self {
        Self::Abi(error)
    }
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use std::ptr::NonNull;

    use ratchet_value::value::HeapObject;

    use super::super::lower_constant_thunk_body;
    use super::*;

    #[test]
    fn constant_lowering_rejects_every_heap_tag_before_clif_payload_emission() {
        let pointer = NonNull::<HeapObject>::dangling();
        for tag in [
            ValueTag::String,
            ValueTag::Path,
            ValueTag::List,
            ValueTag::Attrs,
            ValueTag::Lambda,
            ValueTag::Primop,
            ValueTag::External,
            ValueTag::Thunk,
        ] {
            let value = Value::heap(tag, pointer).expect("dangling test pointer is aligned");
            let error = lower_constant_thunk_body(value)
                .expect_err("heap-backed constants must not enter compiled code");

            assert!(matches!(
                error,
                JitLowerError::UnsupportedHeapConstant { tag: actual } if actual == tag
            ));
        }
    }
}
