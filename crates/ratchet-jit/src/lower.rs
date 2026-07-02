//! Minimal CLIF body lowering for safe JIT smoke tests.
//!
//! This module starts the tier-1 lowering path without executable code. It can
//! build a verified Cranelift [`Function`] for a compiled thunk body that
//! returns a constant runtime [`Value`]. The function body uses the same
//! two-word `Value` ABI as [`crate::abi`], but it is not placed in a
//! `JITModule`, finalized, or called.

use std::{error::Error, fmt};

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, UserFuncName, types},
    settings,
    verifier::{VerifierErrors, verify_function},
};
use ratchet_core::{Ir, IrArena, IrData, IrId, IrKind, IrNode, runtime_thunk_call_signature};
use ratchet_value::value::Value;

use crate::abi::{JitClifSignatureError, clif_signature_for_runtime_call};

/// Cranelift user-function namespace reserved for Core IR root thunks.
///
/// Cranelift treats user function names as caller-owned numeric metadata. The
/// current lowerer uses this namespace with the Core [`IrId`] as the function
/// index so non-executable CLIF artifacts have deterministic per-expression
/// names before `JITModule` integration exists.
pub const AOS_IR_ROOT_FUNCTION_NAMESPACE: u32 = 7;

/// Returns the deterministic CLIF user-function name for a Core IR root.
pub fn clif_name_for_ir_root(root: IrId) -> UserFuncName {
    UserFuncName::user(AOS_IR_ROOT_FUNCTION_NAMESPACE, root.as_u32())
}

/// Lowers a constant runtime value into a verified compiled-thunk CLIF body.
///
/// The returned function has the frozen compiled-thunk runtime signature:
/// `rt`, `env`, and a two-word runtime `Value` return. The current body ignores
/// the runtime and environment parameters and emits two `iconst.i64`
/// instructions for the value tag and payload words. This smoke-test entrypoint
/// uses Cranelift's default user-function name because it is not tied to a Core
/// IR root.
///
/// # Errors
///
/// Returns [`JitLowerError::Abi`] if the runtime thunk signature cannot be
/// lowered to a CLIF signature. Returns [`JitLowerError::Verifier`] if Cranelift
/// rejects the generated single-block function.
pub fn lower_constant_thunk_body(value: Value) -> Result<Function, JitLowerError> {
    lower_constant_thunk_body_with_name(value, UserFuncName::default())
}

fn lower_constant_thunk_body_with_name(
    value: Value,
    name: UserFuncName,
) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(name, signature);
    let entry_block = append_entry_block_params(&mut function);
    emit_value_return(&mut function, entry_block, value);
    verify_clif_function(&function)?;
    Ok(function)
}

/// Lowers a literal IR root into a verified compiled-thunk CLIF body.
///
/// This is the first Core-IR entrypoint for the tier-1 lowerer. It accepts
/// literal `Int`, `Float`, `Bool`, and `Null` roots plus one direct
/// [`IrKind::ThunkAlloc`] wrapper around those literal roots, then reuses
/// the constant thunk body path to build the single-block CLIF body. The
/// returned function name is deterministic: [`AOS_IR_ROOT_FUNCTION_NAMESPACE`]
/// plus the raw Core [`IrId`] root as the Cranelift user-function index.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `root` is not present in
/// `arena`. Returns [`JitLowerError::UnsupportedIrRoot`] when `root` is not one
/// of the supported constant forms. Returns
/// [`JitLowerError::MismatchedConstantData`] when a literal node carries a
/// payload variant that does not match its kind. Returns
/// [`JitLowerError::MissingIrBody`], [`JitLowerError::UnsupportedIrBody`], or
/// [`JitLowerError::MismatchedBodyConstantData`] for malformed direct thunk
/// bodies. Returns
/// [`JitLowerError::MismatchedIrNodeData`] when a supported wrapper node carries
/// the wrong payload shape. Also returns the errors from [`lower_constant_thunk_body`].
pub fn lower_constant_ir_thunk_body(
    arena: &IrArena,
    root: IrId,
) -> Result<Function, JitLowerError> {
    let value = constant_value_for_root(arena, root)?;
    lower_constant_thunk_body_with_name(value, clif_name_for_ir_root(root))
}

/// Lowers the root of a lowered IR artifact into a compiled-thunk CLIF body.
///
/// This is the normal Core-IR entrypoint for the current literal-only lowerer.
/// It delegates to [`lower_constant_ir_thunk_body`] using the artifact's root id
/// and arena, so callers do not have to split the root out manually.
///
/// # Errors
///
/// Returns [`JitLowerError::MissingIrNode`] when `ir.root` is not present in
/// `ir.arena`. Returns [`JitLowerError::UnsupportedIrRoot`] when the root is not
/// one of the supported constant forms. Returns
/// [`JitLowerError::MismatchedConstantData`] when a literal node carries a
/// payload variant that does not match its kind. Returns
/// [`JitLowerError::MissingIrBody`], [`JitLowerError::UnsupportedIrBody`], or
/// [`JitLowerError::MismatchedBodyConstantData`] for malformed direct thunk
/// bodies. Returns
/// [`JitLowerError::MismatchedIrNodeData`] when a supported wrapper node carries
/// the wrong payload shape. Also returns the errors from [`lower_constant_thunk_body`].
pub fn lower_constant_ir_root_thunk_body(ir: &Ir) -> Result<Function, JitLowerError> {
    lower_constant_ir_thunk_body(&ir.arena, ir.root)
}

/// A failure while lowering safe metadata into CLIF.
#[derive(Debug)]
pub enum JitLowerError {
    /// Runtime ABI metadata could not be converted to a CLIF signature.
    Abi(JitClifSignatureError),
    /// Cranelift rejected the generated CLIF function body.
    Verifier(VerifierErrors),
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
    /// The requested IR root is not a literal this precursor can lower.
    UnsupportedIrRoot {
        /// The unsupported root node kind.
        kind: IrKind,
    },
    /// The direct thunk-allocation body is not a literal this precursor can lower.
    UnsupportedIrBody {
        /// The unsupported body node kind.
        kind: IrKind,
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
}

impl fmt::Display for JitLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abi(error) => write!(formatter, "{error}"),
            Self::Verifier(error) => {
                write!(formatter, "generated CLIF failed verification: {error}")
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
                    "IR root kind {kind:?} is not supported by the constant lowerer"
                )
            }
            Self::UnsupportedIrBody { kind } => {
                write!(
                    formatter,
                    "IR thunk body kind {kind:?} is not supported by the constant lowerer"
                )
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
        }
    }
}

impl Error for JitLowerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Abi(error) => Some(error),
            Self::Verifier(error) => Some(error),
            Self::MissingIrNode { .. }
            | Self::MissingIrBody { .. }
            | Self::UnsupportedIrRoot { .. }
            | Self::UnsupportedIrBody { .. }
            | Self::MismatchedConstantData { .. }
            | Self::MismatchedBodyConstantData { .. }
            | Self::MismatchedIrNodeData { .. } => None,
        }
    }
}

impl From<JitClifSignatureError> for JitLowerError {
    fn from(error: JitClifSignatureError) -> Self {
        Self::Abi(error)
    }
}

fn constant_value_for_root(arena: &IrArena, root: IrId) -> Result<Value, JitLowerError> {
    let node = arena
        .node(root)
        .copied()
        .ok_or(JitLowerError::MissingIrNode { root })?;

    match (node.kind, node.data) {
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            let body = arena
                .node(body)
                .copied()
                .ok_or(JitLowerError::MissingIrBody { body })?;
            constant_value_for_body(body)
        }
        (IrKind::ThunkAlloc, data) => Err(JitLowerError::MismatchedIrNodeData {
            kind: IrKind::ThunkAlloc,
            data,
            expected: "body node",
        }),
        _ => constant_value_for_node(node),
    }
}

fn constant_value_for_body(node: IrNode) -> Result<Value, JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
        (IrKind::Bool, IrData::Bool(value)) => Ok(Value::bool(value)),
        (IrKind::Null, IrData::None) => Ok(Value::null()),
        (kind @ (IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null), data) => {
            Err(JitLowerError::MismatchedBodyConstantData { kind, data })
        }
        (kind, _) => Err(JitLowerError::UnsupportedIrBody { kind }),
    }
}

fn constant_value_for_node(node: IrNode) -> Result<Value, JitLowerError> {
    match (node.kind, node.data) {
        (IrKind::Int, IrData::Int(value)) => Ok(Value::int(value)),
        (IrKind::Float, IrData::Float(value)) => Ok(Value::float(value)),
        (IrKind::Bool, IrData::Bool(value)) => Ok(Value::bool(value)),
        (IrKind::Null, IrData::None) => Ok(Value::null()),
        (kind @ (IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null), data) => {
            Err(JitLowerError::MismatchedConstantData { kind, data })
        }
        (kind, _) => Err(JitLowerError::UnsupportedIrRoot { kind }),
    }
}

fn append_entry_block_params(function: &mut Function) -> cranelift_codegen::ir::Block {
    let entry_block = function.dfg.make_block();
    let parameter_types = function
        .signature
        .params
        .iter()
        .map(|parameter| parameter.value_type)
        .collect::<Vec<_>>();

    for parameter_type in parameter_types {
        function.dfg.append_block_param(entry_block, parameter_type);
    }

    let mut cursor = FuncCursor::new(function);
    cursor.insert_block(entry_block);

    entry_block
}

fn emit_value_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    value: Value,
) {
    let tag_word = value.tag() as u64;
    let payload_word = value.payload_bits();
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let tag = cursor.ins().iconst(types::I64, tag_word as i64);
    let payload = cursor.ins().iconst(types::I64, payload_word as i64);
    cursor.ins().return_(&[tag, payload]);
}

fn verify_clif_function(function: &Function) -> Result<(), JitLowerError> {
    let flags = settings::Flags::new(settings::builder());
    verify_function(function, &flags).map_err(JitLowerError::Verifier)
}

#[cfg(test)]
mod tests {
    use cranelift_codegen::ir::{InstructionData, Opcode, Type};
    use ratchet_core::{
        EffectClass, Ir, IrFacts, IrNode, lower, resolve,
        syntax::{Span, SymbolTable, parse_str},
    };
    use ratchet_value::value::ValueTag;

    use super::*;
    use crate::abi::clif_signature_for_runtime_call;

    #[test]
    fn constant_thunk_body_uses_frozen_thunk_signature() {
        let function =
            lower_constant_thunk_body(Value::null()).expect("constant null thunk body lowers");
        let expected_signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())
            .expect("thunk signature lowers");

        assert_eq!(function.name, UserFuncName::default());
        assert_eq!(function.signature, expected_signature);
        assert_eq!(
            entry_block_param_types(&function),
            param_types(&expected_signature)
        );
    }

    #[test]
    fn ir_root_function_name_uses_reserved_namespace_and_root_index() {
        let name = clif_name_for_ir_root(IrId::new(42));
        let user_name = name
            .get_user()
            .expect("IR root CLIF names use user-function metadata");

        assert_eq!(user_name.namespace, AOS_IR_ROOT_FUNCTION_NAMESPACE);
        assert_eq!(user_name.index, 42);
    }

    #[test]
    fn constant_thunk_body_returns_int_value_words() {
        let function =
            lower_constant_thunk_body(Value::int(-7)).expect("constant int thunk body lowers");

        assert_eq!(
            iconst_words(&function),
            vec![ValueTag::Int as u64, Value::int(-7).payload_bits()]
        );
    }

    #[test]
    fn constant_thunk_body_returns_bool_and_null_value_words() {
        let bool_function =
            lower_constant_thunk_body(Value::bool(true)).expect("constant bool thunk body lowers");
        let null_function =
            lower_constant_thunk_body(Value::null()).expect("constant null thunk body lowers");

        assert_eq!(
            iconst_words(&bool_function),
            vec![ValueTag::Bool as u64, Value::bool(true).payload_bits()]
        );
        assert_eq!(
            iconst_words(&null_function),
            vec![ValueTag::Null as u64, Value::null().payload_bits()]
        );
    }

    #[test]
    fn constant_thunk_body_is_verified_clif_without_jit_module() {
        let function = lower_constant_thunk_body(Value::float(-13.25))
            .expect("constant float thunk body lowers");

        let emitted_constants = iconst_values(&function)
            .into_iter()
            .map(|(value, _word)| value)
            .collect::<Vec<_>>();
        assert_eq!(return_operands(&function), emitted_constants);
        assert_eq!(opcodes(&function).last(), Some(&Opcode::Return));
        verify_clif_function(&function).expect("lowered function verifies independently");
    }

    #[test]
    fn constant_ir_thunk_body_lowers_supported_literal_roots() {
        let cases = [
            (
                IrNode::new(
                    IrKind::Int,
                    Span::new(0, 2),
                    EffectClass::pure(),
                    IrData::Int(-9),
                ),
                Value::int(-9),
            ),
            (
                IrNode::new(
                    IrKind::Float,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::Float(2.5),
                ),
                Value::float(2.5),
            ),
            (
                IrNode::new(
                    IrKind::Bool,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::Bool(false),
                ),
                Value::bool(false),
            ),
            (
                IrNode::new(
                    IrKind::Null,
                    Span::new(0, 4),
                    EffectClass::pure(),
                    IrData::None,
                ),
                Value::null(),
            ),
        ];

        for (node, expected_value) in cases {
            let arena = IrArena::from_raw_parts(vec![node], Vec::new());
            let function =
                lower_constant_ir_thunk_body(&arena, IrId::new(0)).expect("literal IR root lowers");

            assert_eq!(
                iconst_words(&function),
                vec![expected_value.tag() as u64, expected_value.payload_bits()]
            );
        }
    }

    #[test]
    fn constant_ir_thunk_body_lowers_direct_literal_thunk_alloc_root() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(4, 6),
                    EffectClass::pure(),
                    IrData::Int(17),
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let function = lower_constant_ir_thunk_body(&arena, IrId::new(1))
            .expect("direct literal thunk allocation lowers");

        assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
        assert_eq!(
            iconst_words(&function),
            vec![ValueTag::Int as u64, Value::int(17).payload_bits()]
        );
    }

    #[test]
    fn constant_ir_thunk_body_rejects_missing_root() {
        let arena = IrArena::new();

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(7))
            .expect_err("missing root is rejected");

        assert!(matches!(error, JitLowerError::MissingIrNode { root } if root == IrId::new(7)));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_unsupported_root_kind() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("string root is not covered by the constant lowerer");

        assert!(matches!(error, JitLowerError::UnsupportedIrRoot { kind } if kind == IrKind::Str));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_mismatched_literal_payload() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 4),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("int root without int payload is malformed");

        assert!(matches!(
            error,
            JitLowerError::MismatchedConstantData {
                kind: IrKind::Int,
                data: IrData::None,
            }
        ));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_missing_thunk_body() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(9)),
            )],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("missing thunk body is rejected");

        assert!(matches!(error, JitLowerError::MissingIrBody { body } if body == IrId::new(9)));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_unsupported_thunk_body_kind() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Str,
                    Span::new(4, 9),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 9),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(1))
            .expect_err("unsupported thunk body kind is rejected");

        assert!(matches!(error, JitLowerError::UnsupportedIrBody { kind } if kind == IrKind::Str));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_mismatched_thunk_body_payload() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Int,
                    Span::new(4, 9),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::ThunkAlloc,
                    Span::new(0, 9),
                    EffectClass::pure(),
                    IrData::Node(IrId::new(0)),
                ),
            ],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(1))
            .expect_err("mismatched thunk body payload is rejected");

        assert!(matches!(
            error,
            JitLowerError::MismatchedBodyConstantData {
                kind: IrKind::Int,
                data: IrData::None,
            }
        ));
    }

    #[test]
    fn constant_ir_thunk_body_rejects_malformed_thunk_alloc_payload() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        );

        let error = lower_constant_ir_thunk_body(&arena, IrId::new(0))
            .expect_err("thunk allocation without body node is malformed");

        assert!(matches!(
            error,
            JitLowerError::MismatchedIrNodeData {
                kind: IrKind::ThunkAlloc,
                data: IrData::None,
                expected: "body node",
            }
        ));
    }

    #[test]
    fn constant_ir_root_thunk_body_lowers_real_literal_ir_artifacts() {
        let cases = [
            ("42", Value::int(42)),
            ("2.5", Value::float(2.5)),
            ("false", Value::bool(false)),
            ("null", Value::null()),
        ];

        for (source, expected_value) in cases {
            let ir = lowered_ir(source);
            let function =
                lower_constant_ir_root_thunk_body(&ir).expect("literal IR artifact lowers");

            assert_eq!(
                iconst_words(&function),
                vec![expected_value.tag() as u64, expected_value.payload_bits()]
            );
        }
    }

    #[test]
    fn constant_ir_root_thunk_body_uses_nonzero_artifact_root() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Str,
                    Span::new(0, 6),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::Int,
                    Span::new(7, 9),
                    EffectClass::pure(),
                    IrData::Int(11),
                ),
            ],
            Vec::new(),
        );
        let ir = minimal_ir(IrId::new(1), arena);

        let function = lower_constant_ir_root_thunk_body(&ir).expect("nonzero literal root lowers");

        assert_eq!(function.name, clif_name_for_ir_root(IrId::new(1)));
        assert_eq!(
            iconst_words(&function),
            vec![ValueTag::Int as u64, Value::int(11).payload_bits()]
        );
    }

    #[test]
    fn constant_ir_root_thunk_body_rejects_missing_artifact_root() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(1),
            )],
            Vec::new(),
        );
        let ir = minimal_ir(IrId::new(5), arena);

        let error =
            lower_constant_ir_root_thunk_body(&ir).expect_err("missing artifact root is rejected");

        assert!(matches!(error, JitLowerError::MissingIrNode { root } if root == IrId::new(5)));
    }

    fn lowered_ir(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    fn minimal_ir(root: IrId, arena: IrArena) -> Ir {
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root,
            arena,
            facts,
            symbols: SymbolTable::new(),
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn entry_block_param_types(function: &Function) -> Vec<Type> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .dfg
            .block_params(entry_block)
            .iter()
            .map(|value| function.dfg.value_type(*value))
            .collect()
    }

    fn param_types(signature: &cranelift_codegen::ir::Signature) -> Vec<Type> {
        signature
            .params
            .iter()
            .map(|parameter| parameter.value_type)
            .collect()
    }

    fn iconst_words(function: &Function) -> Vec<u64> {
        iconst_values(function)
            .into_iter()
            .map(|(_value, word)| word)
            .collect()
    }

    fn iconst_values(function: &Function) -> Vec<(cranelift_codegen::ir::Value, u64)> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .layout
            .block_insts(entry_block)
            .filter_map(|inst| match function.dfg.insts[inst] {
                InstructionData::UnaryImm {
                    opcode: Opcode::Iconst,
                    imm,
                } => Some((function.dfg.inst_results(inst)[0], imm.bits() as u64)),
                _ => None,
            })
            .collect()
    }

    fn return_operands(function: &Function) -> Vec<cranelift_codegen::ir::Value> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        let return_inst = function
            .layout
            .block_insts(entry_block)
            .find(|inst| function.dfg.insts[*inst].opcode() == Opcode::Return)
            .expect("lowered function has a return instruction");
        function.dfg.inst_args(return_inst).to_vec()
    }

    fn opcodes(function: &Function) -> Vec<Opcode> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .layout
            .block_insts(entry_block)
            .map(|inst| function.dfg.insts[inst].opcode())
            .collect()
    }
}
