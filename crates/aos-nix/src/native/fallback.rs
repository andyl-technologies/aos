//! Static analysis that keeps CLI-sensitive and unimplemented expressions
//! fallback-eligible.
//!
//! Before the native evaluator commits to instantiating or JSON-rendering an
//! expression, these preflight passes scan the lowered IR for builtins,
//! search-path lookups, and impure constants whose results depend on C++ Nix
//! CLI configuration. Any such use is reported as
//! [`NativeEvalError::Unsupported`] so the caller can defer to the C++ oracle
//! rather than producing a divergent native result.

use super::*;

pub(super) fn ensure_native_json_subset(
    ir: &Ir,
    expr_len: usize,
    options: &TreeWalkOptions,
) -> Result<(), NativeEvalError> {
    for (index, node) in ir.arena.nodes().iter().enumerate() {
        if !node.effect.is_speculable() {
            if let IrKind::PrimOp = node.kind
                && let IrData::PrimOp { symbol, .. } = node.data
                && let Some(name) = ir.symbols.resolve(symbol)
                && let Some(builtin) = lookup_builtin(name)
            {
                if builtin_allowed_for_native_json_effect(builtin) {
                    continue;
                }
                if let Some(feature) = builtin_native_json_fallback_feature(builtin, options) {
                    return Err(unsupported_native_node(feature, node.span, expr_len));
                }
            }
            return Err(unsupported_native_node(
                "effectful expression evaluation",
                node.span,
                expr_len,
            ));
        }

        if node.kind == IrKind::BuiltinAttr
            && let IrData::Symbol(symbol) = node.data
            && let Some(name) = ir.symbols.resolve(symbol)
            && let Some(feature) = builtin_attr_native_json_fallback_feature(name, options)
        {
            return Err(unsupported_native_node(feature, node.span, expr_len));
        }

        if node.kind == IrKind::GlobalVar
            && let IrData::GlobalVar { symbol, .. } = node.data
        {
            let Some(name) = ir.symbols.resolve(symbol) else {
                continue;
            };
            if name == b"builtins" {
                if let Some(feature) =
                    builtins_global_native_json_fallback_feature(ir, index, options)
                {
                    return Err(unsupported_native_node(feature, node.span, expr_len));
                }
                continue;
            }
            if is_unshadowable_global_name(name)
                && let Some(builtin) = lookup_builtin(name)
                && let Some(feature) = builtin_native_json_fallback_feature(builtin, options)
            {
                return Err(unsupported_native_node(feature, node.span, expr_len));
            }
        }

        if node.kind == IrKind::PrimOp
            && let IrData::PrimOp { symbol, .. } = node.data
            && let Some(name) = ir.symbols.resolve(symbol)
            && let Some(feature) = builtin_native_cli_fallback_feature(name)
        {
            return Err(unsupported_native_node(feature, node.span, expr_len));
        }

        if node.kind == IrKind::SearchPath {
            return Err(unsupported_native_node(
                "configured Nix search path lookup",
                node.span,
                expr_len,
            ));
        }
    }

    Ok(())
}

pub(super) fn builtins_global_native_json_fallback_feature(
    ir: &Ir,
    receiver_index: usize,
    options: &TreeWalkOptions,
) -> Option<&'static str> {
    let mut selected_known_native_builtin = false;
    let mut saw_referencing_attr_path = false;

    for node in ir.arena.nodes() {
        let (receiver, path) = match node.data {
            IrData::Select { receiver, path, .. } | IrData::HasAttr { receiver, path, .. } => {
                (receiver, path)
            }
            _ => continue,
        };
        if !select_receiver_references_global(ir, receiver, receiver_index) {
            continue;
        }
        saw_referencing_attr_path = true;

        let name = match static_single_attr_path(ir, path) {
            StaticSingleAttrPath::Single(name) => name,
            StaticSingleAttrPath::Invalid => continue,
            StaticSingleAttrPath::NotSingle => return Some(cli_sensitive_builtin_feature()),
        };
        if name == b"builtins" {
            return Some(cli_sensitive_builtin_feature());
        }
        let Some(builtin) = lookup_builtin(name) else {
            return Some(cli_sensitive_builtin_feature());
        };
        if let Some(feature) = builtin_native_json_fallback_feature(builtin, options) {
            return Some(feature);
        }

        selected_known_native_builtin = true;
    }

    if selected_known_native_builtin {
        None
    } else if saw_referencing_attr_path {
        None
    } else {
        Some(cli_sensitive_builtin_feature())
    }
}

fn builtin_attr_native_json_fallback_feature(
    name: &[u8],
    options: &TreeWalkOptions,
) -> Option<&'static str> {
    if name == b"builtins" {
        return Some(cli_sensitive_builtin_feature());
    }
    lookup_builtin(name).and_then(|builtin| builtin_native_json_fallback_feature(builtin, options))
}

fn builtin_native_json_fallback_feature(
    builtin: Builtin,
    options: &TreeWalkOptions,
) -> Option<&'static str> {
    if builtin_allowed_for_native_json_effect(builtin) {
        return None;
    }
    if ambient_builtin_constant_available_for_native_json(builtin, options) {
        return None;
    }
    builtin.native_cli_fallback_feature()
}

fn builtin_allowed_for_native_json_effect(builtin: Builtin) -> bool {
    matches!(
        builtin.execution(),
        BuiltinExecution::Import
            | BuiltinExecution::ScopedImport
            | BuiltinExecution::StrictUnary {
                primop: StrictUnaryPrimOp::ToPath,
                ..
            }
    )
}

fn builtin_native_cli_fallback_feature(name: &[u8]) -> Option<&'static str> {
    lookup_builtin(name).and_then(|builtin| builtin.native_cli_fallback_feature())
}

fn cli_sensitive_builtin_feature() -> &'static str {
    NativeCliFallbackFeature::CliSensitiveBuiltinEvaluation.label()
}

fn builtin_available_in_options(builtin: Builtin, options: &TreeWalkOptions) -> bool {
    match builtin.availability() {
        BuiltinAvailability::Always => true,
        BuiltinAvailability::ImpureCurrentSystem => {
            options.eval_mode() != EvalMode::Pure && options.current_system().is_some()
        }
        BuiltinAvailability::ImpureCurrentTime => {
            options.eval_mode() != EvalMode::Pure && options.current_time().is_some()
        }
    }
}

fn ambient_builtin_constant_available_for_native_json(
    builtin: Builtin,
    options: &TreeWalkOptions,
) -> bool {
    match builtin.availability() {
        BuiltinAvailability::Always => false,
        BuiltinAvailability::ImpureCurrentSystem | BuiltinAvailability::ImpureCurrentTime => {
            builtin_available_in_options(builtin, options)
        }
    }
}

pub(super) fn native_instantiation_cli_fallback_feature(
    ir: &Ir,
    options: &TreeWalkOptions,
) -> Option<(&'static str, Span)> {
    for node in ir.arena.nodes() {
        if node.kind == IrKind::BuiltinAttr
            && let IrData::Symbol(symbol) = node.data
            && let Some(name) = ir.symbols.resolve(symbol)
            && builtin_instantiation_attr_is_cli_sensitive(name, options)
        {
            return Some((cli_sensitive_builtin_feature(), node.span));
        }
    }

    for (index, node) in ir.arena.nodes().iter().enumerate() {
        let (IrKind::GlobalVar, IrData::GlobalVar { symbol, .. }) = (node.kind, node.data) else {
            continue;
        };
        let Some(name) = ir.symbols.resolve(symbol) else {
            continue;
        };
        if name != b"builtins" {
            continue;
        };
        if let Some(feature) =
            builtins_global_native_instantiation_fallback_feature(ir, index, options)
        {
            return Some(feature);
        }
    }
    None
}

fn builtin_instantiation_attr_is_cli_sensitive(name: &[u8], options: &TreeWalkOptions) -> bool {
    let Some(builtin) = lookup_builtin(name) else {
        return false;
    };
    match builtin.availability() {
        BuiltinAvailability::Always => false,
        BuiltinAvailability::ImpureCurrentSystem | BuiltinAvailability::ImpureCurrentTime => {
            options.eval_mode() != EvalMode::Pure && !builtin_available_in_options(builtin, options)
        }
    }
}

fn builtins_global_native_instantiation_fallback_feature(
    ir: &Ir,
    receiver_index: usize,
    options: &TreeWalkOptions,
) -> Option<(&'static str, Span)> {
    for node in ir.arena.nodes() {
        let (receiver, path) = match node.data {
            IrData::Select { receiver, path, .. } | IrData::HasAttr { receiver, path, .. } => {
                (receiver, path)
            }
            _ => continue,
        };
        if !select_receiver_references_global(ir, receiver, receiver_index) {
            continue;
        }

        if builtins_instantiation_attr_path_is_cli_sensitive(ir, path, options) {
            return Some((cli_sensitive_builtin_feature(), node.span));
        }
    }
    None
}

fn builtins_instantiation_attr_path_is_cli_sensitive(
    ir: &Ir,
    path: IrAttrPathId,
    options: &TreeWalkOptions,
) -> bool {
    let Some(segments) = ir.attr_paths.get(path.index()) else {
        return true;
    };
    let Some(first) = segments.first() else {
        return false;
    };
    let IrAttrPathSegment::Static(symbol) = first else {
        return true;
    };
    ir.symbols
        .resolve(*symbol)
        .is_some_and(|name| builtin_instantiation_attr_is_cli_sensitive(name, options))
}

fn select_receiver_references_global(ir: &Ir, mut receiver: IrId, global_index: usize) -> bool {
    loop {
        if receiver.index() == global_index {
            return true;
        }

        let Some(node) = ir.arena.node(receiver) else {
            return false;
        };
        let (IrKind::ThunkAlloc, IrData::Node(inner)) = (node.kind, node.data) else {
            return false;
        };
        if inner.index() == receiver.index() {
            return false;
        }
        receiver = inner;
    }
}

enum StaticSingleAttrPath<'a> {
    Single(&'a [u8]),
    Invalid,
    NotSingle,
}

fn static_single_attr_path<'a>(ir: &'a Ir, path: IrAttrPathId) -> StaticSingleAttrPath<'a> {
    let Some(segments) = ir.attr_paths.get(path.index()) else {
        return StaticSingleAttrPath::Invalid;
    };
    if segments.is_empty() {
        return StaticSingleAttrPath::Invalid;
    }
    let [IrAttrPathSegment::Static(symbol)] = segments.as_ref() else {
        return StaticSingleAttrPath::NotSingle;
    };
    match ir.symbols.resolve(*symbol) {
        Some(name) => StaticSingleAttrPath::Single(name),
        None => StaticSingleAttrPath::Invalid,
    }
}
