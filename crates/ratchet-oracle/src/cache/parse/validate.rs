//! Structural validation of decoded parse-cache artifacts.
//!
//! Decoding only checks that bytes are well-formed; these checks additionally
//! verify that every id, slice, and symbol referenced by a decoded resolved AST
//! or lowered IR is in range, so a corrupt-but-parseable artifact is rejected
//! before it reaches the evaluator.

use super::*;

pub(super) fn validate_resolved_artifact(resolved: &ResolvedAst) -> Result<(), String> {
    check_node_id(resolved, resolved.root, "root")?;
    for child in resolved.arena.child_pool() {
        check_node_id(resolved, *child, "child pool")?;
    }
    for node in resolved.arena.nodes() {
        validate_node_data(resolved, node.data)?;
    }
    for frame in resolved.scopes.node_frames().iter().flatten() {
        check_frame_id(resolved, *frame)?;
    }
    for chain in resolved.scopes.with_chains() {
        for scope in chain.scopes.as_ref() {
            check_node_id(resolved, *scope, "with chain")?;
        }
    }
    for inherit in resolved.scopes.inherit_resolutions() {
        if let Some(from) = inherit.from {
            check_node_id(resolved, from, "inherit source")?;
        }
        for source in inherit.sources.as_ref() {
            check_symbol(resolved, source.target)?;
            check_node_id(resolved, source.source, "inherit source")?;
        }
    }
    for inherit in resolved.scopes.node_inherits().iter().flatten() {
        check_inherit_id(resolved, *inherit)?;
    }
    Ok(())
}

fn validate_node_data(resolved: &ResolvedAst, data: NodeData) -> Result<(), String> {
    match data {
        NodeData::None | NodeData::Int(_) | NodeData::Float(_) => Ok(()),
        NodeData::Symbol(symbol) => check_symbol(resolved, symbol),
        NodeData::SearchPath {
            literal,
            search_path,
        } => {
            check_symbol(resolved, literal)?;
            if let Some(search_path) = search_path {
                check_node_id(resolved, search_path, "search-path list")?;
            }
            Ok(())
        }
        NodeData::Node(node) => check_node_id(resolved, node, "node payload"),
        NodeData::Pair { first, second } => {
            check_node_id(resolved, first, "pair first")?;
            check_node_id(resolved, second, "pair second")
        }
        NodeData::Triple {
            first,
            second,
            third,
        } => {
            check_node_id(resolved, first, "triple first")?;
            check_node_id(resolved, second, "triple second")?;
            check_node_id(resolved, third, "triple third")
        }
        NodeData::Children(slice) => check_child_slice(resolved, slice),
        NodeData::Binary { lhs, rhs, .. } => {
            check_node_id(resolved, lhs, "binary lhs")?;
            check_node_id(resolved, rhs, "binary rhs")
        }
        NodeData::Unary { operand, .. } => check_node_id(resolved, operand, "unary operand"),
        NodeData::Select {
            receiver,
            path,
            default,
        } => {
            check_node_id(resolved, receiver, "select receiver")?;
            check_child_slice(resolved, path)?;
            if let Some(default) = default {
                check_node_id(resolved, default, "select default")?;
            }
            Ok(())
        }
        NodeData::HasAttr { receiver, path } => {
            check_node_id(resolved, receiver, "has-attr receiver")?;
            check_child_slice(resolved, path)
        }
        NodeData::Binding { path, value } => {
            check_child_slice(resolved, path)?;
            check_node_id(resolved, value, "binding value")
        }
        NodeData::LetIn { bindings, body } => {
            check_child_slice(resolved, bindings)?;
            check_node_id(resolved, body, "let body")
        }
        NodeData::Inherit { from, names } => {
            if let Some(from) = from {
                check_node_id(resolved, from, "inherit from")?;
            }
            check_child_slice(resolved, names)
        }
        NodeData::FormalSet { formals, alias, .. } => {
            check_child_slice(resolved, formals)?;
            if let Some(alias) = alias {
                check_symbol(resolved, alias)?;
            }
            Ok(())
        }
        NodeData::Formal { name, default } => {
            check_symbol(resolved, name)?;
            if let Some(default) = default {
                check_node_id(resolved, default, "formal default")?;
            }
            Ok(())
        }
        NodeData::Local { .. } | NodeData::Upval { .. } => Ok(()),
        NodeData::WithVar { symbol, chain } => {
            check_symbol(resolved, symbol)?;
            let chain = usize::try_from(chain).map_err(|_| "with-chain id overflow".to_owned())?;
            if chain >= resolved.scopes.with_chains().len() {
                return Err("with-chain id out of range".to_owned());
            }
            Ok(())
        }
    }
}

fn check_node_id(resolved: &ResolvedAst, id: NodeId, what: &'static str) -> Result<(), String> {
    if id.index() < resolved.arena.len() {
        Ok(())
    } else {
        Err(format!("{what} node id out of range"))
    }
}

fn check_symbol(resolved: &ResolvedAst, symbol: Symbol) -> Result<(), String> {
    if resolved.symbols.resolve(symbol).is_some() {
        Ok(())
    } else {
        Err("symbol id out of range".to_owned())
    }
}

fn check_child_slice(resolved: &ResolvedAst, slice: ChildSlice) -> Result<(), String> {
    let end = slice
        .checked_end()
        .ok_or_else(|| "child slice overflow".to_owned())? as usize;
    if end <= resolved.arena.child_pool().len() {
        Ok(())
    } else {
        Err("child slice out of range".to_owned())
    }
}

fn check_frame_id(resolved: &ResolvedAst, id: FrameId) -> Result<(), String> {
    if id.index() < resolved.scopes.frames().len() {
        Ok(())
    } else {
        Err("frame id out of range".to_owned())
    }
}

fn check_inherit_id(resolved: &ResolvedAst, id: InheritGroupId) -> Result<(), String> {
    if id.index() < resolved.scopes.inherit_resolutions().len() {
        Ok(())
    } else {
        Err("inherit id out of range".to_owned())
    }
}

pub(super) fn validate_lowered_ir_artifact(ir: &Ir) -> Result<(), String> {
    if ir.facts.len() != ir.arena.nodes().len() {
        return Err("IR fact count does not match node count".to_owned());
    }
    check_ir_id(ir, ir.root, "root")?;
    for child in ir.arena.child_pool() {
        check_ir_id(ir, *child, "child pool")?;
    }
    for node in ir.arena.nodes() {
        validate_ir_node(ir, *node)?;
    }
    for path in ir.attr_paths.as_ref() {
        for segment in path.as_ref() {
            validate_ir_attr_path_segment(ir, *segment)?;
        }
    }
    for binding in ir.bindings.as_ref() {
        validate_ir_attr_path_segment(ir, binding.key)?;
        check_ir_id(ir, binding.value, "binding value")?;
    }
    for chain in ir.with_chains.as_ref() {
        for scope in chain.scopes.as_ref() {
            check_ir_id(ir, *scope, "with-chain scope")?;
        }
    }
    for shape in ir.shapes.as_ref() {
        for key in shape.keys.as_ref() {
            check_ir_symbol(ir, *key)?;
        }
    }
    validate_lambda_call_summaries(ir)?;
    Ok(())
}

fn validate_lambda_call_summaries(ir: &Ir) -> Result<(), String> {
    let summaries = ir.facts.lambda_call_summaries();
    if summaries
        .windows(2)
        .any(|pair| pair[0].pattern == pair[1].pattern)
    {
        return Err("duplicate lambda call-summary pattern".to_owned());
    }
    for summary in summaries {
        let pattern = ir
            .arena
            .node(summary.pattern)
            .ok_or_else(|| "lambda call-summary pattern out of range".to_owned())?;
        let expected_slots = match pattern.data {
            IrData::Formal { .. } if pattern.kind == IrKind::Formal => 1,
            IrData::FormalSet { formals, alias, .. } if pattern.kind == IrKind::FormalSet => {
                let children = ir
                    .arena
                    .child_slice(formals)
                    .ok_or_else(|| "lambda call-summary formal slice is invalid".to_owned())?;
                let mut names = Vec::new();
                names
                    .try_reserve_exact(children.len())
                    .map_err(|_| "lambda call-summary formal count is too large".to_owned())?;
                for formal in children {
                    let Some(IrNode {
                        kind: IrKind::Formal,
                        data: IrData::Formal { name, .. },
                        ..
                    }) = ir.arena.node(*formal)
                    else {
                        return Err("lambda call-summary pattern has invalid formal".to_owned());
                    };
                    names.push(*name);
                }
                names.len() + usize::from(alias.is_some_and(|alias| !names.contains(&alias)))
            }
            _ => return Err("lambda call-summary key is not a formal pattern".to_owned()),
        };
        if summary.formals.len() != expected_slots {
            return Err("lambda call-summary formal count does not match pattern".to_owned());
        }
        let frame_slots = ir
            .arena
            .nodes()
            .iter()
            .find_map(|node| match node.data {
                IrData::Lambda {
                    pattern,
                    frame: Some(frame),
                    ..
                } if node.kind == IrKind::Lambda && pattern == summary.pattern => ir
                    .frames
                    .get(frame.index())
                    .map(|frame| frame.slot_count as usize),
                _ => None,
            })
            .ok_or_else(|| "lambda call-summary pattern has no lambda frame".to_owned())?;
        if frame_slots != expected_slots {
            return Err("lambda call-summary formal count does not match frame".to_owned());
        }
        if pattern.kind != IrKind::FormalSet && !summary.attr_values.is_empty() {
            return Err("lambda call-summary attribute rules require a formal set".to_owned());
        }
        for attr in &summary.attr_values {
            let mut previous = None;
            for symbol in attr.keys.symbols() {
                check_ir_symbol(ir, *symbol)?;
                if previous.is_some_and(|previous| previous >= *symbol) {
                    return Err("lambda call-summary keys are not strictly ordered".to_owned());
                }
                previous = Some(*symbol);
            }
        }
    }
    Ok(())
}

fn validate_ir_node(ir: &Ir, node: IrNode) -> Result<(), String> {
    validate_ir_node_shape(node)?;
    validate_ir_node_effect(ir, node)?;
    validate_ir_data(ir, node.data)?;
    if let IrData::AttrSet {
        shape,
        bindings,
        has_dynamic,
        ..
    } = node.data
    {
        validate_ir_attrset_shape(ir, shape, bindings, has_dynamic)?;
    }
    Ok(())
}

fn validate_ir_node_shape(node: IrNode) -> Result<(), String> {
    let valid = matches!(
        (node.kind, node.data),
        (IrKind::Int, IrData::Int(_))
            | (IrKind::Float, IrData::Float(_))
            | (IrKind::Bool, IrData::Bool(_))
            | (IrKind::Null, IrData::None)
            | (IrKind::Str, IrData::Symbol(_))
            | (IrKind::Path, IrData::Symbol(_))
            | (IrKind::SearchPath, IrData::SearchPath { .. })
            | (IrKind::Uri, IrData::Symbol(_))
            | (IrKind::LocalVar, IrData::Local { .. })
            | (IrKind::UpvalVar, IrData::Upval { .. })
            | (IrKind::GlobalVar, IrData::GlobalVar { .. })
            | (IrKind::BuiltinAttr, IrData::Symbol(_))
            | (IrKind::List, IrData::Children(_))
            | (IrKind::AttrSet, IrData::AttrSet { .. })
            | (IrKind::Lambda, IrData::Lambda { .. })
            | (IrKind::FormalSet, IrData::FormalSet { .. })
            | (IrKind::Formal, IrData::Formal { .. })
            | (IrKind::Apply, IrData::Pair { .. })
            | (IrKind::Select, IrData::Select { .. })
            | (IrKind::HasAttr, IrData::HasAttr { .. })
            | (IrKind::Let, IrData::Let { .. })
            | (IrKind::With, IrData::Pair { .. })
            | (IrKind::Assert, IrData::Pair { .. })
            | (IrKind::If, IrData::Triple { .. })
            | (IrKind::BinOp, IrData::Binary { .. })
            | (IrKind::UnaryOp, IrData::Unary { .. })
            | (IrKind::Interp, IrData::None)
            | (IrKind::Interp, IrData::Node(_))
            | (IrKind::Interp, IrData::Children(_))
            | (IrKind::ThunkAlloc, IrData::Node(_))
            | (IrKind::PrimOp, IrData::PrimOp { .. })
            | (IrKind::PrimOp, IrData::DialectNode { .. })
            | (IrKind::PrimOp, IrData::DialectScopeVar { .. })
    );
    if valid {
        Ok(())
    } else {
        Err(format!("invalid IR data for {:?} node", node.kind))
    }
}

fn validate_ir_node_effect(ir: &Ir, node: IrNode) -> Result<(), String> {
    let expected = match node.kind {
        IrKind::PrimOp => match node.data {
            IrData::PrimOp { symbol, .. } => primop_effect(ir.symbols.resolve(symbol))
                .ok_or_else(|| format!("unknown IR primop symbol {symbol:?}"))?,
            IrData::DialectNode { op, .. } => dialect_node_effect(op)?,
            IrData::DialectScopeVar { op, .. } => dialect_scope_var_effect(op)?,
            _ => node.effect,
        },
        _ => aos_nix_dialect::nix_effect_of(node.kind),
    };
    if node.effect == expected {
        Ok(())
    } else {
        Err(format!("invalid IR effect for {:?} node", node.kind))
    }
}

fn dialect_node_effect(op: IrDialectOp) -> Result<EffectClass, String> {
    match op {
        aos_nix_dialect::NIX_OP_DERIVATION_STRICT => {
            Ok(aos_nix_dialect::nix_dialect_op_effect_of(op))
        }
        _ => Err(format!("invalid IR dialect node op {op:?}")),
    }
}

fn dialect_scope_var_effect(op: IrDialectOp) -> Result<EffectClass, String> {
    match op {
        aos_nix_dialect::NIX_OP_WITH_VAR => Ok(aos_nix_dialect::nix_dialect_op_effect_of(op)),
        _ => Err(format!("invalid IR dialect scope-var op {op:?}")),
    }
}

fn primop_effect(name: Option<&[u8]>) -> Option<EffectClass> {
    let direct = direct_builtin(name?)?;
    let effect = match direct {
        BuiltinDirect::DerivationStrict => return None,
        BuiltinDirect::StrictUnary { effect }
        | BuiltinDirect::LazyUnary { effect }
        | BuiltinDirect::StrictBinary { effect }
        | BuiltinDirect::StrictLazyBinary { effect }
        | BuiltinDirect::LazyStrictBinary { effect }
        | BuiltinDirect::Sort { effect }
        | BuiltinDirect::StrictTernary { effect } => effect,
    };
    Some(aos_nix_dialect::nix_builtin_effect_of(name, effect))
}

fn validate_ir_data(ir: &Ir, data: IrData) -> Result<(), String> {
    match data {
        IrData::None | IrData::Int(_) | IrData::Float(_) | IrData::Bool(_) => Ok(()),
        IrData::Symbol(symbol) => check_ir_symbol(ir, symbol),
        IrData::GlobalVar { symbol, .. } => check_ir_symbol(ir, symbol),
        IrData::SearchPath {
            literal,
            search_path,
        } => {
            check_ir_symbol(ir, literal)?;
            if let Some(search_path) = search_path {
                check_ir_id(ir, search_path, "search-path list")?;
            }
            Ok(())
        }
        IrData::Node(node) => check_ir_id(ir, node, "node payload"),
        IrData::Pair { first, second } => {
            check_ir_id(ir, first, "pair first")?;
            check_ir_id(ir, second, "pair second")
        }
        IrData::Triple {
            first,
            second,
            third,
        } => {
            check_ir_id(ir, first, "triple first")?;
            check_ir_id(ir, second, "triple second")?;
            check_ir_id(ir, third, "triple third")
        }
        IrData::Children(slice) => check_ir_child_slice(ir, slice),
        IrData::Bindings(slice) => check_ir_binding_slice(ir, slice),
        IrData::Binary { lhs, rhs, .. } => {
            check_ir_id(ir, lhs, "binary lhs")?;
            check_ir_id(ir, rhs, "binary rhs")
        }
        IrData::Unary { operand, .. } => check_ir_id(ir, operand, "unary operand"),
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            check_ir_id(ir, receiver, "select receiver")?;
            check_ir_attr_path_id(ir, path)?;
            if let Some(default) = default {
                check_ir_id(ir, default, "select default")?;
            }
            Ok(())
        }
        IrData::HasAttr { receiver, path, .. } => {
            check_ir_id(ir, receiver, "has-attr receiver")?;
            check_ir_attr_path_id(ir, path)
        }
        IrData::PrimOp { symbol, args } => {
            check_ir_symbol(ir, symbol)?;
            check_ir_child_slice(ir, args)
        }
        IrData::DialectNode { op, argument } => {
            dialect_node_effect(op)?;
            check_ir_id(ir, argument, "dialect op argument")
        }
        IrData::DialectScopeVar {
            op, symbol, chain, ..
        } => {
            dialect_scope_var_effect(op)?;
            check_ir_symbol(ir, symbol)?;
            let chain = usize::try_from(chain).map_err(|_| "with-chain id overflow".to_owned())?;
            if chain >= ir.with_chains.len() {
                return Err("with-chain id out of range".to_owned());
            }
            Ok(())
        }
        IrData::Lambda {
            pattern,
            body,
            frame,
        } => {
            check_ir_id(ir, pattern, "lambda pattern")?;
            check_ir_id(ir, body, "lambda body")?;
            if let Some(frame) = frame {
                check_ir_frame_id(ir, frame)?;
            }
            Ok(())
        }
        IrData::Let {
            bindings,
            body,
            frame,
        } => {
            check_ir_binding_slice(ir, bindings)?;
            check_ir_id(ir, body, "let body")?;
            if let Some(frame) = frame {
                check_ir_frame_id(ir, frame)?;
            }
            Ok(())
        }
        IrData::AttrSet {
            shape,
            bindings,
            frame,
            ..
        } => {
            check_ir_shape_id(ir, shape)?;
            check_ir_binding_slice(ir, bindings)?;
            if let Some(frame) = frame {
                check_ir_frame_id(ir, frame)?;
            }
            Ok(())
        }
        IrData::FormalSet { formals, alias, .. } => {
            check_ir_child_slice(ir, formals)?;
            if let Some(alias) = alias {
                check_ir_symbol(ir, alias)?;
            }
            Ok(())
        }
        IrData::Formal { name, default } => {
            check_ir_symbol(ir, name)?;
            if let Some(default) = default {
                check_ir_id(ir, default, "formal default")?;
            }
            Ok(())
        }
        IrData::Local { .. } | IrData::Upval { .. } => Ok(()),
    }
}

fn validate_ir_attrset_shape(
    ir: &Ir,
    shape: IrShapeId,
    bindings: IrBindingSlice,
    has_dynamic: bool,
) -> Result<(), String> {
    let shape = ir
        .shapes
        .get(shape.index())
        .ok_or_else(|| "IR shape id out of range".to_owned())?;
    let bindings = ir_binding_slice(ir, bindings)?;
    let mut static_keys = Vec::new();
    let mut saw_dynamic = false;
    for binding in bindings {
        match binding.key {
            IrAttrPathSegment::Static(symbol) => static_keys.push(symbol),
            IrAttrPathSegment::Dynamic(_) => saw_dynamic = true,
        }
    }
    if shape.keys.as_ref() != static_keys.as_slice() {
        return Err("IR attrset shape does not match static binding keys".to_owned());
    }
    if has_dynamic != saw_dynamic {
        return Err("IR attrset dynamic flag does not match binding keys".to_owned());
    }
    Ok(())
}

fn validate_ir_attr_path_segment(ir: &Ir, segment: IrAttrPathSegment) -> Result<(), String> {
    match segment {
        IrAttrPathSegment::Static(symbol) => check_ir_symbol(ir, symbol),
        IrAttrPathSegment::Dynamic(node) => check_ir_id(ir, node, "dynamic attr-path segment"),
    }
}

fn check_ir_id(ir: &Ir, id: IrId, what: &'static str) -> Result<(), String> {
    if id.index() < ir.arena.nodes().len() {
        Ok(())
    } else {
        Err(format!("{what} IR id out of range"))
    }
}

fn check_ir_symbol(ir: &Ir, symbol: Symbol) -> Result<(), String> {
    if ir.symbols.resolve(symbol).is_some() {
        Ok(())
    } else {
        Err("IR symbol id out of range".to_owned())
    }
}

fn check_ir_child_slice(ir: &Ir, slice: IrChildSlice) -> Result<(), String> {
    let start = usize::try_from(slice.start).map_err(|_| "IR child slice overflow".to_owned())?;
    let len = usize::try_from(slice.len).map_err(|_| "IR child slice overflow".to_owned())?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| "IR child slice overflow".to_owned())?;
    if end <= ir.arena.child_pool().len() {
        Ok(())
    } else {
        Err("IR child slice out of range".to_owned())
    }
}

fn check_ir_binding_slice(ir: &Ir, slice: IrBindingSlice) -> Result<(), String> {
    ir_binding_slice(ir, slice).map(|_| ())
}

fn ir_binding_slice(ir: &Ir, slice: IrBindingSlice) -> Result<&[IrBinding], String> {
    let start = usize::try_from(slice.start).map_err(|_| "IR binding slice overflow".to_owned())?;
    let len = usize::try_from(slice.len).map_err(|_| "IR binding slice overflow".to_owned())?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| "IR binding slice overflow".to_owned())?;
    ir.bindings
        .get(start..end)
        .ok_or_else(|| "IR binding slice out of range".to_owned())
}

fn check_ir_attr_path_id(ir: &Ir, id: IrAttrPathId) -> Result<(), String> {
    if id.index() < ir.attr_paths.len() {
        Ok(())
    } else {
        Err("IR attr-path id out of range".to_owned())
    }
}

fn check_ir_shape_id(ir: &Ir, id: IrShapeId) -> Result<(), String> {
    if id.index() < ir.shapes.len() {
        Ok(())
    } else {
        Err("IR shape id out of range".to_owned())
    }
}

fn check_ir_frame_id(ir: &Ir, id: FrameId) -> Result<(), String> {
    if id.index() < ir.frames.len() {
        Ok(())
    } else {
        Err("IR frame id out of range".to_owned())
    }
}
