//! Public evaluation entry points and attribute-path index helpers.

use super::*;

/// Evaluates an IR root to weak head normal form with the tree-walk oracle.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if the root node is missing, malformed for its IR
/// kind, fails a scalar type check, or belongs to a part of the interpreter that
/// this Phase-1 slice has not implemented yet. Returns
/// [`TreeWalkErrorKind::HeapValueRequiresOwner`] if the root evaluates to a
/// heap-backed value; use [`eval_whnf_owned`] for those values so their
/// evaluator heap stays alive.
pub fn eval_whnf(ir: &Ir) -> Result<Value, TreeWalkError> {
    eval_whnf_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root to weak head normal form with explicit evaluator options.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if the root node is missing, malformed for its IR
/// kind, fails a scalar type check, or belongs to a part of the interpreter that
/// this Phase-1 slice has not implemented yet. Returns
/// [`TreeWalkErrorKind::HeapValueRequiresOwner`] if the root evaluates to a
/// heap-backed value; use [`eval_whnf_owned_with_options`] for those values so
/// their evaluator heap stays alive.
pub fn eval_whnf_with_options(ir: &Ir, options: TreeWalkOptions) -> Result<Value, TreeWalkError> {
    let outcome = eval_whnf_owned_with_options(ir, options)?;
    if outcome.value.tag().is_heap() {
        let span = ir
            .arena
            .node(ir.root)
            .map(|node| node.span)
            .unwrap_or_default();
        return Err(TreeWalkError::new(
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: outcome.value.tag(),
            },
            span,
        ));
    }
    Ok(outcome.value)
}

/// Evaluates an IR root while returning the heap that owns heap-backed values.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned(ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
    eval_whnf_owned_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root with explicit options while returning the owning heap.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned_with_options(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<EvalOutcome, TreeWalkError> {
    eval_whnf_owned_with_options_and_realizer(ir, options, None)
}

/// Evaluates an IR root with explicit options and an optional IFD realizer.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned_with_options_and_realizer(
    ir: &Ir,
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options(ir, options);
    if let Some(realizer) = ifd_realizer {
        evaluator.set_ifd_realizer(realizer);
    }
    let value = evaluator.eval_root()?;
    let derivations = evaluator.derivation_snapshot()?;
    Ok(EvalOutcome {
        value,
        heap: evaluator.heap,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        derivations,
    })
}

/// Evaluates an IR root and selects an attr path with `nix-instantiate -A` auto-calls.
///
/// Formal-set lambdas encountered before each path segment are called with an
/// empty attrset so defaults are honored. Plain lambdas are left untouched and
/// therefore produce the same type error as ordinary attr selection.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, formal-set auto-call, or
/// attribute selection fails.
pub fn eval_instantiation_attr_path_owned_with_options_and_realizer(
    ir: &Ir,
    attr_path: &[Vec<u8>],
    options: TreeWalkOptions,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    let evaluator = TreeWalk::with_options(ir, options);
    eval_instantiation_attr_path_with_evaluator(ir, attr_path, evaluator, ifd_realizer)
}

/// Evaluates a source-backed IR root and selects an attr path like `nix-instantiate -A`.
///
/// This is the source-provenance variant of
/// [`eval_instantiation_attr_path_owned_with_options_and_realizer`]. It should
/// be used for file-backed root modules so diagnostics and
/// `builtins.unsafeGetAttrPos` can report the original file path and source
/// bytes.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, formal-set auto-call, or
/// attribute selection fails.
pub fn eval_instantiation_attr_path_owned_with_options_source_and_realizer(
    ir: &Ir,
    attr_path: &[Vec<u8>],
    options: TreeWalkOptions,
    source_name: impl Into<Vec<u8>>,
    source: impl Into<Vec<u8>>,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    let evaluator = TreeWalk::with_options_and_source(ir, options, source_name, source);
    eval_instantiation_attr_path_with_evaluator(ir, attr_path, evaluator, ifd_realizer)
}

fn eval_instantiation_attr_path_with_evaluator(
    ir: &Ir,
    attr_path: &[Vec<u8>],
    mut evaluator: TreeWalk,
    ifd_realizer: Option<IfdRealizer>,
) -> Result<EvalOutcome, TreeWalkError> {
    if let Some(realizer) = ifd_realizer {
        evaluator.set_ifd_realizer(realizer);
    }
    let root = evaluator.eval_root()?;
    let span = evaluator.node(ir.root)?.span;
    let value = evaluator.eval_instantiation_attr_path(ir.root, span, root, attr_path)?;
    let derivations = evaluator.derivation_snapshot()?;
    Ok(EvalOutcome {
        value,
        heap: evaluator.heap,
        trace_output: evaluator.trace_output,
        warning_output: evaluator.warning_output,
        derivations,
    })
}

pub(crate) fn attr_path_segment_is_list_index(segment: &[u8]) -> bool {
    parse_attr_path_list_index(segment).is_some()
}

pub(crate) fn parse_attr_path_list_index(segment: &[u8]) -> Option<usize> {
    let index = segment.iter().copied().try_fold(0u32, |index, byte| {
        let digit = u32::from(byte.checked_sub(b'0')?);
        if digit > 9 {
            return None;
        }
        index.checked_mul(10)?.checked_add(digit)
    })?;
    if segment.is_empty() {
        None
    } else {
        Some(index as usize)
    }
}

pub(crate) fn parse_attr_path_list_index_diagnostic(segment: &[u8]) -> i64 {
    segment
        .iter()
        .copied()
        .try_fold(0i64, |index, byte| {
            let digit = i64::from(byte - b'0');
            index.checked_mul(10)?.checked_add(digit)
        })
        .unwrap_or(i64::MAX)
}

/// Evaluates an IR root and renders it like raw `nix-instantiate --eval --strict`.
///
/// The renderer forces list elements and attribute values while printing Nix's
/// raw value syntax: quoted strings, lexicographic attribute keys,
/// `<LAMBDA>`/`<PRIMOP>` placeholders, and `«repeated»` for recursive values.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, nested forcing, or value
/// rendering fails.
pub fn eval_raw_bytes(ir: &Ir) -> Result<Vec<u8>, TreeWalkError> {
    eval_raw_bytes_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root with explicit options and renders raw strict output.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation, nested forcing, or value
/// rendering fails.
pub fn eval_raw_bytes_with_options(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<Vec<u8>, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options(ir, options);
    let value = evaluator.eval_root()?;
    let span = evaluator.node(ir.root)?.span;
    let mut out = Vec::new();
    let mut visited = Vec::new();
    evaluator.write_raw_value(ir.root, span, ir.root, span, value, &mut out, &mut visited)?;
    Ok(out)
}

/// Evaluates an IR root and renders a numeric value like raw `nix-instantiate --eval`.
///
/// Prefer [`eval_raw_bytes`] when the caller needs Nix's complete raw strict
/// value syntax.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails, or if the root value is
/// not an integer or float.
pub fn eval_number_raw_bytes(ir: &Ir) -> Result<Vec<u8>, TreeWalkError> {
    eval_number_raw_bytes_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root with explicit options and renders a numeric raw value.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails, or if the root value is
/// not an integer or float.
pub fn eval_number_raw_bytes_with_options(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<Vec<u8>, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options(ir, options);
    let value = evaluator.eval_root()?;
    let span = evaluator.node(ir.root)?.span;
    TreeWalk::raw_number_bytes(ir.root, span, value)
}
