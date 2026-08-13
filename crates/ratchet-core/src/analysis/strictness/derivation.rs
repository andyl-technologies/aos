//! Derivation-boundary demand seeding (Phase 4 Chunk B).
//!
//! `builtins.derivationStrict` serializes its argument attrset into a `.drv`:
//! it forces the argument to WHNF, then forces the `name` attribute value
//! (throwing if `name` is absent), then `__structuredAttrs` and
//! `__ignoreNulls` when present, then *every* attribute value in sorted
//! (lexicographic) attribute-name order — unconditionally, in every mode
//! (`__ignoreNulls` drops entries only after their force,
//! `__structuredAttrs` changes rendering but not the top-level force loop).
//! Between two forces the serializer performs its own processing (name
//! validation, UTF-8 checks, string coercion) which can raise observable
//! errors, so only the *first* force point is provably preceded by no
//! observable event.
//!
//! From that verified order this module seeds two kinds of facts onto the
//! binding values of a statically-shaped (non-recursive, no dynamic keys)
//! attrset literal, or a fully static chain of literal `//` updates, reaching
//! a derivation boundary:
//!
//! - **Demand marks** (`derivationStrict` only): every attribute value is
//!   forced on every normally-completing execution of the boundary, so each
//!   binding value earns [`Strictness::Demanded`]; the `name` value of a
//!   *syntactically direct* literal argument earns
//!   [`Strictness::DemandedBeforeEffect`], because its force is the first
//!   observable-event opportunity of the whole call.
//! - **Eager-assembly bits** (S2 + S3, consumed through
//!   [`crate::ir::IrFacts::assembly_eager`]): structurally *total* binding
//!   values may be evaluated directly into their slots during frame assembly
//!   (their evaluation is silent, so ordering never matters), plus at most
//!   one non-total value — the first-forced `name` binding of a direct
//!   `derivationStrict` literal. Recursive literals are declined entirely
//!   (eager evaluation could read not-yet-initialized same-frame slots), as
//!   are literals with dynamic keys (their key forces interleave with slot
//!   population).
//!
//! `builtins.derivation` (the Nix-source wrapper around `derivationStrict`)
//! forces its argument during formal-set pattern matching but performs
//! wrapper work (outputs handling, attrset merging) with its own observable
//! events before the serializer loop, so a wrapper boundary licenses the
//! totals-only eager set and no demand marks.

use crate::ir::{IrAttrPathSegment, IrData, IrDialectOp, IrId, IrKind, Strictness};
use crate::syntax::{BinOpKind, Symbol};

use super::collect::{CollectCtx, Sequence, SlotDemand, collect};
use super::frames::{FrameScope, chase_attrset_literal};
use super::{Analysis, StrictnessAnalysisError};

/// The dialect-op key `builtins.derivationStrict` lowers to.
///
/// Mirrors `aos_nix_dialect::NIX_OP_DERIVATION_STRICT`, which this crate
/// cannot name (the dialect crate depends on this one). The value is
/// format-stable: dialect-op keys are serialized raw into persisted `ir.bin`
/// artifacts, so the dialect cannot renumber it without invalidating every
/// stored artifact. A cross-crate equality test in `ratchet-oracle` pins the
/// two constants together.
pub(super) const DERIVATION_STRICT_DIALECT_OP: IrDialectOp = IrDialectOp::new(1);

/// The attribute the `derivationStrict` serializer forces first.
const NAME_ATTR: &[u8] = b"name";

/// How a derivation boundary consumes its argument attrset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DerivationBoundary {
    /// `builtins.derivationStrict`: the serializer's verified force order
    /// (name first, then sorted) starts immediately after the argument force.
    Strict,
    /// `builtins.derivation`: the Nix-source wrapper forces the argument at
    /// pattern match but performs observable wrapper work before the
    /// serializer loop, and its attribute forcing is conditional on the
    /// caller's use of the result.
    Wrapper,
}

/// One surviving binding in a statically resolved boundary shape.
#[derive(Clone, Copy)]
struct BoundaryBinding {
    /// The static attribute key.
    key: Symbol,
    /// The binding value node allocated by the source literal.
    value: IrId,
}

/// One resolved derivation-boundary argument shape.
struct BoundaryShape {
    /// The update result's surviving bindings after RHS shadowing.
    bindings: Vec<BoundaryBinding>,
    /// Whether the shape is the argument expression (possibly behind
    /// `ThunkAlloc` wrappers), rather than chased through variables. Only a
    /// direct shape's assembly is tied to the boundary's execution.
    direct: bool,
}

/// Seeds demand marks and eager-assembly bits for one derivation boundary.
///
/// `argument` is the boundary's single argument expression and `stack` the
/// walk's current frame context (used to chase variable-bound literals).
/// Arguments that do not resolve to a statically-shaped attrset literal seed
/// nothing.
///
/// # Errors
///
/// Returns [`StrictnessAnalysisError`] when node payloads or side tables are
/// internally inconsistent.
pub(super) fn seed_derivation_boundary(
    analysis: &mut Analysis<'_>,
    argument: IrId,
    stack: &[FrameScope],
    boundary: DerivationBoundary,
) -> Result<(), StrictnessAnalysisError> {
    let shape = resolve_boundary_shape(analysis, stack, argument)?;
    // Only a direct `derivationStrict` literal proves the serializer's
    // name-first force order starts immediately after assembly.
    let strict = boundary == DerivationBoundary::Strict;
    let strict_direct = strict && shape.as_ref().is_some_and(|shape| shape.direct);
    let bindings: Vec<BoundaryBinding> = match shape {
        Some(shape) => shape.bindings,
        None => super::summary::boundary_values(analysis, argument, stack)?
            .into_iter()
            .map(|(value, key)| BoundaryBinding { key, value })
            .collect(),
    };
    let seeds: Vec<(IrId, bool)> = bindings
        .into_iter()
        .map(|binding| {
            (
                binding.value,
                analysis.ir.symbols.resolve(binding.key) == Some(NAME_ATTR),
            )
        })
        .collect();
    for (value, is_name) in seeds {
        if strict {
            // The serializer forces every attribute value on every normally
            // completing execution (S1); only the first-forced `name` of a
            // direct literal is additionally proven before-effect (S2).
            let level = if is_name && strict_direct {
                Strictness::DemandedBeforeEffect
            } else {
                Strictness::Demanded
            };
            analysis.mark(value, level);
        }
        let licensed = analysis.total(value) || (is_name && strict_direct);
        if licensed && analysis.node(value)?.kind == IrKind::ThunkAlloc {
            analysis.assembly_eager.push(value);
        }
    }
    Ok(())
}

/// Collects the extra slot demand a `derivationStrict` boundary places on
/// the binding values of a syntactically direct literal argument.
///
/// The `name` value's contribution keeps its levels (it is forced before any
/// serializer event); every other value's contribution is capped behind an
/// opaque step because the serializer's processing of earlier attributes can
/// raise observable errors first. Only the direct literal is collected: its
/// binding values live in the same frame context as the collected call, so
/// their slot coordinates transfer unchanged (a non-recursive attrset
/// introduces no frame).
///
/// # Errors
///
/// Returns [`StrictnessAnalysisError`] when node payloads or side tables are
/// internally inconsistent.
pub(super) fn collect_derivation_strict_boundary(
    analysis: &mut Analysis<'_>,
    argument: IrId,
) -> Result<SlotDemand, StrictnessAnalysisError> {
    let Some(shape) = resolve_direct_shape(analysis, argument)? else {
        return Ok(SlotDemand::default());
    };
    let mut name_value = None;
    let mut rest = Vec::new();
    for binding in shape {
        if name_value.is_none() && analysis.ir.symbols.resolve(binding.key) == Some(NAME_ATTR) {
            name_value = Some(binding.value);
        } else {
            rest.push(binding.value);
        }
    }
    let mut sequence = Sequence::new();
    if let Some(name_value) = name_value {
        let map = collect(analysis, name_value, CollectCtx::Forced)?;
        sequence.push(&map, analysis.total(name_value));
    }
    // Name validation (or the missing-`name` error) can raise an observable
    // event before any later force; every remaining force is capped.
    sequence.push_opaque_step();
    for value in rest {
        let map = collect(analysis, value, CollectCtx::Forced)?;
        sequence.push(&map, false);
    }
    Ok(sequence.finish())
}

/// Resolves a boundary argument to a static attrset shape, syntactically or
/// through the frame-stack chase.
fn resolve_boundary_shape(
    analysis: &Analysis<'_>,
    stack: &[FrameScope],
    argument: IrId,
) -> Result<Option<BoundaryShape>, StrictnessAnalysisError> {
    if let Some(bindings) = resolve_direct_shape(analysis, argument)? {
        return Ok(Some(BoundaryShape {
            bindings,
            direct: true,
        }));
    }
    let mut chase_stack = stack.to_vec();
    let Some(attrset) = chase_attrset_literal(analysis, &mut chase_stack, argument)? else {
        return Ok(None);
    };
    Ok(
        static_literal_bindings(analysis, attrset)?.map(|bindings| BoundaryShape {
            bindings,
            direct: false,
        }),
    )
}

/// Resolves direct static literals and `//` chains, applying RHS shadowing.
fn resolve_direct_shape(
    analysis: &Analysis<'_>,
    argument: IrId,
) -> Result<Option<Vec<BoundaryBinding>>, StrictnessAnalysisError> {
    resolve_direct_shape_inner(analysis, argument, 0)
}

fn resolve_direct_shape_inner(
    analysis: &Analysis<'_>,
    argument: IrId,
    depth: usize,
) -> Result<Option<Vec<BoundaryBinding>>, StrictnessAnalysisError> {
    if depth >= super::frames::CHASE_BUDGET {
        return Ok(None);
    }
    let node = analysis.node(argument)?;
    match node.data {
        IrData::AttrSet { .. } => static_literal_bindings(analysis, argument),
        IrData::Node(body) if node.kind == IrKind::ThunkAlloc => {
            resolve_direct_shape_inner(analysis, body, depth + 1)
        }
        IrData::Binary {
            op: BinOpKind::Update,
            lhs,
            rhs,
        } if node.kind == IrKind::BinOp => {
            let Some(mut left) = resolve_direct_shape_inner(analysis, lhs, depth + 1)? else {
                return Ok(None);
            };
            let Some(right) = resolve_direct_shape_inner(analysis, rhs, depth + 1)? else {
                return Ok(None);
            };
            for binding in right {
                left.retain(|entry| entry.key != binding.key);
                left.push(binding);
            }
            Ok(Some(left))
        }
        _ => Ok(None),
    }
}

/// Returns a literal's all-static bindings, declining recursive/dynamic sets.
fn static_literal_bindings(
    analysis: &Analysis<'_>,
    attrset: IrId,
) -> Result<Option<Vec<BoundaryBinding>>, StrictnessAnalysisError> {
    let node = analysis.node(attrset)?;
    let IrData::AttrSet {
        bindings,
        recursive,
        has_dynamic,
        ..
    } = node.data
    else {
        return Ok(None);
    };
    // Recursive literals risk eager reads of not-yet-initialized same-frame
    // slots (and `__overrides` can replace slot values); dynamic keys force
    // interleaved with slot population and can collide with static lookups.
    if recursive || has_dynamic {
        return Ok(None);
    }
    let mut result = Vec::new();
    for binding in analysis.bindings(attrset, bindings)? {
        let IrAttrPathSegment::Static(key) = binding.key else {
            return Ok(None);
        };
        result.push(BoundaryBinding {
            key,
            value: binding.value,
        });
    }
    Ok(Some(result))
}
