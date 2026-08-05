//! Cross-module GRIN fragment plans for one demand epoch.
//!
//! This module defines a compact, runtime-independent shadow IR between
//! [`crate::ir::Ir`] and a future whole-demand GRIN executor. A
//! [`GrinRegion`] is an inventory of operations and boundaries, not executable
//! bytecode: operations describe virtual allocations, demand edges, guarded
//! calls, and the state that an executor would have to materialize.
//!
//! Source identities retain the caller-owned module id, original [`IrId`],
//! [`Span`], and lexical-frame specialization. Consequently an oracle-side
//! linker can combine fragments from independently lowered modules without
//! renumbering their source IR.
//!
//! Lowering is fail-closed. The reachable IR graph and all referenced side
//! tables are validated by the Promise/PIR planner before a fragment is
//! produced. Dynamic scope, effects, unsupported forms, and guard fallbacks
//! become explicit materialization statepoints. Malformed metadata is an error.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use thiserror::Error;

use crate::analysis::{
    PromiseRegionDisposition, PromiseRegionError, PromiseRegionKey, PromiseRegionOptions,
    PromiseRegionSymbolValidation, PromiseStatepointKind, VirtualAllocationKind,
    plan_promise_region,
};
use crate::ir::{Ir, IrData, IrId, IrKind};
use crate::scope::{FrameId, Upvalue};
use crate::syntax::Span;

/// The default maximum number of guarded targets retained at one call site.
pub const DEFAULT_GRIN_CALL_TARGET_CAP: usize = 4;
/// The exact capture-layout encoding version emitted by this module.
pub const GRIN_CAPTURE_LAYOUT_VERSION: u32 = 1;

/// Identifies one independently lowered module by an exact content digest.
///
/// The digest must cover the serialized IR and resolver side tables used to
/// construct code references. It is deliberately not a process-local module
/// handle: guarded code identities must remain unambiguous across caches and
/// independently linked demand epochs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrinModuleId([u8; 32]);

impl GrinModuleId {
    /// Creates a module identity from its exact content digest.
    pub const fn from_content_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Returns the exact module content digest.
    pub const fn content_digest(self) -> [u8; 32] {
        self.0
    }
}

/// Identifies one caller-owned whole-demand compilation epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrinDemandEpochId(u64);

impl GrinDemandEpochId {
    /// Creates a demand-epoch identity from a caller-owned stable value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the caller-owned stable value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Identifies one frame-specialized source operation across modules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrinSourceKey {
    /// The module that owns the source IR.
    pub module: GrinModuleId,
    /// The original source IR node.
    pub ir: IrId,
    /// The lexical frame specialization used by the plan.
    pub frame: Option<FrameId>,
}

/// Keys a fragment by module, entry node, and lexical frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrinFragmentKey {
    /// The whole-demand epoch that owns this fragment.
    pub epoch: GrinDemandEpochId,
    /// The module containing the entry node.
    pub module: GrinModuleId,
    /// The source IR node at which demand enters.
    pub entry: IrId,
    /// The lexical frame active at entry.
    pub frame: Option<FrameId>,
}

impl GrinFragmentKey {
    /// Creates a cross-module fragment key.
    pub const fn new(
        epoch: GrinDemandEpochId,
        module: GrinModuleId,
        entry: IrId,
        frame: Option<FrameId>,
    ) -> Self {
        Self {
            epoch,
            module,
            entry,
            frame,
        }
    }
}

/// Identifies one virtual allocation site within a fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrinAllocationId(u32);

impl GrinAllocationId {
    /// Returns the zero-based allocation-site index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Identifies one materialization boundary within a fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrinStatepointId(u32);

impl GrinStatepointId {
    /// Returns the zero-based statepoint index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// The virtual heap representation owned by an allocation site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GrinVirtualKind {
    /// A lazy promise with update semantics.
    Promise,
    /// A callable closure and its projected environment.
    Closure,
    /// A lexical environment frame.
    Frame,
    /// A persistent list spine and element vector.
    List,
    /// A statically shaped attribute set.
    Attrs,
}

impl From<VirtualAllocationKind> for GrinVirtualKind {
    fn from(kind: VirtualAllocationKind) -> Self {
        match kind {
            VirtualAllocationKind::Promise => Self::Promise,
            VirtualAllocationKind::Frame => Self::Frame,
            VirtualAllocationKind::Closure => Self::Closure,
            VirtualAllocationKind::List => Self::List,
            VirtualAllocationKind::Attrs => Self::Attrs,
        }
    }
}

/// An exact, versioned closure capture layout.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrinCaptureLayout {
    /// The caller-owned layout format version.
    pub version: u32,
    /// The number of slots in the closure's resolver frame.
    pub slot_count: u32,
    /// Exact free-variable coordinates in resolver capture order.
    pub captures: Box<[Upvalue]>,
    /// Whether the resolver frame is recursively self-visible.
    pub recursive: bool,
    /// Whether dynamic `with` scope is active inside the frame.
    pub has_dynamic_scope: bool,
}

/// An exact cross-module code reference used by guarded dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrinCodeRef {
    /// The exact content identity of the target module.
    pub module: GrinModuleId,
    /// The target lambda definition's original IR id.
    pub definition: IrId,
    /// The target lambda body's original IR id.
    pub body: IrId,
    /// The resolver frame owned by the lambda definition.
    pub resolver_frame: Option<FrameId>,
    /// The exact versioned capture layout expected by generated code.
    pub capture_layout: GrinCaptureLayout,
}

/// A guarded call destination understood by an oracle-side fragment linker.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrinCallTarget {
    /// The exact code identity to compare and dispatch.
    pub code: GrinCodeRef,
}

/// Bounded target metadata supplied for one source application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrinCallSiteTargets {
    /// The application whose forced closure identity must be guarded.
    pub apply: IrId,
    /// Candidate destinations in caller-independent module coordinates.
    pub targets: Box<[GrinCallTarget]>,
    /// Whether analysis discarded candidates after reaching its bound.
    pub overflow: bool,
}

/// Configuration for GRIN fragment lowering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrinRegionOptions {
    /// The maximum lexical-frame specializations admitted for one IR node.
    pub specialization_cap: usize,
    /// The maximum guarded call targets admitted at one application.
    pub call_target_cap: usize,
    /// The symbol-table validation contract for the source IR.
    pub symbol_validation: PromiseRegionSymbolValidation,
}

impl Default for GrinRegionOptions {
    fn default() -> Self {
        Self {
            specialization_cap: crate::DEFAULT_PROMISE_REGION_SPECIALIZATION_CAP,
            call_target_cap: DEFAULT_GRIN_CALL_TARGET_CAP,
            symbol_validation: PromiseRegionSymbolValidation::IrTable,
        }
    }
}

/// Why a GRIN region must return control to its oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GrinStatepointReason {
    /// The Promise/PIR structural planner found a dynamic or unsupported form.
    Structural(PromiseStatepointKind),
    /// No guarded target matched the forced closure identity.
    GuardFallback,
}

/// One declarative operation in a GRIN shadow fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrinOperationKind {
    /// Evaluates an allocation-free source operation inside the region.
    Evaluate {
        /// The original lowered node taxonomy entry.
        kind: IrKind,
    },
    /// Creates a virtual heap object retained inside the region.
    Allocate {
        /// The deterministic allocation-site identity.
        allocation: GrinAllocationId,
        /// The object's virtual representation.
        kind: GrinVirtualKind,
    },
    /// Demands a source value.
    Force {
        /// The frame-specialized value being demanded.
        value: GrinSourceKey,
    },
    /// Declares the update edge taken if forcing a virtual promise succeeds.
    Update {
        /// The promise allocation receiving the result.
        promise: GrinAllocationId,
    },
    /// Dispatches to one of a bounded set after guarding closure identity.
    GuardCall {
        /// The source expression producing the callee.
        callee: GrinSourceKey,
        /// The source expression producing the argument.
        argument: GrinSourceKey,
        /// Canonically ordered guarded destinations.
        targets: Box<[GrinCallTarget]>,
        /// Whether additional targets were omitted by analysis.
        overflow: bool,
        /// The materialization boundary used when no guard matches.
        fallback: GrinStatepointId,
    },
    /// Materializes all live virtual state required by an oracle continuation.
    Materialize {
        /// The statepoint consuming the materialized state.
        statepoint: GrinStatepointId,
    },
    /// Transfers control to the oracle at a conservative boundary.
    Statepoint {
        /// The deterministic boundary identity.
        statepoint: GrinStatepointId,
        /// Why native regional execution cannot continue.
        reason: GrinStatepointReason,
    },
}

/// One operation with its exact source and diagnostic identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrinOperation {
    /// The source module, IR node, and frame specialization.
    pub source: GrinSourceKey,
    /// The original byte span used for diagnostics and deoptimization.
    pub span: Span,
    /// The operation described by this shadow entry.
    pub kind: GrinOperationKind,
}

/// One deterministic virtual allocation record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrinAllocationSite {
    /// The fragment-local allocation identity.
    pub id: GrinAllocationId,
    /// The frame-specialized source that owns the allocation.
    pub source: GrinSourceKey,
    /// The original source byte span.
    pub span: Span,
    /// The virtual representation allocated at the site.
    pub kind: GrinVirtualKind,
}

/// One deterministic oracle/materialization boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrinStatepoint {
    /// The fragment-local statepoint identity.
    pub id: GrinStatepointId,
    /// The frame-specialized source at the boundary.
    pub source: GrinSourceKey,
    /// The original source byte span.
    pub span: Span,
    /// Why regional execution cannot continue.
    pub reason: GrinStatepointReason,
}

/// The bounded lexical-frame specializations retained for one source node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrinNodeSpecializations {
    /// The module containing the source node.
    pub module: GrinModuleId,
    /// The original source IR node.
    pub ir: IrId,
    /// Canonically ordered frame signatures admitted for the node.
    ///
    /// `None` denotes the module root environment and sorts before concrete
    /// frame ids.
    pub frames: Box<[Option<FrameId>]>,
}

/// Deterministic structural accounting for one fragment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrinRegionAccounting {
    /// Distinct source IR nodes represented by the fragment.
    pub unique_ir_nodes: usize,
    /// Total frame-specialized source nodes represented by the fragment.
    pub specializations: usize,
    /// Largest number of frame specializations retained for one source node.
    pub max_specializations_per_node: usize,
    /// Number of declarative operations emitted.
    pub operations: usize,
    /// Number of virtual Promise allocation sites.
    pub promises: usize,
    /// Number of virtual Closure allocation sites.
    pub closures: usize,
    /// Number of virtual Frame allocation sites.
    pub frames: usize,
    /// Number of virtual List allocation sites.
    pub lists: usize,
    /// Number of virtual Attrs allocation sites.
    pub attrs: usize,
    /// Number of materialization statepoints.
    pub statepoints: usize,
    /// Number of guarded call operations.
    pub guarded_calls: usize,
}

impl GrinRegionAccounting {
    /// Returns the total number of virtual allocation sites.
    pub const fn virtual_allocations(self) -> usize {
        self.promises + self.closures + self.frames + self.lists + self.attrs
    }

    fn record_allocation(&mut self, kind: GrinVirtualKind) {
        match kind {
            GrinVirtualKind::Promise => self.promises += 1,
            GrinVirtualKind::Closure => self.closures += 1,
            GrinVirtualKind::Frame => self.frames += 1,
            GrinVirtualKind::List => self.lists += 1,
            GrinVirtualKind::Attrs => self.attrs += 1,
        }
    }
}

/// A module-independent GRIN shadow fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrinRegion {
    /// The fragment's stable cross-module entry identity.
    pub key: GrinFragmentKey,
    /// Declarative operations in deterministic planner order.
    pub operations: Vec<GrinOperation>,
    /// Virtual allocation sites in allocation-id order.
    pub allocations: Vec<GrinAllocationSite>,
    /// Materialization boundaries in statepoint-id order.
    pub statepoints: Vec<GrinStatepoint>,
    /// Bounded specialization sets in ascending source IR-id order.
    pub specializations: Vec<GrinNodeSpecializations>,
    /// Structural counts derived from the emitted artifact.
    pub accounting: GrinRegionAccounting,
}

/// Fail-closed errors from GRIN fragment lowering.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GrinRegionError {
    /// Promise/PIR graph validation or specialization failed.
    #[error(transparent)]
    PromiseRegion(#[from] PromiseRegionError),
    /// The guarded-call target cap was zero.
    #[error("GRIN guarded-call target cap must be nonzero")]
    InvalidCallTargetCap,
    /// More than one target record described an application.
    #[error("duplicate GRIN target metadata for application {apply:?}")]
    DuplicateCallSite {
        /// The multiply described application.
        apply: IrId,
    },
    /// Target metadata referenced a missing or non-application node.
    #[error("GRIN target metadata references non-application node {apply:?}")]
    InvalidCallSite {
        /// The invalid application id.
        apply: IrId,
    },
    /// One target set exceeded the configured bound.
    #[error("application {apply:?} has {count} GRIN targets, exceeding cap {cap}")]
    CallTargetCap {
        /// The overfull application.
        apply: IrId,
        /// The number of supplied targets.
        count: usize,
        /// The configured bound.
        cap: usize,
    },
    /// A target set repeated the same destination.
    #[error("application {apply:?} repeats GRIN target {target:?}")]
    DuplicateCallTarget {
        /// The application containing the duplicate.
        apply: IrId,
        /// The repeated target.
        target: GrinCallTarget,
    },
    /// A same-module destination was not a lambda definition.
    #[error("application {apply:?} targets invalid local lambda {definition:?}")]
    InvalidLocalTarget {
        /// The application containing the invalid target.
        apply: IrId,
        /// The purported lambda definition.
        definition: IrId,
    },
    /// The fragment exceeded `u32` allocation or statepoint addressability.
    #[error("GRIN fragment metadata exceeds u32 addressability")]
    MetadataOverflow,
}

/// Lowers one demand entry into a conservative cross-module GRIN shadow plan.
///
/// `call_sites` may name targets in other independently lowered modules. Every
/// call retains a guard fallback; target metadata is therefore useful even
/// when `overflow` is true. Same-module targets are validated as literal
/// lambda nodes. Target order in the result is canonical and independent of
/// caller insertion order.
///
/// # Errors
///
/// Returns [`GrinRegionError`] when reachable IR or its side tables are
/// malformed, specialization or target bounds are exceeded, target metadata
/// is inconsistent, or fragment-local ids exceed `u32` addressability.
pub fn lower_grin_region(
    ir: &Ir,
    key: GrinFragmentKey,
    call_sites: &[GrinCallSiteTargets],
    options: GrinRegionOptions,
) -> Result<GrinRegion, GrinRegionError> {
    if options.call_target_cap == 0 {
        return Err(GrinRegionError::InvalidCallTargetCap);
    }
    let calls = validate_call_sites(ir, key.module, call_sites, options)?;
    let promise = plan_promise_region(
        ir,
        key.entry,
        key.frame,
        PromiseRegionOptions {
            specialization_cap: options.specialization_cap,
            symbol_validation: options.symbol_validation,
        },
    )?;

    let mut accounting = GrinRegionAccounting {
        unique_ir_nodes: promise.unique_ir_nodes,
        specializations: promise.specialization_count,
        max_specializations_per_node: promise.max_specializations_per_node,
        ..GrinRegionAccounting::default()
    };
    let specializations = collect_specializations(key.module, &promise.nodes);
    let mut allocations = Vec::with_capacity(promise.virtual_allocation_sites.len());
    let mut allocation_by_source_kind = HashMap::new();
    for site in &promise.virtual_allocation_sites {
        let id = GrinAllocationId(
            u32::try_from(allocations.len()).map_err(|_| GrinRegionError::MetadataOverflow)?,
        );
        let source = source_key(key.module, site.key);
        let span = ir
            .arena
            .node(site.key.node)
            .ok_or(PromiseRegionError::InvalidNode { id: site.key.node })?
            .span;
        let kind = GrinVirtualKind::from(site.kind);
        accounting.record_allocation(kind);
        allocations.push(GrinAllocationSite {
            id,
            source,
            span,
            kind,
        });
        allocation_by_source_kind.insert((source, kind), id);
    }

    let mut operations = Vec::new();
    let mut statepoints = Vec::new();
    for planned in &promise.nodes {
        let source = source_key(key.module, planned.key);
        let node = *ir
            .arena
            .node(planned.key.node)
            .ok_or(PromiseRegionError::InvalidNode {
                id: planned.key.node,
            })?;

        for allocation in allocations.iter().filter(|site| site.source == source) {
            operations.push(GrinOperation {
                source,
                span: node.span,
                kind: GrinOperationKind::Allocate {
                    allocation: allocation.id,
                    kind: allocation.kind,
                },
            });
        }

        let supplied_call = calls.get(&planned.key.node.as_u32());
        if node.kind == IrKind::Apply && supplied_call.is_some() {
            lower_guarded_call(
                key.module,
                planned.key,
                node,
                supplied_call.copied(),
                &allocation_by_source_kind,
                &mut operations,
                &mut statepoints,
            )?;
            accounting.guarded_calls += 1;
            continue;
        }

        match planned.disposition {
            PromiseRegionDisposition::Statepoint(reason) => {
                push_statepoint(
                    source,
                    node.span,
                    GrinStatepointReason::Structural(reason),
                    &mut operations,
                    &mut statepoints,
                )?;
            }
            PromiseRegionDisposition::Native | PromiseRegionDisposition::Virtual(_) => {
                push_forces(
                    key.module,
                    planned.key,
                    node,
                    &allocation_by_source_kind,
                    &mut operations,
                );
                if node.kind == IrKind::Apply {
                    if let Some((targets, overflow)) = local_literal_target(ir, key.module, node) {
                        lower_guarded_call(
                            key.module,
                            planned.key,
                            node,
                            Some((&targets, overflow)),
                            &allocation_by_source_kind,
                            &mut operations,
                            &mut statepoints,
                        )?;
                        accounting.guarded_calls += 1;
                    } else {
                        operations.push(GrinOperation {
                            source,
                            span: node.span,
                            kind: GrinOperationKind::Evaluate { kind: node.kind },
                        });
                    }
                } else {
                    operations.push(GrinOperation {
                        source,
                        span: node.span,
                        kind: GrinOperationKind::Evaluate { kind: node.kind },
                    });
                }
            }
        }
    }
    accounting.operations = operations.len();
    accounting.statepoints = statepoints.len();
    debug_assert_eq!(accounting.virtual_allocations(), allocations.len());
    Ok(GrinRegion {
        key,
        operations,
        allocations,
        statepoints,
        specializations,
        accounting,
    })
}

type CanonicalCallSites<'a> = HashMap<u32, (&'a [GrinCallTarget], bool)>;

fn validate_call_sites<'a>(
    ir: &Ir,
    module: GrinModuleId,
    call_sites: &'a [GrinCallSiteTargets],
    options: GrinRegionOptions,
) -> Result<CanonicalCallSites<'a>, GrinRegionError> {
    let mut calls = HashMap::with_capacity(call_sites.len());
    for call in call_sites {
        let Some(node) = ir.arena.node(call.apply) else {
            return Err(GrinRegionError::InvalidCallSite { apply: call.apply });
        };
        if node.kind != IrKind::Apply {
            return Err(GrinRegionError::InvalidCallSite { apply: call.apply });
        }
        if call.targets.len() > options.call_target_cap {
            return Err(GrinRegionError::CallTargetCap {
                apply: call.apply,
                count: call.targets.len(),
                cap: options.call_target_cap,
            });
        }
        let mut seen = HashSet::with_capacity(call.targets.len());
        for target in &call.targets {
            if !seen.insert(target.clone()) {
                return Err(GrinRegionError::DuplicateCallTarget {
                    apply: call.apply,
                    target: target.clone(),
                });
            }
            if target.code.module == module {
                if !ir
                    .arena
                    .node(target.code.definition)
                    .is_some_and(|target| target.kind == IrKind::Lambda)
                {
                    return Err(GrinRegionError::InvalidLocalTarget {
                        apply: call.apply,
                        definition: target.code.definition,
                    });
                }
                let target_node = *ir.arena.node(target.code.definition).ok_or(
                    GrinRegionError::InvalidLocalTarget {
                        apply: call.apply,
                        definition: target.code.definition,
                    },
                )?;
                let IrData::Lambda { body, frame, .. } = target_node.data else {
                    return Err(GrinRegionError::InvalidLocalTarget {
                        apply: call.apply,
                        definition: target.code.definition,
                    });
                };
                if body != target.code.body
                    || frame != target.code.resolver_frame
                    || capture_layout(ir, frame) != Some(target.code.capture_layout.clone())
                {
                    return Err(GrinRegionError::InvalidLocalTarget {
                        apply: call.apply,
                        definition: target.code.definition,
                    });
                }
                plan_promise_region(
                    ir,
                    target.code.definition,
                    target.code.resolver_frame,
                    PromiseRegionOptions {
                        specialization_cap: options.specialization_cap,
                        symbol_validation: options.symbol_validation,
                    },
                )?;
            }
        }
        if calls
            .insert(call.apply.as_u32(), (call.targets.as_ref(), call.overflow))
            .is_some()
        {
            return Err(GrinRegionError::DuplicateCallSite { apply: call.apply });
        }
    }
    Ok(calls)
}

fn source_key(module: GrinModuleId, key: PromiseRegionKey) -> GrinSourceKey {
    GrinSourceKey {
        module,
        ir: key.node,
        frame: key.frame,
    }
}

fn capture_layout(ir: &Ir, frame: Option<FrameId>) -> Option<GrinCaptureLayout> {
    match frame {
        Some(frame) => {
            let info = ir.frames.get(frame.index())?;
            Some(GrinCaptureLayout {
                version: GRIN_CAPTURE_LAYOUT_VERSION,
                slot_count: info.slot_count,
                captures: info.captures.clone(),
                recursive: info.rec,
                has_dynamic_scope: info.has_with,
            })
        }
        None => Some(GrinCaptureLayout {
            version: GRIN_CAPTURE_LAYOUT_VERSION,
            slot_count: 0,
            captures: Box::new([]),
            recursive: false,
            has_dynamic_scope: false,
        }),
    }
}

fn collect_specializations(
    module: GrinModuleId,
    nodes: &[crate::PromiseRegionNode],
) -> Vec<GrinNodeSpecializations> {
    let mut by_node = BTreeMap::<u32, BTreeSet<Option<FrameId>>>::new();
    for node in nodes {
        by_node
            .entry(node.key.node.as_u32())
            .or_default()
            .insert(node.key.frame);
    }
    by_node
        .into_iter()
        .map(|(ir, frames)| GrinNodeSpecializations {
            module,
            ir: IrId::new(ir),
            frames: frames.into_iter().collect(),
        })
        .collect()
}

fn lower_guarded_call(
    module: GrinModuleId,
    key: PromiseRegionKey,
    node: crate::ir::IrNode,
    supplied: Option<(&[GrinCallTarget], bool)>,
    allocation_by_source_kind: &HashMap<(GrinSourceKey, GrinVirtualKind), GrinAllocationId>,
    operations: &mut Vec<GrinOperation>,
    statepoints: &mut Vec<GrinStatepoint>,
) -> Result<(), GrinRegionError> {
    let IrData::Pair {
        first: callee,
        second: argument,
    } = node.data
    else {
        return Err(PromiseRegionError::InvalidPayload {
            id: key.node,
            kind: node.kind,
            expected: "pair payload",
        }
        .into());
    };
    push_force(
        module,
        key.frame,
        callee,
        key.node,
        node.span,
        allocation_by_source_kind,
        operations,
    );
    let statepoint = next_statepoint_id(statepoints)?;
    let source = source_key(module, key);
    let (targets, overflow) = supplied.unwrap_or((&[], true));
    let mut targets = targets.to_vec();
    targets.sort_unstable_by(|left, right| {
        code_ref_sort_key(&left.code).cmp(&code_ref_sort_key(&right.code))
    });
    operations.push(GrinOperation {
        source,
        span: node.span,
        kind: GrinOperationKind::GuardCall {
            callee: GrinSourceKey {
                module,
                ir: callee,
                frame: key.frame,
            },
            argument: GrinSourceKey {
                module,
                ir: argument,
                frame: key.frame,
            },
            targets: targets.into_boxed_slice(),
            overflow,
            fallback: statepoint,
        },
    });
    push_statepoint_with_id(
        statepoint,
        source,
        node.span,
        GrinStatepointReason::GuardFallback,
        operations,
        statepoints,
    );
    Ok(())
}

fn local_literal_target(
    ir: &Ir,
    module: GrinModuleId,
    node: crate::ir::IrNode,
) -> Option<(Box<[GrinCallTarget]>, bool)> {
    let IrData::Pair { mut first, .. } = node.data else {
        return None;
    };
    let mut peeled = false;
    loop {
        let target = ir.arena.node(first)?;
        match target.data {
            IrData::Lambda { .. } if target.kind == IrKind::Lambda => {
                let IrData::Lambda { body, frame, .. } = target.data else {
                    return None;
                };
                return Some((
                    vec![GrinCallTarget {
                        code: GrinCodeRef {
                            module,
                            definition: first,
                            body,
                            resolver_frame: frame,
                            capture_layout: capture_layout(ir, frame)?,
                        },
                    }]
                    .into_boxed_slice(),
                    false,
                ));
            }
            IrData::Node(body) if target.kind == IrKind::ThunkAlloc && !peeled => {
                first = body;
                peeled = true;
            }
            _ => return None,
        }
    }
}

fn code_ref_sort_key(
    code: &GrinCodeRef,
) -> (
    [u8; 32],
    u32,
    u32,
    Option<FrameId>,
    u32,
    u32,
    &[Upvalue],
    bool,
    bool,
) {
    (
        code.module.content_digest(),
        code.definition.as_u32(),
        code.body.as_u32(),
        code.resolver_frame,
        code.capture_layout.version,
        code.capture_layout.slot_count,
        code.capture_layout.captures.as_ref(),
        code.capture_layout.recursive,
        code.capture_layout.has_dynamic_scope,
    )
}

fn push_forces(
    module: GrinModuleId,
    key: PromiseRegionKey,
    node: crate::ir::IrNode,
    allocation_by_source_kind: &HashMap<(GrinSourceKey, GrinVirtualKind), GrinAllocationId>,
    operations: &mut Vec<GrinOperation>,
) {
    let mut force = |value| {
        push_force(
            module,
            key.frame,
            value,
            key.node,
            node.span,
            allocation_by_source_kind,
            operations,
        );
    };
    match (node.kind, node.data) {
        (IrKind::Select, IrData::Select { receiver, .. })
        | (IrKind::HasAttr, IrData::HasAttr { receiver, .. }) => force(receiver),
        (IrKind::If, IrData::Triple { first, .. }) => force(first),
        (IrKind::BinOp, IrData::Binary { lhs, rhs, .. }) => {
            force(lhs);
            force(rhs);
        }
        (IrKind::UnaryOp, IrData::Unary { operand, .. }) => force(operand),
        // Guarded calls emit their callee force together with the guard.
        _ => {}
    }
}

fn push_force(
    module: GrinModuleId,
    frame: Option<FrameId>,
    value: IrId,
    owner: IrId,
    span: Span,
    allocation_by_source_kind: &HashMap<(GrinSourceKey, GrinVirtualKind), GrinAllocationId>,
    operations: &mut Vec<GrinOperation>,
) {
    let source = GrinSourceKey {
        module,
        ir: owner,
        frame,
    };
    let value = GrinSourceKey {
        module,
        ir: value,
        frame,
    };
    operations.push(GrinOperation {
        source,
        span,
        kind: GrinOperationKind::Force { value },
    });
    if let Some(promise) = allocation_by_source_kind
        .get(&(value, GrinVirtualKind::Promise))
        .copied()
    {
        operations.push(GrinOperation {
            source,
            span,
            kind: GrinOperationKind::Update { promise },
        });
    }
}

fn push_statepoint(
    source: GrinSourceKey,
    span: Span,
    reason: GrinStatepointReason,
    operations: &mut Vec<GrinOperation>,
    statepoints: &mut Vec<GrinStatepoint>,
) -> Result<(), GrinRegionError> {
    let id = next_statepoint_id(statepoints)?;
    push_statepoint_with_id(id, source, span, reason, operations, statepoints);
    Ok(())
}

fn push_statepoint_with_id(
    id: GrinStatepointId,
    source: GrinSourceKey,
    span: Span,
    reason: GrinStatepointReason,
    operations: &mut Vec<GrinOperation>,
    statepoints: &mut Vec<GrinStatepoint>,
) {
    operations.push(GrinOperation {
        source,
        span,
        kind: GrinOperationKind::Materialize { statepoint: id },
    });
    operations.push(GrinOperation {
        source,
        span,
        kind: GrinOperationKind::Statepoint {
            statepoint: id,
            reason,
        },
    });
    statepoints.push(GrinStatepoint {
        id,
        source,
        span,
        reason,
    });
}

fn next_statepoint_id(statepoints: &[GrinStatepoint]) -> Result<GrinStatepointId, GrinRegionError> {
    Ok(GrinStatepointId(
        u32::try_from(statepoints.len()).map_err(|_| GrinRegionError::MetadataOverflow)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{EffectClass, IrArena, IrFacts, IrNode};
    use crate::scope::FrameInfo;
    use crate::syntax::{SymbolTable, parse_str};
    use crate::{lower, resolve};

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    fn lower_source(source: &str) -> GrinRegion {
        let ir = lowered(source);
        lower_grin_region(
            &ir,
            GrinFragmentKey::new(GrinDemandEpochId::new(11), module(7), ir.root, None),
            &[],
            GrinRegionOptions::default(),
        )
        .expect("GRIN region lowers")
    }

    #[test]
    fn lowers_known_call_let_and_list_with_stable_source_identity() {
        let region = lower_source("(x: let y = 1; in [ x y ]) 1");

        assert!(region.accounting.frames >= 1);
        assert!(region.accounting.closures >= 1);
        assert!(region.accounting.promises >= 1);
        assert!(region.accounting.lists >= 1);
        assert!(region.accounting.guarded_calls >= 1);
        assert_eq!(
            region.accounting.virtual_allocations(),
            region.allocations.len()
        );
        assert_eq!(
            region.specializations.len(),
            region.accounting.unique_ir_nodes
        );
        assert_eq!(
            region
                .specializations
                .iter()
                .map(|set| set.frames.len())
                .max(),
            Some(region.accounting.max_specializations_per_node)
        );
        assert!(region.operations.iter().all(|operation| {
            operation.source.module == module(7)
                && operation.span
                    == region
                        .operations
                        .iter()
                        .find(|candidate| candidate.source == operation.source)
                        .map(|candidate| candidate.span)
                        .expect("source has a span")
        }));
        assert!(region.operations.iter().any(|operation| {
            matches!(
                operation.kind,
                GrinOperationKind::GuardCall {
                    ref targets,
                    overflow: false,
                    ..
                } if targets.len() == 1
            )
        }));
        let code = region
            .operations
            .iter()
            .find_map(|operation| match &operation.kind {
                GrinOperationKind::GuardCall { targets, .. } => {
                    targets.first().map(|target| &target.code)
                }
                _ => None,
            })
            .expect("known call has an exact code reference");
        let lambda = region
            .operations
            .iter()
            .find(|operation| operation.source.ir == code.definition)
            .expect("lambda source is represented");
        assert_eq!(code.module.content_digest(), [7; 32]);
        assert_eq!(lambda.source.module, code.module);
        assert_eq!(code.capture_layout.version, GRIN_CAPTURE_LAYOUT_VERSION);
    }

    #[test]
    fn dynamic_scope_and_effects_materialize_fail_closed() {
        let dynamic = lower_source("let key = \"answer\"; in { ${key} = 42; }");
        assert!(dynamic.statepoints.iter().any(|statepoint| {
            matches!(
                statepoint.reason,
                GrinStatepointReason::Structural(PromiseStatepointKind::DynamicAttrSet)
            )
        }));
        assert_eq!(
            dynamic
                .operations
                .iter()
                .filter(|operation| matches!(operation.kind, GrinOperationKind::Materialize { .. }))
                .count(),
            dynamic.statepoints.len()
        );

        let span = Span::new(4, 9);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                span,
                EffectClass::new(1, false),
                IrData::Int(1),
            )],
            Vec::new(),
        );
        let ir = raw_ir(IrId::new(0), arena);
        let effect = lower_grin_region(
            &ir,
            GrinFragmentKey::new(GrinDemandEpochId::new(11), module(1), ir.root, None),
            &[],
            GrinRegionOptions::default(),
        )
        .expect("effect boundary lowers");
        assert_eq!(effect.statepoints[0].span, span);
        assert_eq!(
            effect.statepoints[0].reason,
            GrinStatepointReason::Structural(PromiseStatepointKind::Effect)
        );

        let unsupported = lower_source("assert true; 1");
        assert!(unsupported.statepoints.iter().any(|statepoint| {
            matches!(
                statepoint.reason,
                GrinStatepointReason::Structural(PromiseStatepointKind::Unsupported)
            )
        }));
    }

    #[test]
    fn canonicalizes_bounded_cross_module_guard_targets() {
        let ir = lowered("f: f 1");
        let apply = ir
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find_map(|(index, node)| (node.kind == IrKind::Apply).then(|| IrId::new(index as u32)))
            .expect("application exists");
        let call = GrinCallSiteTargets {
            apply,
            targets: vec![external_target(9, 8), external_target(8, 9)].into_boxed_slice(),
            overflow: true,
        };
        let region = lower_grin_region(
            &ir,
            GrinFragmentKey::new(GrinDemandEpochId::new(11), module(7), apply, None),
            &[call],
            GrinRegionOptions::default(),
        )
        .expect("cross-module targets lower");
        let guard = region
            .operations
            .iter()
            .find_map(|operation| match &operation.kind {
                GrinOperationKind::GuardCall {
                    targets, overflow, ..
                } => Some((targets, overflow)),
                _ => None,
            })
            .expect("guard exists");
        assert!(*guard.1);
        assert_eq!(guard.0[0].code.module, module(8));
        assert_eq!(
            region.statepoints[0].reason,
            GrinStatepointReason::GuardFallback
        );
    }

    #[test]
    fn rejects_overfull_and_invalid_target_metadata() {
        let ir = lowered("f: f 1");
        let apply = ir
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find_map(|(index, node)| (node.kind == IrKind::Apply).then(|| IrId::new(index as u32)))
            .expect("application exists");
        let target = external_target(9, 0);
        let call = GrinCallSiteTargets {
            apply,
            targets: vec![target.clone(), target.clone()].into_boxed_slice(),
            overflow: false,
        };
        assert!(matches!(
            lower_grin_region(
                &ir,
                GrinFragmentKey::new(GrinDemandEpochId::new(11), module(7), apply, None,),
                &[call],
                GrinRegionOptions::default(),
            ),
            Err(GrinRegionError::DuplicateCallTarget { .. })
        ));

        let overfull = GrinCallSiteTargets {
            apply,
            targets: vec![target, external_target(9, 1)].into_boxed_slice(),
            overflow: true,
        };
        assert!(matches!(
            lower_grin_region(
                &ir,
                GrinFragmentKey::new(GrinDemandEpochId::new(11), module(7), apply, None,),
                &[overfull],
                GrinRegionOptions {
                    call_target_cap: 1,
                    ..GrinRegionOptions::default()
                },
            ),
            Err(GrinRegionError::CallTargetCap { .. })
        ));

        let lambda = ir
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find_map(|(index, node)| {
                (node.kind == IrKind::Lambda).then(|| IrId::new(index as u32))
            })
            .expect("lambda exists");
        let mut wrong_layout = local_target(&ir, module(7), lambda);
        wrong_layout.code.capture_layout.version =
            wrong_layout.code.capture_layout.version.wrapping_add(1);
        assert!(matches!(
            lower_grin_region(
                &ir,
                GrinFragmentKey::new(GrinDemandEpochId::new(11), module(7), apply, None,),
                &[GrinCallSiteTargets {
                    apply,
                    targets: vec![wrong_layout].into_boxed_slice(),
                    overflow: false,
                }],
                GrinRegionOptions::default(),
            ),
            Err(GrinRegionError::InvalidLocalTarget { .. })
        ));
    }

    fn raw_ir(root: IrId, arena: IrArena) -> Ir {
        let facts = IrFacts::conservative(arena.nodes().len());
        Ir {
            root,
            arena,
            facts,
            symbols: SymbolTable::new(),
            frames: Box::<[FrameInfo]>::default(),
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    fn module(seed: u8) -> GrinModuleId {
        GrinModuleId::from_content_digest([seed; 32])
    }

    fn external_target(module_seed: u8, definition: u32) -> GrinCallTarget {
        GrinCallTarget {
            code: GrinCodeRef {
                module: module(module_seed),
                definition: IrId::new(definition),
                body: IrId::new(definition.wrapping_add(1)),
                resolver_frame: None,
                capture_layout: GrinCaptureLayout {
                    version: GRIN_CAPTURE_LAYOUT_VERSION,
                    slot_count: 0,
                    captures: Box::new([]),
                    recursive: false,
                    has_dynamic_scope: false,
                },
            },
        }
    }

    fn local_target(ir: &Ir, module: GrinModuleId, definition: IrId) -> GrinCallTarget {
        let node = ir.arena.node(definition).expect("local definition exists");
        let IrData::Lambda { body, frame, .. } = node.data else {
            panic!("local definition is a lambda");
        };
        GrinCallTarget {
            code: GrinCodeRef {
                module,
                definition,
                body,
                resolver_frame: frame,
                capture_layout: capture_layout(ir, frame).expect("frame layout exists"),
            },
        }
    }
}
