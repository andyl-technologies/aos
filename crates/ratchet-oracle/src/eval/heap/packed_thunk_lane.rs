//! Headerless packed thunk destinations for a future moving publication.
//!
//! This module owns an isolated destination representation. It is not wired to
//! evaluator allocation, resolution, or publication. A collector can use it
//! after tracing to construct stable thunk heads and shape-specific suspended
//! work without reproducing the ordinary flat closure header or allocation
//! registry.
//!
//! ```text
//! head lane (fixed stride, direct u32 index)
//!   word: invalid-marker:u32 | payload:u32                 8 bytes
//!     SUSP | shape:3,index:29   suspended work handle
//!     BLKH | shape:3,index:29   claimed work handle
//!     any valid Candidate-C compressed value word          forced result
//!
//! work pools (one append-only direct-index vector per shape)
//!   Node                  module:u32 node:u32 env:u32       12 bytes
//!   Apply / GenList       node-ref, span, value,            40 bytes
//!                         node-ref, value
//!   Apply2                three (node-ref, span, value)     72 bytes
//!   Select                node-ref, value, attr-path        24 bytes
//!   BuiltinAttr           symbol:u32 builtin:u32             8 bytes
//! ```
//!
//! Pool slots use safe [`Option`] storage so completed work is dropped without
//! `unsafe`. On 64-bit targets that adds a four-byte presence discriminant to
//! the four-byte-aligned shapes and an eight-byte discriminant to the
//! eight-byte-aligned shapes: 16, 48, 48, 80, 32, and 12 bytes respectively. Slots are
//! never reused within one packed generation. Consequently taking work makes
//! its handle permanently stale, providing ABA rejection without a generation
//! side table. The next moving collection builds a new lane and new direct
//! indices.
//!
//! Internal lane, frame, and work coordinates are `u32`. Arbitrary evaluator
//! values remain exact validated 64-bit Candidate-C words so immediates, tags,
//! reservation domains, offsets, and the forced-thunk shortcut are preserved.
//! No source forwarding table, pointer registry, hash table, or per-head
//! allocation header is retained.

use std::cell::Cell;
use std::mem;

use ratchet_value::heap::{ArenaDomainId, StableLaneCoordinate, StableReservedLane};
use thiserror::Error;

use crate::value::compressed::CompressedValueWord;

const SUSPENDED_MARKER: u64 = 0x5355_5350_0000_0000;
const BLACKHOLE_MARKER: u64 = 0x424c_4b48_0000_0000;
const MARKER_MASK: u64 = (u32::MAX as u64) << 32;
const WORK_SHAPE_SHIFT: u32 = 29;
const WORK_INDEX_MASK: u32 = (1 << WORK_SHAPE_SHIFT) - 1;
const MAX_WORK_INDEX: usize = WORK_INDEX_MASK as usize;

/// An exact validated Candidate-C evaluator value word.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedValueWord(CompressedValueWord);

impl PackedValueWord {
    /// Preserves an already-validated Candidate-C word.
    pub(crate) const fn new(word: CompressedValueWord) -> Self {
        Self(word)
    }

    /// Validates and preserves a raw Candidate-C word.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError::InvalidValueWord`] when the raw word
    /// violates Candidate-C kind, forced-bit, domain, or immediate invariants.
    pub(crate) fn from_raw(raw: u64) -> Result<Self, PackedThunkLaneError> {
        CompressedValueWord::from_raw(raw)
            .map(Self)
            .map_err(|_| PackedThunkLaneError::InvalidValueWord { raw })
    }

    /// Returns the exact Candidate-C word.
    pub(crate) const fn compressed(self) -> CompressedValueWord {
        self.0
    }

    /// Returns the complete raw encoding.
    pub(crate) const fn raw(self) -> u64 {
        self.0.raw()
    }
}

/// A direct fixed-stride index in the stable thunk-head lane.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedThunkRef(u32);

impl PackedThunkRef {
    /// Creates a direct reference from an already-decoded lane index.
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the direct head-lane index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

/// A direct reference to a lowered node.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedNodeRef {
    module: u32,
    node: u32,
}

impl PackedNodeRef {
    /// Creates a packed node reference.
    pub(crate) const fn new(module: u32, node: u32) -> Self {
        Self { module, node }
    }

    /// Returns the packed module index.
    pub(crate) const fn module(self) -> u32 {
        self.module
    }

    /// Returns the module-local lowered-node index.
    pub(crate) const fn node(self) -> u32 {
        self.node
    }
}

/// A compact source-span coordinate.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedSpan {
    start: u32,
    end: u32,
}

impl PackedSpan {
    /// Creates a compact half-open source span.
    pub(crate) const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Returns the inclusive start coordinate.
    pub(crate) const fn start(self) -> u32 {
        self.start
    }

    /// Returns the exclusive end coordinate.
    pub(crate) const fn end(self) -> u32 {
        self.end
    }
}

/// Suspended work for an ordinary lowered-node thunk.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedNodeWork {
    body: PackedNodeRef,
    environment: u32,
}

impl PackedNodeWork {
    /// Creates packed Node work.
    pub(crate) const fn new(body: PackedNodeRef, environment: u32) -> Self {
        Self { body, environment }
    }

    /// Returns the lowered body coordinate.
    pub(crate) const fn body(self) -> PackedNodeRef {
        self.body
    }

    /// Returns the direct packed-frame-chain index.
    pub(crate) const fn environment(self) -> u32 {
        self.environment
    }
}

/// Suspended work shared by Apply and `GenListElemAtAddOne` thunks.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedApplyWork {
    function: PackedNodeRef,
    function_span: PackedSpan,
    function_value: PackedValueWord,
    argument: PackedNodeRef,
    argument_value: PackedValueWord,
}

impl PackedApplyWork {
    /// Creates packed single-argument application work.
    pub(crate) const fn new(
        function: PackedNodeRef,
        function_span: PackedSpan,
        function_value: PackedValueWord,
        argument: PackedNodeRef,
        argument_value: PackedValueWord,
    ) -> Self {
        Self {
            function,
            function_span,
            function_value,
            argument,
            argument_value,
        }
    }

    /// Returns the lowered function coordinate.
    pub(crate) const fn function(self) -> PackedNodeRef {
        self.function
    }

    /// Returns the function source span.
    pub(crate) const fn function_span(self) -> PackedSpan {
        self.function_span
    }

    /// Returns the direct function-value reference.
    pub(crate) const fn function_value(self) -> PackedValueWord {
        self.function_value
    }

    /// Returns the lowered argument coordinate.
    pub(crate) const fn argument(self) -> PackedNodeRef {
        self.argument
    }

    /// Returns the direct lazy-argument reference.
    pub(crate) const fn argument_value(self) -> PackedValueWord {
        self.argument_value
    }
}

/// One function or argument operand in a packed two-argument application.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedApply2Operand {
    node: PackedNodeRef,
    span: PackedSpan,
    value: PackedValueWord,
}

impl PackedApply2Operand {
    /// Creates one packed Apply2 operand.
    pub(crate) const fn new(node: PackedNodeRef, span: PackedSpan, value: PackedValueWord) -> Self {
        Self { node, span, value }
    }

    /// Returns the lowered node coordinate.
    pub(crate) const fn node(self) -> PackedNodeRef {
        self.node
    }

    /// Returns the operand source span.
    pub(crate) const fn span(self) -> PackedSpan {
        self.span
    }

    /// Returns the direct lazy-value reference.
    pub(crate) const fn value(self) -> PackedValueWord {
        self.value
    }
}

/// Suspended work for a two-argument application thunk.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedApply2Work {
    function: PackedApply2Operand,
    first_argument: PackedApply2Operand,
    second_argument: PackedApply2Operand,
}

impl PackedApply2Work {
    /// Creates packed two-argument application work.
    pub(crate) const fn new(
        function: PackedApply2Operand,
        first_argument: PackedApply2Operand,
        second_argument: PackedApply2Operand,
    ) -> Self {
        Self {
            function,
            first_argument,
            second_argument,
        }
    }

    /// Returns the function operand.
    pub(crate) const fn function(self) -> PackedApply2Operand {
        self.function
    }

    /// Returns the first lazy argument.
    pub(crate) const fn first_argument(self) -> PackedApply2Operand {
        self.first_argument
    }

    /// Returns the second lazy argument.
    pub(crate) const fn second_argument(self) -> PackedApply2Operand {
        self.second_argument
    }
}

/// Suspended work for a static attribute-selection thunk.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedSelectWork {
    select: PackedNodeRef,
    receiver: PackedValueWord,
    attr_path: u32,
}

impl PackedSelectWork {
    /// Creates packed selection work.
    pub(crate) const fn new(
        select: PackedNodeRef,
        receiver: PackedValueWord,
        attr_path: u32,
    ) -> Self {
        Self {
            select,
            receiver,
            attr_path,
        }
    }

    /// Returns the lowered selection coordinate.
    pub(crate) const fn select(self) -> PackedNodeRef {
        self.select
    }

    /// Returns the direct receiver reference.
    pub(crate) const fn receiver(self) -> PackedValueWord {
        self.receiver
    }

    /// Returns the module-local attribute-path index.
    pub(crate) const fn attr_path(self) -> u32 {
        self.attr_path
    }
}

/// Suspended work for a lazily reified builtin attribute.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedBuiltinAttrWork {
    symbol: u32,
    builtin: u32,
}

impl PackedBuiltinAttrWork {
    /// Creates packed builtin-attribute work.
    pub(crate) const fn new(symbol: u32, builtin: u32) -> Self {
        Self { symbol, builtin }
    }

    /// Returns the packed source symbol.
    pub(crate) const fn symbol(self) -> u32 {
        self.symbol
    }

    /// Returns the packed builtin-registry coordinate.
    pub(crate) const fn builtin(self) -> u32 {
        self.builtin
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackedWorkShape {
    Node = 0,
    Apply = 1,
    GenListElemAtAddOne = 2,
    Apply2 = 3,
    Select = 4,
    BuiltinAttr = 5,
}

impl PackedWorkShape {
    const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Node),
            1 => Some(Self::Apply),
            2 => Some(Self::GenListElemAtAddOne),
            3 => Some(Self::Apply2),
            4 => Some(Self::Select),
            5 => Some(Self::BuiltinAttr),
            _ => None,
        }
    }
}

/// A shape-tagged direct index into one packed work pool.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedThunkWorkHandle(u32);

impl PackedThunkWorkHandle {
    fn checked(shape: PackedWorkShape, index: usize) -> Option<Self> {
        let index = u32::try_from(index).ok()?;
        if index > WORK_INDEX_MASK {
            return None;
        }
        Some(Self(((shape as u32) << WORK_SHAPE_SHIFT) | index))
    }

    /// Decodes a raw work handle.
    ///
    /// Returns `None` when its shape bits are reserved.
    pub(crate) const fn from_raw(raw: u32) -> Option<Self> {
        match PackedWorkShape::from_raw(raw >> WORK_SHAPE_SHIFT) {
            Some(_) => Some(Self(raw)),
            None => None,
        }
    }

    /// Returns the encoded 32-bit handle.
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }

    fn shape(self) -> PackedWorkShape {
        // `PackedThunkWorkHandle` construction validates these bits.
        match PackedWorkShape::from_raw(self.0 >> WORK_SHAPE_SHIFT) {
            Some(shape) => shape,
            None => unreachable!("validated packed work handle lost its shape"),
        }
    }

    fn index(self) -> usize {
        (self.0 & WORK_INDEX_MASK) as usize
    }
}

/// The publication state stored in an eight-byte packed thunk head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackedThunkState {
    /// The head points at unclaimed suspended work.
    Suspended(PackedThunkWorkHandle),
    /// A force operation owns the named suspended work.
    Blackhole(PackedThunkWorkHandle),
    /// The head contains a published direct result reference.
    Forced(PackedValueWord),
}

/// The result of trying to claim a packed thunk head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackedThunkClaim {
    /// This caller changed the head from suspended to blackholed.
    Claimed(PackedThunkWorkHandle),
    /// Another force already published the terminal result.
    AlreadyForced(PackedValueWord),
}

#[repr(transparent)]
#[derive(Debug)]
struct PackedThunkHead {
    word: Cell<u64>,
}

impl PackedThunkHead {
    fn suspended(handle: PackedThunkWorkHandle) -> Self {
        Self {
            word: Cell::new(SUSPENDED_MARKER | u64::from(handle.raw())),
        }
    }

    fn forced(result: PackedValueWord) -> Self {
        Self {
            word: Cell::new(result.raw()),
        }
    }

    fn state(&self) -> Result<PackedThunkState, PackedThunkLaneError> {
        let word = self.word.get();
        if let Ok(value) = CompressedValueWord::from_raw(word) {
            return Ok(PackedThunkState::Forced(PackedValueWord::new(value)));
        }
        let payload = word as u32;
        match word & MARKER_MASK {
            SUSPENDED_MARKER => PackedThunkWorkHandle::from_raw(payload)
                .map(PackedThunkState::Suspended)
                .ok_or(PackedThunkLaneError::InvalidHeadEncoding { word }),
            BLACKHOLE_MARKER => PackedThunkWorkHandle::from_raw(payload)
                .map(PackedThunkState::Blackhole)
                .ok_or(PackedThunkLaneError::InvalidHeadEncoding { word }),
            _ => Err(PackedThunkLaneError::InvalidHeadEncoding { word }),
        }
    }
}

#[derive(Debug)]
struct PackedWorkPool<T> {
    slots: Vec<Option<T>>,
}

impl<T> Default for PackedWorkPool<T> {
    fn default() -> Self {
        Self { slots: Vec::new() }
    }
}

impl<T> PackedWorkPool<T> {
    fn allocate(
        &mut self,
        shape: PackedWorkShape,
        work: T,
    ) -> Result<PackedThunkWorkHandle, PackedThunkLaneError> {
        let index = self.slots.len();
        let handle = PackedThunkWorkHandle::checked(shape, index).ok_or(
            PackedThunkLaneError::WorkIndexOverflow {
                shape: shape.name(),
                index,
            },
        )?;
        self.slots
            .try_reserve_exact(1)
            .map_err(|_| PackedThunkLaneError::AllocationFailed { lane: shape.name() })?;
        self.slots.push(Some(work));
        Ok(handle)
    }

    fn get(
        &self,
        expected: PackedWorkShape,
        handle: PackedThunkWorkHandle,
    ) -> Result<&T, PackedThunkLaneError> {
        if handle.shape() != expected {
            return Err(PackedThunkLaneError::ShapeMismatch {
                expected: expected.name(),
                actual: handle.shape().name(),
            });
        }
        self.slots
            .get(handle.index())
            .and_then(Option::as_ref)
            .ok_or(PackedThunkLaneError::StaleWorkHandle { raw: handle.raw() })
    }

    fn take(
        &mut self,
        expected: PackedWorkShape,
        handle: PackedThunkWorkHandle,
    ) -> Result<T, PackedThunkLaneError> {
        if handle.shape() != expected {
            return Err(PackedThunkLaneError::ShapeMismatch {
                expected: expected.name(),
                actual: handle.shape().name(),
            });
        }
        self.slots
            .get_mut(handle.index())
            .and_then(Option::take)
            .ok_or(PackedThunkLaneError::StaleWorkHandle { raw: handle.raw() })
    }

    fn bytes(&self) -> usize {
        self.slots.len().saturating_mul(mem::size_of::<Option<T>>())
    }

    fn capacity_bytes(&self) -> usize {
        self.slots
            .capacity()
            .saturating_mul(mem::size_of::<Option<T>>())
    }
}

impl PackedWorkShape {
    const fn name(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Apply => "apply",
            Self::GenListElemAtAddOne => "gen-list-elem-at-add-one",
            Self::Apply2 => "apply2",
            Self::Select => "select",
            Self::BuiltinAttr => "builtin-attr",
        }
    }
}

/// Exact logical element counts admitted for one packed thunk destination.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackedThunkLaneCapacities {
    /// Stable thunk heads, including already-forced heads.
    pub(crate) heads: usize,
    /// Suspended Node work records.
    pub(crate) node: usize,
    /// Suspended Apply work records.
    pub(crate) apply: usize,
    /// Suspended `GenListElemAtAddOne` work records.
    pub(crate) gen_list_elem_at_add_one: usize,
    /// Suspended Apply2 work records.
    pub(crate) apply2: usize,
    /// Suspended Select work records.
    pub(crate) select: usize,
    /// Suspended BuiltinAttr work records.
    pub(crate) builtin_attr: usize,
}

/// Exact initialized byte accounting for one packed thunk lane.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackedThunkLaneBytes {
    /// Fixed-stride stable-head bytes.
    pub(crate) heads: usize,
    /// Safe Node work-slot bytes.
    pub(crate) node: usize,
    /// Safe Apply work-slot bytes.
    pub(crate) apply: usize,
    /// Safe `GenListElemAtAddOne` work-slot bytes.
    pub(crate) gen_list_elem_at_add_one: usize,
    /// Safe Apply2 work-slot bytes.
    pub(crate) apply2: usize,
    /// Safe Select work-slot bytes.
    pub(crate) select: usize,
    /// Safe BuiltinAttr work-slot bytes.
    pub(crate) builtin_attr: usize,
}

impl PackedThunkLaneBytes {
    /// Returns the sum of all head and work-pool bytes.
    pub(crate) const fn total(self) -> usize {
        self.heads
            .saturating_add(self.node)
            .saturating_add(self.apply)
            .saturating_add(self.gen_list_elem_at_add_one)
            .saturating_add(self.apply2)
            .saturating_add(self.select)
            .saturating_add(self.builtin_attr)
    }
}

/// An unpublished, headerless packed thunk destination.
#[derive(Debug, Default)]
pub(crate) struct PackedThunkLane {
    heads: Vec<PackedThunkHead>,
    node: PackedWorkPool<PackedNodeWork>,
    apply: PackedWorkPool<PackedApplyWork>,
    gen_list_elem_at_add_one: PackedWorkPool<PackedApplyWork>,
    apply2: PackedWorkPool<PackedApply2Work>,
    select: PackedWorkPool<PackedSelectWork>,
    builtin_attr: PackedWorkPool<PackedBuiltinAttrWork>,
    admitted: Option<PackedThunkLaneCapacities>,
    admitted_capacity_bytes: Option<PackedThunkLaneBytes>,
}

impl PackedThunkLane {
    /// Creates an empty packed thunk destination.
    pub(crate) const fn new() -> Self {
        Self {
            heads: Vec::new(),
            node: PackedWorkPool { slots: Vec::new() },
            apply: PackedWorkPool { slots: Vec::new() },
            gen_list_elem_at_add_one: PackedWorkPool { slots: Vec::new() },
            apply2: PackedWorkPool { slots: Vec::new() },
            select: PackedWorkPool { slots: Vec::new() },
            builtin_attr: PackedWorkPool { slots: Vec::new() },
            admitted: None,
            admitted_capacity_bytes: None,
        }
    }

    /// Creates an empty lane with exact logical per-lane admission limits.
    ///
    /// Every backing vector is reserved before the lane is returned. The
    /// allocator-granted capacities, which may be larger than the requested
    /// logical counts, become the immutable measured-capacity ceiling exposed
    /// by [`Self::admitted_capacity_bytes`]. Appends fail before mutation when
    /// their logical lane is full.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] if a requested coordinate cannot be
    /// encoded or any backing vector cannot reserve its complete count.
    pub(crate) fn try_with_capacities(
        admitted: PackedThunkLaneCapacities,
    ) -> Result<Self, PackedThunkLaneError> {
        validate_admitted_thunk_capacities(admitted)?;
        let mut lane = Self::new();
        reserve_exact(&mut lane.heads, admitted.heads, "thunk-head")?;
        reserve_exact(&mut lane.node.slots, admitted.node, "node")?;
        reserve_exact(&mut lane.apply.slots, admitted.apply, "apply")?;
        reserve_exact(
            &mut lane.gen_list_elem_at_add_one.slots,
            admitted.gen_list_elem_at_add_one,
            "gen-list-elem-at-add-one",
        )?;
        reserve_exact(&mut lane.apply2.slots, admitted.apply2, "apply2")?;
        reserve_exact(&mut lane.select.slots, admitted.select, "select")?;
        reserve_exact(
            &mut lane.builtin_attr.slots,
            admitted.builtin_attr,
            "builtin-attr",
        )?;
        lane.admitted = Some(admitted);
        lane.admitted_capacity_bytes = Some(lane.capacity_bytes());
        Ok(lane)
    }

    /// Returns the measured vector-capacity ceiling fixed at admission.
    ///
    /// Returns `None` for an unbounded lane created by [`Self::new`].
    pub(crate) const fn admitted_capacity_bytes(&self) -> Option<PackedThunkLaneBytes> {
        self.admitted_capacity_bytes
    }

    /// Allocates a suspended Node head and work record.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] if a direct index overflows or storage
    /// cannot be reserved.
    pub(crate) fn allocate_node(
        &mut self,
        work: PackedNodeWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_append("node", self.node.slots.len(), |limits| limits.node)?;
        let reference = self.reserve_head()?;
        let handle = self.node.allocate(PackedWorkShape::Node, work)?;
        self.heads.push(PackedThunkHead::suspended(handle));
        Ok(reference)
    }

    /// Allocates a suspended Apply head and work record.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] if a direct index overflows or storage
    /// cannot be reserved.
    pub(crate) fn allocate_apply(
        &mut self,
        work: PackedApplyWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_append("apply", self.apply.slots.len(), |limits| limits.apply)?;
        let reference = self.reserve_head()?;
        let handle = self.apply.allocate(PackedWorkShape::Apply, work)?;
        self.heads.push(PackedThunkHead::suspended(handle));
        Ok(reference)
    }

    /// Allocates a suspended `GenListElemAtAddOne` head and work record.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] if a direct index overflows or storage
    /// cannot be reserved.
    pub(crate) fn allocate_gen_list_elem_at_add_one(
        &mut self,
        work: PackedApplyWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_append(
            "gen-list-elem-at-add-one",
            self.gen_list_elem_at_add_one.slots.len(),
            |limits| limits.gen_list_elem_at_add_one,
        )?;
        let reference = self.reserve_head()?;
        let handle = self
            .gen_list_elem_at_add_one
            .allocate(PackedWorkShape::GenListElemAtAddOne, work)?;
        self.heads.push(PackedThunkHead::suspended(handle));
        Ok(reference)
    }

    /// Allocates a suspended Apply2 head and work record.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] if a direct index overflows or storage
    /// cannot be reserved.
    pub(crate) fn allocate_apply2(
        &mut self,
        work: PackedApply2Work,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_append("apply2", self.apply2.slots.len(), |limits| limits.apply2)?;
        let reference = self.reserve_head()?;
        let handle = self.apply2.allocate(PackedWorkShape::Apply2, work)?;
        self.heads.push(PackedThunkHead::suspended(handle));
        Ok(reference)
    }

    /// Allocates a suspended Select head and work record.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] if a direct index overflows or storage
    /// cannot be reserved.
    pub(crate) fn allocate_select(
        &mut self,
        work: PackedSelectWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_append("select", self.select.slots.len(), |limits| limits.select)?;
        let reference = self.reserve_head()?;
        let handle = self.select.allocate(PackedWorkShape::Select, work)?;
        self.heads.push(PackedThunkHead::suspended(handle));
        Ok(reference)
    }

    /// Allocates a suspended BuiltinAttr head and work record.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] if a direct index overflows or storage
    /// cannot be reserved.
    pub(crate) fn allocate_builtin_attr(
        &mut self,
        work: PackedBuiltinAttrWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_append("builtin-attr", self.builtin_attr.slots.len(), |limits| {
            limits.builtin_attr
        })?;
        let reference = self.reserve_head()?;
        let handle = self
            .builtin_attr
            .allocate(PackedWorkShape::BuiltinAttr, work)?;
        self.heads.push(PackedThunkHead::suspended(handle));
        Ok(reference)
    }

    /// Allocates an already-forced stable head.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] if the head index overflows or storage
    /// cannot be reserved.
    pub(crate) fn allocate_forced(
        &mut self,
        result: PackedValueWord,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        let reference = self.reserve_head()?;
        self.heads.push(PackedThunkHead::forced(result));
        Ok(reference)
    }

    fn reserve_head(&mut self) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        let index = u32::try_from(self.heads.len()).map_err(|_| {
            PackedThunkLaneError::HeadIndexOverflow {
                index: self.heads.len(),
            }
        })?;
        self.heads
            .try_reserve_exact(1)
            .map_err(|_| PackedThunkLaneError::AllocationFailed { lane: "thunk-head" })?;
        Ok(PackedThunkRef(index))
    }

    fn preflight_head(&self) -> Result<(), PackedThunkLaneError> {
        if let Some(admitted) = self.admitted
            && self.heads.len() >= admitted.heads
        {
            return Err(PackedThunkLaneError::CapacityExceeded {
                lane: "thunk-head",
                admitted: admitted.heads,
                attempted: self.heads.len().saturating_add(1),
            });
        }
        Ok(())
    }

    fn preflight_append(
        &self,
        lane: &'static str,
        initialized: usize,
        admitted: impl FnOnce(PackedThunkLaneCapacities) -> usize,
    ) -> Result<(), PackedThunkLaneError> {
        self.preflight_head()?;
        if let Some(limits) = self.admitted {
            let limit = admitted(limits);
            if initialized >= limit {
                return Err(PackedThunkLaneError::CapacityExceeded {
                    lane,
                    admitted: limit,
                    attempted: initialized.saturating_add(1),
                });
            }
        }
        Ok(())
    }

    /// Reads one stable head's publication state.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for an out-of-range reference or an
    /// invalid encoded state.
    pub(crate) fn state(
        &self,
        reference: PackedThunkRef,
    ) -> Result<PackedThunkState, PackedThunkLaneError> {
        self.head(reference)?.state()
    }

    /// Claims suspended work by installing a blackhole.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for an invalid head or when the head is
    /// already blackholed.
    pub(crate) fn claim(
        &self,
        reference: PackedThunkRef,
    ) -> Result<PackedThunkClaim, PackedThunkLaneError> {
        let head = self.head(reference)?;
        match head.state()? {
            PackedThunkState::Suspended(handle) => {
                head.word.set(BLACKHOLE_MARKER | u64::from(handle.raw()));
                Ok(PackedThunkClaim::Claimed(handle))
            }
            PackedThunkState::Blackhole(_) => {
                Err(PackedThunkLaneError::Blackhole { head: reference.0 })
            }
            PackedThunkState::Forced(result) => Ok(PackedThunkClaim::AlreadyForced(result)),
        }
    }

    /// Restores a claimed head to its suspended state.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when the head is invalid, is not
    /// blackholed, or belongs to another claim.
    pub(crate) fn abort(
        &self,
        reference: PackedThunkRef,
        claim: PackedThunkWorkHandle,
    ) -> Result<(), PackedThunkLaneError> {
        let head = self.head(reference)?;
        match head.state()? {
            PackedThunkState::Blackhole(actual) if actual == claim => {
                head.word.set(SUSPENDED_MARKER | u64::from(claim.raw()));
                Ok(())
            }
            PackedThunkState::Blackhole(actual) => Err(PackedThunkLaneError::ClaimMismatch {
                expected: actual.raw(),
                actual: claim.raw(),
            }),
            _ => Err(PackedThunkLaneError::NotBlackhole { head: reference.0 }),
        }
    }

    /// Publishes a forced result and permanently takes the claimed work slot.
    ///
    /// All validation precedes mutation. A successful return makes `claim`
    /// stale and stores `result` in the stable head.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when the head/claim is invalid, the
    /// work handle is stale, or its shape does not match its pool.
    pub(crate) fn publish(
        &mut self,
        reference: PackedThunkRef,
        claim: PackedThunkWorkHandle,
        result: PackedValueWord,
    ) -> Result<(), PackedThunkLaneError> {
        let state = self.state(reference)?;
        match state {
            PackedThunkState::Blackhole(actual) if actual == claim => {}
            PackedThunkState::Blackhole(actual) => {
                return Err(PackedThunkLaneError::ClaimMismatch {
                    expected: actual.raw(),
                    actual: claim.raw(),
                });
            }
            _ => return Err(PackedThunkLaneError::NotBlackhole { head: reference.0 }),
        }
        self.validate_work(claim)?;
        self.take_work(claim)?;
        let head = self.head(reference)?;
        head.word.set(result.raw());
        Ok(())
    }

    /// Resolves Node work through an exact shape-tagged direct index.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn node_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedNodeWork, PackedThunkLaneError> {
        self.node.get(PackedWorkShape::Node, handle)
    }

    /// Resolves Apply work through an exact shape-tagged direct index.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn apply_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedApplyWork, PackedThunkLaneError> {
        self.apply.get(PackedWorkShape::Apply, handle)
    }

    /// Resolves `GenListElemAtAddOne` work through an exact direct index.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn gen_list_elem_at_add_one_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedApplyWork, PackedThunkLaneError> {
        self.gen_list_elem_at_add_one
            .get(PackedWorkShape::GenListElemAtAddOne, handle)
    }

    /// Resolves Apply2 work through an exact shape-tagged direct index.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn apply2_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedApply2Work, PackedThunkLaneError> {
        self.apply2.get(PackedWorkShape::Apply2, handle)
    }

    /// Resolves Select work through an exact shape-tagged direct index.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn select_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedSelectWork, PackedThunkLaneError> {
        self.select.get(PackedWorkShape::Select, handle)
    }

    /// Resolves BuiltinAttr work through an exact shape-tagged direct index.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn builtin_attr_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedBuiltinAttrWork, PackedThunkLaneError> {
        self.builtin_attr.get(PackedWorkShape::BuiltinAttr, handle)
    }

    /// Returns exact initialized bytes for heads and safe work slots.
    pub(crate) fn initialized_bytes(&self) -> PackedThunkLaneBytes {
        PackedThunkLaneBytes {
            heads: self
                .heads
                .len()
                .saturating_mul(mem::size_of::<PackedThunkHead>()),
            node: self.node.bytes(),
            apply: self.apply.bytes(),
            gen_list_elem_at_add_one: self.gen_list_elem_at_add_one.bytes(),
            apply2: self.apply2.bytes(),
            select: self.select.bytes(),
            builtin_attr: self.builtin_attr.bytes(),
        }
    }

    /// Returns allocated vector-capacity bytes for heads and safe work slots.
    ///
    /// This is the conservative resident-memory quantity used by packed-heap
    /// projections. It deliberately charges unused allocator-granted vector
    /// capacity rather than assuming that initialized length equals storage.
    pub(crate) fn capacity_bytes(&self) -> PackedThunkLaneBytes {
        PackedThunkLaneBytes {
            heads: self
                .heads
                .capacity()
                .saturating_mul(mem::size_of::<PackedThunkHead>()),
            node: self.node.capacity_bytes(),
            apply: self.apply.capacity_bytes(),
            gen_list_elem_at_add_one: self.gen_list_elem_at_add_one.capacity_bytes(),
            apply2: self.apply2.capacity_bytes(),
            select: self.select.capacity_bytes(),
            builtin_attr: self.builtin_attr.capacity_bytes(),
        }
    }

    fn head(&self, reference: PackedThunkRef) -> Result<&PackedThunkHead, PackedThunkLaneError> {
        self.heads
            .get(reference.0 as usize)
            .ok_or(PackedThunkLaneError::UnknownHead { index: reference.0 })
    }

    fn validate_work(&self, handle: PackedThunkWorkHandle) -> Result<(), PackedThunkLaneError> {
        match handle.shape() {
            PackedWorkShape::Node => self.node_work(handle).map(|_| ()),
            PackedWorkShape::Apply => self.apply_work(handle).map(|_| ()),
            PackedWorkShape::GenListElemAtAddOne => {
                self.gen_list_elem_at_add_one_work(handle).map(|_| ())
            }
            PackedWorkShape::Apply2 => self.apply2_work(handle).map(|_| ()),
            PackedWorkShape::Select => self.select_work(handle).map(|_| ()),
            PackedWorkShape::BuiltinAttr => self.builtin_attr_work(handle).map(|_| ()),
        }
    }

    fn take_work(&mut self, handle: PackedThunkWorkHandle) -> Result<(), PackedThunkLaneError> {
        match handle.shape() {
            PackedWorkShape::Node => self.node.take(PackedWorkShape::Node, handle).map(drop),
            PackedWorkShape::Apply => self.apply.take(PackedWorkShape::Apply, handle).map(drop),
            PackedWorkShape::GenListElemAtAddOne => self
                .gen_list_elem_at_add_one
                .take(PackedWorkShape::GenListElemAtAddOne, handle)
                .map(drop),
            PackedWorkShape::Apply2 => self.apply2.take(PackedWorkShape::Apply2, handle).map(drop),
            PackedWorkShape::Select => self.select.take(PackedWorkShape::Select, handle).map(drop),
            PackedWorkShape::BuiltinAttr => self
                .builtin_attr
                .take(PackedWorkShape::BuiltinAttr, handle)
                .map(drop),
        }
    }
}

/// One fixed-capacity stable work pool for active packed thunks.
#[derive(Debug)]
struct ActivePackedWorkPool<T> {
    slots: Option<StableReservedLane<Option<T>>>,
    admitted: usize,
}

impl<T> ActivePackedWorkPool<T> {
    fn try_with_capacity(
        admitted: usize,
        lane: &'static str,
    ) -> Result<Self, PackedThunkLaneError> {
        let slots = if admitted == 0 {
            None
        } else {
            Some(
                StableReservedLane::with_capacity(admitted)
                    .map_err(|_| PackedThunkLaneError::AllocationFailed { lane })?,
            )
        };
        Ok(Self { slots, admitted })
    }

    fn len(&self) -> usize {
        self.slots.as_ref().map_or(0, StableReservedLane::len)
    }

    fn preflight_allocate(
        &self,
        shape: PackedWorkShape,
    ) -> Result<PackedThunkWorkHandle, PackedThunkLaneError> {
        let index = self.len();
        let handle = PackedThunkWorkHandle::checked(shape, index).ok_or(
            PackedThunkLaneError::WorkIndexOverflow {
                shape: shape.name(),
                index,
            },
        )?;
        if index >= self.admitted {
            return Err(PackedThunkLaneError::CapacityExceeded {
                lane: shape.name(),
                admitted: self.admitted,
                attempted: index.saturating_add(1),
            });
        }
        Ok(handle)
    }

    fn push_preflighted(&mut self, shape: PackedWorkShape, handle: PackedThunkWorkHandle, work: T) {
        let Some(slots) = self.slots.as_mut() else {
            unreachable!("preflighted nonempty stable work lane is absent");
        };
        let coordinate = match slots.try_push(Some(work)) {
            Ok(coordinate) => coordinate,
            Err(error) => {
                unreachable!("preflighted stable {} append failed: {error}", shape.name())
            }
        };
        if coordinate.as_u32() != handle.index() as u32 {
            unreachable!("stable packed work coordinate disagrees with its direct handle");
        }
    }

    fn get(
        &self,
        expected: PackedWorkShape,
        handle: PackedThunkWorkHandle,
    ) -> Result<&T, PackedThunkLaneError> {
        if handle.shape() != expected {
            return Err(PackedThunkLaneError::ShapeMismatch {
                expected: expected.name(),
                actual: handle.shape().name(),
            });
        }
        self.slots
            .as_ref()
            .and_then(|slots| slots.get(StableLaneCoordinate::from_u32(handle.index() as u32)))
            .and_then(Option::as_ref)
            .ok_or(PackedThunkLaneError::StaleWorkHandle { raw: handle.raw() })
    }

    fn take(
        &mut self,
        expected: PackedWorkShape,
        handle: PackedThunkWorkHandle,
    ) -> Result<T, PackedThunkLaneError> {
        if handle.shape() != expected {
            return Err(PackedThunkLaneError::ShapeMismatch {
                expected: expected.name(),
                actual: handle.shape().name(),
            });
        }
        self.slots
            .as_mut()
            .and_then(|slots| slots.get_mut(StableLaneCoordinate::from_u32(handle.index() as u32)))
            .and_then(Option::take)
            .ok_or(PackedThunkLaneError::StaleWorkHandle { raw: handle.raw() })
    }

    fn initialized_bytes(&self) -> usize {
        self.len().saturating_mul(mem::size_of::<Option<T>>())
    }

    fn capacity_bytes(&self) -> usize {
        self.admitted.saturating_mul(mem::size_of::<Option<T>>())
    }

    fn virtual_reserved_bytes(&self) -> usize {
        self.slots
            .as_ref()
            .map_or(0, StableReservedLane::virtual_reserved_bytes)
    }
}

/// A fixed-capacity, append-active packed thunk store with stable addresses.
///
/// Every nonempty head or work lane owns a demand-paged virtual reservation.
/// Appending never reallocates or copies initialized heads or work records, so
/// direct `u32` coordinates remain valid while the store is live. Work slots
/// retain the legacy [`Option`] tombstone: successful publication takes the
/// claimed slot permanently and therefore preserves stale-handle/ABA rejection.
///
/// This increment is intentionally not connected to [`EvalHeap`](super::EvalHeap).
#[derive(Debug)]
pub(crate) struct ActivePackedThunkLane {
    owner_domain: ArenaDomainId,
    heads: Option<StableReservedLane<PackedThunkHead>>,
    node: ActivePackedWorkPool<PackedNodeWork>,
    apply: ActivePackedWorkPool<PackedApplyWork>,
    gen_list_elem_at_add_one: ActivePackedWorkPool<PackedApplyWork>,
    apply2: ActivePackedWorkPool<PackedApply2Work>,
    select: ActivePackedWorkPool<PackedSelectWork>,
    builtin_attr: ActivePackedWorkPool<PackedBuiltinAttrWork>,
    admitted: PackedThunkLaneCapacities,
}

impl ActivePackedThunkLane {
    /// Creates an empty active store with immutable admitted capacities.
    ///
    /// Nonzero lanes reserve their complete virtual address ranges before this
    /// method returns. Physical pages remain demand-paged until records are
    /// appended.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when a capacity cannot be encoded or a
    /// stable virtual reservation cannot be established.
    pub(crate) fn try_with_capacities(
        owner_domain: ArenaDomainId,
        admitted: PackedThunkLaneCapacities,
    ) -> Result<Self, PackedThunkLaneError> {
        validate_admitted_thunk_capacities(admitted)?;
        let heads = if admitted.heads == 0 {
            None
        } else {
            Some(
                StableReservedLane::with_capacity(admitted.heads)
                    .map_err(|_| PackedThunkLaneError::AllocationFailed { lane: "thunk-head" })?,
            )
        };
        Ok(Self {
            owner_domain,
            heads,
            node: ActivePackedWorkPool::try_with_capacity(admitted.node, "node")?,
            apply: ActivePackedWorkPool::try_with_capacity(admitted.apply, "apply")?,
            gen_list_elem_at_add_one: ActivePackedWorkPool::try_with_capacity(
                admitted.gen_list_elem_at_add_one,
                "gen-list-elem-at-add-one",
            )?,
            apply2: ActivePackedWorkPool::try_with_capacity(admitted.apply2, "apply2")?,
            select: ActivePackedWorkPool::try_with_capacity(admitted.select, "select")?,
            builtin_attr: ActivePackedWorkPool::try_with_capacity(
                admitted.builtin_attr,
                "builtin-attr",
            )?,
            admitted,
        })
    }

    /// Returns the single packed-epoch domain for every published coordinate.
    ///
    /// The private domains owned by individual [`StableReservedLane`] backing
    /// mappings are deliberately never exposed. Resolution first selects this
    /// epoch owner and then the typed lane, keeping all head/work coordinates
    /// in one externally visible domain.
    pub(crate) const fn owner_domain(&self) -> ArenaDomainId {
        self.owner_domain
    }

    /// Allocates one suspended Node thunk.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when either admitted lane is full.
    pub(crate) fn allocate_node(
        &mut self,
        work: PackedNodeWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        let handle = self.node.preflight_allocate(PackedWorkShape::Node)?;
        self.node
            .push_preflighted(PackedWorkShape::Node, handle, work);
        Ok(self.push_preflighted_head(PackedThunkHead::suspended(handle)))
    }

    /// Allocates one suspended Apply thunk.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when either admitted lane is full.
    pub(crate) fn allocate_apply(
        &mut self,
        work: PackedApplyWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        let handle = self.apply.preflight_allocate(PackedWorkShape::Apply)?;
        self.apply
            .push_preflighted(PackedWorkShape::Apply, handle, work);
        Ok(self.push_preflighted_head(PackedThunkHead::suspended(handle)))
    }

    /// Allocates one suspended `GenListElemAtAddOne` thunk.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when either admitted lane is full.
    pub(crate) fn allocate_gen_list_elem_at_add_one(
        &mut self,
        work: PackedApplyWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        let handle = self
            .gen_list_elem_at_add_one
            .preflight_allocate(PackedWorkShape::GenListElemAtAddOne)?;
        self.gen_list_elem_at_add_one.push_preflighted(
            PackedWorkShape::GenListElemAtAddOne,
            handle,
            work,
        );
        Ok(self.push_preflighted_head(PackedThunkHead::suspended(handle)))
    }

    /// Allocates one suspended Apply2 thunk.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when either admitted lane is full.
    pub(crate) fn allocate_apply2(
        &mut self,
        work: PackedApply2Work,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        let handle = self.apply2.preflight_allocate(PackedWorkShape::Apply2)?;
        self.apply2
            .push_preflighted(PackedWorkShape::Apply2, handle, work);
        Ok(self.push_preflighted_head(PackedThunkHead::suspended(handle)))
    }

    /// Allocates one suspended Select thunk.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when either admitted lane is full.
    pub(crate) fn allocate_select(
        &mut self,
        work: PackedSelectWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        let handle = self.select.preflight_allocate(PackedWorkShape::Select)?;
        self.select
            .push_preflighted(PackedWorkShape::Select, handle, work);
        Ok(self.push_preflighted_head(PackedThunkHead::suspended(handle)))
    }

    /// Allocates one suspended BuiltinAttr thunk.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when either admitted lane is full.
    pub(crate) fn allocate_builtin_attr(
        &mut self,
        work: PackedBuiltinAttrWork,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        let handle = self
            .builtin_attr
            .preflight_allocate(PackedWorkShape::BuiltinAttr)?;
        self.builtin_attr
            .push_preflighted(PackedWorkShape::BuiltinAttr, handle, work);
        Ok(self.push_preflighted_head(PackedThunkHead::suspended(handle)))
    }

    /// Allocates one already-forced thunk head.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when the admitted head lane is full.
    pub(crate) fn allocate_forced(
        &mut self,
        result: PackedValueWord,
    ) -> Result<PackedThunkRef, PackedThunkLaneError> {
        self.preflight_head()?;
        Ok(self.push_preflighted_head(PackedThunkHead::forced(result)))
    }

    /// Reads one head's current publication state.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for an unknown or malformed head.
    pub(crate) fn state(
        &self,
        reference: PackedThunkRef,
    ) -> Result<PackedThunkState, PackedThunkLaneError> {
        self.head(reference)?.state()
    }

    /// Claims suspended work by installing a blackhole in its stable head.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for an invalid or already-blackholed
    /// head.
    pub(crate) fn claim(
        &self,
        reference: PackedThunkRef,
    ) -> Result<PackedThunkClaim, PackedThunkLaneError> {
        let head = self.head(reference)?;
        match head.state()? {
            PackedThunkState::Suspended(handle) => {
                head.word.set(BLACKHOLE_MARKER | u64::from(handle.raw()));
                Ok(PackedThunkClaim::Claimed(handle))
            }
            PackedThunkState::Blackhole(_) => {
                Err(PackedThunkLaneError::Blackhole { head: reference.0 })
            }
            PackedThunkState::Forced(result) => Ok(PackedThunkClaim::AlreadyForced(result)),
        }
    }

    /// Restores a matching claimed head to its suspended state.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a mismatched, invalid, or
    /// non-blackholed head.
    pub(crate) fn abort(
        &self,
        reference: PackedThunkRef,
        claim: PackedThunkWorkHandle,
    ) -> Result<(), PackedThunkLaneError> {
        let head = self.head(reference)?;
        match head.state()? {
            PackedThunkState::Blackhole(actual) if actual == claim => {
                head.word.set(SUSPENDED_MARKER | u64::from(claim.raw()));
                Ok(())
            }
            PackedThunkState::Blackhole(actual) => Err(PackedThunkLaneError::ClaimMismatch {
                expected: actual.raw(),
                actual: claim.raw(),
            }),
            _ => Err(PackedThunkLaneError::NotBlackhole { head: reference.0 }),
        }
    }

    /// Publishes a forced result and permanently takes its claimed work slot.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] when the claim does not own the head or
    /// its shape-local work coordinate is stale.
    pub(crate) fn publish(
        &mut self,
        reference: PackedThunkRef,
        claim: PackedThunkWorkHandle,
        result: PackedValueWord,
    ) -> Result<(), PackedThunkLaneError> {
        match self.state(reference)? {
            PackedThunkState::Blackhole(actual) if actual == claim => {}
            PackedThunkState::Blackhole(actual) => {
                return Err(PackedThunkLaneError::ClaimMismatch {
                    expected: actual.raw(),
                    actual: claim.raw(),
                });
            }
            _ => return Err(PackedThunkLaneError::NotBlackhole { head: reference.0 }),
        }
        self.validate_work(claim)?;
        self.take_work(claim)?;
        self.head(reference)?.word.set(result.raw());
        Ok(())
    }

    /// Resolves Node work through its direct shape-local coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn node_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedNodeWork, PackedThunkLaneError> {
        self.node.get(PackedWorkShape::Node, handle)
    }

    /// Resolves Apply work through its direct shape-local coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn apply_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedApplyWork, PackedThunkLaneError> {
        self.apply.get(PackedWorkShape::Apply, handle)
    }

    /// Resolves `GenListElemAtAddOne` work through its direct coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn gen_list_elem_at_add_one_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedApplyWork, PackedThunkLaneError> {
        self.gen_list_elem_at_add_one
            .get(PackedWorkShape::GenListElemAtAddOne, handle)
    }

    /// Resolves Apply2 work through its direct shape-local coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn apply2_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedApply2Work, PackedThunkLaneError> {
        self.apply2.get(PackedWorkShape::Apply2, handle)
    }

    /// Resolves Select work through its direct shape-local coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn select_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedSelectWork, PackedThunkLaneError> {
        self.select.get(PackedWorkShape::Select, handle)
    }

    /// Resolves BuiltinAttr work through its direct shape-local coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedThunkLaneError`] for a wrong-shape or stale handle.
    pub(crate) fn builtin_attr_work(
        &self,
        handle: PackedThunkWorkHandle,
    ) -> Result<&PackedBuiltinAttrWork, PackedThunkLaneError> {
        self.builtin_attr.get(PackedWorkShape::BuiltinAttr, handle)
    }

    /// Returns exact initialized bytes for heads and tombstoned work slots.
    pub(crate) fn initialized_bytes(&self) -> PackedThunkLaneBytes {
        PackedThunkLaneBytes {
            heads: self
                .head_len()
                .saturating_mul(mem::size_of::<PackedThunkHead>()),
            node: self.node.initialized_bytes(),
            apply: self.apply.initialized_bytes(),
            gen_list_elem_at_add_one: self.gen_list_elem_at_add_one.initialized_bytes(),
            apply2: self.apply2.initialized_bytes(),
            select: self.select.initialized_bytes(),
            builtin_attr: self.builtin_attr.initialized_bytes(),
        }
    }

    /// Returns exact admitted payload bytes, excluding alignment padding.
    pub(crate) fn capacity_bytes(&self) -> PackedThunkLaneBytes {
        PackedThunkLaneBytes {
            heads: self
                .admitted
                .heads
                .saturating_mul(mem::size_of::<PackedThunkHead>()),
            node: self.node.capacity_bytes(),
            apply: self.apply.capacity_bytes(),
            gen_list_elem_at_add_one: self.gen_list_elem_at_add_one.capacity_bytes(),
            apply2: self.apply2.capacity_bytes(),
            select: self.select.capacity_bytes(),
            builtin_attr: self.builtin_attr.capacity_bytes(),
        }
    }

    /// Returns total virtual reservation bytes, including alignment padding.
    pub(crate) fn virtual_reserved_bytes(&self) -> usize {
        self.heads
            .as_ref()
            .map_or(0, StableReservedLane::virtual_reserved_bytes)
            .saturating_add(self.node.virtual_reserved_bytes())
            .saturating_add(self.apply.virtual_reserved_bytes())
            .saturating_add(self.gen_list_elem_at_add_one.virtual_reserved_bytes())
            .saturating_add(self.apply2.virtual_reserved_bytes())
            .saturating_add(self.select.virtual_reserved_bytes())
            .saturating_add(self.builtin_attr.virtual_reserved_bytes())
    }

    fn head_len(&self) -> usize {
        self.heads.as_ref().map_or(0, StableReservedLane::len)
    }

    fn preflight_head(&self) -> Result<(), PackedThunkLaneError> {
        let initialized = self.head_len();
        if initialized >= self.admitted.heads {
            return Err(PackedThunkLaneError::CapacityExceeded {
                lane: "thunk-head",
                admitted: self.admitted.heads,
                attempted: initialized.saturating_add(1),
            });
        }
        Ok(())
    }

    fn push_preflighted_head(&mut self, head: PackedThunkHead) -> PackedThunkRef {
        let Some(heads) = self.heads.as_mut() else {
            unreachable!("preflighted nonempty stable thunk-head lane is absent");
        };
        let coordinate = match heads.try_push(head) {
            Ok(coordinate) => coordinate,
            Err(error) => {
                unreachable!("preflighted stable thunk-head append failed: {error}")
            }
        };
        PackedThunkRef(coordinate.as_u32())
    }

    fn head(&self, reference: PackedThunkRef) -> Result<&PackedThunkHead, PackedThunkLaneError> {
        self.heads
            .as_ref()
            .and_then(|heads| heads.get(StableLaneCoordinate::from_u32(reference.0)))
            .ok_or(PackedThunkLaneError::UnknownHead { index: reference.0 })
    }

    fn validate_work(&self, handle: PackedThunkWorkHandle) -> Result<(), PackedThunkLaneError> {
        match handle.shape() {
            PackedWorkShape::Node => self.node_work(handle).map(|_| ()),
            PackedWorkShape::Apply => self.apply_work(handle).map(|_| ()),
            PackedWorkShape::GenListElemAtAddOne => {
                self.gen_list_elem_at_add_one_work(handle).map(|_| ())
            }
            PackedWorkShape::Apply2 => self.apply2_work(handle).map(|_| ()),
            PackedWorkShape::Select => self.select_work(handle).map(|_| ()),
            PackedWorkShape::BuiltinAttr => self.builtin_attr_work(handle).map(|_| ()),
        }
    }

    fn take_work(&mut self, handle: PackedThunkWorkHandle) -> Result<(), PackedThunkLaneError> {
        match handle.shape() {
            PackedWorkShape::Node => self.node.take(PackedWorkShape::Node, handle).map(drop),
            PackedWorkShape::Apply => self.apply.take(PackedWorkShape::Apply, handle).map(drop),
            PackedWorkShape::GenListElemAtAddOne => self
                .gen_list_elem_at_add_one
                .take(PackedWorkShape::GenListElemAtAddOne, handle)
                .map(drop),
            PackedWorkShape::Apply2 => self.apply2.take(PackedWorkShape::Apply2, handle).map(drop),
            PackedWorkShape::Select => self.select.take(PackedWorkShape::Select, handle).map(drop),
            PackedWorkShape::BuiltinAttr => self
                .builtin_attr
                .take(PackedWorkShape::BuiltinAttr, handle)
                .map(drop),
        }
    }
}

fn reserve_exact<T>(
    lane: &mut Vec<T>,
    elements: usize,
    name: &'static str,
) -> Result<(), PackedThunkLaneError> {
    lane.try_reserve_exact(elements)
        .map_err(|_| PackedThunkLaneError::AllocationFailed { lane: name })
}

fn validate_admitted_thunk_capacities(
    admitted: PackedThunkLaneCapacities,
) -> Result<(), PackedThunkLaneError> {
    if admitted.heads > u32::MAX as usize {
        return Err(PackedThunkLaneError::HeadIndexOverflow {
            index: admitted.heads.saturating_sub(1),
        });
    }
    for (shape, count) in [
        (PackedWorkShape::Node, admitted.node),
        (PackedWorkShape::Apply, admitted.apply),
        (
            PackedWorkShape::GenListElemAtAddOne,
            admitted.gen_list_elem_at_add_one,
        ),
        (PackedWorkShape::Apply2, admitted.apply2),
        (PackedWorkShape::Select, admitted.select),
        (PackedWorkShape::BuiltinAttr, admitted.builtin_attr),
    ] {
        if count > (WORK_INDEX_MASK as usize).saturating_add(1) {
            return Err(PackedThunkLaneError::WorkIndexOverflow {
                shape: shape.name(),
                index: count.saturating_sub(1),
            });
        }
    }
    Ok(())
}

/// A checked packed-lane allocation, lookup, or publication failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum PackedThunkLaneError {
    /// A direct stable-head index no longer fits in `u32`.
    #[error("packed thunk head index {index} does not fit in u32")]
    HeadIndexOverflow {
        /// The rejected index.
        index: usize,
    },
    /// A shape-local work index exceeds the 29-bit handle payload.
    #[error("packed {shape} work index {index} exceeds the 29-bit handle payload")]
    WorkIndexOverflow {
        /// The destination work shape.
        shape: &'static str,
        /// The rejected index.
        index: usize,
    },
    /// Safe destination storage could not grow.
    #[error("packed thunk destination could not reserve {lane} storage")]
    AllocationFailed {
        /// The destination lane that failed.
        lane: &'static str,
    },
    /// An append exceeded a caller-admitted logical lane count.
    #[error("packed {lane} capacity {admitted} rejects length {attempted}")]
    CapacityExceeded {
        /// The affected lane.
        lane: &'static str,
        /// The exact caller-admitted element count.
        admitted: usize,
        /// The length the rejected append would have produced.
        attempted: usize,
    },
    /// A direct head reference lies outside the initialized lane.
    #[error("packed thunk head index {index} is not initialized")]
    UnknownHead {
        /// The rejected direct index.
        index: u32,
    },
    /// A head word has an unknown marker or malformed work handle.
    #[error("packed thunk head contains invalid word 0x{word:016x}")]
    InvalidHeadEncoding {
        /// The invalid head word.
        word: u64,
    },
    /// A requested forced value is not a valid Candidate-C value word.
    #[error("packed thunk value contains invalid word 0x{raw:016x}")]
    InvalidValueWord {
        /// The rejected raw Candidate-C word.
        raw: u64,
    },
    /// A work handle names the wrong shape pool.
    #[error("packed work handle has {actual} shape, expected {expected}")]
    ShapeMismatch {
        /// The requested pool shape.
        expected: &'static str,
        /// The encoded handle shape.
        actual: &'static str,
    },
    /// A work handle is out of range or names an already-taken slot.
    #[error("packed work handle 0x{raw:08x} is stale")]
    StaleWorkHandle {
        /// The rejected encoded handle.
        raw: u32,
    },
    /// A force attempted to claim an already-blackholed head.
    #[error("packed thunk head {head} is blackholed")]
    Blackhole {
        /// The direct head index.
        head: u32,
    },
    /// A publication or abort used another head's claim.
    #[error("packed thunk claim mismatch: head owns 0x{expected:08x}, got 0x{actual:08x}")]
    ClaimMismatch {
        /// The handle retained by the blackholed head.
        expected: u32,
        /// The supplied claim handle.
        actual: u32,
    },
    /// Publication or abort requires a currently blackholed head.
    #[error("packed thunk head {head} is not blackholed")]
    NotBlackhole {
        /// The direct head index.
        head: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::{ArenaDomainId, ArenaIndex};
    use crate::value::ValueTag;

    fn node(module: u32, node: u32) -> PackedNodeRef {
        PackedNodeRef::new(module, node)
    }

    fn span(start: u32, end: u32) -> PackedSpan {
        PackedSpan::new(start, end)
    }

    fn value(value: u32) -> PackedValueWord {
        PackedValueWord::new(
            CompressedValueWord::inline_int(i64::from(value))
                .unwrap_or_else(|error| panic!("test integer must be representable: {error}")),
        )
    }

    fn active_owner_domain() -> ArenaDomainId {
        ArenaDomainId::allocate_logical()
            .unwrap_or_else(|error| panic!("active packed owner domain allocates: {error}"))
    }

    fn claimed(lane: &PackedThunkLane, reference: PackedThunkRef) -> PackedThunkWorkHandle {
        match lane.claim(reference) {
            Ok(PackedThunkClaim::Claimed(handle)) => handle,
            other => panic!("expected claimed work, got {other:?}"),
        }
    }

    fn active_claimed(
        lane: &ActivePackedThunkLane,
        reference: PackedThunkRef,
    ) -> PackedThunkWorkHandle {
        match lane.claim(reference) {
            Ok(PackedThunkClaim::Claimed(handle)) => handle,
            other => panic!("expected active claimed work, got {other:?}"),
        }
    }

    #[test]
    fn exact_layouts_match_the_packed_contract() {
        assert_eq!(mem::size_of::<PackedValueWord>(), 8);
        assert_eq!(mem::size_of::<PackedThunkRef>(), 4);
        assert_eq!(mem::size_of::<PackedThunkWorkHandle>(), 4);
        assert_eq!(mem::size_of::<PackedThunkHead>(), 8);
        assert_eq!(mem::size_of::<PackedNodeRef>(), 8);
        assert_eq!(mem::size_of::<PackedSpan>(), 8);
        assert_eq!(mem::size_of::<PackedNodeWork>(), 12);
        assert_eq!(mem::size_of::<PackedApplyWork>(), 40);
        assert_eq!(mem::size_of::<PackedApply2Operand>(), 24);
        assert_eq!(mem::size_of::<PackedApply2Work>(), 72);
        assert_eq!(mem::size_of::<PackedSelectWork>(), 24);
        assert_eq!(mem::size_of::<PackedBuiltinAttrWork>(), 8);
        assert_eq!(mem::size_of::<Option<PackedNodeWork>>(), 16);
        assert_eq!(mem::size_of::<Option<PackedApplyWork>>(), 48);
        assert_eq!(mem::size_of::<Option<PackedApply2Work>>(), 80);
        assert_eq!(mem::size_of::<Option<PackedSelectWork>>(), 32);
        assert_eq!(mem::size_of::<Option<PackedBuiltinAttrWork>>(), 12);
    }

    #[test]
    fn admitted_lane_exact_fill_preserves_measured_capacity() {
        let admitted = PackedThunkLaneCapacities {
            heads: 3,
            node: 1,
            apply: 1,
            ..PackedThunkLaneCapacities::default()
        };
        let mut lane = PackedThunkLane::try_with_capacities(admitted).unwrap();
        let capacity = lane.admitted_capacity_bytes().unwrap();
        assert_eq!(lane.capacity_bytes(), capacity);

        lane.allocate_node(PackedNodeWork::new(node(1, 2), 3))
            .unwrap();
        lane.allocate_apply(PackedApplyWork::new(
            node(4, 5),
            span(6, 7),
            value(8),
            node(9, 10),
            value(11),
        ))
        .unwrap();
        lane.allocate_forced(value(12)).unwrap();

        assert_eq!(lane.capacity_bytes(), capacity);
        assert_eq!(lane.initialized_bytes().heads, 3 * 8);
        assert_eq!(lane.initialized_bytes().node, 16);
        assert_eq!(lane.initialized_bytes().apply, 48);
    }

    #[test]
    fn admitted_lane_underfill_and_overfill_never_grow() {
        let admitted = PackedThunkLaneCapacities {
            heads: 2,
            node: 1,
            ..PackedThunkLaneCapacities::default()
        };
        let mut underfilled = PackedThunkLane::try_with_capacities(admitted).unwrap();
        let initial_capacity = underfilled.capacity_bytes();
        assert_eq!(underfilled.initialized_bytes().total(), 0);
        underfilled
            .allocate_node(PackedNodeWork::new(node(1, 2), 3))
            .unwrap();
        let initialized = underfilled.initialized_bytes();
        let rejected = underfilled.allocate_node(PackedNodeWork::new(node(4, 5), 6));
        assert_eq!(
            rejected,
            Err(PackedThunkLaneError::CapacityExceeded {
                lane: "node",
                admitted: 1,
                attempted: 2,
            })
        );
        assert_eq!(underfilled.initialized_bytes(), initialized);
        assert_eq!(underfilled.capacity_bytes(), initial_capacity);

        underfilled.allocate_forced(value(7)).unwrap();
        let full = underfilled.initialized_bytes();
        assert_eq!(
            underfilled.allocate_forced(value(8)),
            Err(PackedThunkLaneError::CapacityExceeded {
                lane: "thunk-head",
                admitted: 2,
                attempted: 3,
            })
        );
        assert_eq!(underfilled.initialized_bytes(), full);
        assert_eq!(underfilled.capacity_bytes(), initial_capacity);
    }

    #[test]
    fn active_lane_addresses_and_direct_coordinates_stay_stable_while_appending() {
        let admitted = PackedThunkLaneCapacities {
            heads: 4,
            node: 2,
            ..PackedThunkLaneCapacities::default()
        };
        let owner_domain = active_owner_domain();
        let mut lane = ActivePackedThunkLane::try_with_capacities(owner_domain, admitted).unwrap();
        assert_eq!(lane.owner_domain(), owner_domain);
        let first = lane
            .allocate_node(PackedNodeWork::new(node(1, 2), 3))
            .unwrap();
        let first_handle = match lane.state(first).unwrap() {
            PackedThunkState::Suspended(handle) => handle,
            other => panic!("expected suspended active thunk, got {other:?}"),
        };
        let head_address = lane.head(first).unwrap() as *const PackedThunkHead;
        let work_address = lane.node_work(first_handle).unwrap() as *const PackedNodeWork;

        let forced = lane.allocate_forced(value(4)).unwrap();
        let second = lane
            .allocate_node(PackedNodeWork::new(node(5, 6), 7))
            .unwrap();

        assert_eq!(first.index(), 0);
        assert_eq!(forced.index(), 1);
        assert_eq!(second.index(), 2);
        assert_eq!(
            lane.head(first).unwrap() as *const PackedThunkHead,
            head_address
        );
        assert_eq!(
            lane.node_work(first_handle).unwrap() as *const PackedNodeWork,
            work_address
        );
        assert_eq!(
            lane.node_work(first_handle).unwrap(),
            &PackedNodeWork::new(node(1, 2), 3)
        );
    }

    #[test]
    fn active_lane_preserves_claim_abort_publish_and_stale_handle_semantics() {
        let admitted = PackedThunkLaneCapacities {
            heads: 7,
            node: 1,
            apply: 1,
            gen_list_elem_at_add_one: 1,
            apply2: 1,
            select: 1,
            builtin_attr: 1,
        };
        let mut lane =
            ActivePackedThunkLane::try_with_capacities(active_owner_domain(), admitted).unwrap();
        let node_work = PackedNodeWork::new(node(1, 2), 3);
        let apply_work =
            PackedApplyWork::new(node(4, 5), span(6, 7), value(8), node(9, 10), value(11));
        let gen_work = PackedApplyWork::new(
            node(12, 13),
            span(14, 15),
            value(16),
            node(17, 18),
            value(19),
        );
        let operand = PackedApply2Operand::new(node(20, 21), span(22, 23), value(24));
        let apply2_work = PackedApply2Work::new(operand, operand, operand);
        let select_work = PackedSelectWork::new(node(25, 26), value(27), 28);
        let builtin_work = PackedBuiltinAttrWork::new(29, 30);

        let node_ref = lane.allocate_node(node_work).unwrap();
        let apply_ref = lane.allocate_apply(apply_work).unwrap();
        let gen_ref = lane.allocate_gen_list_elem_at_add_one(gen_work).unwrap();
        let apply2_ref = lane.allocate_apply2(apply2_work).unwrap();
        let select_ref = lane.allocate_select(select_work).unwrap();
        let builtin_ref = lane.allocate_builtin_attr(builtin_work).unwrap();
        let cases = [
            (node_ref, value(100)),
            (apply_ref, value(101)),
            (gen_ref, value(102)),
            (apply2_ref, value(103)),
            (select_ref, value(104)),
            (builtin_ref, value(105)),
        ];

        let aborted = active_claimed(&lane, node_ref);
        lane.abort(node_ref, aborted).unwrap();
        assert_eq!(
            lane.state(node_ref),
            Ok(PackedThunkState::Suspended(aborted))
        );

        for (reference, result) in cases {
            let handle = active_claimed(&lane, reference);
            lane.publish(reference, handle, result).unwrap();
            assert_eq!(lane.state(reference), Ok(PackedThunkState::Forced(result)));
            assert_eq!(
                lane.validate_work(handle),
                Err(PackedThunkLaneError::StaleWorkHandle { raw: handle.raw() })
            );
            assert_eq!(
                lane.claim(reference),
                Ok(PackedThunkClaim::AlreadyForced(result))
            );
        }
    }

    #[test]
    fn active_lane_accounts_fixed_capacity_and_initialized_bytes_exactly() {
        let admitted = PackedThunkLaneCapacities {
            heads: 2,
            node: 1,
            ..PackedThunkLaneCapacities::default()
        };
        let mut lane =
            ActivePackedThunkLane::try_with_capacities(active_owner_domain(), admitted).unwrap();
        let capacity = lane.capacity_bytes();
        assert_eq!(capacity.heads, 2 * mem::size_of::<PackedThunkHead>());
        assert_eq!(capacity.node, mem::size_of::<Option<PackedNodeWork>>());
        assert_eq!(capacity.total(), 32);
        assert!(lane.virtual_reserved_bytes() >= capacity.total());
        assert_eq!(lane.initialized_bytes().total(), 0);

        let reference = lane
            .allocate_node(PackedNodeWork::new(node(1, 2), 3))
            .unwrap();
        let initialized = lane.initialized_bytes();
        assert_eq!(initialized.heads, mem::size_of::<PackedThunkHead>());
        assert_eq!(initialized.node, mem::size_of::<Option<PackedNodeWork>>());
        let handle = active_claimed(&lane, reference);
        lane.publish(reference, handle, value(4)).unwrap();
        assert_eq!(lane.initialized_bytes(), initialized);
        assert_eq!(lane.capacity_bytes(), capacity);

        lane.allocate_forced(value(5)).unwrap();
        assert_eq!(
            lane.allocate_forced(value(6)),
            Err(PackedThunkLaneError::CapacityExceeded {
                lane: "thunk-head",
                admitted: 2,
                attempted: 3,
            })
        );
        assert_eq!(lane.capacity_bytes(), capacity);
    }

    #[test]
    fn every_shape_round_trips_and_publishes_a_forced_result() {
        let mut lane = PackedThunkLane::new();
        let node_work = PackedNodeWork::new(node(1, 2), 3);
        let apply_work =
            PackedApplyWork::new(node(4, 5), span(6, 7), value(8), node(9, 10), value(11));
        let gen_work = PackedApplyWork::new(
            node(12, 13),
            span(14, 15),
            value(16),
            node(17, 18),
            value(19),
        );
        let apply2_work = PackedApply2Work::new(
            PackedApply2Operand::new(node(20, 21), span(22, 23), value(24)),
            PackedApply2Operand::new(node(25, 26), span(27, 28), value(29)),
            PackedApply2Operand::new(node(30, 31), span(32, 33), value(34)),
        );
        let select_work = PackedSelectWork::new(node(35, 36), value(37), 38);
        let builtin_work = PackedBuiltinAttrWork::new(39, 40);

        let node_ref = lane.allocate_node(node_work).unwrap();
        let apply_ref = lane.allocate_apply(apply_work).unwrap();
        let gen_ref = lane.allocate_gen_list_elem_at_add_one(gen_work).unwrap();
        let apply2_ref = lane.allocate_apply2(apply2_work).unwrap();
        let select_ref = lane.allocate_select(select_work).unwrap();
        let builtin_ref = lane.allocate_builtin_attr(builtin_work).unwrap();

        let cases = [
            (node_ref, value(100)),
            (apply_ref, value(101)),
            (gen_ref, value(102)),
            (apply2_ref, value(103)),
            (select_ref, value(104)),
            (builtin_ref, value(105)),
        ];
        for (reference, result) in cases {
            let handle = claimed(&lane, reference);
            match handle.shape() {
                PackedWorkShape::Node => assert_eq!(lane.node_work(handle), Ok(&node_work)),
                PackedWorkShape::Apply => assert_eq!(lane.apply_work(handle), Ok(&apply_work)),
                PackedWorkShape::GenListElemAtAddOne => {
                    assert_eq!(lane.gen_list_elem_at_add_one_work(handle), Ok(&gen_work))
                }
                PackedWorkShape::Apply2 => assert_eq!(lane.apply2_work(handle), Ok(&apply2_work)),
                PackedWorkShape::Select => assert_eq!(lane.select_work(handle), Ok(&select_work)),
                PackedWorkShape::BuiltinAttr => {
                    assert_eq!(lane.builtin_attr_work(handle), Ok(&builtin_work))
                }
            }
            lane.publish(reference, handle, result).unwrap();
            assert_eq!(lane.state(reference), Ok(PackedThunkState::Forced(result)));
            assert_eq!(
                lane.validate_work(handle),
                Err(PackedThunkLaneError::StaleWorkHandle { raw: handle.raw() })
            );
            assert_eq!(
                lane.claim(reference),
                Ok(PackedThunkClaim::AlreadyForced(result))
            );
        }
    }

    #[test]
    fn blackholes_abort_and_claim_identity_fail_closed() {
        let mut lane = PackedThunkLane::new();
        let first = lane
            .allocate_node(PackedNodeWork::new(node(1, 2), 3))
            .unwrap();
        let second = lane
            .allocate_node(PackedNodeWork::new(node(4, 5), 6))
            .unwrap();
        let first_claim = claimed(&lane, first);
        let second_claim = claimed(&lane, second);

        assert_eq!(
            lane.claim(first),
            Err(PackedThunkLaneError::Blackhole {
                head: first.index()
            })
        );
        assert_eq!(
            lane.abort(first, second_claim),
            Err(PackedThunkLaneError::ClaimMismatch {
                expected: first_claim.raw(),
                actual: second_claim.raw(),
            })
        );
        assert_eq!(
            lane.publish(first, second_claim, value(99)),
            Err(PackedThunkLaneError::ClaimMismatch {
                expected: first_claim.raw(),
                actual: second_claim.raw(),
            })
        );
        lane.abort(first, first_claim).unwrap();
        assert_eq!(
            lane.state(first),
            Ok(PackedThunkState::Suspended(first_claim))
        );
        assert_eq!(lane.node_work(first_claim).unwrap().environment(), 3);
    }

    #[test]
    fn wrong_shape_stale_and_unknown_access_fail_closed() {
        let mut lane = PackedThunkLane::new();
        let reference = lane
            .allocate_apply(PackedApplyWork::new(
                node(1, 2),
                span(3, 4),
                value(5),
                node(6, 7),
                value(8),
            ))
            .unwrap();
        let handle = claimed(&lane, reference);
        assert_eq!(
            lane.node_work(handle),
            Err(PackedThunkLaneError::ShapeMismatch {
                expected: "node",
                actual: "apply",
            })
        );
        lane.publish(reference, handle, value(9)).unwrap();
        assert_eq!(
            lane.apply_work(handle),
            Err(PackedThunkLaneError::StaleWorkHandle { raw: handle.raw() })
        );
        assert_eq!(
            lane.state(PackedThunkRef(u32::MAX)),
            Err(PackedThunkLaneError::UnknownHead { index: u32::MAX })
        );
        assert!(PackedThunkWorkHandle::from_raw(6 << WORK_SHAPE_SHIFT).is_none());
        assert!(PackedThunkWorkHandle::from_raw(7 << WORK_SHAPE_SHIFT).is_none());
    }

    #[test]
    fn checked_handle_construction_rejects_overflow() {
        assert!(PackedThunkWorkHandle::checked(PackedWorkShape::Node, MAX_WORK_INDEX).is_some());
        assert!(
            PackedThunkWorkHandle::checked(PackedWorkShape::Node, MAX_WORK_INDEX + 1).is_none()
        );
        assert_eq!(
            PackedThunkWorkHandle::checked(PackedWorkShape::BuiltinAttr, 17)
                .map(PackedThunkWorkHandle::raw),
            Some((PackedWorkShape::BuiltinAttr as u32) << WORK_SHAPE_SHIFT | 17)
        );
    }

    #[test]
    fn byte_accounting_has_no_header_or_registry_charge() {
        let mut lane = PackedThunkLane::new();
        let suspended = lane
            .allocate_node(PackedNodeWork::new(node(1, 2), 3))
            .unwrap();
        let _forced = lane.allocate_forced(value(4)).unwrap();
        let bytes = lane.initialized_bytes();
        assert_eq!(bytes.heads, 2 * 8);
        assert_eq!(bytes.node, 16);
        assert_eq!(bytes.total(), 32);
        let capacity = lane.capacity_bytes();
        assert!(capacity.heads >= bytes.heads);
        assert!(capacity.node >= bytes.node);
        assert!(capacity.total() >= bytes.total());

        let handle = claimed(&lane, suspended);
        lane.publish(suspended, handle, value(5)).unwrap();
        assert_eq!(lane.initialized_bytes(), bytes);
    }

    #[test]
    fn field_accessors_preserve_all_coordinates() {
        let node_ref = node(1, 2);
        assert_eq!(node_ref.module(), 1);
        assert_eq!(node_ref.node(), 2);
        let source_span = span(3, 4);
        assert_eq!(source_span.start(), 3);
        assert_eq!(source_span.end(), 4);
        let apply = PackedApplyWork::new(node_ref, source_span, value(5), node(6, 7), value(8));
        assert_eq!(apply.function(), node_ref);
        assert_eq!(apply.function_span(), source_span);
        assert_eq!(apply.function_value(), value(5));
        assert_eq!(apply.argument(), node(6, 7));
        assert_eq!(apply.argument_value(), value(8));

        let operand = PackedApply2Operand::new(node(9, 10), span(11, 12), value(13));
        assert_eq!(operand.node(), node(9, 10));
        assert_eq!(operand.span(), span(11, 12));
        assert_eq!(operand.value(), value(13));
        let apply2 = PackedApply2Work::new(operand, operand, operand);
        assert_eq!(apply2.function(), operand);
        assert_eq!(apply2.first_argument(), operand);
        assert_eq!(apply2.second_argument(), operand);

        let select = PackedSelectWork::new(node(14, 15), value(16), 17);
        assert_eq!(select.select(), node(14, 15));
        assert_eq!(select.receiver(), value(16));
        assert_eq!(select.attr_path(), 17);
        let builtin = PackedBuiltinAttrWork::new(18, 19);
        assert_eq!(builtin.symbol(), 18);
        assert_eq!(builtin.builtin(), 19);
    }

    #[test]
    fn forced_words_preserve_candidate_c_tags_domains_offsets_and_markers() {
        let first_domain = ArenaDomainId::from_raw(1).unwrap();
        let last_domain = ArenaDomainId::from_raw((1 << 23) - 1).unwrap();
        let heap_tags = [
            ValueTag::String,
            ValueTag::Path,
            ValueTag::List,
            ValueTag::Attrs,
            ValueTag::Lambda,
            ValueTag::Primop,
            ValueTag::External,
            ValueTag::Thunk,
        ];
        let mut words = vec![
            CompressedValueWord::inline_int(i64::from(i32::MIN)).unwrap(),
            CompressedValueWord::inline_int(i64::from(i32::MAX)).unwrap(),
            CompressedValueWord::boolean(false),
            CompressedValueWord::boolean(true),
            CompressedValueWord::null(),
        ];
        for (ordinal, tag) in heap_tags.into_iter().enumerate() {
            let domain = if ordinal % 2 == 0 {
                first_domain
            } else {
                last_domain
            };
            let offset = if ordinal % 2 == 0 {
                ArenaIndex::new(ordinal as u32)
            } else {
                ArenaIndex::new(u32::MAX - ordinal as u32)
            };
            words.push(CompressedValueWord::heap(domain, tag, offset).unwrap());
        }
        words.push(
            CompressedValueWord::heap(last_domain, ValueTag::Thunk, ArenaIndex::new(u32::MAX))
                .unwrap()
                .with_forced_bit()
                .unwrap(),
        );

        let mut lane = PackedThunkLane::new();
        for word in words {
            let packed = PackedValueWord::from_raw(word.raw()).unwrap();
            assert_eq!(packed.raw(), word.raw());
            assert_eq!(packed.compressed().semantic_tag(), word.semantic_tag());
            assert_eq!(packed.compressed().arena_domain(), word.arena_domain());
            assert_eq!(packed.compressed().arena_index(), word.arena_index());
            assert_eq!(
                packed.compressed().is_forced_thunk(),
                word.is_forced_thunk()
            );
            let reference = lane.allocate_forced(packed).unwrap();
            assert_eq!(lane.state(reference), Ok(PackedThunkState::Forced(packed)));
        }

        let handle = PackedThunkWorkHandle::checked(PackedWorkShape::Node, MAX_WORK_INDEX).unwrap();
        let suspended = SUSPENDED_MARKER | u64::from(handle.raw());
        let blackhole = BLACKHOLE_MARKER | u64::from(handle.raw());
        assert!(CompressedValueWord::from_raw(suspended).is_err());
        assert!(CompressedValueWord::from_raw(blackhole).is_err());
        assert_eq!(
            PackedValueWord::from_raw(u64::MAX),
            Err(PackedThunkLaneError::InvalidValueWord { raw: u64::MAX })
        );
    }
}
