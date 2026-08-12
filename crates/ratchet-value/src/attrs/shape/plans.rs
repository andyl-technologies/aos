//! Static literal and update planning for shaped attrsets.

use std::convert::TryFrom;

use thiserror::Error;

use crate::syntax::{Symbol, SymbolTable};
use crate::value::Value;

use super::descriptor::ShapeError;
use super::ids::ShapeId;
use super::instance::{ShapedAttrs, ShapedAttrsError};
use super::table::{ShapeHandle, ShapeTable, ShapeTableTransition};

/// A compile-time resolved shape plan for a static attrset literal.
///
/// The plan stores the final interned shape plus the placement map from binding
/// source slots to symbol-sorted value slots. Future runtime integration can
/// reuse this descriptor so static literals fill a values array directly instead
/// of looking up the shape for every instance. This precursor is not connected
/// to active evaluator attr allocation.
#[derive(Clone, Debug)]
pub struct StaticShapePlan {
    shape: ShapeHandle,
    source_to_symbol_slots: Box<[u32]>,
}

impl StaticShapePlan {
    /// Resolves a static attrset's construction-order keys through `table`.
    ///
    /// # Errors
    ///
    /// Returns [`StaticShapePlanError::DuplicateKey`] when `keys` repeats a
    /// static key. Returns [`StaticShapePlanError::Shape`] when transition-tree
    /// lookup or shape construction fails. Returns
    /// [`StaticShapePlanError::AllocationFailed`] when the placement table
    /// cannot be reserved.
    pub fn resolve(
        table: &mut ShapeTable,
        keys: &[Symbol],
        symbols: &SymbolTable,
    ) -> Result<Self, StaticShapePlanError> {
        let mut shape = table.empty();
        for (source_slot, key) in keys.iter().copied().enumerate() {
            let source_slot = u32::try_from(source_slot).map_err(|_| {
                StaticShapePlanError::Shape(ShapeError::TooManyKeys { len: keys.len() })
            })?;
            match table.transition_insert_key(&shape, key, symbols)? {
                ShapeTableTransition::ExistingKey { slot, .. } => {
                    return Err(StaticShapePlanError::DuplicateKey {
                        key,
                        source_slot,
                        symbol_slot: slot,
                    });
                }
                ShapeTableTransition::AppendKey { child, .. } => {
                    shape = child;
                }
            }
        }

        let mut source_to_symbol_slots = Vec::new();
        source_to_symbol_slots
            .try_reserve_exact(shape.shape().source_order().len())
            .map_err(|_| StaticShapePlanError::AllocationFailed {
                slots: shape.shape().source_order().len(),
            })?;
        source_to_symbol_slots.extend_from_slice(shape.shape().source_order());

        Ok(Self {
            shape,
            source_to_symbol_slots: source_to_symbol_slots.into_boxed_slice(),
        })
    }

    /// Returns the resolved interned shape.
    pub fn shape(&self) -> &ShapeHandle {
        &self.shape
    }

    /// Returns the number of static bindings in the plan.
    pub fn len(&self) -> usize {
        self.source_to_symbol_slots.len()
    }

    /// Returns whether the plan has no bindings.
    pub fn is_empty(&self) -> bool {
        self.source_to_symbol_slots.is_empty()
    }

    /// Returns the value placement map from source slots to symbol slots.
    pub fn source_to_symbol_slots(&self) -> &[u32] {
        &self.source_to_symbol_slots
    }

    /// Returns the symbol-sorted slot for `source_slot`.
    pub fn symbol_slot_for_source_slot(&self, source_slot: u32) -> Option<u32> {
        self.source_to_symbol_slots
            .get(source_slot as usize)
            .copied()
    }

    /// Instantiates shaped attrs from values supplied in static source order.
    ///
    /// This uses the precomputed slot map rather than resolving the shape again.
    ///
    /// # Errors
    ///
    /// Returns [`StaticShapePlanError::ValueCountMismatch`] when `values` does
    /// not contain one value per planned static binding. Returns
    /// [`StaticShapePlanError::AllocationFailed`] if the value array cannot be
    /// reserved. Returns [`StaticShapePlanError::PlanSlotOutOfRange`] if the
    /// cached plan placement is internally inconsistent, and
    /// [`StaticShapePlanError::ShapedAttrs`] if final shaped attrset
    /// construction fails.
    pub fn instantiate(&self, values: &[Value]) -> Result<ShapedAttrs, StaticShapePlanError> {
        let expected = self.len();
        if values.len() != expected {
            return Err(StaticShapePlanError::ValueCountMismatch {
                expected,
                actual: values.len(),
            });
        }

        let mut values_by_symbol = Vec::new();
        values_by_symbol
            .try_reserve_exact(expected)
            .map_err(|_| StaticShapePlanError::AllocationFailed { slots: expected })?;
        values_by_symbol.resize(expected, Value::null());
        for (source_slot, symbol_slot) in self.source_to_symbol_slots.iter().copied().enumerate() {
            let Some(target) = values_by_symbol.get_mut(symbol_slot as usize) else {
                return Err(StaticShapePlanError::PlanSlotOutOfRange {
                    slot: symbol_slot,
                    len: expected,
                });
            };
            *target = values[source_slot];
        }

        ShapedAttrs::from_symbol_order_boxed(
            self.shape.clone(),
            values_by_symbol.into_boxed_slice(),
        )
        .map_err(StaticShapePlanError::ShapedAttrs)
    }
}

/// A failed static shape-plan operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StaticShapePlanError {
    /// Transition-tree or shape descriptor construction failed.
    #[error("static shape plan failed: {0}")]
    Shape(#[from] ShapeError),
    /// The static key list repeated a key.
    #[error("duplicate static shape key {key:?} at source slot {source_slot}")]
    DuplicateKey {
        /// The duplicated static key.
        key: Symbol,
        /// The duplicate key's construction-order slot.
        source_slot: u32,
        /// The existing symbol-sorted slot for the key.
        symbol_slot: u32,
    },
    /// The value array length did not match the planned key count.
    #[error("static shape plan expected {expected} values, got {actual}")]
    ValueCountMismatch {
        /// The number of values required by the plan.
        expected: usize,
        /// The number of values supplied by the caller.
        actual: usize,
    },
    /// A precomputed placement slot referenced a non-existent value slot.
    #[error("static shape plan slot {slot} is out of range for {len} values")]
    PlanSlotOutOfRange {
        /// The invalid symbol slot.
        slot: u32,
        /// The number of values in the instance.
        len: usize,
    },
    /// Scratch storage for the plan or value array could not be reserved.
    #[error("failed to reserve static shape-plan storage for {slots} slots")]
    AllocationFailed {
        /// The slot count whose storage could not be reserved.
        slots: usize,
    },
    /// The final shaped attrset construction failed.
    #[error("static shape-plan attr construction failed: {0}")]
    ShapedAttrs(#[from] ShapedAttrsError),
}

/// A small shape-stable `//` update-merge planner for shaped attrsets.
///
/// This is the safe value-level precursor for RFC-0007 section 09's flat-copy
/// update path: it computes the result shape through the transition tree and
/// assembles values in source order before filling the shaped value array. It
/// mirrors the current shallow update rule: left bindings keep their source
/// order, right values overwrite shared-key slots, and new right keys append in
/// right source order.
#[derive(Clone, Debug)]
pub struct ShapedUpdatePlan {
    static_plan: StaticShapePlan,
    left_shape: ShapeHandle,
    right_shape: ShapeHandle,
    source_keys: Box<[Symbol]>,
}

impl ShapedUpdatePlan {
    /// Plans a shaped `//` update merge.
    ///
    /// # Errors
    ///
    /// Returns [`ShapedUpdateError::LengthOverflow`] if the result source entry
    /// count overflows. Returns [`ShapedUpdateError::AllocationFailed`] if
    /// scratch storage cannot be reserved. Returns
    /// [`ShapedUpdateError::StaticShape`] if result-shape resolution fails.
    ///
    /// `left`, `right`, and `symbols` must belong to the same symbol universe.
    pub fn plan(
        table: &mut ShapeTable,
        left: &ShapedAttrs,
        right: &ShapedAttrs,
        symbols: &SymbolTable,
    ) -> Result<Self, ShapedUpdateError> {
        let appended_right = right
            .iter_source_order()
            .filter(|entry| !left.shape().shape().contains_key(entry.key))
            .count();
        let result_len =
            left.len()
                .checked_add(appended_right)
                .ok_or(ShapedUpdateError::LengthOverflow {
                    left_len: left.len(),
                    right_len: appended_right,
                })?;
        let mut source_keys = Vec::new();
        source_keys.try_reserve_exact(result_len).map_err(|_| {
            ShapedUpdateError::AllocationFailed {
                entries: result_len,
            }
        })?;
        source_keys.extend(left.iter_source_order().map(|entry| entry.key));
        for entry in right.iter_source_order() {
            if !left.shape().shape().contains_key(entry.key) {
                source_keys.push(entry.key);
            }
        }

        let static_plan = StaticShapePlan::resolve(table, &source_keys, symbols)?;
        Ok(Self {
            static_plan,
            left_shape: left.shape().clone(),
            right_shape: right.shape().clone(),
            source_keys: source_keys.into_boxed_slice(),
        })
    }

    /// Returns the static shape plan for the merged result.
    pub const fn static_plan(&self) -> &StaticShapePlan {
        &self.static_plan
    }

    /// Returns the merged result's source-order keys.
    pub fn source_keys(&self) -> &[Symbol] {
        &self.source_keys
    }

    /// Returns the resolved result shape handle.
    pub fn shape(&self) -> &ShapeHandle {
        self.static_plan.shape()
    }

    /// Returns the left operand shape this plan was built for.
    pub const fn left_shape(&self) -> &ShapeHandle {
        &self.left_shape
    }

    /// Returns the right operand shape this plan was built for.
    pub const fn right_shape(&self) -> &ShapeHandle {
        &self.right_shape
    }

    /// Instantiates the planned update result.
    ///
    /// # Errors
    ///
    /// Returns [`ShapedUpdateError::OperandShapeMismatch`] if either operand's
    /// shape differs from the shapes used when planning. Returns
    /// [`ShapedUpdateError::AllocationFailed`] if the source-order value vector
    /// cannot be reserved. Returns
    /// [`ShapedUpdateError::MissingPlannedKey`] if the source-key plan
    /// cannot be found in either operand. Returns
    /// [`ShapedUpdateError::StaticShape`] if value-array instantiation fails.
    pub fn instantiate(
        &self,
        left: &ShapedAttrs,
        right: &ShapedAttrs,
    ) -> Result<ShapedAttrs, ShapedUpdateError> {
        if !self.left_shape.ptr_eq(left.shape()) {
            return Err(ShapedUpdateError::OperandShapeMismatch {
                side: ShapedUpdateOperand::Left,
                expected: self.left_shape.id(),
                actual: left.shape().id(),
            });
        }
        if !self.right_shape.ptr_eq(right.shape()) {
            return Err(ShapedUpdateError::OperandShapeMismatch {
                side: ShapedUpdateOperand::Right,
                expected: self.right_shape.id(),
                actual: right.shape().id(),
            });
        }

        let mut values = Vec::new();
        values
            .try_reserve_exact(self.source_keys.len())
            .map_err(|_| ShapedUpdateError::AllocationFailed {
                entries: self.source_keys.len(),
            })?;
        for key in self.source_keys.iter().copied() {
            let Some(value) = right.get(key).or_else(|| left.get(key)) else {
                return Err(ShapedUpdateError::MissingPlannedKey { key });
            };
            values.push(value);
        }
        self.static_plan
            .instantiate(&values)
            .map_err(ShapedUpdateError::StaticShape)
    }
}

/// A failed shaped update-merge planning or instantiation operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ShapedUpdateError {
    /// The result source-entry count overflowed.
    #[error("shaped update length overflow while combining {left_len} and {right_len}")]
    LengthOverflow {
        /// The left operand length.
        left_len: usize,
        /// The right operand length.
        right_len: usize,
    },
    /// Scratch storage for merged keys or values could not be reserved.
    #[error("failed to reserve shaped update storage for {entries} entries")]
    AllocationFailed {
        /// The entry count whose storage could not be reserved.
        entries: usize,
    },
    /// Static result-shape planning or instantiation failed.
    #[error("shaped update static plan failed: {0}")]
    StaticShape(#[from] StaticShapePlanError),
    /// An operand did not match the shape used when planning.
    #[error("shaped update {side:?} operand shape changed from planned {expected:?} to {actual:?}")]
    OperandShapeMismatch {
        /// Which operand changed shape.
        side: ShapedUpdateOperand,
        /// The planned operand shape id.
        expected: ShapeId,
        /// The supplied operand shape id.
        actual: ShapeId,
    },
    /// A planned result key was not present in either operand.
    #[error("shaped update planned key {key:?} is missing from both operands")]
    MissingPlannedKey {
        /// The missing planned key.
        key: Symbol,
    },
}

/// Which shaped update operand failed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShapedUpdateOperand {
    /// The left operand.
    Left,
    /// The right operand.
    Right,
}
