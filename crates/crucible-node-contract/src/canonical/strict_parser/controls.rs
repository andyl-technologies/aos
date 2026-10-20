//! Names only additional fixed controls introduced by the shared parser seam.
//!
//! Existing Parser/scalar/container controls remain in the original declaration.
//! These additions describe actual helper operands, initializers, returns and
//! Result propagation. They supply no String/Vec/Map/error backing, allocator
//! permission, retained owner, constructor extent or physical stack bound.

use super::{ContainerKind, ContractError, Map, Parser, Value, ValueStart};
use std::{convert::Infallible, mem::size_of, ops::ControlFlow};

// A const item describes each actual Result ? operation without creating a
// second run-time accounting walk. Error conversion stays Contract-local.
const fn try_controls<Output, Return>() -> usize {
    size_of::<Result<Output, ContractError>>() // Result::branch owned input
        + size_of::<Output>() // Ok binding
        + size_of::<Output>() // Continue constructor owned input
        + size_of::<ContractError>() // Err binding
        + size_of::<ContractError>() // residual Err constructor owned input
        + size_of::<Result<Infallible, ContractError>>() // residual initializer
        + size_of::<Result<Infallible, ContractError>>() // Break constructor owned input
        + size_of::<ControlFlow<Result<Infallible, ContractError>, Output>>() // initializer
        + size_of::<ControlFlow<Result<Infallible, ContractError>, Output>>() // return
        + size_of::<Result<Infallible, ContractError>>() // FromResidual input
        + size_of::<ContractError>() // residual Err binding
        + size_of::<ContractError>() // identity From input
        + size_of::<ContractError>() // identity From return
        + size_of::<ContractError>() // enclosing Err constructor owned input
        + size_of::<Result<Return, ContractError>>() // enclosing Err initializer
        + size_of::<Result<Return, ContractError>>() // FromResidual return
}

const PRECHECK: usize = size_of::<&[u8]>() // check_limits bytes argument
    + size_of::<usize>() // maximum_bytes argument
    + size_of::<usize>() // maximum_depth argument
    + size_of::<bool>() // maximum_depth == 0 result
    + size_of::<bool>() // maximum_depth > 64 result
    + size_of::<bool>() // bytes.len() >maximum_bytes result
    + size_of::<Result<(), ContractError>>() // helper Ok initializer
    + size_of::<Result<(), ContractError>>() // helper return
    + try_controls::<(), Value>(); // parse_json_with_depth's new ?

// Exactly one Scalar map executes in any value_start call. String, literal and
// number alternatives have these same Value -> ValueStart operand types. The
// String -> Value map and all scalar constructors themselves are unchanged.
const SCALAR_MAP: usize = size_of::<Result<Value, ContractError>>() // map input
    + size_of::<Value>() // map Ok binding
    + size_of::<(Value,)>() // FnOnce::call_once argument tuple
    + size_of::<()>() // capture-free FnOnce receiver
    + size_of::<Value>() // Scalar constructor owned input
    + size_of::<ValueStart>() // Scalar constructor return
    + size_of::<ValueStart>() // FnOnce::call_once return
    + size_of::<ValueStart>() // map Ok initializer operand
    + size_of::<ContractError>() // map Err binding
    + size_of::<ContractError>() // map Err constructor owned input
    + size_of::<Result<ValueStart, ContractError>>() // map Result initializer
    + size_of::<Result<ValueStart, ContractError>>() // map return
    + size_of::<()>(); // capture-free Scalar constructor function item

const VALUE_START: usize = size_of::<&mut Parser<'static>>() // added helper receiver
    + size_of::<ValueStart>() // direct Array/Object variant initializer
    + size_of::<ValueStart>() // direct Ok constructor owned input
    + size_of::<Result<ValueStart, ContractError>>() // direct Result initializer
    + size_of::<Result<ValueStart, ContractError>>() // helper return
    + SCALAR_MAP
    + try_controls::<ValueStart, Value>() // value's new helper ?
    + size_of::<ValueStart>() // value's match input
    + size_of::<Value>() // scalar match binding
    + size_of::<Value>() // scalar arm's Ok constructor owned input
    + size_of::<Result<Value, ContractError>>(); // scalar arm's new Ok initializer

const BEGIN_CONTAINER: usize = size_of::<&mut Parser<'static>>()
    + size_of::<usize>() // depth argument
    + size_of::<bool>() // depth comparison result
    + size_of::<Result<(), ContractError>>() // helper initializer
    + size_of::<Result<(), ContractError>>() // helper return
    + try_controls::<(), Value>(); // array/object begin ?

const ARRAY_BEFORE_CHILD: usize = size_of::<&Parser<'static>>()
    + size_of::<usize>() // actual initialized length argument
    + size_of::<bool>() // initialized length comparison
    + size_of::<Result<(), ContractError>>() // helper initializer
    + size_of::<Result<(), ContractError>>() // helper return
    + try_controls::<(), Value>(); // array's new ?

const OBJECT_KEY: usize = size_of::<&mut Parser<'static>>()
    + size_of::<String>() // delegating helper's returned key
    + size_of::<Result<String, ContractError>>(); // extra helper return

const OBJECT_BEFORE_CHILD: usize = size_of::<&mut Parser<'static>>()
    + size_of::<&Map<String, Value>>() // helper's same real map argument
    + size_of::<&String>() // helper's same decoded key argument
    + size_of::<bool>() // duplicate membership outcome
    + size_of::<bool>() // original take-colon outcome
    + size_of::<Result<(), ContractError>>() // helper initializer
    + size_of::<Result<(), ContractError>>() // helper return
    + try_controls::<(), Value>(); // object's new ?

const AFTER_CHILD: usize = size_of::<&mut Parser<'static>>()
    + size_of::<ContainerKind>() // actual container argument/match input
    + size_of::<(u8, &str)>() // selected match arm tuple initializer
    + size_of::<(u8, &str)>() // match return/destructure input
    + size_of::<u8>() // selected close delimiter binding
    + size_of::<&str>() // original static refusal binding
    + size_of::<bool>() // original take-close outcome
    + size_of::<bool>() // original take-comma outcome
    + size_of::<bool>() // helper's close/continue return operand
    + size_of::<Result<bool, ContractError>>() // helper initializer
    + size_of::<Result<bool, ContractError>>() // helper return
    + try_controls::<bool, Value>(); // array/object's new ?

/// Adds the defining fixed windows for the unchanged maximum recursion shape.
///
/// There are at most 64 opened container frames and one scalar or refused
/// container child below them. Each value frame receives its own start/Result
/// controls. Each opened container frame is conservatively assigned both array
/// and object helper families. A separate terminal begin window names the 65th
/// container entry before its depth refusal; it is not borrowed from a returned
/// outer begin. Loop iterations reuse the same fixed windows. No operation or
/// backing demand derives from a caller maximum or allocation capacity.
pub(in super::super) const TRANSITION_COUNTER_SCRATCH_BYTES: usize = PRECHECK
    + 65 * VALUE_START
    + 64 * (BEGIN_CONTAINER + ARRAY_BEFORE_CHILD + OBJECT_KEY + OBJECT_BEFORE_CHILD + AFTER_CHILD)
    + BEGIN_CONTAINER; // terminal entered container, refused before construction
