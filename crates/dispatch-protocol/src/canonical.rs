//! Deterministic CBOR commitments bind semantic models and solve requests.
//!
//! Records use local unsigned field keys from the published mapping. Arbitrary
//! dictionaries become ordered entry arrays; semantic sets sort encoded elements.
//! Objective tiers remain ordered. Model version one has major one and minor zero.

use dispatch_model::{Assignment, ValidatedProblem};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{wire::SolveOptions, ProtocolError};

/// Encodes a validated model with the published deterministic CBOR mapping.
///
/// # Errors
///
/// Returns an error if serialization or the typed canonical mapping fails.
pub fn model_bytes(model: &ValidatedProblem) -> Result<Vec<u8>, ProtocolError> {
    let value = serde_json::to_value(model.problem())?;
    encode(&value, Shape::Record(Record::Problem))
}

/// Commits a complete model, including observations but excluding search hints.
///
/// # Errors
///
/// Returns an error if canonical encoding fails.
pub fn model_digest(model: &ValidatedProblem) -> Result<[u8; 32], ProtocolError> {
    let mut hash = Sha256::new();
    hash.update(b"dispatch:model\0");
    hash.update(model.problem().model_version.to_be_bytes());
    hash.update(0_u32.to_be_bytes());
    hash.update(model_bytes(model)?);
    Ok(hash.finalize().into())
}

/// Commits a Rebalancer solve's model, options, and independent warm-start hint.
///
/// # Errors
///
/// Returns an error if any committed value cannot be canonically encoded.
pub fn request_digest(
    model: &ValidatedProblem,
    options: &SolveOptions,
    hint: Option<&Assignment>,
) -> Result<[u8; 32], ProtocolError> {
    request_digest_for_backend(model, "rebalancer", options, hint)
}

/// Commits a solve with an explicit backend selection identity.
///
/// # Errors
///
/// Returns an error if model, hint, or options cannot be canonically encoded.
pub fn request_digest_for_backend(
    model: &ValidatedProblem,
    backend: &str,
    options: &SolveOptions,
    hint: Option<&Assignment>,
) -> Result<[u8; 32], ProtocolError> {
    let options_value = json!({
        "mode": options.mode.to_string(),
        "wall_time_millis": options.wall_time_millis.to_string(),
        "threads": options.threads.to_string(),
        "seed": options.seed.map(|seed| seed.to_string()),
        "memory_bytes": options.memory_bytes.to_string(),
        "cpu_time_millis": options.cpu_time_millis.to_string(),
        "maximum_iterations": options.maximum_iterations.to_string(),
    });
    let mut bytes = Vec::new();
    head(5, 6, &mut bytes);
    head(0, 1, &mut bytes);
    let digest = model_digest(model)?;
    head(2, digest.len() as u64, &mut bytes);
    bytes.extend_from_slice(&digest);
    head(0, 2, &mut bytes);
    scalar(&Value::String(backend.into()), &mut bytes)?;
    head(0, 3, &mut bytes);
    bytes.extend_from_slice(&encode(&options_value, Shape::Record(Record::Options))?);
    head(0, 4, &mut bytes);
    match hint {
        Some(hint) => bytes.extend_from_slice(&encode(
            &serde_json::to_value(hint)?,
            Shape::Record(Record::Assignment),
        )?),
        None => bytes.push(0xf6),
    }
    head(0, 5, &mut bytes);
    bytes.extend_from_slice(&[0x82, 0x01, 0x00]);
    head(0, 6, &mut bytes);
    scalar(&Value::String("solve".into()), &mut bytes)?;

    let mut hash = Sha256::new();
    hash.update(b"dispatch:request\0");
    hash.update(bytes);
    Ok(hash.finalize().into())
}

#[derive(Clone, Copy)]
enum Record {
    Problem,
    Dimension,
    Item,
    Demand,
    Target,
    Capacity,
    Assignment,
    Binding,
    Observation,
    Holding,
    HoldingKind,
    Constraint,
    Rule,
    AssignmentCosts,
    MovementCosts,
    ComponentId,
    ObjectiveTier,
    ObjectiveTerm,
    UtilizationMember,
    UtilizationReference,
    Metric,
    Options,
}

enum Shape {
    Scalar,
    Quantity,
    Rational,
    Record(Record),
    Dictionary(Box<Shape>),
    Sequence(Box<Shape>, Ordering),
}

#[derive(Clone, Copy)]
enum Ordering {
    Ordered,
    Set,
}

fn map(shape: Shape) -> Shape {
    Shape::Dictionary(Box::new(shape))
}

fn set(shape: Shape) -> Shape {
    Shape::Sequence(Box::new(shape), Ordering::Set)
}

fn ordered(shape: Shape) -> Shape {
    Shape::Sequence(Box::new(shape), Ordering::Ordered)
}

fn fields(record: Record, value: &Value) -> Result<Vec<(&'static str, Shape)>, ProtocolError> {
    use Record::*;
    use Shape::{Quantity as Q, Rational as R, Record as Rec, Scalar as S};

    let fields = match record {
        Problem => vec![
            ("model_version", Q),
            ("observation_basis", map(S)),
            ("items", map(Rec(Item))),
            ("targets", map(Rec(Target))),
            ("dimensions", map(Rec(Dimension))),
            ("domains", map(set(S))),
            ("groups", map(set(S))),
            ("target_sets", map(set(S))),
            ("scope_families", map(map(set(S)))),
            ("observed", map(Rec(Observation))),
            ("holdings", set(Rec(Holding))),
            ("constraints", set(Rec(Constraint))),
            ("objectives", ordered(Rec(ObjectiveTier))),
        ],
        Dimension => vec![("unit", S), ("quantum", Q)],
        Item => vec![
            ("domain", S),
            ("deferrable", S),
            ("demands", map(Rec(Demand))),
        ],
        Demand => vec![("default", Q), ("overrides", map(Q))],
        Target => vec![("capacities", map(Rec(Capacity))), ("fixed_load", map(Q))],
        Capacity => match tag(value)? {
            "finite" => vec![("kind", S), ("limit", Q)],
            "unbounded" => vec![("kind", S)],
            other => return unknown(other),
        },
        Assignment => vec![("bindings", map(Rec(Binding)))],
        Binding => match tag(value)? {
            "target" => vec![("kind", S), ("target", S)],
            "deferred" | "unplaced" => vec![("kind", S)],
            other => return unknown(other),
        },
        Observation => vec![("binding", Rec(Binding)), ("charges", map(Q))],
        Holding => vec![
            ("id", S),
            ("target", S),
            ("dimension", S),
            ("quantity", Q),
            ("kind", Rec(HoldingKind)),
        ],
        HoldingKind => match tag(value)? {
            "ordinary" => vec![("kind", S), ("item", S)],
            "additional" => vec![("kind", S), ("retained_at_final", S)],
            other => return unknown(other),
        },
        Constraint => vec![("id", S), ("enforcement", S), ("rule", Rec(Rule))],
        Rule => match tag(value)? {
            "eligibility" => vec![("kind", S), ("items", set(S)), ("targets", set(S))],
            "fixed_placement" => vec![("kind", S), ("bindings", map(Rec(Binding)))],
            "capacity" => vec![
                ("kind", S),
                ("target_set", S),
                ("dimension", S),
                ("phase", S),
                ("limit", Q),
            ],
            "admission" => vec![("kind", S), ("group", S), ("minimum", Q), ("maximum", Q)],
            "atomic_admission" => vec![("kind", S), ("group", S)],
            "co_location" => vec![("kind", S), ("group", S), ("family", S)],
            "spread" => vec![
                ("kind", S),
                ("group", S),
                ("family", S),
                ("minimum", Q),
                ("maximum_per_member", Q),
                ("when_admitted", S),
            ],
            "movement_budget" => vec![
                ("kind", S),
                ("items", set(S)),
                ("costs", Rec(MovementCosts)),
                ("limit", R),
            ],
            other => return unknown(other),
        },
        AssignmentCosts => vec![("default", R), ("targets", map(R)), ("deferred", R)],
        MovementCosts => vec![
            ("unit", S),
            ("categories", set(S)),
            ("costs", map(Rec(AssignmentCosts))),
        ],
        ComponentId => vec![("constraint", S), ("component", S)],
        ObjectiveTier => vec![("id", S), ("terms", set(Rec(ObjectiveTerm)))],
        ObjectiveTerm => vec![
            ("id", S),
            ("direction", S),
            ("weight", R),
            ("normalizer", R),
            ("metric", Rec(Metric)),
        ],
        UtilizationMember => vec![
            ("id", S),
            ("target_set", S),
            ("dimension", S),
            ("phase", S),
            ("capacity", Q),
        ],
        UtilizationReference => vec![("member", Rec(UtilizationMember)), ("reference", R)],
        Metric => match tag(value)? {
            "admitted_count" | "used_targets" => vec![("kind", S), ("items", set(S))],
            "admitted_priority" => vec![("kind", S), ("priorities", map(R))],
            "assignment_cost" => vec![("kind", S), ("costs", map(Rec(AssignmentCosts)))],
            "movement_cost" => vec![
                ("kind", S),
                ("items", set(S)),
                ("costs", Rec(MovementCosts)),
            ],
            "repair_debt" => vec![("kind", S), ("components", set(Rec(ComponentId)))],
            "maximum_utilization" | "utilization_range" => {
                vec![("kind", S), ("members", set(Rec(UtilizationMember)))]
            }
            "total_absolute_deviation" => {
                vec![("kind", S), ("members", set(Rec(UtilizationReference)))]
            }
            other => return unknown(other),
        },
        Options => vec![
            ("mode", Q),
            ("wall_time_millis", Q),
            ("threads", Q),
            ("seed", Q),
            ("memory_bytes", Q),
            ("cpu_time_millis", Q),
            ("maximum_iterations", Q),
        ],
    };
    Ok(fields)
}

fn tag(value: &Value) -> Result<&str, ProtocolError> {
    value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolError::Canonical("missing variant kind".into()))
}

fn unknown<T>(kind: &str) -> Result<T, ProtocolError> {
    Err(ProtocolError::Canonical(format!("unknown variant {kind}")))
}

fn encode(value: &Value, shape: Shape) -> Result<Vec<u8>, ProtocolError> {
    let mut output = Vec::new();
    encode_into(value, shape, &mut output)?;
    Ok(output)
}

fn encode_into(value: &Value, shape: Shape, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
    if value.is_null() {
        output.push(0xf6);
        return Ok(());
    }
    match shape {
        Shape::Scalar => scalar(value, output)?,
        Shape::Quantity => {
            let number = value
                .as_str()
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or_else(|| {
                    ProtocolError::Canonical("expected exact unsigned quantity".into())
                })?;
            head(0, number, output);
        }
        Shape::Rational => {
            let object = value
                .as_object()
                .ok_or_else(|| ProtocolError::Canonical("expected rational record".into()))?;
            if object.len() != 2 {
                return Err(ProtocolError::Canonical(
                    "unexpected rational fields".into(),
                ));
            }
            output.push(0x82);
            for name in ["numerator", "denominator"] {
                scalar(
                    object.get(name).ok_or_else(|| {
                        ProtocolError::Canonical(format!("missing rational {name}"))
                    })?,
                    output,
                )?;
            }
        }
        Shape::Record(record) => {
            let object = value
                .as_object()
                .ok_or_else(|| ProtocolError::Canonical("expected record".into()))?;
            let fields = fields(record, value)?;
            if object.len() != fields.len() {
                return Err(ProtocolError::Canonical("unexpected record fields".into()));
            }
            head(5, fields.len() as u64, output);
            for (index, (name, field_shape)) in fields.into_iter().enumerate() {
                head(0, index as u64 + 1, output);
                let field = object
                    .get(name)
                    .ok_or_else(|| ProtocolError::Canonical(format!("missing field {name}")))?;
                encode_into(field, field_shape, output)?;
            }
        }
        Shape::Dictionary(element_shape) => {
            let object = value
                .as_object()
                .ok_or_else(|| ProtocolError::Canonical("expected dictionary".into()))?;
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            head(4, entries.len() as u64, output);
            for (key, entry) in entries {
                output.push(0x82);
                scalar(&Value::String(key.clone()), output)?;
                encode_into(entry, clone_shape(&element_shape), output)?;
            }
        }
        Shape::Sequence(element_shape, ordering) => {
            let array = value
                .as_array()
                .ok_or_else(|| ProtocolError::Canonical("expected collection".into()))?;
            let mut elements = array
                .iter()
                .map(|element| encode(element, clone_shape(&element_shape)))
                .collect::<Result<Vec<_>, _>>()?;
            if matches!(ordering, Ordering::Set) {
                elements.sort_unstable();
                if elements.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(ProtocolError::Canonical("duplicate set element".into()));
                }
            }
            head(4, elements.len() as u64, output);
            for element in elements {
                output.extend_from_slice(&element);
            }
        }
    }
    Ok(())
}

fn clone_shape(shape: &Shape) -> Shape {
    match shape {
        Shape::Scalar => Shape::Scalar,
        Shape::Quantity => Shape::Quantity,
        Shape::Rational => Shape::Rational,
        Shape::Record(record) => Shape::Record(*record),
        Shape::Dictionary(element) => map(clone_shape(element)),
        Shape::Sequence(element, ordering) => {
            Shape::Sequence(Box::new(clone_shape(element)), *ordering)
        }
    }
}

fn scalar(value: &Value, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
    match value {
        Value::Null => output.push(0xf6),
        Value::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        Value::String(value) => {
            head(3, value.len() as u64, output);
            output.extend_from_slice(value.as_bytes());
        }
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                head(0, value, output);
            } else if let Some(value) = value.as_i64() {
                head(1, value.unsigned_abs() - 1, output);
            } else {
                return Err(ProtocolError::Canonical(
                    "floating point is forbidden".into(),
                ));
            }
        }
        _ => return Err(ProtocolError::Canonical("expected scalar value".into())),
    }
    Ok(())
}

fn head(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    if value < 24 {
        output.push(prefix | value as u8);
    } else if let Ok(value) = u8::try_from(value) {
        output.extend_from_slice(&[prefix | 24, value]);
    } else if let Ok(value) = u16::try_from(value) {
        output.push(prefix | 25);
        output.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        output.push(prefix | 26);
        output.extend_from_slice(&value.to_be_bytes());
    } else {
        output.push(prefix | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn quantities_use_shortest_big_endian_unsigned_encoding() {
        assert_eq!(encode(&json!("23"), Shape::Quantity).unwrap(), [0x17]);
        assert_eq!(encode(&json!("24"), Shape::Quantity).unwrap(), [0x18, 0x18]);
        assert_eq!(
            encode(&json!("18446744073709551615"), Shape::Quantity).unwrap(),
            [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn semantic_sets_and_dictionary_order_are_stable() {
        let left = encode(&json!(["b", "a"]), set(Shape::Scalar)).unwrap();
        let right = encode(&json!(["a", "b"]), set(Shape::Scalar)).unwrap();
        assert_eq!(left, right);
        assert_eq!(
            encode(&json!({"b":"2","a":"1"}), map(Shape::Quantity)).unwrap(),
            [0x82, 0x82, 0x61, 0x61, 0x01, 0x82, 0x61, 0x62, 0x02]
        );
    }
}
