//! Exact typed JSON decoding rejects duplicate keys before constructing models.
//!
//! Resource quantities are carried as canonical decimal strings by the model
//! types. This module additionally bounds wire bytes, conservative decoded
//! storage, string sizes, node counts, and nesting during construction.

use std::fmt;

use serde::de::{DeserializeOwned, DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde_json::{Map, Number, Value};

use crate::wire::WireLimits;
use crate::ProtocolError;

/// Bounds both received JSON and its decoded semantic construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonLimits {
    /// Maximum wire size checked before parsing.
    pub max_bytes: usize,
    /// Conservative decoded-storage charge, including container overhead.
    pub max_decoded_bytes: usize,
    /// Maximum nested container depth.
    pub max_nesting: usize,
    /// Maximum number of decoded scalar or container values.
    pub max_values: usize,
    /// Maximum UTF-8 bytes in any key or string value.
    pub max_string_bytes: usize,
}

impl Default for JsonLimits {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024 * 1024,
            max_decoded_bytes: 64 * 1024 * 1024,
            max_nesting: 32,
            max_values: 1_000_000,
            max_string_bytes: 4096,
        }
    }
}

/// Imports a bounded exact JSON document into a strict semantic type.
///
/// # Errors
///
/// Returns an error for exceeded bounds, duplicate keys, floating-point values,
/// malformed JSON, or fields rejected by the destination type. Destination
/// records must deny unknown fields; portable model records already do so.
pub fn from_slice<T: DeserializeOwned>(
    bytes: &[u8],
    limits: JsonLimits,
) -> Result<T, ProtocolError> {
    if bytes.len() > limits.max_bytes {
        return Err(ProtocolError::JsonLimit("wire bytes"));
    }

    let mut budget = Budget {
        limits,
        values: 0,
        storage: 0,
        exceeded: None,
    };
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let decoded = Seed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut decoder);
    let value = decoded.map_err(|source| match budget.exceeded {
        Some(bound) => ProtocolError::JsonLimit(bound),
        None => ProtocolError::Json(source),
    })?;
    decoder.end()?;
    Ok(serde_json::from_value(value)?)
}

/// Exports a typed semantic value using its published JSON representation.
///
/// # Errors
///
/// Returns the serializer error if the value cannot be represented as JSON.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    Ok(serde_json::to_vec(value)?)
}

/// Imports and validates a model under negotiated decoded-input limits.
///
/// # Errors
///
/// Returns strict JSON errors, exceeded entity bounds, or semantic model errors.
pub fn decode_problem(
    bytes: &[u8],
    limits: &WireLimits,
) -> Result<dispatch_model::ValidatedProblem, ProtocolError> {
    let problem: dispatch_model::Problem = from_slice(bytes, limits.json_limits()?)?;
    check_model_limits(&problem, limits)?;
    Ok(dispatch_model::validate(problem)?)
}

impl WireLimits {
    /// Converts negotiated wire limits into conservative JSON construction bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if a bound cannot be represented by this platform.
    pub fn json_limits(&self) -> Result<JsonLimits, ProtocolError> {
        Ok(JsonLimits {
            max_bytes: usize::try_from(self.max_problem_bytes)
                .map_err(|_| ProtocolError::JsonLimit("platform wire size"))?,
            max_decoded_bytes: usize::try_from(self.max_decoded_bytes)
                .map_err(|_| ProtocolError::JsonLimit("platform decoded size"))?,
            max_nesting: self.max_nesting as usize,
            max_values: usize::try_from(self.max_decoded_bytes / 128)
                .map_err(|_| ProtocolError::JsonLimit("platform node count"))?,
            max_string_bytes: self.max_string_bytes as usize,
        })
    }
}

/// Checks compact-model entity counts before semantic construction expands them.
///
/// # Errors
///
/// Returns an error for any entity collection exceeding its negotiated bound.
pub fn check_model_limits(
    problem: &dispatch_model::Problem,
    limits: &WireLimits,
) -> Result<(), ProtocolError> {
    fn bound(actual: usize, maximum: u64, name: &'static str) -> Result<(), ProtocolError> {
        if u64::try_from(actual).map_or(true, |actual| actual > maximum) {
            return Err(ProtocolError::JsonLimit(name));
        }
        Ok(())
    }
    fn sum(mut values: impl Iterator<Item = usize>) -> Result<usize, ProtocolError> {
        values.try_fold(0_usize, |total, count| {
            total
                .checked_add(count)
                .ok_or(ProtocolError::JsonLimit("entity count overflow"))
        })
    }
    bound(problem.items.len(), limits.max_items, "items")?;
    bound(problem.targets.len(), limits.max_targets, "targets")?;
    bound(
        problem.dimensions.len(),
        limits.max_dimensions,
        "dimensions",
    )?;
    bound(
        problem.constraints.len(),
        limits.max_constraints,
        "constraints",
    )?;
    let objective_count = problem
        .objectives
        .len()
        .checked_add(sum(problem.objectives.iter().map(|tier| tier.terms.len()))?)
        .ok_or(ProtocolError::JsonLimit("objective count overflow"))?;
    bound(objective_count, limits.max_objectives, "objectives")?;
    bound(
        sum(problem.domains.values().map(Vec::len))?,
        limits.max_domain_entries,
        "candidate-domain entries",
    )?;
    let memberships = sum(problem
        .groups
        .values()
        .map(Vec::len)
        .chain(problem.target_sets.values().map(Vec::len))
        .chain(
            problem
                .scope_families
                .values()
                .flat_map(|members| members.values().map(Vec::len)),
        ))?;
    bound(memberships, limits.max_memberships, "memberships")?;
    let overrides = sum(problem
        .items
        .values()
        .flat_map(|item| item.demands.values().map(|demand| demand.overrides.len()))
        .chain(
            problem
                .targets
                .values()
                .flat_map(|target| [target.capacities.len(), target.fixed_load.len()]),
        ))?;
    bound(overrides, limits.max_overrides, "resource overrides")?;
    bound(problem.holdings.len(), limits.max_memberships, "holdings")?;
    Ok(())
}

struct Budget {
    limits: JsonLimits,
    values: usize,
    storage: usize,
    exceeded: Option<&'static str>,
}

impl Budget {
    fn value<E: Error>(&mut self, depth: usize) -> Result<(), E> {
        if depth > self.limits.max_nesting {
            return Err(self.reject::<E>("nesting"));
        }
        self.values = self
            .values
            .checked_add(1)
            .ok_or_else(|| self.reject::<E>("value count"))?;
        if self.values > self.limits.max_values {
            return Err(self.reject::<E>("value count"));
        }
        // The bound includes transient container capacity and typed conversion.
        self.charge::<E>(128)
    }

    fn string<E: Error>(&mut self, value: &str) -> Result<(), E> {
        if value.len() > self.limits.max_string_bytes {
            return Err(self.reject::<E>("string bytes"));
        }
        self.charge::<E>(value.len())
    }

    fn charge<E: Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.storage = self
            .storage
            .checked_add(bytes)
            .ok_or_else(|| self.reject::<E>("decoded bytes"))?;
        if self.storage > self.limits.max_decoded_bytes {
            return Err(self.reject::<E>("decoded bytes"));
        }
        Ok(())
    }

    fn reject<E: Error>(&mut self, bound: &'static str) -> E {
        self.exceeded = Some(bound);
        E::custom(format!("JSON {bound} bound exceeded"))
    }
}

struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        self.budget.value::<D::Error>(self.depth)?;
        decoder.deserialize_any(JsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct JsonVisitor<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> Visitor<'de> for JsonVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded exact JSON value without duplicate keys")
    }

    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: Error>(self, _value: f64) -> Result<Value, E> {
        Err(E::custom(
            "floating-point JSON values are not exact model data",
        ))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        self.budget.string::<E>(value)?;
        Ok(Value::String(value.into()))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        self.budget.string::<E>(&value)?;
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        if self.depth >= self.budget.limits.max_nesting {
            return Err(self.budget.reject::<A::Error>("nesting"));
        }

        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        if self.depth >= self.budget.limits.max_nesting {
            return Err(self.budget.reject::<A::Error>("nesting"));
        }

        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            self.budget.string::<A::Error>(&key)?;
            self.budget.charge::<A::Error>(128)?;
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate JSON key {key:?}")));
            }
            let value = object.next_value_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn escaped_duplicate_keys_are_rejected_before_map_conversion() {
        let input = br#"{"x":"1","\u0078":"2"}"#;
        assert!(from_slice::<Value>(input, JsonLimits::default()).is_err());
    }

    #[test]
    fn node_and_depth_limits_apply_during_construction() {
        let input = b"[[[0]]]";
        let limits = JsonLimits {
            max_nesting: 1,
            ..JsonLimits::default()
        };
        assert!(matches!(
            from_slice::<Value>(input, limits),
            Err(ProtocolError::JsonLimit("nesting"))
        ));

        let limits = JsonLimits {
            max_values: 2,
            ..JsonLimits::default()
        };
        assert!(matches!(
            from_slice::<Value>(b"[0,1]", limits),
            Err(ProtocolError::JsonLimit("value count"))
        ));
    }

    #[test]
    fn large_quantity_strings_preserve_their_exact_value() {
        let input = br#""18446744073709551615""#;
        let quantity: dispatch_model::Quantity = from_slice(input, JsonLimits::default()).unwrap();
        assert_eq!(to_vec(&quantity).unwrap(), input);
        assert!(from_slice::<dispatch_model::Quantity>(
            b"18446744073709551615",
            JsonLimits::default()
        )
        .is_err());
    }

    #[test]
    fn empty_containers_count_toward_the_nesting_bound() {
        let limits = JsonLimits {
            max_nesting: 1,
            ..JsonLimits::default()
        };

        for input in [b"[[]]".as_slice(), br#"{"inner":{}}"#.as_slice()] {
            assert!(matches!(
                from_slice::<Value>(input, limits),
                Err(ProtocolError::JsonLimit("nesting"))
            ));
        }

        assert!(from_slice::<Value>(b"[]", limits).is_ok());
        assert!(from_slice::<Value>(b"{}", limits).is_ok());
        assert!(from_slice::<Value>(b"[0]", limits).is_ok());
    }
}
