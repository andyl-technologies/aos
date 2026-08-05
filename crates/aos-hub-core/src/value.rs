//! Dialect-neutral SQL values and rows.
//!
//! The hub's database layer speaks to three SQL engines (sqlite, postgres,
//! mysql) through one async `Backend` trait. That trait moves data in and out
//! as a single common shape so the per-engine drivers stay thin: a [`Value`] is
//! the union of the column types the hub actually stores, and a [`Row`] is a
//! positional vector of them with a typed [`Row::get`] accessor.
//!
//! # Value taxonomy
//!
//! The hub schema uses only five storage classes, mapped one-to-one onto
//! [`Value`]:
//!
//! ```text
//! Value::Null        SQL NULL
//! Value::Int(i64)    INTEGER / BIGINT (booleans stored as 0/1 land here)
//! Value::Real(f64)   REAL / DOUBLE   (unused by the current schema; present
//!                                      for completeness)
//! Value::Text(String) TEXT / VARCHAR
//! Value::Bytes(Vec<u8>) BLOB / BYTEA / LONGBLOB
//! ```
//!
//! # Binding and reading
//!
//! Method code builds a parameter list with the [`ToValue`] conversions and
//! reads result columns with [`FromValue`]. Both are deliberately small and
//! lossless for the type set the methods use (`i64`, `Option<i64>`, `String`,
//! `Option<String>`, `bool`, and `u32`/`u64` widened to `i64`):
//!
//! ```
//! use aos_hub_core::value::{Row, Value};
//!
//! let row = Row::new(vec![Value::Int(7), Value::Text("curl".into()), Value::Null]);
//! assert_eq!(row.get::<i64>(0).unwrap(), 7);
//! assert_eq!(row.get::<String>(1).unwrap(), "curl");
//! assert_eq!(row.get::<Option<String>>(2).unwrap(), None);
//! ```

use anyhow::{bail, Result};

/// A dialect-neutral SQL value: the union of the column types the hub stores.
///
/// Integers (including booleans, stored as `0`/`1`) live in [`Value::Int`];
/// floating-point columns in [`Value::Real`]; text in [`Value::Text`]; binary
/// blobs in [`Value::Bytes`]; and SQL `NULL` in [`Value::Null`].
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// SQL `NULL`.
    Null,
    /// A signed 64-bit integer (`INTEGER`/`BIGINT`; also booleans as `0`/`1`).
    Int(i64),
    /// A 64-bit float (`REAL`/`DOUBLE`).
    Real(f64),
    /// UTF-8 text (`TEXT`/`VARCHAR`).
    Text(String),
    /// A binary blob (`BLOB`/`BYTEA`/`LONGBLOB`).
    Bytes(Vec<u8>),
}

impl Value {
    /// Returns `true` when this value is [`Value::Null`].
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// A positional row of [`Value`]s with a typed column accessor.
///
/// Backends return query results as `Vec<Row>`; method code reads columns by
/// zero-based index with [`Row::get`], mirroring the `row.get::<_, T>(idx)`
/// shape of the rusqlite code the hub grew from.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    values: Vec<Value>,
}

impl Row {
    /// Builds a row from an owned vector of column values.
    #[must_use]
    pub fn new(values: Vec<Value>) -> Self {
        Self { values }
    }

    /// Returns the number of columns in the row.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` when the row has no columns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Reads column `idx`, converting it to `T` via [`FromValue`].
    ///
    /// # Errors
    ///
    /// Returns an error when `idx` is out of range or the stored value cannot
    /// be converted to `T` (for example a non-null value read as the wrong
    /// type, or a `NULL` read into a non-`Option` target).
    pub fn get<T: FromValue>(&self, idx: usize) -> Result<T> {
        let value = self.values.get(idx).ok_or_else(|| {
            anyhow::anyhow!(
                "column index {idx} out of range (row has {} columns)",
                self.values.len()
            )
        })?;
        T::from_value(value)
    }

    /// Borrows the raw value at column `idx`, if present.
    #[must_use]
    pub fn value(&self, idx: usize) -> Option<&Value> {
        self.values.get(idx)
    }
}

/// Conversion from a Rust value into a dialect-neutral [`Value`] for binding.
pub trait ToValue {
    /// Converts `self` into the [`Value`] bound to a SQL parameter.
    fn to_value(&self) -> Value;
}

/// Conversion from a dialect-neutral [`Value`] read out of a result row.
pub trait FromValue: Sized {
    /// Converts `value` into `Self`.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` cannot represent `Self` (a type mismatch,
    /// or a `NULL` for a non-`Option` target).
    fn from_value(value: &Value) -> Result<Self>;
}

impl ToValue for Value {
    fn to_value(&self) -> Value {
        self.clone()
    }
}

impl ToValue for i64 {
    fn to_value(&self) -> Value {
        Value::Int(*self)
    }
}

impl ToValue for i32 {
    fn to_value(&self) -> Value {
        Value::Int(i64::from(*self))
    }
}

impl ToValue for u32 {
    fn to_value(&self) -> Value {
        Value::Int(i64::from(*self))
    }
}

impl ToValue for u64 {
    fn to_value(&self) -> Value {
        // The hub's u64 columns (sizes, counts) never exceed i64::MAX in
        // practice; saturate rather than panic.
        Value::Int(i64::try_from(*self).unwrap_or(i64::MAX))
    }
}

impl ToValue for bool {
    fn to_value(&self) -> Value {
        Value::Int(i64::from(*self))
    }
}

impl ToValue for f64 {
    fn to_value(&self) -> Value {
        Value::Real(*self)
    }
}

impl ToValue for str {
    fn to_value(&self) -> Value {
        Value::Text(self.to_string())
    }
}

impl ToValue for String {
    fn to_value(&self) -> Value {
        Value::Text(self.clone())
    }
}

impl ToValue for Vec<u8> {
    fn to_value(&self) -> Value {
        Value::Bytes(self.clone())
    }
}

impl ToValue for [u8] {
    fn to_value(&self) -> Value {
        Value::Bytes(self.to_vec())
    }
}

impl<T: ToValue> ToValue for Option<T> {
    fn to_value(&self) -> Value {
        match self {
            Some(v) => v.to_value(),
            None => Value::Null,
        }
    }
}

impl<T: ToValue + ?Sized> ToValue for &T {
    fn to_value(&self) -> Value {
        (**self).to_value()
    }
}

impl FromValue for Value {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(value.clone())
    }
}

impl FromValue for i64 {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Int(n) => Ok(*n),
            // Some engines surface aggregate/boolean results as a different
            // class; coerce the lossless numeric cases.
            Value::Real(f) => Ok(*f as i64),
            Value::Text(s) => s
                .parse::<i64>()
                .map_err(|_| anyhow::anyhow!("expected integer, got text {s:?}")),
            other => bail!("expected integer, got {other:?}"),
        }
    }
}

impl FromValue for u64 {
    fn from_value(value: &Value) -> Result<Self> {
        let n = i64::from_value(value)?;
        u64::try_from(n).map_err(|_| anyhow::anyhow!("expected non-negative integer, got {n}"))
    }
}

impl FromValue for u32 {
    fn from_value(value: &Value) -> Result<Self> {
        let n = i64::from_value(value)?;
        u32::try_from(n).map_err(|_| anyhow::anyhow!("integer {n} out of range for u32"))
    }
}

impl FromValue for bool {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(i64::from_value(value)? != 0)
    }
}

impl FromValue for f64 {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Real(f) => Ok(*f),
            Value::Int(n) => Ok(*n as f64),
            other => bail!("expected real, got {other:?}"),
        }
    }
}

impl FromValue for String {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Text(s) => Ok(s.clone()),
            Value::Bytes(b) => String::from_utf8(b.clone())
                .map_err(|_| anyhow::anyhow!("expected UTF-8 text in bytes column")),
            // Numeric-to-text coercion keeps the few columns where an engine
            // may report an integer literal as text working uniformly.
            Value::Int(n) => Ok(n.to_string()),
            other => bail!("expected text, got {other:?}"),
        }
    }
}

impl FromValue for Vec<u8> {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Bytes(b) => Ok(b.clone()),
            Value::Text(s) => Ok(s.clone().into_bytes()),
            other => bail!("expected bytes, got {other:?}"),
        }
    }
}

impl<T: FromValue> FromValue for Option<T> {
    fn from_value(value: &Value) -> Result<Self> {
        if value.is_null() {
            Ok(None)
        } else {
            Ok(Some(T::from_value(value)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_scalars() {
        assert_eq!(7_i64.to_value(), Value::Int(7));
        assert_eq!(true.to_value(), Value::Int(1));
        assert_eq!(3_u32.to_value(), Value::Int(3));
        assert_eq!("x".to_value(), Value::Text("x".into()));
        assert_eq!(Some(5_i64).to_value(), Value::Int(5));
        assert_eq!(Option::<i64>::None.to_value(), Value::Null);
    }

    #[test]
    fn reads_typed_columns() {
        let row = Row::new(vec![
            Value::Int(42),
            Value::Text("curl".into()),
            Value::Null,
            Value::Int(1),
        ]);
        assert_eq!(row.get::<i64>(0).unwrap(), 42);
        assert_eq!(row.get::<u64>(0).unwrap(), 42);
        assert_eq!(row.get::<String>(1).unwrap(), "curl");
        assert_eq!(row.get::<Option<String>>(2).unwrap(), None);
        assert_eq!(row.get::<Option<i64>>(2).unwrap(), None);
        assert!(row.get::<bool>(3).unwrap());
    }

    #[test]
    fn out_of_range_and_null_errors() {
        let row = Row::new(vec![Value::Null]);
        assert!(row.get::<i64>(0).is_err());
        assert!(row.get::<String>(5).is_err());
    }
}
