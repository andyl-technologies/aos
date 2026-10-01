//! Bounded private-cell capture and exact one-row reconstruction.
//!
//! Private wrappers deliberately do not implement serialization or raw `Debug`.
//! Explicit private callbacks/writers are confidentiality boundaries: callers
//! must not direct them to public artifacts, logs, or unrestricted transports.
//! This module performs no SQL, filesystem, encryption, or activation operation.
//! Digests establish internal consistency, not authenticated source provenance.
//!
//! The private scalar codec admits only this closed, versioned JSON shape:
//!
//! ```json
//! {"version":1,"scalar":{"kind":"text","value":"exact original"}}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;

use anyhow::{ensure, Result};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::{
    cell_digest, payload_len, scalar, value_at, ClassifiedCell, ClassifiedSnapshotRow,
    SnapshotClassifier, SnapshotPrivateDependency, SnapshotRowDisposition, SnapshotScalar,
    MAX_CELL_BYTES, MAX_ROW_BYTES,
};
use crate::value::{Row, Value};

const MAX_SCALAR_JSON_BYTES: usize = 6 * MAX_CELL_BYTES + 128;

/// A classified row paired with its bounded, explicitly private originals.
///
/// Authentication-transient and source-metadata dispositions contain no private
/// originals. This wrapper is not automatically serializable.
pub struct CapturedSnapshotRow {
    classified: SnapshotRowDisposition,
    originals: Vec<PrivateSnapshotCell>,
}

impl fmt::Debug for CapturedSnapshotRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedSnapshotRow")
            .field("private_cell_count", &self.originals.len())
            .finish_non_exhaustive()
    }
}

impl CapturedSnapshotRow {
    /// Borrows metadata containing no raw private cell originals.
    pub fn classified(&self) -> &SnapshotRowDisposition {
        &self.classified
    }

    /// Borrows originals for an explicitly private capture pipeline.
    pub fn private_cells(&self) -> &[PrivateSnapshotCell] {
        &self.originals
    }

    /// Transfers metadata and private originals to a bounded capture pipeline.
    pub fn into_parts(self) -> (SnapshotRowDisposition, Vec<PrivateSnapshotCell>) {
        (self.classified, self.originals)
    }
}

/// One exact original cell with its independently checked dependency locator.
///
/// Debug output is redacted, and no automatic serialization/deserialization is
/// implemented. This is neither an encrypted cell nor a source-sealer operation.
/// Raw input/output memory is sensitive; this seam makes no memory-erasure claim.
pub struct PrivateSnapshotCell {
    dependency: SnapshotPrivateDependency,
    value: Value,
}

impl fmt::Debug for PrivateSnapshotCell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSnapshotCell { <redacted> }")
    }
}

impl PrivateSnapshotCell {
    /// Returns the exact metadata locator without exposing its private value.
    pub fn dependency(&self) -> &SnapshotPrivateDependency {
        &self.dependency
    }

    /// Runs an explicitly private callback on the original typed source value.
    ///
    /// The callback owns confidentiality of any copies, diagnostics, or output.
    pub fn with_private_value<T>(&self, callback: impl FnOnce(&Value) -> T) -> T {
        callback(&self.value)
    }

    /// Decodes one bounded version-one scalar and checks its declared dependency.
    ///
    /// # Errors
    ///
    /// Rejects excessive input/value lengths, duplicate or unknown fields,
    /// unsupported versions/types, noncanonical integers/hex, nonfinite reals,
    /// or a payload length/digest mismatch. Errors exclude input and parser detail.
    pub fn from_private_scalar_json(
        dependency: SnapshotPrivateDependency,
        bytes: &[u8],
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_SCALAR_JSON_BYTES && dependency.payload_bytes <= MAX_CELL_BYTES,
            "snapshot private scalar exceeds limits"
        );
        let envelope: ScalarEnvelope = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("snapshot private scalar JSON is invalid"))?;
        ensure!(
            envelope.version == 1,
            "snapshot private scalar version is invalid"
        );
        let scalar = envelope.scalar.0;
        Self::from_private_scalar(dependency, &scalar)
    }

    pub(super) fn from_private_scalar(
        dependency: SnapshotPrivateDependency,
        scalar: &SnapshotScalar,
    ) -> Result<Self> {
        let value = decode_scalar(scalar)?;
        validate_original(&dependency, &value)?;
        Ok(Self { dependency, value })
    }

    /// Writes the exact scalar through an explicitly private versioned codec.
    ///
    /// The writer owns confidentiality; this method supplies no encryption or
    /// authentication and must not be directed at logs or public archive output.
    ///
    /// # Errors
    ///
    /// Returns a redacted error if the original fails bounds/identity validation
    /// or the writer fails. A writer failure may leave partial private bytes.
    pub fn write_private_scalar_json(&self, writer: impl Write) -> Result<()> {
        validate_original(&self.dependency, &self.value)?;
        let scalar = scalar(&self.value)?;
        let encoded = serde_json::json!({"version": 1, "scalar": scalar});
        serde_json::to_writer(writer, &encoded)
            .map_err(|_| anyhow::anyhow!("snapshot private scalar write failed"))
    }
}

/// A revalidated exact row that remains behind an explicit private boundary.
///
/// This wrapper grants no SQL insertion, job execution, namespace adoption or
/// provider access. It has redacted Debug output and no automatic serialization.
pub struct ReconstructedSnapshotRow {
    row: Row,
}

impl fmt::Debug for ReconstructedSnapshotRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReconstructedSnapshotRow { <redacted> }")
    }
}

impl ReconstructedSnapshotRow {
    /// Runs an explicitly private callback on the revalidated source-order row.
    ///
    /// The callback owns confidentiality of any copies, diagnostics, or output.
    pub fn with_private_row<T>(&self, callback: impl FnOnce(&Row) -> T) -> T {
        callback(&self.row)
    }
}

impl SnapshotClassifier {
    /// Captures only the declared exact private cells from one admitted row.
    ///
    /// Original JSON and typed values are copied without normalization. Existing
    /// source-cell/row limits and all current classification rules apply before
    /// any capture is returned; omitted dispositions produce no private payload.
    ///
    /// # Errors
    ///
    /// Returns a value-redacted error under the conditions of [`Self::classify`].
    pub fn capture_private_row(&self, table: &str, row: &Row) -> Result<CapturedSnapshotRow> {
        let classified = self.classify(table, row)?;
        let mut originals = Vec::new();
        if let SnapshotRowDisposition::Retained(retained) = &classified {
            let contract = self
                .tables
                .get(table)
                .ok_or_else(|| anyhow::anyhow!("snapshot table is unclassified"))?;
            for dependency in &retained.private_dependencies {
                let index = contract
                    .columns
                    .iter()
                    .position(|column| column.name == dependency.column)
                    .ok_or_else(|| anyhow::anyhow!("snapshot private locator is invalid"))?;
                originals.push(PrivateSnapshotCell {
                    dependency: dependency.clone(),
                    value: value_at(row, index)?.clone(),
                });
            }
        }

        Ok(CapturedSnapshotRow {
            classified,
            originals,
        })
    }

    /// Reconstructs and reclassifies one row using exactly its private originals.
    ///
    /// Every table/key/column/digest/reason/length locator must match one-to-one.
    /// Source order and PK identity are derived from the existing contract; full
    /// reclassification equality rejects policy, storage-class, and metadata
    /// tampering. No source JSON is parsed and rewritten for reconstruction.
    ///
    /// # Errors
    ///
    /// Rejects unknown shapes, excessive payloads, duplicate/missing/extra or
    /// mismatched originals, invalid scalars, or reclassification differences.
    /// Errors expose no supplied values, identifiers, or parser details.
    pub fn reconstruct_private_row(
        &self,
        classified: &ClassifiedSnapshotRow,
        originals: &[PrivateSnapshotCell],
    ) -> Result<ReconstructedSnapshotRow> {
        let contract = self
            .tables
            .get(&classified.table)
            .ok_or_else(|| anyhow::anyhow!("snapshot reconstruction table is unclassified"))?;
        ensure!(
            contract.disposition == "retain"
                && classified.cells.len() == contract.columns.len()
                && originals.len() <= contract.columns.len()
                && classified.private_dependencies.len() == originals.len(),
            "snapshot reconstruction shape differs"
        );

        let mut declarations = BTreeMap::new();
        for dependency in &classified.private_dependencies {
            validate_locator(dependency)?;
            ensure!(
                dependency.table == classified.table
                    && contract
                        .columns
                        .iter()
                        .any(|column| column.name == dependency.column)
                    && declarations
                        .insert(dependency.column.as_str(), dependency)
                        .is_none(),
                "snapshot private locator is duplicated or differs"
            );
        }
        let mut supplied = BTreeMap::new();
        let mut payload = 0usize;
        for (original, declared) in originals.iter().zip(&classified.private_dependencies) {
            ensure!(
                &original.dependency == declared,
                "snapshot private original order or locator differs"
            );
            validate_original(&original.dependency, &original.value)?;
            payload = bounded_payload(payload, &original.value)?;
            ensure!(
                declarations
                    .get(original.dependency.column.as_str())
                    .copied()
                    == Some(&original.dependency)
                    && supplied
                        .insert(original.dependency.column.as_str(), original)
                        .is_none(),
                "snapshot private original is duplicated or differs"
            );
        }

        let mut values = Vec::with_capacity(contract.columns.len());
        let mut used = BTreeSet::new();
        for column in &contract.columns {
            let cell = classified
                .cells
                .get(&column.name)
                .ok_or_else(|| anyhow::anyhow!("snapshot reconstruction column differs"))?;
            let value = match cell {
                ClassifiedCell::Scalar(scalar) => {
                    ensure!(
                        !declarations.contains_key(column.name.as_str()),
                        "snapshot private declaration differs"
                    );
                    // Reject the cumulative budget before cloning text or
                    // allocating a decoded byte payload.
                    payload = bounded_size(payload, scalar_payload_len(scalar)?)?;
                    decode_scalar(scalar)?
                }
                ClassifiedCell::External(digest) => {
                    let original = supplied
                        .get(column.name.as_str())
                        .ok_or_else(|| anyhow::anyhow!("snapshot private original is absent"))?;
                    ensure!(
                        &original.dependency.cell_digest == digest,
                        "snapshot private digest differs"
                    );
                    used.insert(column.name.as_str());
                    original.value.clone()
                }
            };
            values.push(value);
        }
        ensure!(
            used.len() == supplied.len(),
            "snapshot private original is extra"
        );
        let row = Row::new(values);
        let reclassified = self.classify(&classified.table, &row)?;
        ensure!(
            reclassified == SnapshotRowDisposition::Retained(classified.clone()),
            "snapshot reconstruction reclassification differs"
        );

        Ok(ReconstructedSnapshotRow { row })
    }
}

fn validate_original(dependency: &SnapshotPrivateDependency, value: &Value) -> Result<()> {
    validate_locator(dependency)?;
    ensure!(
        payload_len(value) <= MAX_CELL_BYTES
            && dependency.payload_bytes == payload_len(value)
            && dependency.cell_digest == cell_digest(value),
        "snapshot private original length or digest differs"
    );
    if let Value::Real(value) = value {
        ensure!(value.is_finite(), "snapshot real value is not finite");
    }
    Ok(())
}

fn validate_locator(dependency: &SnapshotPrivateDependency) -> Result<()> {
    ensure!(
        !dependency.table.is_empty()
            && dependency.table.len() <= 128
            && !dependency.column.is_empty()
            && dependency.column.len() <= 128
            && dependency.primary_key_digest.len() == 64
            && lowercase_hex(&dependency.primary_key_digest)
            && dependency.cell_digest.len() == 64
            && lowercase_hex(&dependency.cell_digest)
            && dependency.payload_bytes <= MAX_CELL_BYTES,
        "snapshot private locator is invalid"
    );
    Ok(())
}

fn bounded_payload(total: usize, value: &Value) -> Result<usize> {
    bounded_size(total, payload_len(value))
}

fn bounded_size(total: usize, size: usize) -> Result<usize> {
    let total = total
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("snapshot row payload exceeds limits"))?;
    ensure!(
        size <= MAX_CELL_BYTES && total <= MAX_ROW_BYTES,
        "snapshot row payload exceeds limits"
    );
    Ok(total)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalarEnvelope {
    version: u8,
    scalar: PrivateScalarWire,
}

// Deserialize the two scalar fields directly. A malformed array/object payload
// fails before allocating a generic JSON tree; duplicate/unknown keys reject.
pub(super) struct PrivateScalarWire(pub(super) SnapshotScalar);

impl<'de> Deserialize<'de> for PrivateScalarWire {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ScalarVisitor;

        impl<'de> Visitor<'de> for ScalarVisitor {
            type Value = PrivateScalarWire;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed snapshot scalar object")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut kind = None;
                let mut value = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "kind" if kind.is_none() => kind = Some(map.next_value::<String>()?),
                        "value" if value.is_none() => value = Some(map.next_value::<String>()?),
                        _ => {
                            return Err(de::Error::custom(
                                "snapshot scalar member is unknown or duplicated",
                            ));
                        }
                    }
                }
                let kind =
                    kind.ok_or_else(|| de::Error::custom("snapshot scalar kind is absent"))?;
                if kind == "null" {
                    if value.is_some() {
                        return Err(de::Error::custom("snapshot null scalar has a payload"));
                    }
                    return Ok(PrivateScalarWire(SnapshotScalar::Null));
                }
                let value =
                    value.ok_or_else(|| de::Error::custom("snapshot scalar payload is absent"))?;
                let scalar = match kind.as_str() {
                    "integer" => SnapshotScalar::Integer(value),
                    "real_bits" => SnapshotScalar::RealBits(value),
                    "text" => SnapshotScalar::Text(value),
                    "bytes_hex" => SnapshotScalar::BytesHex(value),
                    _ => return Err(de::Error::custom("snapshot scalar kind is unknown")),
                };
                Ok(PrivateScalarWire(scalar))
            }
        }

        deserializer.deserialize_map(ScalarVisitor)
    }
}

pub(super) fn scalar_payload_len(scalar: &SnapshotScalar) -> Result<usize> {
    match scalar {
        SnapshotScalar::Integer(text) => {
            canonical_integer(text)?;
            Ok(8)
        }
        SnapshotScalar::RealBits(text) => {
            finite_real(text)?;
            Ok(8)
        }
        SnapshotScalar::Text(text) => {
            ensure!(
                text.len() <= MAX_CELL_BYTES,
                "snapshot text scalar exceeds limits"
            );
            Ok(text.len())
        }
        SnapshotScalar::BytesHex(text) => {
            ensure!(
                text.len() <= 2 * MAX_CELL_BYTES && text.len() % 2 == 0 && lowercase_hex(text),
                "snapshot bytes scalar is invalid"
            );
            Ok(text.len() / 2)
        }
        SnapshotScalar::Null => Ok(0),
    }
}

fn decode_scalar(scalar: &SnapshotScalar) -> Result<Value> {
    scalar_payload_len(scalar)?;
    Ok(match scalar {
        SnapshotScalar::Integer(text) => Value::Int(canonical_integer(text)?),
        SnapshotScalar::RealBits(text) => Value::Real(finite_real(text)?),
        SnapshotScalar::Text(text) => Value::Text(text.clone()),
        SnapshotScalar::BytesHex(text) => Value::Bytes(
            hex::decode(text).map_err(|_| anyhow::anyhow!("snapshot bytes scalar is invalid"))?,
        ),
        SnapshotScalar::Null => Value::Null,
    })
}

fn canonical_integer(text: &str) -> Result<i64> {
    ensure!(text.len() <= 20, "snapshot integer scalar is invalid");
    let integer = text
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("snapshot integer scalar is invalid"))?;
    ensure!(
        integer.to_string() == text,
        "snapshot integer scalar is invalid"
    );
    Ok(integer)
}

fn finite_real(text: &str) -> Result<f64> {
    ensure!(
        text.len() == 16 && lowercase_hex(text),
        "snapshot real scalar is invalid"
    );
    let bits = u64::from_str_radix(text, 16)
        .map_err(|_| anyhow::anyhow!("snapshot real scalar is invalid"))?;
    let real = f64::from_bits(bits);
    ensure!(real.is_finite(), "snapshot real value is not finite");
    Ok(real)
}

fn lowercase_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
