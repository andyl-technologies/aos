//! Canonical registry of versioned Crucible schemas.
//!
//! Every durable record, process-protocol message, CLI output contract, and
//! QEMU migration section that Crucible versions independently has one row in
//! `data/schema-registry.tsv`. Owning crates compare their compiled schema
//! constants against this registry in their own tests, and the campaign gate
//! traceability test checks that every row names cataloged compatibility gates.
//!
//! The file is tab separated. Lines that are empty or start with `#` are
//! comments; every other line has exactly five fields:
//!
//! ```text
//! # schema-name	version	owner	object-kind	compatibility-gates
//! crucible.content-envelope	1	crucible-store::content_envelope	envelope	gate:content-address,gate:campaign-store-equivalence
//! ```
//!
//! - `schema-name` is the stable dotted schema identity.
//! - `version` is the current positive schema version.
//! - `owner` names the `crate::module` (or `qemu-patch::section`) that defines
//!   the encoding.
//! - `object-kind` classifies the record, such as `envelope` or
//!   `process-protocol-message`.
//! - `compatibility-gates` is a comma-separated list of canonical gate names
//!   that must pass before the schema changes.

use std::error::Error;
use std::fmt;

/// Raw text of the canonical schema registry.
///
/// Consumers that assert exact rows may match lines of this text directly;
/// structured consumers should prefer [`schema_registry_entries`].
pub const SCHEMA_REGISTRY: &str = include_str!("../data/schema-registry.tsv");

/// One parsed row of the schema registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaRegistryEntry<'a> {
    /// Stable dotted schema identity.
    pub name: &'a str,
    /// Current positive schema version.
    pub version: u32,
    /// `crate::module` or patch section that owns the encoding.
    pub owner: &'a str,
    /// Classification of the encoded object.
    pub object_kind: &'a str,
    /// Comma-separated canonical compatibility gate names.
    pub compatibility_gates: &'a str,
}

impl<'a> SchemaRegistryEntry<'a> {
    /// Returns the compatibility gate names in registry order.
    pub fn gates(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        self.compatibility_gates.split(',')
    }
}

/// A malformed schema registry line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaRegistryError {
    /// One-based line number of the malformed line.
    pub line: usize,
    /// Description of the malformation.
    pub reason: String,
}

impl fmt::Display for SchemaRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "schema registry line {}: {}",
            self.line, self.reason
        )
    }
}

impl Error for SchemaRegistryError {}

/// Parses every schema row of the canonical registry in file order.
///
/// # Errors
///
/// Returns [`SchemaRegistryError`] for the first row that does not contain
/// exactly five tab-separated fields, has a non-positive or non-numeric
/// version, or leaves the owner, object kind, or gate list empty.
pub fn schema_registry_entries() -> Result<Vec<SchemaRegistryEntry<'static>>, SchemaRegistryError> {
    parse_schema_registry(SCHEMA_REGISTRY)
}

/// Finds the canonical registry row for one schema name.
///
/// # Errors
///
/// Returns [`SchemaRegistryError`] when the registry itself is malformed; see
/// [`schema_registry_entries`].
pub fn find_schema(
    name: &str,
) -> Result<Option<SchemaRegistryEntry<'static>>, SchemaRegistryError> {
    Ok(schema_registry_entries()?
        .into_iter()
        .find(|entry| entry.name == name))
}

fn parse_schema_registry(text: &str) -> Result<Vec<SchemaRegistryEntry<'_>>, SchemaRegistryError> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(index, line)| parse_entry(index + 1, line))
        .collect()
}

fn parse_entry(
    line_number: usize,
    line: &str,
) -> Result<SchemaRegistryEntry<'_>, SchemaRegistryError> {
    let malformed = |reason: &str| SchemaRegistryError {
        line: line_number,
        reason: reason.to_owned(),
    };

    let fields = line.split('\t').collect::<Vec<_>>();
    let [name, version, owner, object_kind, compatibility_gates] = fields.as_slice() else {
        return Err(malformed("expected five tab-separated fields"));
    };

    let version = version
        .parse::<u32>()
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| malformed("version must be a positive integer"))?;
    if name.is_empty() || owner.is_empty() || object_kind.is_empty() {
        return Err(malformed("name, owner, and object kind must be non-empty"));
    }
    if compatibility_gates.split(',').any(str::is_empty) {
        return Err(malformed("every compatibility gate must be non-empty"));
    }

    Ok(SchemaRegistryEntry {
        name,
        version,
        owner,
        object_kind,
        compatibility_gates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_registry_parses_with_unique_names() -> Result<(), SchemaRegistryError> {
        let entries = schema_registry_entries()?;
        let mut names = std::collections::BTreeSet::new();

        assert!(!entries.is_empty(), "schema registry must not be empty");
        for entry in entries {
            assert!(names.insert(entry.name), "duplicate schema {}", entry.name);
        }

        Ok(())
    }

    #[test]
    fn malformed_rows_are_rejected_with_line_numbers() {
        let cases = [
            "# header\nname\t1\towner::m\tkind",
            "# header\nname\t0\towner::m\tkind\tgate:a",
            "# header\nname\tx\towner::m\tkind\tgate:a",
            "# header\nname\t1\t\tkind\tgate:a",
            "# header\nname\t1\towner::m\tkind\tgate:a,",
        ];

        for case in cases {
            let line = parse_schema_registry(case).err().map(|error| error.line);
            assert_eq!(line, Some(2), "{case}");
        }
    }

    #[test]
    fn find_schema_returns_the_exact_row() -> Result<(), SchemaRegistryError> {
        let entry = find_schema("crucible.content-envelope")?;

        assert_eq!(
            entry.map(|entry| (entry.version, entry.owner)),
            Some((1, "crucible-store::content_envelope"))
        );
        assert_eq!(find_schema("crucible.not-a-schema")?, None);

        Ok(())
    }
}
