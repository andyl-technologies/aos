//! Reset-only serving initialization, distinct from historical archive replay.
//!
//! A serving database is either empty or bears the new exact current singleton.
//! Historical integer versions do not authorize a live migration. This check
//! does not attest arbitrary schema integrity; snapshot verification separately
//! checks its generation-specific trusted catalogue.

use crate::db::{MIGRATIONS, SCHEMA_IDENTITY};
use anyhow::{ensure, Result};

/// Bounds SQLite metadata read before serving initialization.
pub const MAX_SCHEMA_OBJECTS: usize = 4096;
/// Bounds total SQLite metadata bytes.
pub const MAX_SCHEMA_BYTES: usize = 16 * 1024 * 1024;
/// Bounds one SQLite SQL definition.
pub const MAX_SCHEMA_DEFINITION_BYTES: usize = 128 * 1024;
/// Bounds one SQLite identifier.
pub const MAX_SCHEMA_IDENTIFIER_BYTES: usize = 255;

/// Explains the required explicit reset without claiming a catalogue attestation.
pub const RESET_REQUIRED: &str = "This nonempty Hub schema cannot serve under the current schema identity. Preserve the source database and recovery evidence, then explicitly initialize a new canonical database or use a separately reviewed manual import. Initialization refused before schema bookkeeping writes.";

/// One SQLite metadata row read under the held initialization lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteSchemaObject {
    /// SQLite object type.
    pub kind: String,
    /// Object name.
    pub name: String,
    /// Parent table name.
    pub table: String,
    /// Persisted SQL, absent for implicit indexes.
    pub definition: Option<String>,
}

/// Selects the current native or Worker migration singleton.
#[derive(Debug, Clone, Copy)]
pub enum SqliteMigrationLedger {
    /// Native version singleton.
    Native,
    /// Worker singleton with id zero.
    Worker,
}

/// The only admitted serving initialization states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaAdmission {
    /// Zero for an empty schema; current migration count for a reopen.
    pub applied: usize,
}

/// Checks empty initialization or exact current identity/version singleton.
///
/// The caller holds the same connection's migration lock and reads these rows
/// only after detecting the actual metadata tables. No prefix inference occurs.
///
/// # Errors
/// Returns explicit reset/import guidance for any other nonempty state.
pub fn admit_serving(empty: bool, version: &[i64], identity: &[String]) -> Result<SchemaAdmission> {
    if empty {
        ensure!(
            version.is_empty() && identity.is_empty(),
            "{RESET_REQUIRED}"
        );
        return Ok(SchemaAdmission { applied: 0 });
    }
    ensure!(
        version == [i64::try_from(MIGRATIONS.len())?] && identity == [SCHEMA_IDENTITY],
        "{RESET_REQUIRED}"
    );
    Ok(SchemaAdmission {
        applied: MIGRATIONS.len(),
    })
}

/// Applies the reset-only admission rule to bounded SQLite metadata.
///
/// # Errors
/// Returns reset/import guidance for metadata overflow or invalid singletons.
pub fn admit_sqlite(
    objects: &[SqliteSchemaObject],
    ledger: SqliteMigrationLedger,
    version: &[i64],
    singleton_id: &[i64],
    identity: &[String],
) -> Result<SchemaAdmission> {
    ensure!(objects.len() <= MAX_SCHEMA_OBJECTS, "{RESET_REQUIRED}");
    let mut total = 0usize;
    for object in objects {
        ensure!(
            object.name.len() <= MAX_SCHEMA_IDENTIFIER_BYTES
                && object.table.len() <= MAX_SCHEMA_IDENTIFIER_BYTES
                && object
                    .definition
                    .as_ref()
                    .is_none_or(|sql| sql.len() <= MAX_SCHEMA_DEFINITION_BYTES),
            "{RESET_REQUIRED}"
        );
        total = total
            .checked_add(
                object.kind.len()
                    + object.name.len()
                    + object.table.len()
                    + object.definition.as_ref().map_or(0, String::len),
            )
            .ok_or_else(|| anyhow::anyhow!(RESET_REQUIRED))?;
    }
    ensure!(total <= MAX_SCHEMA_BYTES, "{RESET_REQUIRED}");
    match ledger {
        SqliteMigrationLedger::Native => ensure!(singleton_id.is_empty(), "{RESET_REQUIRED}"),
        SqliteMigrationLedger::Worker => ensure!(
            singleton_id.len() == version.len() && singleton_id.iter().all(|id| *id == 0),
            "{RESET_REQUIRED}"
        ),
    }
    admit_serving(objects.is_empty(), version, identity)
}
