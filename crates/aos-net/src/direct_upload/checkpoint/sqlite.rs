//! Closed bounded checkpoint records and atomic SQLite wave transactions.

use std::collections::BTreeMap;

use aos_proto_types::direct_upload::*;
use rusqlite::{Connection, OptionalExtension as _, Transaction};
use serde::{Serialize, de::DeserializeOwned};

use crate::direct_upload::DirectClientError;

pub(super) const RECORDS_DDL: &str = "CREATE TABLE direct_records (
    kind TEXT NOT NULL CHECK (kind IN ('intent','session','grant','receipt','observed','complete','publication_header','publication_admission','oci_allocation')),
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 256),
    placement TEXT NOT NULL,
    part INTEGER NOT NULL CHECK (part BETWEEN 0 AND 10000),
    body BLOB NOT NULL CHECK (typeof(body)='blob' AND length(body)<=262144),
    PRIMARY KEY(kind,owner,placement,part)
) WITHOUT ROWID";

pub(super) const IDENTITY_DDL: &str = "CREATE TABLE direct_identity (
    id INTEGER PRIMARY KEY CHECK (id=1),
    namespace TEXT NOT NULL CHECK(length(namespace)=64),
    run_id TEXT NOT NULL CHECK(length(run_id)=64),
    schema_version INTEGER NOT NULL CHECK(schema_version=1)
)";

const PAGE_COUNT_LIMIT: u32 = 262_144;

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    version: u32,
    value: T,
}

pub(super) fn limits(connection: &Connection) -> Result<(), DirectClientError> {
    use rusqlite::limits::Limit;
    connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_DIRECT_CONTROL_BYTES as i32);
    connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 16 * 1024);
    connection.set_limit(Limit::SQLITE_LIMIT_COLUMN, 16);
    connection.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 32);
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| DirectClientError::Checkpoint)?;
    Ok(())
}

pub(super) fn configure(connection: &Connection) -> Result<(), DirectClientError> {
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=ON;").map_err(|_| DirectClientError::Checkpoint)?;
    connection
        .pragma_update(None, "max_page_count", PAGE_COUNT_LIMIT)
        .map_err(|_| DirectClientError::Checkpoint)?;
    Ok(())
}

pub(super) fn initialize(
    connection: &mut Connection,
    namespace: &str,
    run_id: &str,
) -> Result<(), DirectClientError> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| DirectClientError::Checkpoint)?;
    transaction
        .execute_batch(IDENTITY_DDL)
        .map_err(|_| DirectClientError::Checkpoint)?;
    transaction
        .execute_batch(RECORDS_DDL)
        .map_err(|_| DirectClientError::Checkpoint)?;
    transaction
        .execute(
            "INSERT INTO direct_identity(id,namespace,run_id,schema_version) VALUES(1,?1,?2,1)",
            rusqlite::params![namespace, run_id],
        )
        .map_err(|_| DirectClientError::Checkpoint)?;
    transaction
        .pragma_update(None, "user_version", 1)
        .map_err(|_| DirectClientError::Checkpoint)?;
    transaction
        .commit()
        .map_err(|_| DirectClientError::Checkpoint)
}

pub(super) fn validate(
    connection: &Connection,
    namespace: &str,
) -> Result<String, DirectClientError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| DirectClientError::Checkpoint)?;
    if version != 1 {
        return Err(DirectClientError::Checkpoint);
    }
    let mut statement = connection
        .prepare("SELECT name,type,sql FROM sqlite_schema ORDER BY name")
        .map_err(|_| DirectClientError::Checkpoint)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
            ))
        })
        .map_err(|_| DirectClientError::Checkpoint)?;
    let mut actual = BTreeMap::new();
    for row in rows {
        let (name, value) = row.map_err(|_| DirectClientError::Checkpoint)?;
        if actual.len() >= 2 {
            return Err(DirectClientError::Checkpoint);
        }
        actual.insert(name, value);
    }
    let expected = BTreeMap::from([
        (
            "direct_identity".into(),
            ("table".into(), IDENTITY_DDL.into()),
        ),
        (
            "direct_records".into(),
            ("table".into(), RECORDS_DDL.into()),
        ),
    ]);
    if actual != expected {
        return Err(DirectClientError::Checkpoint);
    }
    let identity: (String, String, i64, i64) = connection.query_row("SELECT namespace,run_id,schema_version,(SELECT count(*) FROM direct_identity) FROM direct_identity WHERE id=1", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(|_| DirectClientError::Checkpoint)?;
    if identity.0 != namespace
        || !valid_direct_digest(&identity.1)
        || identity.2 != 1
        || identity.3 != 1
    {
        return Err(DirectClientError::Checkpoint);
    }
    Ok(identity.1)
}

pub(super) fn read<T: DeserializeOwned>(
    connection: &Connection,
    kind: &str,
    owner: &str,
    placement: u64,
    part: u32,
) -> Result<Option<T>, DirectClientError> {
    let bytes: Option<Vec<u8>> = connection.query_row("SELECT body FROM direct_records WHERE kind=?1 AND owner=?2 AND placement=?3 AND part=?4", rusqlite::params![kind,owner,placement.to_string(),part], |row| row.get(0)).optional().map_err(|_| DirectClientError::Checkpoint)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let record: Record<T> =
        decode_direct_control(&bytes).map_err(|_| DirectClientError::Checkpoint)?;
    if record.version != 1 {
        return Err(DirectClientError::Checkpoint);
    }
    Ok(Some(record.value))
}

pub(super) fn write<T: Serialize>(
    transaction: &Transaction<'_>,
    kind: &str,
    owner: &str,
    placement: u64,
    part: u32,
    value: &T,
) -> Result<(), DirectClientError> {
    let bytes = encode_direct_control(&Record { version: 1, value })
        .map_err(|_| DirectClientError::Checkpoint)?;
    transaction.execute("INSERT INTO direct_records(kind,owner,placement,part,body) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(kind,owner,placement,part) DO UPDATE SET body=excluded.body", rusqlite::params![kind,owner,placement.to_string(),part,bytes]).map_err(|_| DirectClientError::Checkpoint)?;
    Ok(())
}

pub(super) fn immutable<T: Serialize + DeserializeOwned + PartialEq>(
    transaction: &Transaction<'_>,
    kind: &str,
    owner: &str,
    placement: u64,
    part: u32,
    value: &T,
) -> Result<(), DirectClientError> {
    match read::<T>(transaction, kind, owner, placement, part)? {
        Some(previous) if &previous != value => Err(DirectClientError::Checkpoint),
        Some(_) => Ok(()),
        None => write(transaction, kind, owner, placement, part, value),
    }
}
