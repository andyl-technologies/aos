//! Real serialized SQLite transactions and exact canonical retained records.

use std::time::Duration;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::{
    control::{
        StorageAuthorityDeniedTransition, StorageAuthorityPublication,
        MAX_AUTHORITY_PUBLICATION_BYTES,
    },
    lease::{IssuerTransition, LeaseClock, LeaseInteger},
    StorageAuthorityAdmissionState,
};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};

use super::{AuthorityJournal, IssuerInstallation, IssuerLiveState, IssuerPublicationReceipt};

const APPLICATION_ID: i32 = 0x414f534a;
const MARKER_LIMIT: usize = 4096;
const JOURNAL_LIMIT: usize = 16 * 1024;
const RECEIPT_LIMIT: usize = 1024;

const SCHEMA: &[(&str, &str, &str)] = &[
    ("table", "installation_marker", "CREATE TABLE installation_marker (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), marker BLOB NOT NULL)"),
    ("table", "authority_state", "CREATE TABLE authority_state (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), publication BLOB NOT NULL, journal BLOB NOT NULL)"),
    ("table", "publication_receipts", "CREATE TABLE publication_receipts (generation TEXT PRIMARY KEY, publication BLOB NOT NULL, receipt BLOB NOT NULL) WITHOUT ROWID"),
    // REPLACE may bypass delete triggers; insertion guards preserve immutable
    // marker/history even for that SQLite conflict-resolution form.
    ("trigger", "marker_no_reinsert", "CREATE TRIGGER marker_no_reinsert BEFORE INSERT ON installation_marker WHEN EXISTS (SELECT 1 FROM installation_marker) BEGIN SELECT RAISE(ABORT, 'immutable installation marker'); END"),
    ("trigger", "receipts_no_replace", "CREATE TRIGGER receipts_no_replace BEFORE INSERT ON publication_receipts WHEN EXISTS (SELECT 1 FROM publication_receipts WHERE generation = NEW.generation) BEGIN SELECT RAISE(ABORT, 'immutable publication receipt'); END"),
    ("trigger", "marker_no_update", "CREATE TRIGGER marker_no_update BEFORE UPDATE ON installation_marker BEGIN SELECT RAISE(ABORT, 'immutable installation marker'); END"),
    ("trigger", "marker_no_delete", "CREATE TRIGGER marker_no_delete BEFORE DELETE ON installation_marker BEGIN SELECT RAISE(ABORT, 'immutable installation marker'); END"),
    ("trigger", "receipts_no_update", "CREATE TRIGGER receipts_no_update BEFORE UPDATE ON publication_receipts BEGIN SELECT RAISE(ABORT, 'immutable publication receipt'); END"),
    ("trigger", "receipts_no_delete", "CREATE TRIGGER receipts_no_delete BEFORE DELETE ON publication_receipts BEGIN SELECT RAISE(ABORT, 'immutable publication receipt'); END"),
];

pub(super) fn initialize(adapter: &AuthorityJournal, snapshot: &IssuerLiveState) -> Result<()> {
    let mut connection = connection(adapter)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", 1)?;
    for (_, _, statement) in SCHEMA {
        transaction.execute_batch(statement)?;
    }
    transaction.execute(
        "INSERT INTO installation_marker VALUES (1, ?1)",
        [encode(&adapter.marker, MARKER_LIMIT)?],
    )?;
    transaction.execute(
        "INSERT INTO authority_state VALUES (1, ?1, ?2)",
        params![
            encode(&snapshot.publication, MAX_AUTHORITY_PUBLICATION_BYTES)?,
            encode(&snapshot.journal, JOURNAL_LIMIT)?
        ],
    )?;
    insert_receipt(&transaction, &snapshot.publication)?;
    transaction
        .commit()
        .context("committing initial issuer installation")?;
    Ok(())
}

pub(super) fn load(adapter: &AuthorityJournal) -> Result<IssuerLiveState> {
    let mut connection = connection(adapter)?;
    let transaction = connection.transaction()?;
    let snapshot = load_transaction(&transaction, adapter)?;
    transaction.commit()?;
    adapter.file.validate_current()?;
    Ok(snapshot)
}

pub(super) fn receipt(
    adapter: &AuthorityJournal,
    generation: LeaseInteger,
) -> Result<Option<IssuerPublicationReceipt>> {
    let mut connection = connection(adapter)?;
    let transaction = connection.transaction()?;
    load_transaction(&transaction, adapter)?;
    let receipt = read_receipt(&transaction, &adapter.marker, generation)?;
    transaction.commit()?;
    adapter.file.validate_current()?;
    Ok(receipt)
}

pub(super) fn commit_lease(
    adapter: &AuthorityJournal,
    transition: IssuerTransition,
    before_commit: impl FnOnce(),
) -> Result<()> {
    let mut connection = connection(adapter)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = load_transaction(&transaction, adapter)?;
    ensure!(
        current.journal == transition.expected,
        "issuer journal CAS conflict"
    );
    validate_lease_transition(&transition)?;
    let next = IssuerLiveState {
        installation: adapter.marker.clone(),
        publication: current.publication,
        journal: transition.next,
    };
    next.validate()?;
    transaction.execute(
        "UPDATE authority_state SET journal = ?1 WHERE singleton = 1",
        [encode(&next.journal, JOURNAL_LIMIT)?],
    )?;
    before_commit();
    transaction
        .commit()
        .context("committing issuer lease journal; outcome may be indeterminate")?;
    adapter.file.validate_current()?;
    Ok(())
}

pub(super) fn commit_publication(
    adapter: &AuthorityJournal,
    transition: IssuerTransition,
    publication: StorageAuthorityPublication,
    clock: LeaseClock,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<IssuerPublicationReceipt> {
    commit_control(
        adapter,
        transition,
        PublicationChange::Advance(publication),
        clock,
        before_commit,
    )
}

pub(super) fn commit_denial(
    adapter: &AuthorityJournal,
    transition: IssuerTransition,
    denial: StorageAuthorityDeniedTransition,
    clock: LeaseClock,
) -> Result<IssuerPublicationReceipt> {
    commit_control(
        adapter,
        transition,
        PublicationChange::Deny(denial),
        clock,
        || Ok(()),
    )
}

enum PublicationChange {
    Advance(StorageAuthorityPublication),
    Deny(StorageAuthorityDeniedTransition),
}

fn commit_control(
    adapter: &AuthorityJournal,
    transition: IssuerTransition,
    change: PublicationChange,
    clock: LeaseClock,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<IssuerPublicationReceipt> {
    let mut connection = connection(adapter)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = load_transaction(&transaction, adapter)?;
    ensure!(
        current.journal == transition.expected,
        "issuer journal CAS conflict"
    );
    let (publication, prepared) = match change {
        PublicationChange::Advance(publication) => {
            let prepared = current.journal.prepare_publication(&publication, clock)?;
            (publication, prepared)
        }
        PublicationChange::Deny(denial) => {
            let prepared = current.journal.prepare_denied_gap(&denial, clock)?;
            (denial.publication, prepared)
        }
    };
    ensure!(
        prepared == transition,
        "publication transition differs from actual retained head"
    );
    let next = IssuerLiveState {
        installation: adapter.marker.clone(),
        publication,
        journal: transition.next,
    };
    next.validate()?;
    transaction.execute(
        "UPDATE authority_state SET publication = ?1, journal = ?2 WHERE singleton = 1",
        params![
            encode(&next.publication, MAX_AUTHORITY_PUBLICATION_BYTES)?,
            encode(&next.journal, JOURNAL_LIMIT)?
        ],
    )?;
    let receipt = insert_receipt(&transaction, &next.publication)?;
    before_commit()?;
    transaction
        .commit()
        .context("committing issuer publication; outcome may be indeterminate")?;
    adapter.file.validate_current()?;
    Ok(receipt)
}

fn validate_lease_transition(transition: &IssuerTransition) -> Result<()> {
    transition.expected.validate()?;
    transition.next.validate()?;
    let expected = &transition.expected;
    let next = &transition.next;
    ensure!(
        next.clock_floor >= expected.clock_floor
            && next.largest_issued_expiry >= expected.largest_issued_expiry,
        "issuer history cannot move backwards"
    );
    let mut permitted = expected.clone();
    permitted.clock_floor = next.clock_floor;
    if next.last_sequence != expected.last_sequence {
        ensure!(
            expected.state == StorageAuthorityAdmissionState::Admitted
                && expected.last_sequence.get().checked_add(1) == Some(next.last_sequence.get()),
            "invalid issuance sequence transition"
        );
        permitted.last_sequence = next.last_sequence;
        permitted.largest_issued_expiry = next.largest_issued_expiry;
    }
    ensure!(
        permitted == *next,
        "lease transition changes publication or retained history"
    );
    Ok(())
}

fn connection(adapter: &AuthorityJournal) -> Result<Connection> {
    adapter.file.validate_current()?;
    let connection = Connection::open_with_flags(
        &adapter.file.path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    adapter.file.validate_current()?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    ensure!(
        journal_mode == "delete",
        "issuer journal requires rollback-journal mode; WAL is unsupported"
    );
    connection.execute_batch("PRAGMA synchronous = EXTRA; PRAGMA trusted_schema = OFF; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY; PRAGMA mmap_size = 0;")?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    ensure!(
        synchronous == 3,
        "issuer journal requires EXTRA synchronous commits"
    );
    let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    ensure!(integrity == "ok", "issuer journal integrity check failed");
    Ok(connection)
}

fn load_transaction(
    transaction: &rusqlite::Transaction<'_>,
    adapter: &AuthorityJournal,
) -> Result<IssuerLiveState> {
    let application: i32 =
        transaction.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    ensure!(
        application == APPLICATION_ID && version == 1,
        "issuer journal schema identity changed"
    );
    let mut statement = transaction.prepare(
        "SELECT type, name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let actual: Vec<(String, String, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut expected: Vec<_> = SCHEMA
        .iter()
        .map(|(kind, name, sql)| (kind.to_string(), name.to_string(), sql.to_string()))
        .collect();
    expected.sort_by(|left, right| left.1.cmp(&right.1));
    ensure!(actual == expected, "issuer journal schema changed");
    let marker: IssuerInstallation = decode(
        &bounded_blob(
            transaction,
            "SELECT length(marker), marker FROM installation_marker WHERE singleton = 1",
            [],
            MARKER_LIMIT,
        )?,
        MARKER_LIMIT,
    )?;
    marker.validate()?;
    ensure!(
        marker == adapter.marker,
        "issuer installation marker changed"
    );
    let publication = decode(
        &bounded_blob(
            transaction,
            "SELECT length(publication), publication FROM authority_state WHERE singleton = 1",
            [],
            MAX_AUTHORITY_PUBLICATION_BYTES,
        )?,
        MAX_AUTHORITY_PUBLICATION_BYTES,
    )?;
    let journal = decode(
        &bounded_blob(
            transaction,
            "SELECT length(journal), journal FROM authority_state WHERE singleton = 1",
            [],
            JOURNAL_LIMIT,
        )?,
        JOURNAL_LIMIT,
    )?;
    let snapshot = IssuerLiveState {
        installation: marker.clone(),
        publication,
        journal,
    };
    snapshot.validate()?;
    let receipt = read_receipt(transaction, &marker, snapshot.journal.generation)?
        .context("issuer head has no historical receipt")?;
    ensure!(
        receipt == IssuerPublicationReceipt::from_publication(&snapshot.publication)?,
        "issuer head receipt differs from publication"
    );
    Ok(snapshot)
}

fn insert_receipt(
    transaction: &rusqlite::Transaction<'_>,
    publication: &StorageAuthorityPublication,
) -> Result<IssuerPublicationReceipt> {
    let receipt = IssuerPublicationReceipt::from_publication(publication)?;
    transaction.execute(
        "INSERT INTO publication_receipts VALUES (?1, ?2, ?3)",
        params![
            receipt.generation.get().to_string(),
            encode(publication, MAX_AUTHORITY_PUBLICATION_BYTES)?,
            encode(&receipt, RECEIPT_LIMIT)?
        ],
    )?;
    Ok(receipt)
}

fn read_receipt(
    transaction: &rusqlite::Transaction<'_>,
    marker: &IssuerInstallation,
    generation: LeaseInteger,
) -> Result<Option<IssuerPublicationReceipt>> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM publication_receipts WHERE generation = ?1)",
        [generation.get().to_string()],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let bytes = bounded_blob(
        transaction,
        "SELECT length(receipt), receipt FROM publication_receipts WHERE generation = ?1",
        [generation.get().to_string()],
        RECEIPT_LIMIT,
    )?;
    let receipt: IssuerPublicationReceipt = decode(&bytes, RECEIPT_LIMIT)?;
    let publication: StorageAuthorityPublication = decode(&bounded_blob(transaction, "SELECT length(publication), publication FROM publication_receipts WHERE generation = ?1", [generation.get().to_string()], MAX_AUTHORITY_PUBLICATION_BYTES)?, MAX_AUTHORITY_PUBLICATION_BYTES)?;
    publication.validate(
        &marker.authority.guard_namespace_id,
        &marker.executor_identity,
    )?;
    ensure!(
        publication.authority == marker.authority
            && receipt.generation == generation
            && receipt == IssuerPublicationReceipt::from_publication(&publication)?,
        "issuer receipt history is corrupt or belongs to another installation"
    );
    Ok(Some(receipt))
}

fn bounded_blob(
    transaction: &rusqlite::Transaction<'_>,
    query: &str,
    parameters: impl rusqlite::Params,
    limit: usize,
) -> Result<Vec<u8>> {
    Ok(transaction.query_row(query, parameters, |row| {
        let length: i64 = row.get(0)?;
        if length < 0 || length as u64 > limit as u64 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        row.get(1)
    })?)
}

fn encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= limit,
        "issuer journal record exceeds size bound"
    );
    Ok(bytes)
}

fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8], limit: usize) -> Result<T> {
    ensure!(
        bytes.len() <= limit,
        "issuer journal record exceeds size bound"
    );
    let value: T = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&value)? == bytes,
        "issuer journal record is not canonical closed JSON"
    );
    Ok(value)
}
