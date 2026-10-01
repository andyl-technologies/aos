//! Format 3 schema, exact recovery originals and single-consumption transactions.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::lease::{LeaseClock, LeaseInteger};
use rusqlite::{params, Transaction, TransactionBehavior};

use crate::authority_journal::recovery::{
    self as wire, ClockRecoveryPlan, ClockRecoveryPolicy, ClockRecoveryReceipt,
    ClockRecoveryReview, MAX_CLOCK_RECOVERY_BYTES,
};
use crate::authority_journal::{AuthorityJournal, IssuerLiveState};

pub(super) const SCHEMA: &[(&str, &str, &str)] = &[
    ("table", "authority_clock", "CREATE TABLE authority_clock (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), floor TEXT NOT NULL, session TEXT, ceiling TEXT NOT NULL)"),
    ("table", "clock_recovery_policy", "CREATE TABLE clock_recovery_policy (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), policy BLOB NOT NULL, file BLOB NOT NULL)"),
    ("table", "clock_resolutions", "CREATE TABLE clock_resolutions (plan_digest TEXT PRIMARY KEY, previous_session TEXT NOT NULL UNIQUE, successor_session TEXT NOT NULL UNIQUE, review BLOB NOT NULL, receipt BLOB NOT NULL) WITHOUT ROWID"),
    ("table", "clock_resolution_consumptions", "CREATE TABLE clock_resolution_consumptions (plan_digest TEXT PRIMARY KEY REFERENCES clock_resolutions(plan_digest) ON DELETE RESTRICT) WITHOUT ROWID"),
    ("trigger", "clock_session_no_change", "CREATE TRIGGER clock_session_no_change BEFORE UPDATE OF session ON authority_clock WHEN OLD.session IS NOT NULL AND NEW.session IS NOT OLD.session AND NOT EXISTS (SELECT 1 FROM clock_resolutions r WHERE r.previous_session = OLD.session AND r.successor_session = NEW.session AND NOT EXISTS (SELECT 1 FROM clock_resolution_consumptions c WHERE c.plan_digest = r.plan_digest)) BEGIN SELECT RAISE(ABORT, 'unresolved clock session'); END"),
    ("trigger", "clock_policy_no_reinsert", "CREATE TRIGGER clock_policy_no_reinsert BEFORE INSERT ON clock_recovery_policy WHEN EXISTS (SELECT 1 FROM clock_recovery_policy) BEGIN SELECT RAISE(ABORT, 'immutable clock policy'); END"),
    ("trigger", "clock_policy_no_update", "CREATE TRIGGER clock_policy_no_update BEFORE UPDATE ON clock_recovery_policy BEGIN SELECT RAISE(ABORT, 'immutable clock policy'); END"),
    ("trigger", "clock_policy_no_delete", "CREATE TRIGGER clock_policy_no_delete BEFORE DELETE ON clock_recovery_policy BEGIN SELECT RAISE(ABORT, 'immutable clock policy'); END"),
    ("trigger", "clock_resolution_no_reinsert", "CREATE TRIGGER clock_resolution_no_reinsert BEFORE INSERT ON clock_resolutions WHEN EXISTS (SELECT 1 FROM clock_resolutions WHERE plan_digest = NEW.plan_digest OR previous_session = NEW.previous_session OR successor_session = NEW.successor_session) BEGIN SELECT RAISE(ABORT, 'immutable clock resolution'); END"),
    ("trigger", "clock_resolution_no_update", "CREATE TRIGGER clock_resolution_no_update BEFORE UPDATE ON clock_resolutions BEGIN SELECT RAISE(ABORT, 'immutable clock resolution'); END"),
    ("trigger", "clock_resolution_no_delete", "CREATE TRIGGER clock_resolution_no_delete BEFORE DELETE ON clock_resolutions BEGIN SELECT RAISE(ABORT, 'immutable clock resolution'); END"),
    ("trigger", "clock_consumption_no_reinsert", "CREATE TRIGGER clock_consumption_no_reinsert BEFORE INSERT ON clock_resolution_consumptions WHEN EXISTS (SELECT 1 FROM clock_resolution_consumptions WHERE plan_digest = NEW.plan_digest) BEGIN SELECT RAISE(ABORT, 'immutable clock consumption'); END"),
    ("trigger", "clock_consumption_no_update", "CREATE TRIGGER clock_consumption_no_update BEFORE UPDATE ON clock_resolution_consumptions BEGIN SELECT RAISE(ABORT, 'immutable clock consumption'); END"),
    ("trigger", "clock_consumption_no_delete", "CREATE TRIGGER clock_consumption_no_delete BEFORE DELETE ON clock_resolution_consumptions BEGIN SELECT RAISE(ABORT, 'immutable clock consumption'); END"),
];

pub(super) fn initialize_policy(
    transaction: &Transaction<'_>,
    adapter: &AuthorityJournal,
    policy: &ClockRecoveryPolicy,
) -> Result<()> {
    policy.validate()?;
    transaction.execute(
        "INSERT INTO clock_recovery_policy VALUES (1, ?1, ?2)",
        params![
            wire::encode(policy)?,
            wire::encode(&adapter.file.recovery_identity())?
        ],
    )?;
    Ok(())
}

fn require_format(transaction: &Transaction<'_>) -> Result<()> {
    let format: i32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    ensure!(
        format == 3,
        "clock recovery requires freshly initialized journal format 3; format 2 is not upgraded"
    );
    Ok(())
}

pub(crate) fn installed_policy(transaction: &Transaction<'_>) -> Result<ClockRecoveryPolicy> {
    require_format(transaction)?;
    let policy: ClockRecoveryPolicy = wire::decode(&super::bounded_blob(
        transaction,
        "SELECT length(policy), policy FROM clock_recovery_policy WHERE singleton = 1",
        [],
        MAX_CLOCK_RECOVERY_BYTES,
    )?)?;
    policy.validate()?;
    Ok(policy)
}

fn ceiling(transaction: &Transaction<'_>) -> Result<LeaseInteger> {
    let value: String = transaction.query_row("SELECT ceiling FROM authority_clock WHERE singleton = 1 AND length(ceiling) BETWEEN 1 AND 19", [], |row| row.get(0))?;
    let parsed = value.parse::<i64>()?;
    ensure!(
        parsed.to_string() == value,
        "noncanonical retained clock ceiling"
    );
    LeaseInteger::new(parsed)
}

pub(super) fn validate_retained_clock(
    transaction: &Transaction<'_>,
    adapter: &AuthorityJournal,
    state: &IssuerLiveState,
) -> Result<()> {
    let policy = installed_policy(transaction)?;
    let original_file: wire::ClockRecoveryFile = wire::decode(&super::bounded_blob(
        transaction,
        "SELECT length(file), file FROM clock_recovery_policy WHERE singleton = 1",
        [],
        1024,
    )?)?;
    ensure!(
        original_file == adapter.file.recovery_identity(),
        "clock recovery journal was copied, replaced or moved to another durable resource"
    );
    ensure!(
        policy.total_uncertainty()?
            <= state
                .journal
                .policy
                .timing_profile
                .maximum_clock_uncertainty
                .get(),
        "recovery clock policy exceeds retained profile"
    );
    ensure!(
        ceiling(transaction)? >= super::read_clock_floor(transaction)?,
        "retained clock ceiling precedes floor"
    );
    // Validate the exact consumed receipt for the current successor, if present.
    // Historical receipts are checked when explicitly read; no history is pruned.
    if let Some(session) = super::read_clock_session(transaction)? {
        let digest: Option<String> = transaction
            .query_row(
                "SELECT plan_digest FROM clock_resolutions WHERE successor_session = ?1",
                [&session],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(digest) = digest {
            let receipt = read_receipt(transaction, &digest, &policy)?;
            let consumed: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM clock_resolution_consumptions WHERE plan_digest = ?1)",
                [&digest],
                |row| row.get(0),
            )?;
            ensure!(
                consumed && receipt.review.plan.successor_session == session,
                "clock successor lacks exact durable consumption"
            );
        }
    }
    Ok(())
}

use rusqlite::OptionalExtension as _;

pub(super) fn retain_observation_ceiling(
    transaction: &Transaction<'_>,
    clock: LeaseClock,
) -> Result<()> {
    let version: i32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 2 {
        return Ok(());
    }
    require_format(transaction)?;
    let next = LeaseInteger::new(
        clock
            .observed_at
            .checked_add(clock.uncertainty)
            .context("clock ceiling overflow")?,
    )?;
    if next > ceiling(transaction)? {
        ensure!(
            transaction.execute(
                "UPDATE authority_clock SET ceiling = ?1 WHERE singleton = 1",
                [next.get().to_string()]
            )? == 1,
            "clock ceiling disappeared"
        );
    }
    Ok(())
}

pub(crate) fn verify_policy(
    adapter: &AuthorityJournal,
    expected: Option<&ClockRecoveryPolicy>,
) -> Result<()> {
    let mut connection = super::connection(adapter)?;
    let transaction = connection.transaction()?;
    super::load_transaction(&transaction, adapter)?;
    let version: i32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match expected {
        Some(expected) => ensure!(
            installed_policy(&transaction)? == *expected,
            "configured recovery policy differs from immutable installation"
        ),
        None => ensure!(
            version == 2,
            "journal format 3 requires its exact recovery configuration"
        ),
    }
    transaction.commit()?;
    adapter.file.validate_current()
}

pub(crate) fn inspect(
    adapter: &AuthorityJournal,
    policy: &ClockRecoveryPolicy,
    now: i64,
) -> Result<ClockRecoveryPlan> {
    let mut connection = super::connection(adapter)?;
    let transaction = connection.transaction()?;
    let state = super::load_transaction(&transaction, adapter)?;
    ensure!(
        installed_policy(&transaction)? == *policy,
        "recovery policy differs"
    );
    let session = super::read_clock_session(&transaction)?
        .context("fresh journal has no unresolved clock session")?;
    let plan = ClockRecoveryPlan {
        version: 1,
        file: adapter.file.recovery_identity(),
        expected_head: state.head()?,
        expected_session: session,
        expected_floor: super::read_clock_floor(&transaction)?,
        expected_ceiling: ceiling(&transaction)?,
        policy_digest: wire::canonical_digest(policy)?,
        successor_session: random_identity()?,
        nonce: random_identity()?,
        issued_at: LeaseInteger::new(now)?,
        expires_at: LeaseInteger::new(
            now.checked_add(policy.maximum_review_seconds.get())
                .context("review deadline overflow")?,
        )?,
    };
    plan.validate(policy)?;
    transaction.commit()?;
    adapter.file.validate_current()?;
    Ok(plan)
}

fn compare_original(
    transaction: &Transaction<'_>,
    adapter: &AuthorityJournal,
    plan: &ClockRecoveryPlan,
) -> Result<()> {
    let state = super::load_transaction(transaction, adapter)?;
    ensure!(
        plan.file == adapter.file.recovery_identity()
            && plan.expected_head == state.head()?
            && Some(plan.expected_session.as_str())
                == super::read_clock_session(transaction)?.as_deref()
            && plan.expected_floor == super::read_clock_floor(transaction)?
            && plan.expected_ceiling == ceiling(transaction)?,
        "clock recovery original changed or belongs to a different durable resource"
    );
    Ok(())
}

pub(crate) fn resolve(
    adapter: &AuthorityJournal,
    policy: &ClockRecoveryPolicy,
    review: &ClockRecoveryReview,
    observed_at: i64,
) -> Result<ClockRecoveryReceipt> {
    review.validate(policy)?;
    wire::validate_observation(&review.plan, policy, observed_at)?;
    let mut connection = super::connection(adapter)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        installed_policy(&transaction)? == *policy,
        "recovery policy differs"
    );
    compare_original(&transaction, adapter, &review.plan)?;
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM clock_resolutions WHERE plan_digest = ?1)",
        [&review.plan_digest],
        |row| row.get(0),
    )?;
    let receipt = if exists {
        let receipt = read_receipt(&transaction, &review.plan_digest, policy)?;
        ensure!(
            receipt.review == *review,
            "clock recovery replay changed original review"
        );
        ensure!(
            observed_at >= receipt.observed_at.get(),
            "recovery replay clock rolled back"
        );
        receipt
    } else {
        let used: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM clock_resolutions WHERE previous_session = ?1 OR successor_session = ?1)",
            [&review.plan.successor_session], |row| row.get(0),
        )?;
        ensure!(
            !used,
            "clock successor identity was already used in retained history"
        );
        let receipt = ClockRecoveryReceipt {
            version: 1,
            review: review.clone(),
            observed_at: LeaseInteger::new(observed_at)?,
            uncertainty: LeaseInteger::new(policy.total_uncertainty()?)?,
        };
        receipt.validate(policy)?;
        transaction.execute(
            "INSERT INTO clock_resolutions VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                review.plan_digest,
                review.plan.expected_session,
                review.plan.successor_session,
                wire::encode(review)?,
                wire::encode(&receipt)?
            ],
        )?;
        receipt
    };
    transaction
        .commit()
        .context("committing explicit clock resolution; outcome may be indeterminate")?;
    adapter.file.validate_current()?;
    Ok(receipt)
}

pub(crate) fn consume(adapter: &AuthorityJournal, expected: &ClockRecoveryReceipt) -> Result<()> {
    let mut connection = super::connection(adapter)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let policy = installed_policy(&transaction)?;
    expected.validate(&policy)?;
    compare_original(&transaction, adapter, &expected.review.plan)?;
    ensure!(
        read_receipt(&transaction, &expected.review.plan_digest, &policy)? == *expected,
        "clock resolution receipt differs from retained positive"
    );
    ensure!(
        transaction.execute(
            "UPDATE authority_clock SET session = ?1 WHERE singleton = 1 AND session = ?2",
            params![
                expected.review.plan.successor_session,
                expected.review.plan.expected_session
            ]
        )? == 1,
        "clock successor CAS failed"
    );
    transaction.execute(
        "INSERT INTO clock_resolution_consumptions VALUES (?1)",
        [&expected.review.plan_digest],
    )?;
    super::retain_clock_floor(&transaction, expected.observed_at)?;
    retain_observation_ceiling(
        &transaction,
        LeaseClock {
            observed_at: expected.observed_at.get(),
            uncertainty: expected.uncertainty.get(),
        },
    )?;
    transaction
        .commit()
        .context("consuming clock resolution once; outcome may be indeterminate")?;
    adapter.file.validate_current()
}

fn read_receipt(
    transaction: &Transaction<'_>,
    digest: &str,
    policy: &ClockRecoveryPolicy,
) -> Result<ClockRecoveryReceipt> {
    wire::hex_identity(digest)?;
    let receipt: ClockRecoveryReceipt = wire::decode(&super::bounded_blob(
        transaction,
        "SELECT length(receipt), receipt FROM clock_resolutions WHERE plan_digest = ?1",
        [digest],
        MAX_CLOCK_RECOVERY_BYTES,
    )?)?;
    let review: ClockRecoveryReview = wire::decode(&super::bounded_blob(
        transaction,
        "SELECT length(review), review FROM clock_resolutions WHERE plan_digest = ?1",
        [digest],
        MAX_CLOCK_RECOVERY_BYTES,
    )?)?;
    let (previous, successor): (String, String) = transaction.query_row("SELECT previous_session, successor_session FROM clock_resolutions WHERE plan_digest = ?1 AND length(previous_session) = 64 AND length(successor_session) = 64", [digest], |row| Ok((row.get(0)?, row.get(1)?)))?;
    receipt.validate(policy)?;
    ensure!(
        receipt.review == review
            && review.plan_digest == digest
            && review.plan.expected_session == previous
            && review.plan.successor_session == successor,
        "retained clock resolution fields differ"
    );
    Ok(receipt)
}

fn random_identity() -> Result<String> {
    use rand::TryRngCore as _;
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| anyhow::anyhow!("recovery entropy unavailable"))?;
    Ok(hex::encode(bytes))
}
