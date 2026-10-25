// SPDX-License-Identifier: AGPL-3.0-only
//! Verifies SQLite writer ownership across a read-modify-write transaction.

use std::time::Duration;

use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, ErrorCode};

use super::SqliteDb;

#[test]
fn transaction_reserves_writer_before_reading() {
	let directory = mktemp::Temp::new_dir().unwrap();
	let path = directory.join("metadata.sqlite");
	let db = SqliteDb::open(SqliteConnectionManager::file(&path), false).unwrap();
	let tree = db.open_tree("writer_regression").unwrap();
	tree.insert(b"key", b"before").unwrap();

	let competing = Connection::open(&path).unwrap();
	competing.busy_timeout(Duration::ZERO).unwrap();

	db.transaction::<_, (), _>(|tx| {
		assert_eq!(
			tx.get(&tree, b"key")?.as_deref(),
			Some(b"before".as_slice())
		);

		// A deferred read transaction would let this connection commit first,
		// making the adapter's subsequent write fail with SQLITE_BUSY_SNAPSHOT.
		let error = competing
			.execute(
				"INSERT INTO tree_writer_regression (k, v) VALUES (?1, ?2)",
				[b"other".as_slice(), b"competing".as_slice()],
			)
			.unwrap_err();
		assert_eq!(error.sqlite_error_code(), Some(ErrorCode::DatabaseBusy));

		tx.insert(&tree, b"key", b"after")?;
		Ok(())
	})
	.unwrap();

	// Commit releases the SQLite writer reservation for other connections.
	competing
		.execute(
			"INSERT INTO tree_writer_regression (k, v) VALUES (?1, ?2)",
			[b"other".as_slice(), b"competing".as_slice()],
		)
		.unwrap();
	assert_eq!(
		tree.get(b"key").unwrap().as_deref(),
		Some(b"after".as_slice())
	);
	assert_eq!(
		tree.get(b"other").unwrap().as_deref(),
		Some(b"competing".as_slice())
	);
}
