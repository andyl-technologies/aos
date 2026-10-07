//! Checked batch metadata validation through borrowed SQLite column bytes.

use rusqlite::types::ValueRef;

use super::*;

pub(in crate::content_store::sqlite) fn advance_with_boundary(
    connection: &Connection,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    quarantined: &std::sync::atomic::AtomicBool,
) -> Result<(), StoreError> {
    let (instance, generation) = load_with_boundary(connection, true, boundary, quarantined)?;
    let next = generation.checked_add(1).ok_or(StoreError::Quota)?;
    let next_sql = i64::try_from(next).map_err(|_| StoreError::Quota)?;
    let checksum = metadata_checksum(instance, next);
    boundary()?;
    busy::retry(connection, true, quarantined, boundary, |_| {
        connection
            .execute(
                diagnostic::UPDATE_SQL,
                params![next_sql, checksum.as_slice()],
            )
            .map_err(|source| database_error("advance-sqlite-blob-generation", source))
    })?;
    boundary()?;
    Ok(())
}

pub(in crate::content_store::sqlite) fn load_with_boundary(
    connection: &Connection,
    transactional: bool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    quarantined: &std::sync::atomic::AtomicBool,
) -> Result<([u8; 32], u64), StoreError> {
    boundary()?;
    // SQLite may materialize each column in its separately bounded allocator.
    // Borrowing the value avoids an unbounded Rust Vec before length checks.
    let row = busy::retry(connection, transactional, quarantined, boundary, |_| {
        connection
            .query_row(diagnostic::METADATA_SQL, [], |row| {
                Ok((
                    fixed_blob(row, 0, "instance")?,
                    row.get::<_, i64>(1)?,
                    fixed_blob(row, 2, "checksum")?,
                ))
            })
            .map_err(|source| database_error("read-sqlite-blob-metadata", source))
    })?;
    boundary()?;
    let (Some(instance), generation, Some(checksum)) = row else {
        return Err(invalid_metadata());
    };
    let generation = u64::try_from(generation).map_err(|_| invalid_metadata())?;
    if generation == 0 || checksum != metadata_checksum(instance, generation) {
        return Err(invalid_metadata());
    }
    Ok((instance, generation))
}

fn fixed_blob(
    row: &rusqlite::Row<'_>,
    index: usize,
    name: &'static str,
) -> rusqlite::Result<Option<[u8; 32]>> {
    match row.get_ref(index)? {
        ValueRef::Blob(bytes) => Ok(bytes.try_into().ok()),
        other => Err(rusqlite::Error::InvalidColumnType(
            index,
            name.to_owned(),
            other.data_type(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owned_decode::DecodeBudget;

    fn same_failure(expected: StoreError, actual: StoreError) {
        match (expected, actual) {
            (StoreError::Quota, StoreError::Quota) => {}
            (
                StoreError::InvalidComposition { reason: a },
                StoreError::InvalidComposition { reason: b },
            ) => assert_eq!(a, b),
            (
                StoreError::StreamIo {
                    operation: a,
                    source: a_source,
                },
                StoreError::StreamIo {
                    operation: b,
                    source: b_source,
                },
            ) => {
                assert_eq!(a, b);
                assert_eq!(
                    a_source
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<rusqlite::Error>()),
                    b_source
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<rusqlite::Error>())
                );
            }
            (expected, actual) => panic!("different metadata failures: {expected:?}, {actual:?}"),
        }
    }

    #[test]
    fn malformed_metadata_and_overflow_preserve_generic_errors_and_rollback() {
        if super::super::tests::isolated_heap_test(
            "content_store::sqlite::batch::metadata::tests::malformed_metadata_and_overflow_preserve_generic_errors_and_rollback",
        ) {
            return;
        }
        for mutation in [
            "UPDATE metadata SET instance = zeroblob(65536)",
            "UPDATE metadata SET instance = 'wrong-type'",
            "UPDATE metadata SET checksum = zeroblob(31)",
            "UPDATE metadata SET checksum = 'wrong-type'",
            "UPDATE metadata SET generation = 'wrong-type'",
            "UPDATE metadata SET generation = 0",
            "UPDATE metadata SET checksum = zeroblob(32)",
            "overflow",
        ] {
            let root = tempfile::tempdir().expect("component metadata");
            let guard = super::super::tests::original_quota();
            let backend = super::super::tests::bounded_leaf("component", root.path(), &guard);
            let inputs = super::super::tests::objects();
            let account =
                DecodeBudget::for_store(guard.clone()).expect("same finite original authority");
            let _scope = account.enter();
            let connection = backend.lock_connection().expect("metadata mutation");
            if mutation == "overflow" {
                let (instance, _) = load_metadata(&connection).expect("valid original metadata");
                let checksum = metadata_checksum(instance, i64::MAX as u64);
                connection
                    .execute(
                        "UPDATE metadata SET generation = ?1, checksum = ?2",
                        params![i64::MAX, checksum.as_slice()],
                    )
                    .expect("last representable generation");
            } else {
                connection
                    .execute(mutation, [])
                    .expect("malformed component row");
            }
            let expected = advance_metadata(&connection).expect_err("generic metadata refusal");
            let actual = advance_with_boundary(&connection, &mut || Ok(()), &backend.quarantined)
                .expect_err("checked metadata refusal");
            same_failure(expected, actual);
            drop(connection);

            backend
                .put_many_if_absent_with_boundary(&inputs, &mut || Ok(()))
                .expect_err("metadata refusal rolls back newly staged rows");
            let connection = backend
                .lock_connection()
                .expect("original connection released");
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                        .get::<_, usize>(0))
                    .expect("rollback row count"),
                0
            );
        }
    }

    #[test]
    fn original_boundary_cancels_after_metadata_read_before_update() {
        let root = tempfile::tempdir().expect("component metadata");
        let backend = SqliteBlobBackend::open("component", root.path()).expect("component catalog");
        let guard = super::super::tests::original_quota();
        let account = DecodeBudget::for_store(guard.clone()).expect("original authority");
        let _scope = account.enter();
        let connection = backend.lock_connection().expect("same connection");
        let mut calls = 0;
        let error = advance_with_boundary(
            &connection,
            &mut || {
                calls += 1;
                guard.verify()?;
                if calls == 3 {
                    Err(super::super::tests::expired())
                } else {
                    Ok(())
                }
            },
            &backend.quarantined,
        )
        .expect_err("original callback stops metadata update");
        super::super::tests::assert_expired(error);
        assert_eq!(calls, 3);
        assert_eq!(
            load_metadata(&connection).expect("unchanged generation").1,
            1
        );
        advance_metadata(&connection).expect("unchanged generic update");
        advance_with_boundary(&connection, &mut || guard.verify(), &backend.quarantined)
            .expect("checked update");
        assert_eq!(
            load_metadata(&connection)
                .expect("exact successive generations")
                .1,
            3
        );
    }
}
