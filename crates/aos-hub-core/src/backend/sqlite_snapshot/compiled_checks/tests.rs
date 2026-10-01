//! Exact trusted-catalogue coverage, lexical bounds and SQLite CHECK semantics.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use super::*;

fn table(name: &str, sql: &str) -> SchemaObject {
    SchemaObject {
        kind: "table".into(),
        name: name.into(),
        table: name.into(),
        sql: Some(sql.into()),
    }
}

#[test]
fn declarations_preserve_literals_quotes_comments_and_nested_parentheses() {
    let sql = r#"CREATE TABLE "odd""table"(
        "CHECK" TEXT DEFAULT 'CHECK(ignored)',
        [right)column] TEXT,
        `left(column` TEXT,
        -- CHECK(ignored)
        /* CHECK(ignored) and ( ) */
        CHECK(instr("CHECK", 'it''s ( CHECK(fake) )') >= 0),
        CONSTRAINT "named CHECK" CHECK((length([right)column]) > 0)
            AND `left(column` <> 'héllo CHECK()'),
        CHECK(1 -- trailing comment must remain inside its expression
        )
    ); -- trailing comment
    "#;

    let checks = extract_table_checks(sql).unwrap();

    assert_eq!(checks.len(), 3);
    assert_eq!(checks[0], "instr(\"CHECK\", 'it''s ( CHECK(fake) )') >= 0");
    assert_eq!(
        checks[1],
        "(length([right)column]) > 0)\n            AND `left(column` <> 'héllo CHECK()'"
    );
    assert_eq!(
        checks[2],
        "1 -- trailing comment must remain inside its expression\n        "
    );
}

#[test]
fn keyword_matching_is_case_insensitive_and_respects_identifier_boundaries() {
    let checks = extract_table_checks(
        "cReAtE /* prefix */ TaBlE t(checksum TEXT, αCHECK TEXT, _CHECK TEXT, check$tail TEXT, x INT cHeCk /* gap */ (x IN (0,1)))",
    )
    .unwrap();

    assert_eq!(checks, ["x IN (0,1)"]);
}

#[test]
fn malformed_or_unsupported_envelopes_fail_with_value_free_errors() {
    for sql in [
        "CREATE VIRTUAL TABLE private_table USING fts5(x)",
        "CREATE TABLE IF NOT EXISTS private_table(x)",
        "CREATE TABLE main.private_table(x)",
        "CREATE TABLE private_table AS SELECT 1",
        "CREATE TABLE private_table(x) STRICT",
        "CREATE TABLE private_table(x) WITHOUT ROWID",
        "CREATE TABLE private_table(x); SELECT 'PRIVATE-SECRET'",
        "CREATE TABLE private_table(x);;",
        "CREATE TABLE private_table(x CHECK 1)",
        "CREATE TABLE private_table(x CHECK())",
        "CREATE TABLE private_table(x CHECK(1; SELECT 1))",
        "CREATE TABLE private_table(x CHECK((1))",
        "CREATE TABLE private_table(x CHECK('PRIVATE-SECRET))",
        "CREATE TABLE private_table(x CHECK(\"PRIVATE-SECRET))",
        "CREATE TABLE private_table(x CHECK(`PRIVATE-SECRET))",
        "CREATE TABLE private_table(x CHECK([PRIVATE-SECRET))",
        "CREATE TABLE private_table(x CHECK(1 /* PRIVATE-SECRET))",
        "CREATE TABLE private_table(x CHECK(1)) /* PRIVATE-SECRET",
        "CREATE TABLE private_table(x DEFAULT (CHECK(1)))",
    ] {
        let error = extract_table_checks(sql).unwrap_err();

        assert!(!format!("{error:#} {error:?}").contains("PRIVATE-SECRET"));
        assert!(!format!("{error:#} {error:?}").contains("private_table"));
    }
}

#[test]
fn empty_tables_and_quoted_check_names_do_not_invent_constraints() {
    for sql in [
        "CREATE TABLE t(x TEXT)",
        "CREATE TABLE t(\"CHECK\" TEXT, `CHECK` TEXT, [CHECK] TEXT)",
        "CREATE TABLE t(x TEXT DEFAULT 'CHECK(1)') /* CHECK(1) */",
    ] {
        assert!(extract_table_checks(sql).unwrap().is_empty());
    }
}

#[test]
fn ddl_expression_nesting_and_count_limits_reject_before_excess_copies() {
    let over_expression = format!("CREATE TABLE t(x CHECK('{}'))", "x".repeat(MAX_CHECK_BYTES));
    assert!(extract_table_checks(&over_expression).is_err());
    let over_ddl = format!(
        "CREATE TABLE t(x) -- {}",
        "x".repeat(MAX_SCHEMA_SQL_BYTES as usize)
    );
    assert!(extract_table_checks(&over_ddl).is_err());
    let checks = format!(
        "CREATE TABLE t(x {})",
        "CHECK(1) ".repeat(MAX_CHECKS_PER_TABLE + 1)
    );
    assert!(extract_table_checks(&checks).is_err());
    let nested = format!(
        "CREATE TABLE t(x CHECK({}1{}))",
        "(".repeat(MAX_PARENTHESES),
        ")".repeat(MAX_PARENTHESES)
    );
    assert!(extract_table_checks(&nested).is_err());
    let exact_expression = format!("CREATE TABLE t(x CHECK({}))", "1".repeat(MAX_CHECK_BYTES));
    assert_eq!(
        extract_table_checks(&exact_expression).unwrap()[0].len(),
        MAX_CHECK_BYTES
    );
}

#[test]
fn catalogue_identity_and_aggregate_limits_are_checked() {
    let first = table("t", "CREATE TABLE t(x CHECK(1))");
    let duplicate = table("t", "CREATE TABLE t(x CHECK(1))");
    assert!(extract_compiled_checks(&[first, duplicate]).is_err());

    let mut missing = table("t", "CREATE TABLE t(x)");
    missing.sql = None;
    assert!(extract_compiled_checks(&[missing]).is_err());
    let mut mismatch = table("t", "CREATE TABLE t(x)");
    mismatch.table = "other".into();
    assert!(extract_compiled_checks(&[mismatch]).is_err());
    let oversized = (0..=MAX_SCHEMA_OBJECTS)
        .map(|index| table(&format!("t{index}"), "CREATE TABLE t(x)"))
        .collect::<Vec<_>>();
    assert!(extract_compiled_checks(&oversized).is_err());
    let total_checks = (0..=MAX_CHECKS / MAX_CHECKS_PER_TABLE)
        .map(|index| {
            table(
                &format!("t{index}"),
                &format!(
                    "CREATE TABLE t{index}(x {})",
                    "CHECK(1) ".repeat(MAX_CHECKS_PER_TABLE)
                ),
            )
        })
        .collect::<Vec<_>>();
    assert!(extract_compiled_checks(&total_checks).is_err());
}

#[tokio::test]
async fn current_compiled_catalogue_preserves_every_declared_check() {
    let (objects, tables) = super::super::compiled_schema().await.unwrap();

    let checks = extract_compiled_checks(&objects).unwrap();

    // This exact count binds the current eight-migration catalogue. A future
    // constraint change requires reviewing extraction coverage alongside it.
    assert_eq!(checks.values().map(Vec::len).sum::<usize>(), 683);
    for name in checks.keys() {
        assert!(tables.iter().any(|table| &table.name == name));
    }
    assert_eq!(checks["route_oci_capabilities"], ["serves_web IN(0, 1)"]);
    assert_eq!(checks["oci_phase5_upgrade_guard"], ["marker = 0"]);
    // This declaration uses `CHECK (` rather than the adjacent token spelling.
    assert_eq!(checks["delivery_workflows"].len(), 1);
    assert!(checks.contains_key("storage_authority_admission_revisions"));
    assert_eq!(checks["direct_upload_baselines"], ["activated_at > 0"]);
    assert_eq!(checks["direct_upload_abort_intents"].len(), 2);
    assert_eq!(checks["mirror_import_objects"].len(), 7);
    assert_eq!(checks["surface_object_usage"].len(), 3);
    assert_eq!(checks["binding_identity_reservations"].len(), 3);
    assert!(checks["oci_upload_sessions"]
        .iter()
        .any(|check| check.contains("authenticated_source_bytes >= 0")));
}

#[tokio::test]
async fn not_predicates_preserve_null_pass_false_rejection_and_collation() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await
        .unwrap();
    let ddl = "CREATE TABLE t(label TEXT COLLATE NOCASE CHECK(label = 'foo'), optional INTEGER CHECK(optional IN(0,1)), flag INTEGER CHECK(flag = 1 -- trailing\n))";
    sqlx::raw_sql(ddl).execute(&pool).await.unwrap();
    let checks = extract_table_checks(ddl).unwrap();
    let predicate = checks
        .iter()
        .map(|expression| format!("NOT(\n{expression}\n)"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let query = format!("SELECT EXISTS(SELECT 1 FROM t WHERE {predicate} LIMIT 1)");
    sqlx::query("INSERT INTO t VALUES('FOO', NULL, 1)")
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        sqlx::query_scalar::<_, i64>(&query)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&pool)
        .await
        .unwrap();
    for sql in [
        "INSERT INTO t VALUES('bar', NULL, 1)",
        "INSERT INTO t VALUES('FOO', 2, 1)",
        "INSERT INTO t VALUES('FOO', NULL, 0)",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&query)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        sqlx::query("DELETE FROM t WHERE rowid > 1")
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
}
