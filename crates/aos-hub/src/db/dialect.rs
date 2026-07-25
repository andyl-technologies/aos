//! Per-dialect SQL translation, re-exported from [`aos_hub_core::dialect`].
//!
//! The translation logic moved to the runtime-agnostic core crate (RFC-0004
//! Phase 5) so the Cloudflare Worker's D1 backend can share it; this re-export
//! keeps the hub's `db::dialect::…` paths stable. The tests live here because
//! several assert against the hub's [`MIGRATIONS`](crate::db::MIGRATIONS) and
//! [`split_statements`](crate::db::backend::split_statements).

pub use aos_hub_core::dialect::*;

#[cfg(test)]
mod tests {
    use super::*;
    use aos_hub_core::value::Value;

    #[test]
    fn sqlite_is_identity_placeholders() {
        let t = Dialect::Sqlite
            .translate("SELECT a FROM t WHERE id = ?1 AND b = ?2")
            .unwrap();
        assert_eq!(t.sql, "SELECT a FROM t WHERE id = ?1 AND b = ?2");
        assert_eq!(t.param_order, vec![0, 1]);
    }

    #[test]
    fn postgres_dollar_placeholders() {
        let t = Dialect::Postgres
            .translate("INSERT INTO t (a, b) VALUES (?1, ?2)")
            .unwrap();
        assert_eq!(t.sql, "INSERT INTO t (a, b) VALUES ($1, $2)");
        assert_eq!(t.param_order, vec![0, 1]);
    }

    #[test]
    fn mysql_positional_placeholders() {
        let t = Dialect::Mysql
            .translate("INSERT INTO t (a, b) VALUES (?1, ?2)")
            .unwrap();
        assert_eq!(t.sql, "INSERT INTO t (a, b) VALUES (?, ?)");
        assert_eq!(t.param_order, vec![0, 1]);
    }

    #[test]
    fn mysql_reused_placeholder_duplicates_param() {
        let t = Dialect::Mysql
            .translate("INSERT INTO t (a, b, c) VALUES (?1, ?2, ?2)")
            .unwrap();
        assert_eq!(t.sql, "INSERT INTO t (a, b, c) VALUES (?, ?, ?)");
        assert_eq!(t.param_order, vec![0, 1, 1]);
        let params = [Value::Int(10), Value::Int(20), Value::Int(30)];
        // Source has only params for ?1 and ?2; the reuse repeats ?2's value.
        let ordered = order_params(&params[..2], &t.param_order);
        assert_eq!(
            ordered,
            vec![Value::Int(10), Value::Int(20), Value::Int(20)]
        );
    }

    #[test]
    fn ddl_autoincrement_pk() {
        let src = "CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER, body BLOB)";
        let pg = Dialect::Postgres.translate(src).unwrap();
        assert!(pg.sql.contains("id BIGSERIAL PRIMARY KEY"), "{}", pg.sql);
        assert!(pg.sql.contains("n BIGINT"), "{}", pg.sql);
        assert!(pg.sql.contains("body BYTEA"), "{}", pg.sql);

        let my = Dialect::Mysql.translate(src).unwrap();
        assert!(
            my.sql.contains("id BIGINT AUTO_INCREMENT PRIMARY KEY"),
            "{}",
            my.sql
        );
        assert!(my.sql.contains("n BIGINT"), "{}", my.sql);
        assert!(my.sql.contains("body LONGBLOB"), "{}", my.sql);
    }

    #[test]
    fn ddl_text_narrowed_only_on_mysql() {
        let src = "CREATE TABLE t (id TEXT PRIMARY KEY, name TEXT)";
        assert!(Dialect::Postgres
            .translate(src)
            .unwrap()
            .sql
            .contains("id TEXT PRIMARY KEY"));
        assert!(Dialect::Sqlite
            .translate(src)
            .unwrap()
            .sql
            .contains("id TEXT PRIMARY KEY"));
        let my = Dialect::Mysql.translate(src).unwrap();
        assert!(my.sql.contains("id VARCHAR(255) PRIMARY KEY"), "{}", my.sql);
        assert!(my.sql.contains("name VARCHAR(255)"), "{}", my.sql);
    }

    #[test]
    fn ddl_longtext_is_not_narrowed_to_varchar() {
        // A `LONGTEXT` column (a sealed secret, key line, or payload) must keep
        // an unbounded type on mysql — never `VARCHAR(255)`, which would
        // truncate a secret — and map to plain `TEXT` on postgres/sqlite. The
        // sibling bounded `TEXT` column still narrows on mysql.
        let src = "CREATE TABLE t (id TEXT PRIMARY KEY, secret_enc LONGTEXT NOT NULL)";

        let my = Dialect::Mysql.translate(src).unwrap().sql;
        assert!(my.contains("secret_enc LONGTEXT NOT NULL"), "{my}");
        assert!(
            !my.contains("secret_enc VARCHAR(255)") && !my.contains("LONGVARCHAR"),
            "a LONGTEXT secret must not be narrowed/corrupted: {my}"
        );
        // The bounded indexable column still narrows.
        assert!(my.contains("id VARCHAR(255) PRIMARY KEY"), "{my}");

        for dialect in [Dialect::Postgres, Dialect::Sqlite] {
            let out = dialect.translate(src).unwrap().sql;
            // postgres/sqlite have no LONGTEXT: postgres maps it to TEXT, sqlite
            // keeps it verbatim (TEXT affinity). Either way the secret column is
            // unbounded and never a VARCHAR.
            assert!(!out.contains("VARCHAR"), "{dialect:?}: {out}");
        }
        assert!(Dialect::Postgres
            .translate(src)
            .unwrap()
            .sql
            .contains("secret_enc TEXT NOT NULL"));
    }

    #[test]
    fn ddl_real_secret_columns_are_unbounded_on_mysql() {
        // Guard the actual migrations: every security-relevant secret/key/JSON
        // column declared LONGTEXT must translate to an unbounded mysql type,
        // never VARCHAR(255). This catches a regression where a column is
        // changed back to TEXT or a new secret column is added as TEXT.
        let mut saw_secret_enc = false;
        for migration in crate::db::MIGRATIONS {
            for stmt in crate::db::backend::split_statements(migration) {
                let my = Dialect::Mysql.translate(&stmt).unwrap().sql;
                // A corrupted stash would leave `LONGVARCHAR(255)` anywhere.
                assert!(
                    !my.contains("LONGVARCHAR"),
                    "corrupted LONGTEXT stash: {my}"
                );
                // Every column whose name ends in `secret_enc` (`secret_enc`,
                // `client_secret_enc`) must be unbounded on mysql, not a
                // truncating VARCHAR. Scan the column declaration lines.
                for line in my.lines() {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("secret_enc") || trimmed.starts_with("client_secret_enc")
                    {
                        saw_secret_enc = true;
                        assert!(
                            trimmed.contains("LONGTEXT"),
                            "a *secret_enc column must be LONGTEXT on mysql: {line:?}"
                        );
                        assert!(
                            !trimmed.contains("VARCHAR"),
                            "a *secret_enc column must not be a bounded VARCHAR: {line:?}"
                        );
                    }
                }
            }
        }
        assert!(saw_secret_enc, "expected a secret_enc column in the schema");
    }

    #[test]
    fn ddl_idtext_is_binary_collated_only_on_mysql() {
        // M-6: a security-identity `IDTEXT` column (OIDC iss/sub) must be
        // byte-exact. On mysql that means an explicit `utf8mb4_bin` collation,
        // because the server-default collation is case-insensitive and would
        // collapse case-variant identities onto one row (account takeover). On
        // postgres/sqlite `TEXT` is already case-sensitive, so `IDTEXT` is plain
        // `TEXT` with no collation clause.
        let src = "CREATE TABLE t (issuer IDTEXT NOT NULL, subject IDTEXT NOT NULL)";

        let my = Dialect::Mysql.translate(src).unwrap().sql;
        assert!(
            my.contains("issuer VARCHAR(255) COLLATE utf8mb4_bin NOT NULL"),
            "issuer must be binary-collated on mysql: {my}"
        );
        assert!(
            my.contains("subject VARCHAR(255) COLLATE utf8mb4_bin NOT NULL"),
            "subject must be binary-collated on mysql: {my}"
        );
        // The marker must never leak into emitted SQL.
        assert!(!my.contains("IDTEXT"), "IDTEXT marker leaked: {my}");

        for dialect in [Dialect::Postgres, Dialect::Sqlite] {
            let out = dialect.translate(src).unwrap().sql;
            assert!(
                out.contains("issuer TEXT NOT NULL") && out.contains("subject TEXT NOT NULL"),
                "{dialect:?}: identity columns are plain case-sensitive TEXT: {out}"
            );
            assert!(
                !out.contains("COLLATE"),
                "{dialect:?}: no collation clause: {out}"
            );
            assert!(!out.contains("IDTEXT"), "{dialect:?}: IDTEXT leaked: {out}");
        }
    }

    #[test]
    fn ddl_oidc_identity_columns_are_binary_collated_on_mysql() {
        // Guard the actual `user_identities` migration: its `issuer`/`subject`
        // OIDC columns must translate to a byte-exact mysql type so a
        // case-variant `sub` cannot collapse onto a victim's user_id (sec M-6).
        let mut saw_identity = false;
        for migration in crate::db::MIGRATIONS {
            for stmt in crate::db::backend::split_statements(migration) {
                if !stmt.contains("CREATE TABLE user_identities") {
                    continue;
                }
                saw_identity = true;
                let my = Dialect::Mysql.translate(&stmt).unwrap().sql;
                for col in ["issuer", "subject"] {
                    let line = my
                        .lines()
                        .find(|l| l.trim_start().starts_with(col))
                        .unwrap_or_else(|| panic!("no {col} column line in: {my}"));
                    assert!(
                        line.contains("COLLATE utf8mb4_bin"),
                        "user_identities.{col} must be binary-collated on mysql: {line:?}"
                    );
                }
            }
        }
        assert!(
            saw_identity,
            "expected the user_identities table in the schema"
        );
    }

    #[tokio::test]
    async fn v13_operations_migration_translates_for_every_dialect() {
        // The v13 operations migration must split and translate cleanly on
        // postgres and mysql (the dialect contract tests need a live server;
        // this is the offline translation-only smoke check).
        // v13 is the 13th migration (index 12); `.last()` now points at v14.
        let v13 = crate::db::MIGRATIONS
            .get(12)
            .expect("v13 operations migration");
        for stmt in crate::db::backend::split_statements(v13) {
            for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
                dialect
                    .translate(&stmt)
                    .unwrap_or_else(|e| panic!("v13 stmt failed for {dialect:?}: {e}\n{stmt}"));
            }
        }
        // Spot-check the org_quotas FK primary key maps to a plain column, not
        // an autoincrement (it carries an explicit value on every write).
        let create = crate::db::backend::split_statements(v13)
            .into_iter()
            .find(|s| s.contains("CREATE TABLE org_quotas"))
            .expect("org_quotas DDL present");
        let pg = Dialect::Postgres.translate(&create).unwrap().sql;
        // org_id is `INTEGER PRIMARY KEY REFERENCES`, so it follows the same
        // BIGSERIAL spelling the existing per-org tables use; the upsert always
        // supplies org_id explicitly so the serial default is never taken.
        assert!(
            pg.contains("BIGSERIAL PRIMARY KEY REFERENCES orgs(id)"),
            "{pg}"
        );
    }

    #[test]
    fn v14_repair_jobs_migration_translates_for_every_dialect() {
        // The v14 repair_jobs migration must split and translate cleanly on
        // every dialect — its column names avoid SQL reserved words and it uses
        // the standard INTEGER PRIMARY KEY / TEXT shapes.
        let v14 = crate::db::MIGRATIONS
            .get(13)
            .expect("v14 repair_jobs migration");
        for stmt in crate::db::backend::split_statements(v14) {
            for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
                dialect
                    .translate(&stmt)
                    .unwrap_or_else(|e| panic!("v14 stmt failed for {dialect:?}: {e}\n{stmt}"));
            }
        }
        let create = crate::db::backend::split_statements(v14)
            .into_iter()
            .find(|s| s.contains("CREATE TABLE repair_jobs"))
            .expect("repair_jobs DDL present");
        // The synthetic id is an autoincrement PK on every dialect.
        let pg = Dialect::Postgres.translate(&create).unwrap().sql;
        assert!(pg.contains("BIGSERIAL PRIMARY KEY"), "{pg}");
        let my = Dialect::Mysql.translate(&create).unwrap().sql;
        assert!(my.contains("BIGINT AUTO_INCREMENT PRIMARY KEY"), "{my}");
        // TEXT columns narrow to an indexable VARCHAR on mysql.
        assert!(my.contains("VARCHAR(255)"), "{my}");
        assert!(!my.contains("TEXT"), "all TEXT narrowed on mysql: {my}");
    }

    #[test]
    fn v15_change_request_columns_migration_translates_for_every_dialect() {
        // The v15 migration adds git_ref/git_commit to config_changesets via
        // plain ALTER TABLE ... ADD COLUMN ... TEXT; the column names avoid
        // reserved words and translate cleanly on every dialect.
        let v15 = crate::db::MIGRATIONS
            .get(14)
            .expect("v15 change-request columns migration");
        let stmts = crate::db::backend::split_statements(v15);
        assert_eq!(stmts.len(), 2, "two ALTER statements: {stmts:?}");
        for stmt in &stmts {
            assert!(
                stmt.contains("ALTER TABLE config_changesets ADD COLUMN"),
                "{stmt}"
            );
            for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
                dialect
                    .translate(stmt)
                    .unwrap_or_else(|e| panic!("v15 stmt failed for {dialect:?}: {e}\n{stmt}"));
            }
        }
        // The added TEXT column narrows to VARCHAR on mysql (added columns are
        // not PKs, so no autoincrement spelling is involved).
        let git_ref = stmts
            .iter()
            .find(|s| s.contains("git_ref"))
            .expect("git_ref ALTER present");
        let my = Dialect::Mysql.translate(git_ref).unwrap().sql;
        assert!(my.contains("VARCHAR(255)"), "{my}");
    }

    #[test]
    fn v16_mirror_and_frontends_migration_translates_for_every_dialect() {
        // The v16 migration adds mirror_sources, frontends, and frontend_probes.
        // Its column names (`mode`, `domain`, `verify`, `advertised`, …) avoid
        // SQL reserved-identifier hazards on every dialect, and the standard
        // INTEGER PRIMARY KEY / TEXT shapes translate cleanly.
        let v16 = crate::db::MIGRATIONS
            .get(15)
            .expect("v16 mirror/frontends migration");
        for stmt in crate::db::backend::split_statements(v16) {
            for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
                dialect
                    .translate(&stmt)
                    .unwrap_or_else(|e| panic!("v16 stmt failed for {dialect:?}: {e}\n{stmt}"));
            }
        }
        // mirror_sources keys on the registry FK (explicit value on every
        // write), so its PK maps to BIGSERIAL/BIGINT, not an autoincrement.
        let mirror = crate::db::backend::split_statements(v16)
            .into_iter()
            .find(|s| s.contains("CREATE TABLE mirror_sources"))
            .expect("mirror_sources DDL present");
        let pg = Dialect::Postgres.translate(&mirror).unwrap().sql;
        assert!(
            pg.contains("BIGSERIAL PRIMARY KEY REFERENCES registries(id)"),
            "{pg}"
        );
        // frontends has a synthetic autoincrement id on every dialect; its TEXT
        // columns (domain, mode, base_path) narrow to an indexable VARCHAR on
        // mysql so the UNIQUE(domain, base_path) index is valid.
        let frontends = crate::db::backend::split_statements(v16)
            .into_iter()
            .find(|s| s.contains("CREATE TABLE frontends"))
            .expect("frontends DDL present");
        let my = Dialect::Mysql.translate(&frontends).unwrap().sql;
        assert!(my.contains("BIGINT AUTO_INCREMENT PRIMARY KEY"), "{my}");
        assert!(my.contains("VARCHAR(255)"), "{my}");
        assert!(!my.contains("TEXT"), "all TEXT narrowed on mysql: {my}");
    }

    #[test]
    fn mysql_upsert_do_update() {
        let src =
            "INSERT INTO t (a, b) VALUES (?1, ?2) ON CONFLICT(a) DO UPDATE SET b = excluded.b";
        let my = Dialect::Mysql.translate(src).unwrap();
        assert_eq!(
            my.sql,
            "INSERT INTO t (a, b) VALUES (?, ?) ON DUPLICATE KEY UPDATE b = VALUES(b)"
        );
    }

    #[test]
    fn mysql_upsert_do_nothing() {
        let src = "INSERT INTO t (a) VALUES (?1) ON CONFLICT(a) DO NOTHING";
        let my = Dialect::Mysql.translate(src).unwrap();
        assert_eq!(my.sql, "INSERT IGNORE INTO t (a) VALUES (?)");
    }

    #[test]
    fn postgres_keeps_on_conflict() {
        let src = "INSERT INTO t (a) VALUES (?1) ON CONFLICT(a) DO NOTHING";
        let pg = Dialect::Postgres.translate(src).unwrap();
        assert!(pg.sql.contains("ON CONFLICT(a) DO NOTHING"), "{}", pg.sql);
    }
}
