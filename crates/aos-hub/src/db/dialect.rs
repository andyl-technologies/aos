//! Per-dialect SQL translation, re-exported from [`aos_hub_core::dialect`].
//!
//! The translation logic moved to the runtime-agnostic core crate (RFC-0004
//! Phase 5) so the Cloudflare Worker's HubDb backend can share it; this re-export
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
    fn mysql_quotes_rate_limit_reserved_identifiers() {
        let source = "CREATE TABLE rate_limits(\
                      class TEXT NOT NULL,\
                      key TEXT NOT NULL,\
                      window INTEGER NOT NULL,\
                      PRIMARY KEY(class, key, window),\
                      note TEXT DEFAULT 'key window',\
                      window_name TEXT\
                      )";

        let translated = Dialect::Mysql.translate(source).unwrap().sql;
        assert!(translated.contains("`key` VARCHAR(255) NOT NULL"));
        assert!(translated.contains("`window` BIGINT NOT NULL"));
        assert!(translated.contains("PRIMARY KEY(class, `key`, `window`)"));
        assert!(translated.contains("DEFAULT 'key window'"));
        assert!(translated.contains("window_name VARCHAR(255)"));
    }

    #[test]
    fn postgres_quotes_rate_limit_window_identifier() {
        let translated = Dialect::Postgres
            .translate("CREATE TABLE rate_limits(window INTEGER, key TEXT)")
            .unwrap()
            .sql;
        assert_eq!(
            translated,
            "CREATE TABLE rate_limits(\"window\" BIGINT, key TEXT)"
        );
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
    fn ddl_autoincrement_phrase_rewrite_skips_non_executable_text() {
        let src = "CREATE TABLE t (\
                   id INTEGER PRIMARY KEY, \
                   spaced INTEGER\n PRIMARY\tKEY, \
                   near INTEGER PRIMARY KEYED, \
                   literal TEXT DEFAULT 'INTEGER PRIMARY KEY', \
                   escaped TEXT DEFAULT 'INTEGER PRIMARY KEY''INTEGER PRIMARY KEY', \
                   \"INTEGER PRIMARY KEY\" TEXT, \
                   `INTEGER PRIMARY KEY` TEXT, \
                   [INTEGER PRIMARY KEY] TEXT \
                   /* INTEGER PRIMARY KEY */); -- INTEGER PRIMARY KEY";

        for (dialect, primary_key) in [
            (Dialect::Postgres, "BIGSERIAL PRIMARY KEY"),
            (Dialect::Mysql, "BIGINT AUTO_INCREMENT PRIMARY KEY"),
        ] {
            let sql = dialect.translate(src).unwrap().sql;
            assert!(
                sql.contains(&format!("id {primary_key}")),
                "{dialect:?}: {sql}"
            );
            assert!(
                sql.contains(&format!("spaced {primary_key}")),
                "{dialect:?}: variable whitespace was not recognized: {sql}"
            );
            assert!(
                sql.contains("near BIGINT PRIMARY KEYED"),
                "{dialect:?}: a longer token was mistaken for PRIMARY KEY: {sql}"
            );
            for untouched in [
                "'INTEGER PRIMARY KEY'",
                "'INTEGER PRIMARY KEY''INTEGER PRIMARY KEY'",
                "\"INTEGER PRIMARY KEY\"",
                "`INTEGER PRIMARY KEY`",
                "[INTEGER PRIMARY KEY]",
                "/* INTEGER PRIMARY KEY */",
                "-- INTEGER PRIMARY KEY",
            ] {
                assert!(
                    sql.contains(untouched),
                    "{dialect:?}: protected text {untouched:?} was rewritten: {sql}"
                );
            }
        }
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
    fn mysql_longtext_defaults_use_expression_syntax() {
        for migration in crate::db::MIGRATIONS {
            for line in migration.lines().filter(|line| line.contains("LONGTEXT")) {
                if let Some((_, default)) = line.split_once("DEFAULT") {
                    assert!(
                        default.trim_start().starts_with('('),
                        "MySQL 8.0.16 requires LONGTEXT defaults as expressions: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn ddl_idtext_is_binary_collated_only_on_mysql() {
        // M-6: a security-identity `IDTEXT` column (OIDC iss/sub) must be
        // byte-exact. MySQL-family default collations are case-insensitive and
        // may collapse a trailing-space variant, so use a binary string on
        // that dialect. On postgres/sqlite `TEXT` is already case-sensitive.
        let src = "CREATE TABLE t (issuer IDTEXT NOT NULL, subject IDTEXT NOT NULL)";

        let my = Dialect::Mysql.translate(src).unwrap().sql;
        assert!(
            my.contains("issuer VARBINARY(255) NOT NULL"),
            "issuer must be byte-exact on mysql: {my}"
        );
        assert!(
            my.contains("subject VARBINARY(255) NOT NULL"),
            "subject must be byte-exact on mysql: {my}"
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
    fn ddl_keytext_is_bounded_and_binary_collated_on_every_dialect() {
        let capacities = [32, 64, 128, 255, 512, 1024];
        let src = "CREATE TABLE t (k32 KEYTEXT32, k64 KEYTEXT64, \
                   k128 KEYTEXT128, k255 KEYTEXT255, k512 KEYTEXT512, \
                   k1024 KEYTEXT1024)";

        let sqlite = Dialect::Sqlite.translate(src).unwrap().sql;
        let postgres = Dialect::Postgres.translate(src).unwrap().sql;
        let mysql = Dialect::Mysql.translate(src).unwrap().sql;

        for (column, capacity) in ["k32", "k64", "k128", "k255", "k512", "k1024"]
            .into_iter()
            .zip(capacities)
        {
            assert!(
                sqlite.contains(&format!("{column} TEXT COLLATE BINARY")),
                "{column} must use SQLite's bytewise collation: {sqlite}"
            );
            assert!(
                postgres.contains(&format!("{column} VARCHAR({capacity}) COLLATE \"C\"")),
                "{column} must use postgres's deterministic C collation: {postgres}"
            );
            assert!(
                mysql.contains(&format!("{column} VARBINARY({capacity})")),
                "{column} must use mysql's byte-exact binary type: {mysql}"
            );
        }

        for (dialect, sql) in [
            (Dialect::Sqlite, sqlite),
            (Dialect::Postgres, postgres),
            (Dialect::Mysql, mysql),
        ] {
            assert!(
                !sql.contains("KEYTEXT") && !sql.contains("KEY_EXACT"),
                "{dialect:?}: KEYTEXT marker or sentinel leaked: {sql}"
            );
        }
    }

    #[test]
    fn mysql_topology_ddl_preserves_the_minimum_version_contract() {
        // Supported MySQL-family servers must enforce CHECK constraints; the
        // binary key type itself works consistently on MySQL and MariaDB.
        let sql = Dialect::Mysql
            .translate("CREATE TABLE t (kind KEYTEXT32 NOT NULL, CHECK (kind IN ('a', 'b')))")
            .unwrap()
            .sql;

        assert!(
            sql.contains("VARBINARY(32)"),
            "topology keys require byte-exact MySQL storage: {sql}"
        );
        assert!(
            sql.contains("CHECK (kind IN ('a', 'b'))"),
            "topology integrity depends on enforced CHECK constraints: {sql}"
        );
    }

    #[test]
    fn mysql_indexes_unbounded_consumer_cache_urls_by_digest() {
        let source = "CREATE TABLE consumer_cache_publication_intents(\
                      change_id KEYTEXT64 NOT NULL,\
                      committed_url LONGTEXT NOT NULL,\
                      PRIMARY KEY(change_id, committed_url)\
                      )";

        let translated = Dialect::Mysql.translate(source).unwrap().sql;
        assert!(translated.contains("committed_url LONGTEXT NOT NULL"));
        assert!(translated.contains(
            "committed_url_digest BINARY(32) GENERATED ALWAYS AS \
             (UNHEX(SHA2(committed_url, 256))) STORED"
        ));
        assert!(translated.contains("UNIQUE(change_id, committed_url_digest)"));
        assert!(!translated.contains("PRIMARY KEY(change_id, committed_url)"));

        let insert = Dialect::Mysql
            .translate(
                "INSERT INTO consumer_cache_publication_intents \
                 (change_id, committed_url) VALUES (?1, ?2) \
                 ON CONFLICT(change_id, committed_url) DO NOTHING",
            )
            .unwrap()
            .sql;
        assert_eq!(
            insert,
            "INSERT IGNORE INTO consumer_cache_publication_intents \
             (change_id, committed_url) VALUES (?, ?)"
        );
    }

    #[test]
    fn ddl_keytext_rewrite_skips_non_type_tokens() {
        let src = "CREATE TABLE t (actual KEYTEXT64, KEYTEXT640 TEXT, \
                   prefix_KEYTEXT64 TEXT, KEYTEXT64_suffix TEXT, \
                   literal TEXT DEFAULT 'KEYTEXT64', \
                   escaped TEXT DEFAULT 'KEYTEXT64''KEYTEXT32', \
                   \"KEYTEXT64\" TEXT, `KEYTEXT64` TEXT, [KEYTEXT64] TEXT \
                   /* KEYTEXT64 block comment */); -- KEYTEXT64 line comment";

        for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
            let sql = dialect.translate(src).unwrap().sql;
            assert!(
                !sql.contains("actual KEYTEXT64"),
                "{dialect:?}: the actual type marker must be translated: {sql}"
            );
            for untouched in [
                "KEYTEXT640",
                "prefix_KEYTEXT64",
                "KEYTEXT64_suffix",
                "'KEYTEXT64'",
                "'KEYTEXT64''KEYTEXT32'",
                "\"KEYTEXT64\"",
                "`KEYTEXT64`",
                "[KEYTEXT64]",
                "/* KEYTEXT64 block comment */",
                "-- KEYTEXT64 line comment",
            ] {
                assert!(
                    sql.contains(untouched),
                    "{dialect:?}: non-type token {untouched:?} was rewritten: {sql}"
                );
            }
        }
    }

    #[test]
    fn topology_v34_keytext_translates_without_leaks_and_fits_mysql_indexes() {
        const BIGINT_INDEX_BYTES: usize = 8;
        const INNODB_MAX_INDEX_BYTES: usize = 3_072;

        let v34 = crate::db::MIGRATIONS
            .iter()
            .find(|migration| {
                migration.contains("CREATE TABLE registry_publications")
                    && migration.contains("CREATE TABLE surface_placements")
                    && migration.contains("KEYTEXT512")
            })
            .expect("v34 topology migration");
        let statements = crate::db::backend::split_statements(v34);
        assert!(!statements.is_empty(), "v34 must contain executable DDL");

        for statement in &statements {
            for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
                let sql = dialect.translate(statement).unwrap().sql;
                assert!(
                    !sql.contains("KEYTEXT") && !sql.contains("KEY_EXACT"),
                    "v34 marker leaked for {dialect:?}: {sql}"
                );
            }
        }

        let release_artifacts = statements
            .iter()
            .find(|statement| statement.contains("CREATE TABLE release_artifacts"))
            .expect("release_artifacts DDL");
        let release_mysql = Dialect::Mysql.translate(release_artifacts).unwrap().sql;
        for declaration in [
            "package_name VARBINARY(128)",
            "package_version VARBINARY(64)",
            "platform VARBINARY(64)",
            "artifact_kind VARBINARY(32)",
            "store_hash VARBINARY(64)",
        ] {
            assert!(release_mysql.contains(declaration), "{release_mysql}");
        }
        let release_index_bytes = 128 + 64 + 64 + 32 + 64 + BIGINT_INDEX_BYTES;
        assert_eq!(release_index_bytes, 360);
        assert!(release_index_bytes <= INNODB_MAX_INDEX_BYTES);

        let root_reasons = statements
            .iter()
            .find(|statement| statement.contains("CREATE TABLE cache_root_reasons"))
            .expect("cache_root_reasons DDL");
        let roots_mysql = Dialect::Mysql.translate(root_reasons).unwrap().sql;
        for declaration in [
            "store_hash VARBINARY(64)",
            "source_kind VARBINARY(32)",
            "source_ref VARBINARY(255)",
        ] {
            assert!(roots_mysql.contains(declaration), "{roots_mysql}");
        }
        let roots_index_bytes = 64 + 32 + 255 + BIGINT_INDEX_BYTES;
        assert_eq!(roots_index_bytes, 359);
        assert!(roots_index_bytes <= INNODB_MAX_INDEX_BYTES);
    }

    #[test]
    fn oci_catalog_ddl_translates_without_markers_and_fits_mysql_indexes() {
        const BIGINT_INDEX_BYTES: usize = 8;
        const INNODB_MAX_INDEX_BYTES: usize = 3_072;

        let oci = crate::db::MIGRATIONS
            .iter()
            .find(|migration| {
                migration.contains("CREATE TABLE oci_repositories")
                    && migration.contains("CREATE TABLE oci_gc_generations")
            })
            .expect("OCI catalog migration");
        let statements = crate::db::backend::split_statements(oci);
        assert!(!statements.is_empty(), "OCI migration must contain DDL");

        for statement in &statements {
            for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
                let sql = dialect.translate(statement).unwrap().sql;
                assert!(
                    !sql.contains("KEYTEXT"),
                    "OCI marker leaked for {dialect:?}: {sql}"
                );
                if dialect == Dialect::Postgres {
                    assert!(!sql.contains("LONGTEXT"), "{sql}");
                }
                if dialect == Dialect::Mysql {
                    assert!(!sql.contains("LONGVARCHAR"), "{sql}");
                }
            }
        }

        let repositories = statements
            .iter()
            .find(|statement| statement.contains("CREATE TABLE oci_repositories"))
            .expect("OCI repository DDL");
        let repositories_mysql = Dialect::Mysql.translate(repositories).unwrap().sql;
        assert!(
            repositories_mysql.contains("name VARBINARY(255)"),
            "{repositories_mysql}"
        );
        let repository_unique_bytes = BIGINT_INDEX_BYTES + 255;
        assert!(repository_unique_bytes <= INNODB_MAX_INDEX_BYTES);

        let release_roots = statements
            .iter()
            .find(|statement| statement.contains("CREATE TABLE oci_release_roots"))
            .expect("OCI release-root DDL");
        let release_roots_mysql = Dialect::Mysql.translate(release_roots).unwrap().sql;
        for declaration in [
            "release_id BIGINT NOT NULL",
            "release_tag VARBINARY(255)",
            "container_name VARBINARY(128)",
        ] {
            assert!(
                release_roots_mysql.contains(declaration),
                "{release_roots_mysql}"
            );
        }
        let release_roots_mysql_compact = release_roots_mysql
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            release_roots_mysql_compact.contains(
                "FOREIGN KEY(release_id, registry_id) REFERENCES releases(id, registry_id)"
            ),
            "release roots must use the pre-v20 numeric release identity: {release_roots_mysql}"
        );
        assert!(
            !release_roots_mysql_compact.contains(
                "FOREIGN KEY(registry_id, release_tag) REFERENCES releases(registry_id, semver)"
            ),
            "v20 must not require a new physical type for legacy releases.semver: {release_roots_mysql}"
        );
        let release_root_primary_bytes = BIGINT_INDEX_BYTES + 255 + BIGINT_INDEX_BYTES + 128;
        assert!(release_root_primary_bytes <= INNODB_MAX_INDEX_BYTES);
    }

    #[test]
    fn fresh_mysql_release_identity_is_byte_exact_and_legacy_shape_is_frozen() {
        let baseline = crate::db::MIGRATIONS
            .first()
            .expect("hard-cutover baseline migration");
        let statements = crate::db::backend::split_statements(baseline);

        let releases = statements
            .iter()
            .find(|statement| statement.contains("CREATE TABLE releases"))
            .expect("legacy releases DDL");
        let releases_mysql = Dialect::Mysql.translate(releases).unwrap().sql;
        assert!(
            releases_mysql.contains("semver VARBINARY(255) NOT NULL"),
            "fresh release identities must remain byte-exact: {releases_mysql}"
        );

        let legacy = Dialect::Mysql
            .translate(
                "CREATE TABLE releases(\
                 id INTEGER PRIMARY KEY,\
                 registry_id INTEGER NOT NULL,\
                 semver TEXT NOT NULL,\
                 UNIQUE(registry_id, semver))",
            )
            .unwrap()
            .sql;
        assert!(
            legacy.contains("semver VARCHAR(255) NOT NULL"),
            "the frozen v19 release key must remain reproducible: {legacy}"
        );
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
                        line.contains("VARBINARY(255)"),
                        "user_identities.{col} must be byte-exact on mysql: {line:?}"
                    );
                }
            }
        }
        assert!(
            saw_identity,
            "expected the user_identities table in the schema"
        );
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
