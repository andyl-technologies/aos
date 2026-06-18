//! Per-dialect SQL translation for the hub's three backends.
//!
//! The hub's `Database` methods write **one** flavor of
//! SQL — the sqlite common subset, with `?N` numbered placeholders and
//! sqlite DDL types. [`Dialect::translate`] rewrites that single source form
//! into the concrete syntax each engine expects, so the methods never branch
//! on the backend. The intentional FTS divergence and the handful of upsert
//! shapes that differ between engines are isolated here (and, for upserts,
//! handled by the methods choosing a dialect-appropriate statement).
//!
//! # Placeholders
//!
//! The source uses sqlite-style numbered placeholders `?1`, `?2`, …. Each
//! dialect rewrites them and reports the *order* in which the caller's
//! parameters must be supplied:
//!
//! ```text
//! source   INSERT INTO t (a, b) VALUES (?1, ?2)
//! sqlite   INSERT INTO t (a, b) VALUES (?1, ?2)      params [p1, p2]
//! postgres INSERT INTO t (a, b) VALUES ($1, $2)      params [p1, p2]
//! mysql    INSERT INTO t (a, b) VALUES (?, ?)        params [p1, p2]
//! ```
//!
//! sqlite and postgres keep numbered placeholders, so a reused or
//! out-of-order number Just Works and [`Translated::param_order`] is the
//! identity over the distinct numbers. mysql uses positional `?`, so a reused
//! number (`… VALUES (?14, ?14)`) is emitted as two `?` and `param_order`
//! lists the source index twice — the `Backend`
//! duplicates that parameter when binding:
//!
//! ```text
//! source   VALUES (?1, ?2, ?2)
//! mysql    VALUES (?, ?, ?)     param_order [0, 1, 1]
//! ```
//!
//! # DDL type mapping
//!
//! [`Dialect::translate`] rewrites the migration DDL so one `MIGRATIONS`
//! array builds on every engine. The rules, applied to `CREATE TABLE` /
//! `ALTER TABLE` text:
//!
//! ```text
//! source                          postgres                  mysql
//! INTEGER PRIMARY KEY             BIGSERIAL PRIMARY KEY     BIGINT AUTO_INCREMENT PRIMARY KEY
//! INTEGER (bare column type)      BIGINT                    BIGINT
//! TEXT                            TEXT                      VARCHAR(255) (see note)
//! LONGTEXT                        TEXT                      LONGTEXT
//! IDTEXT                          TEXT                      VARCHAR(255) COLLATE utf8mb4_bin
//! BLOB                            BYTEA                     LONGBLOB
//! AUTOINCREMENT (sqlite-only)     (removed)                 (removed)
//! ```
//!
//! `IDTEXT` marks a **security-identity** string column — an OIDC `iss`/`sub`,
//! or any value used as an equality auth key. On mysql its default collation is
//! case-, accent-, and trailing-space-insensitive, which would collapse
//! case-variant identities onto one row and enable an account-takeover (sec
//! M-6); the explicit `utf8mb4_bin` collation forces byte-exact matching.
//! sqlite and postgres `TEXT` are already case-sensitive, so `IDTEXT` is plain
//! `TEXT` there. (EMAIL columns are deliberately *not* `IDTEXT`: emails are
//! conventionally case-insensitive and binary-collating them without
//! normalization would split one address across rows.)
//!
//! Note: mysql cannot index/PK a `TEXT` column without a prefix length, and
//! several hub tables use a `TEXT PRIMARY KEY` (`tokens.id`, `sessions.id_hash`,
//! …). The mysql translation therefore narrows `TEXT` to `VARCHAR(255)`,
//! which is ample for the hub's hex hashes, slugs, and UUIDs and is indexable.
//! On postgres and sqlite `TEXT` is unbounded and kept verbatim.
//!
//! `VARCHAR(255)` would, however, **silently truncate** a value longer than 255
//! characters on mysql — which for a sealed secret, a public-key line, a JSON
//! array, or a webhook payload would corrupt the value and break decryption or
//! signature verification. Such columns are declared `LONGTEXT` in the source
//! DDL: an unbounded text type that is never indexed and so never needs a
//! bounded `VARCHAR`. `LONGTEXT` maps to mysql `LONGTEXT`, to postgres `TEXT`
//! (which has no `LONGTEXT` and is already unbounded), and is kept verbatim on
//! sqlite (where it has plain `TEXT` affinity). The `TEXT -> VARCHAR(255)`
//! narrowing is careful not to rewrite the `TEXT` *inside* `LONGTEXT`.
//!
//! # DML divergences not handled by `translate`
//!
//! Two shapes differ enough that the methods select a dialect-specific
//! statement rather than relying on a textual rewrite (the rewrite would be
//! fragile):
//!
//! - **Upserts.** `INSERT … ON CONFLICT(col) DO UPDATE/NOTHING` is native on
//!   sqlite and postgres; mysql spells it `ON DUPLICATE KEY UPDATE` /
//!   `INSERT IGNORE`. `translate` rewrites the common single-target cases it
//!   can recognize (the private `rewrite_upsert` step); methods with more
//!   elaborate upserts pass already-appropriate SQL.
//! - **`RETURNING`.** Supported by sqlite and postgres and by mysql for the
//!   `DELETE … RETURNING` and `UPDATE … RETURNING` the hub uses (MariaDB) —
//!   but the pure-Rust `mysql` crate targets MySQL, which lacks
//!   `UPDATE … RETURNING`. Those two methods fall back to a select-then-write
//!   on mysql (see `consume_magic_link` / `take_oidc_flow`).

use anyhow::Result;

use crate::value::Value;

/// The SQL engine a `Backend` drives.
///
/// `Dialect` carries no connection; it is the pure translation half of the
/// abstraction and is cheap to copy and pass around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// SQLite (and its Cloudflare D1 twin) — the source dialect.
    Sqlite,
    /// PostgreSQL.
    Postgres,
    /// MySQL.
    Mysql,
}

/// A source statement rewritten for one [`Dialect`].
///
/// `sql` is the engine-specific statement; `param_order` lists, for each
/// positional placeholder in `sql` left-to-right, the zero-based index into
/// the caller's parameter slice that fills it. For sqlite and postgres the
/// placeholders stay numbered, so `param_order` is `[0, 1, …]` over the
/// distinct numbers and binding uses the caller's slice directly.
#[derive(Debug, Clone, PartialEq)]
pub struct Translated {
    /// The engine-specific statement text.
    pub sql: String,
    /// Source-parameter index for each positional placeholder, in order.
    pub param_order: Vec<usize>,
}

impl Dialect {
    /// Translates a source (sqlite-flavored) statement into this dialect.
    ///
    /// Rewrites placeholders and DDL types per the [module rules](self), and
    /// rewrites the recognizable `ON CONFLICT` upsert forms for mysql. The
    /// returned [`Translated::param_order`] tells the backend how to lay out
    /// the bound parameters (it matters only for mysql's positional `?`).
    ///
    /// # Errors
    ///
    /// This implementation is infallible today; the `Result` leaves room for
    /// a future dialect to reject an unrepresentable construct without a
    /// breaking signature change.
    pub fn translate(self, sql: &str) -> Result<Translated> {
        let sql = match self {
            Dialect::Mysql => self.rewrite_upsert(sql),
            // sqlite and postgres share ON CONFLICT, so no upsert rewrite.
            _ => sql.to_string(),
        };
        let sql = self.rewrite_ddl_types(&sql);
        let sql = self.quote_reserved(&sql);
        Ok(self.rewrite_placeholders(&sql))
    }

    /// Quotes the one hub column whose name collides with a SQL reserved word.
    ///
    /// `channel_partitions.release` clashes with `RELEASE` (a reserved
    /// keyword on postgres and mysql). The source SQL writes the bare
    /// identifier `release`; this wraps each standalone occurrence in the
    /// dialect's identifier quote — `"release"` on postgres, `` `release` ``
    /// on mysql — while leaving the unrelated `releases` table untouched (the
    /// trailing `s` is not a word boundary). sqlite tolerates the bare name,
    /// so it is left unquoted there.
    fn quote_reserved(self, sql: &str) -> String {
        let (open, close) = match self {
            Dialect::Sqlite => return sql.to_string(),
            Dialect::Postgres => ('"', '"'),
            Dialect::Mysql => ('`', '`'),
        };
        replace_word(sql, "release", &format!("{open}release{close}"))
    }

    /// Rewrites `?N` placeholders for this dialect, returning the parameter
    /// order.
    fn rewrite_placeholders(self, sql: &str) -> Translated {
        let mut out = String::with_capacity(sql.len());
        let mut order = Vec::new();
        let mut chars = sql.char_indices().peekable();
        while let Some((_, c)) = chars.next() {
            if c == '?' {
                // Collect the following digit run.
                let mut digits = String::new();
                while let Some(&(_, d)) = chars.peek() {
                    if d.is_ascii_digit() {
                        digits.push(d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if digits.is_empty() {
                    // A bare `?` (not used by the hub source, but pass through).
                    out.push('?');
                    continue;
                }
                let n: usize = digits.parse().unwrap_or(1);
                let src_idx = n - 1;
                match self {
                    Dialect::Sqlite => {
                        out.push('?');
                        out.push_str(&digits);
                    }
                    Dialect::Postgres => {
                        out.push('$');
                        out.push_str(&digits);
                    }
                    Dialect::Mysql => out.push('?'),
                }
                order.push(src_idx);
            } else {
                out.push(c);
            }
        }
        Translated {
            sql: out,
            param_order: order,
        }
    }

    /// Rewrites sqlite DDL column types for this dialect.
    ///
    /// A no-op for [`Dialect::Sqlite`]. For postgres and mysql it maps the
    /// autoincrement primary key, the bare `INTEGER`, and `BLOB` per the
    /// [module rules](self), and narrows `TEXT` to an indexable `VARCHAR` on
    /// mysql.
    fn rewrite_ddl_types(self, sql: &str) -> String {
        if self == Dialect::Sqlite {
            // sqlite is the source dialect; it keeps `LONGTEXT` verbatim (plain
            // TEXT affinity). It does not know the `IDTEXT` security-identity
            // marker (see the mysql/postgres branch), and its `TEXT` is already
            // case-sensitive (byte-exact), so map `IDTEXT` to plain `TEXT` for a
            // clean on-disk schema.
            return sql.replace("IDTEXT", "TEXT");
        }
        // Order matters: the autoincrement PK must be matched before the bare
        // INTEGER rule, and AUTOINCREMENT removed regardless.
        let pk = match self {
            Dialect::Postgres => "BIGSERIAL PRIMARY KEY",
            Dialect::Mysql => "BIGINT AUTO_INCREMENT PRIMARY KEY",
            Dialect::Sqlite => unreachable!(),
        };
        let mut s = sql.replace("INTEGER PRIMARY KEY", pk);
        // Strip the sqlite-only AUTOINCREMENT keyword (the PK rule already
        // supplied the engine's own auto-increment spelling).
        s = s.replace(" AUTOINCREMENT", "");
        // Bare INTEGER -> BIGINT. After the PK replacement no `INTEGER PRIMARY
        // KEY` remains, so any leftover INTEGER is a plain column/reference.
        s = s.replace("INTEGER", "BIGINT");
        // `LONGTEXT` is the source marker for an *unbounded* text column — a
        // sealed secret, a public-key line, a JSON array, or a webhook payload —
        // that must never be silently truncated. It is never indexed, so it does
        // not need a bounded VARCHAR. Stash it behind a sentinel so the generic
        // `TEXT -> VARCHAR(255)` narrowing below cannot rewrite the `TEXT`
        // *inside* `LONGTEXT`, then restore it to the dialect's unbounded type.
        // The sentinel must not itself contain the substring `TEXT`, or the
        // narrowing below would rewrite it to `VARCHAR(255)` and the restore
        // would no longer match. Use null-byte delimiters around a `TEXT`-free
        // token (null can never appear in the source DDL).
        const LONGTEXT_SENTINEL: &str = "\u{0}LONG_UNBOUNDED\u{0}";
        s = s.replace("LONGTEXT", LONGTEXT_SENTINEL);
        // `IDTEXT` is the source marker for a *security-identity* string column
        // — an OIDC `iss`/`sub`, or any value used as an equality auth key. On
        // mysql the default collation (`utf8mb4_general_ci` / `*_0900_ai_ci`) is
        // case-, accent-, and trailing-space-insensitive, so `Alice`, `alice`,
        // and `alice ` collapse to one key in a `WHERE issuer=? AND subject=?`
        // lookup and the composite PK. OIDC `sub` is case-sensitive per spec and
        // is never normalized here, so on mysql an attacker who can assert a
        // case-variant `sub` from the same trusted IdP would resolve to a
        // victim's `user_id` and log in as them (sec M-6). Declaring these
        // columns with the byte-exact `utf8mb4_bin` collation forces
        // exact-byte matching, restoring the case-sensitive behavior sqlite and
        // postgres already have. Stash behind a sentinel (TEXT-free, null
        // delimited) so the generic `TEXT -> VARCHAR(255)` narrowing below does
        // not rewrite the `TEXT` *inside* `IDTEXT`.
        //
        // NOTE: do **not** apply binary collation to EMAIL columns — emails are
        // conventionally case-insensitive and are not normalized consistently
        // here; binary-collating them without normalizing would split a single
        // address across rows. Email collation is tracked separately (M-7) and
        // its takeover arm is gated by verified-domain checks.
        const IDTEXT_SENTINEL: &str = "\u{0}ID_BINARY\u{0}";
        s = s.replace("IDTEXT", IDTEXT_SENTINEL);
        let mut s = match self {
            Dialect::Postgres => s.replace("BLOB", "BYTEA"),
            // mysql: narrow only the *bounded, indexable* `TEXT` columns (hex
            // hashes, slugs, UUIDs, key ids — all well under 255) to an
            // indexable `VARCHAR(255)`, because mysql cannot PK/index a `TEXT`
            // without a prefix length. The `LONGTEXT` columns are exempt (stashed
            // above) so a long secret/key/payload is stored intact rather than
            // truncated to 255 chars, which would corrupt a sealed secret or a
            // public key and break decryption/verification.
            Dialect::Mysql => s
                .replace("BLOB", "LONGBLOB")
                .replace("TEXT", "VARCHAR(255)"),
            Dialect::Sqlite => unreachable!(),
        };
        // Restore the unbounded text type: `LONGTEXT` on mysql, plain `TEXT` on
        // postgres (which has no `LONGTEXT` and whose `TEXT` is already
        // unbounded).
        let unbounded = match self {
            Dialect::Mysql => "LONGTEXT",
            Dialect::Postgres => "TEXT",
            Dialect::Sqlite => unreachable!(),
        };
        s = s.replace(LONGTEXT_SENTINEL, unbounded);
        // Restore the security-identity text type. Only mysql needs an explicit
        // collation; on postgres a plain (case-sensitive) `TEXT` is already
        // byte-exact for these columns.
        let identity = match self {
            Dialect::Mysql => "VARCHAR(255) COLLATE utf8mb4_bin",
            Dialect::Postgres => "TEXT",
            Dialect::Sqlite => unreachable!(),
        };
        s = s.replace(IDTEXT_SENTINEL, identity);
        s
    }

    /// Rewrites the recognizable sqlite/postgres `ON CONFLICT` upserts into
    /// mysql's `ON DUPLICATE KEY UPDATE` / `INSERT IGNORE`.
    ///
    /// Handles the two shapes the hub writes:
    ///
    /// - `INSERT … ON CONFLICT(<cols>) DO NOTHING` → `INSERT IGNORE …`
    /// - `INSERT … ON CONFLICT(<cols>) DO UPDATE SET <a> = excluded.<x>, …`
    ///   → `INSERT … ON DUPLICATE KEY UPDATE <a> = VALUES(<x>), …`
    ///
    /// `excluded.<col>` (the postgres/sqlite name for the would-be-inserted
    /// row) becomes mysql's `VALUES(<col>)`. Statements without an
    /// `ON CONFLICT` clause pass through untouched.
    fn rewrite_upsert(self, sql: &str) -> String {
        debug_assert_eq!(self, Dialect::Mysql);
        let Some(pos) = find_keyword(sql, "ON CONFLICT") else {
            return sql.to_string();
        };
        let head = &sql[..pos];
        let rest = &sql[pos..];
        // Skip past the conflict-target parenthesis: ON CONFLICT(...) or
        // ON CONFLICT (...).
        let after_target = match rest.find(')') {
            Some(p) => &rest[p + 1..],
            None => rest,
        };
        let after_target = after_target.trim_start();
        if let Some(do_update) = strip_prefix_ci(after_target, "DO UPDATE SET") {
            let assignments = do_update.trim();
            // excluded.col -> VALUES(col)
            let rewritten = rewrite_excluded(assignments);
            // INSERT IGNORE is not needed; ON DUPLICATE KEY UPDATE.
            format!("{} ON DUPLICATE KEY UPDATE {rewritten}", head.trim_end())
        } else if strip_prefix_ci(after_target, "DO NOTHING").is_some() {
            // INSERT IGNORE INTO … — splice IGNORE after the leading INSERT.
            let head = head.trim_end();
            let body = strip_prefix_ci(head.trim_start(), "INSERT").unwrap_or(head);
            format!("INSERT IGNORE{body}")
        } else {
            // Unrecognized; leave as-is (will surface as a SQL error if hit).
            sql.to_string()
        }
    }
}

/// Replaces every whole-word, case-sensitive occurrence of `word` in `sql`
/// with `repl`.
///
/// A match is a run of `word` bounded on both sides by a non-identifier
/// character (or a string boundary), so `release` in `channel_partitions`'
/// column list is replaced but `releases` (the table) and `release_id` are
/// not.
fn replace_word(sql: &str, word: &str, repl: &str) -> String {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < bytes.len() {
        if sql[i..].starts_with(word) {
            let before_ok = i == 0 || !is_ident(sql[..i].chars().next_back().unwrap_or(' '));
            let after = i + word.len();
            let after_ok =
                after >= bytes.len() || !is_ident(sql[after..].chars().next().unwrap_or(' '));
            if before_ok && after_ok {
                out.push_str(repl);
                i = after;
                continue;
            }
        }
        let ch = sql[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Rewrites every `excluded.<ident>` reference to mysql's `VALUES(<ident>)`.
fn rewrite_excluded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if s[i..].len() >= 9 && s[i..i + 9].eq_ignore_ascii_case("excluded.") {
            i += 9;
            // Capture the identifier following the dot.
            let start = i;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c.is_alphanumeric() || c == '_' {
                    i += 1;
                } else {
                    break;
                }
            }
            let ident = &s[start..i];
            out.push_str("VALUES(");
            out.push_str(ident);
            out.push(')');
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Case-insensitively finds a keyword at a word-ish boundary in `sql`.
fn find_keyword(sql: &str, kw: &str) -> Option<usize> {
    let lower = sql.to_ascii_lowercase();
    let kw = kw.to_ascii_lowercase();
    lower.find(&kw)
}

/// Strips a case-insensitive prefix and the single space after it, if present.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Reorders a source parameter slice according to a [`Translated::param_order`].
///
/// For sqlite and postgres the order is the ascending distinct numbers and
/// the result equals the input; for mysql it expands reused placeholders by
/// repeating the source value. Returns owned [`Value`]s ready to bind.
#[must_use]
pub fn order_params(params: &[Value], order: &[usize]) -> Vec<Value> {
    order
        .iter()
        .map(|&i| params.get(i).cloned().unwrap_or(Value::Null))
        .collect()
}
