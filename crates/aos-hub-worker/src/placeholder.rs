//! Placeholder translation for the Durable Object SQLite backend.
//!
//! This module owns [`numbered_to_positional`], the pure SQL/parameter rewrite
//! the [`SqlDoBackend`](crate::sqldobackend::SqlDoBackend) applies before handing
//! a statement to the DO's local SQLite engine. It is deliberately free of any
//! `worker`/wasm dependency so it compiles — and is unit-tested — on the native
//! target too, where the rest of the worker glue is `wasm32`-only.
//!
//! # Why a translation is needed
//!
//! Durable Object SQLite's `exec` binds variadic values **positionally** to
//! anonymous `?` placeholders; it does not honor sqlite's numbered `?N` binding,
//! and it corrupts a bound `NULL` (storing it as the JavaScript string
//! `"[object Object]"`). The hub's shared SQL uses numbered `?N` placeholders and
//! binds `None` columns as `NULL`, so this rewrite adapts both for the DO engine
//! while keeping that shared SQL the single source of truth.
//!
//! ```text
//! "… WHERE a = ?1 AND b = ?2", [Int(7), Null]
//!   ->  "… WHERE a = ? AND b = NULL", [Int(7)]
//! ```

use aos_hub_core::value::Value;

/// Rewrites numbered sqlite placeholders (`?1`, `?2`, …) to **anonymous
/// positional** `?` and returns the parameter list in appearance order, while
/// **inlining any `NULL` parameter as a literal `NULL` token**.
///
/// Durable Object SQLite's `exec` binds variadic values **positionally** to `?`
/// placeholders; it does not honor sqlite's numbered `?N` binding (a `?N` query
/// silently fails to bind, so a `WHERE col = ?1` matches nothing — the bug that
/// 404'd nested registries and broke sign-in). This expands the caller's
/// `?N`-numbered params (which the hub's SQL uses, and which `prepare(Sqlite)`
/// preserves) into the per-appearance order DO SQLite needs, duplicating a
/// reused `?N`. `?N` tokens inside single-quoted string literals are left alone.
///
/// # The `NULL`-binding corruption
///
/// A bound `null` value crossing into the DO engine through worker-rs's variadic
/// `exec` is **not** stored as SQL `NULL`: it lands as the JavaScript string
/// `"[object Object]"`, so nullable topology values read back as text and fail
/// typed row mapping. A SQL-literal `NULL` stores
/// correctly (`typeof` reports `null`), so this emits `NULL` directly into the
/// SQL for any [`Value::Null`] parameter and omits it from the binding list,
/// keeping the remaining `?` placeholders aligned with the remaining bindings.
/// Non-`NULL` parameters are unaffected.
///
/// # Examples
///
/// ```no_run
/// # use aos_hub_core::value::Value;
/// # use aos_hub_worker::placeholder::numbered_to_positional;
/// let (sql, params) =
///     numbered_to_positional("SELECT * FROM t WHERE a = ?1 AND b = ?2", &[Value::Int(7), Value::Null]);
/// assert_eq!(sql, "SELECT * FROM t WHERE a = ? AND b = NULL");
/// assert_eq!(params, vec![Value::Int(7)]);
/// ```
#[must_use]
pub fn numbered_to_positional(sql: &str, params: &[Value]) -> (String, Vec<Value>) {
    let mut out = String::with_capacity(sql.len());
    let mut bound = Vec::new();
    let mut chars = sql.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\'' {
                in_string = false;
            }
            continue;
        }
        match c {
            '\'' => {
                in_string = true;
                out.push(c);
            }
            '?' if chars.peek().is_some_and(|d| d.is_ascii_digit()) => {
                let mut n = 0usize;
                while let Some(d) = chars.peek().and_then(|d| d.to_digit(10)) {
                    n = n * 10 + d as usize;
                    chars.next();
                }
                match n.checked_sub(1).and_then(|i| params.get(i)) {
                    // A bound `NULL` is corrupted by the DO `exec` binding path
                    // (stored as `"[object Object]"`), so inline it as a literal
                    // `NULL` token and bind nothing for this placeholder.
                    Some(Value::Null) => out.push_str("NULL"),
                    Some(p) => {
                        out.push('?');
                        bound.push(p.clone());
                    }
                    // An out-of-range `?N` (no matching param) keeps the `?` so
                    // the engine reports the arity mismatch rather than silently
                    // shifting the remaining bindings.
                    None => out.push('?'),
                }
            }
            _ => out.push(c),
        }
    }
    (out, bound)
}

#[cfg(test)]
mod tests {
    use super::numbered_to_positional;
    use aos_hub_core::value::Value;

    #[test]
    fn expands_numbered_to_positional_in_order() {
        let (sql, params) = numbered_to_positional(
            "SELECT * FROM t WHERE a = ?1 AND b = ?2",
            &[Value::Int(1), Value::Text("x".into())],
        );
        assert_eq!(sql, "SELECT * FROM t WHERE a = ? AND b = ?");
        assert_eq!(params, vec![Value::Int(1), Value::Text("x".into())]);
    }

    #[test]
    fn duplicates_a_reused_numbered_placeholder() {
        let (sql, params) =
            numbered_to_positional("VALUES (?1, ?1, ?2)", &[Value::Int(9), Value::Int(8)]);
        assert_eq!(sql, "VALUES (?, ?, ?)");
        assert_eq!(params, vec![Value::Int(9), Value::Int(9), Value::Int(8)]);
    }

    #[test]
    fn leaves_numbered_tokens_inside_string_literals_alone() {
        let (sql, params) = numbered_to_positional("SELECT '?1' , ?1", &[Value::Int(3)]);
        assert_eq!(sql, "SELECT '?1' , ?");
        assert_eq!(params, vec![Value::Int(3)]);
    }

    // A bound nullable topology value is inlined as
    // a literal `NULL` rather than bound, because the DO `exec` path stores a
    // bound null as the string `"[object Object]"`.
    #[test]
    fn inlines_a_bound_null_as_a_literal_and_omits_it_from_bindings() {
        let (sql, params) = numbered_to_positional(
            "INSERT INTO example (a, optional_value, name) VALUES (?1, ?2, ?3)",
            &[Value::Int(1), Value::Null, Value::Text("topology".into())],
        );
        assert_eq!(
            sql,
            "INSERT INTO example (a, optional_value, name) VALUES (?, NULL, ?)"
        );
        assert_eq!(params, vec![Value::Int(1), Value::Text("topology".into())]);
    }

    #[test]
    fn inlines_multiple_nulls_keeping_remaining_bindings_aligned() {
        let (sql, params) = numbered_to_positional(
            "VALUES (?1, ?2, ?3, ?4)",
            &[
                Value::Null,
                Value::Text("".into()),
                Value::Null,
                Value::Text("tail".into()),
            ],
        );
        assert_eq!(sql, "VALUES (NULL, ?, NULL, ?)");
        assert_eq!(
            params,
            vec![Value::Text("".into()), Value::Text("tail".into())]
        );
    }
}
