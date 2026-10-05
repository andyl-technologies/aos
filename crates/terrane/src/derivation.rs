//! Owns read-only loading of explicitly selected advisory derivation evidence.
//!
//! The common Memo service retains recipe lookup keys separately from immutable
//! record addresses. Native loading supplies actual fetched Memo/Node bytes to
//! that service without changing recipe inputs or inferring current authority.
//! These shared declarations do not qualify runtime replay; the owning check
//! requires actual loading, failure, divergence and mandatory-input witnesses.
