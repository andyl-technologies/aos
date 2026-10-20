//! Binds historical Source rows without a native Source challenge borrower.
//!
//! Domain's ordinary and selected non-Provider replays keep their existing full
//! semantic checks. A missing actual challenge history leaves Source dependency
//! pending; only the distinct Source provider owner can close it.

aos_sandbox_ledger_replay::define_source_no_history_replay_data_v1!();
