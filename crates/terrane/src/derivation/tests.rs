//! Collects executable common Memo adapter and native persistence witnesses.

#[cfg(all(feature = "tokio", unix))]
mod native;
