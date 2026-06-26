//! The database backend, re-exported from [`aos_hub_core::backend`].
//!
//! Both the engine-neutral abstraction (the async [`Backend`] trait, the
//! [`Statement`] unit of atomic work, the `split_statements`/`with_returning_id`/
//! `prepare` helpers) and the native [`SqlxBackend`] driver now live in the core
//! crate (RFC-0004 Phase 5); `SqlxBackend` is compiled only for native targets
//! (it needs `sqlx`, which does not build for wasm32). This re-export keeps the
//! hub's `db::backend::…` paths stable.

pub use aos_hub_core::backend::*;
