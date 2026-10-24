//! Shares exact Source World admission facts between publication and cleanup.
//!
//! These dependencies bind the actual retained Pending, native token, ledger
//! publication and original holders. They grant no Main or Source authority.

#[path = "source_world_admission/pending.rs"]
mod pending;
#[path = "source_world_admission/lower.rs"]
mod lower;
#[path = "source_world_admission/facade.rs"]
mod facade;

#[path = "source_world_admission/origin.rs"]
mod origin;

pub(super) use origin::{ORIGIN_BODY, ORIGIN_PUBLICATION, ORIGIN_RUNNERS, ORIGIN_FINDING, ORIGIN_OWNER};
pub(super) use pending::{PREPARED_WORLD, PENDING_LAYOUT, PENDING_POST_BODY};
pub(super) use lower::{
    NATIVE_WORLD, TOKEN, POOL_CLAIM, LEDGER, MAIN_CHECK, NATIVE_LAYOUT, PREPARATION_CLASS,
    LIVE_CLASS,
};
pub(super) use facade::{ADMISSION, FACADE, RECEIVER_API};

#[cfg(test)]
#[path = "source_world_admission/tests.rs"]
mod tests;
