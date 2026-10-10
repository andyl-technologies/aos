//! Registry publication transactions, staged objects, and static distribution.

pub mod container_stage;
pub mod hub_publication;
pub mod hub_stage;
pub mod membership;
pub mod nixcache;
pub mod pack;
pub mod release;
pub mod staging;
pub mod static_stage;
pub mod static_upload;
mod thinpack;
pub mod transport;
pub mod tuf;
pub mod webgen;

pub(crate) use aos_registry_client::registry::{
    channel, keys, objectstore, parse, state, store, support,
};
