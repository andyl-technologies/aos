//! Registry publication transactions, staged objects, and static distribution.

pub mod container_stage;
pub mod hub_publication;
pub mod hub_stage;
pub mod nixcache;
pub mod release;
pub mod staging;
pub mod static_stage;
pub mod static_upload;
pub mod webgen;
pub mod tuf;
pub mod pack;
mod thinpack;

use aos_registry_client::registry::{parse, store, keys, repo, porcelain, objectstore, membership, channel, support, verify, transport, state};
