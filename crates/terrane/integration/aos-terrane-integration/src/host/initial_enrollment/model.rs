//! Encodes separate administrative first-enrollment records.
//!
//! These records live outside the bucket and never alter portable content bytes.
//! Immutable claim rendering excludes the mutable provisioning phase.
//!
//! ```toml
//! version = 3
//! epoch = "00000000000000000000000000000001"
//! phase = "provisioning"
//! creators = []
//! roles = []
//! entries = []
//! [registry]
//! device = 1
//! inode = 2
//! ```

use super::super::{ProvisioningPhase, claims};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub(in crate::host) const VERSION: u32 = 3;
pub(super) const MAX_ENTRIES: usize = 1024;
pub(super) const MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct Custody {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::host) enum Kind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::host) enum Origin {
    Creator,
    Scaffold,
    Administrative,
}

/// Records the original bounded native stat observation, without granting authority.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct StatPreimage {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blocks: u64,
    pub block_size: u64,
    pub atime: i64,
    pub atime_nsec: i64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct ProjectPreimage {
    pub device: u64,
    pub inode: u64,
    pub project_id: u32,
    pub inherit: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct Entry {
    pub owner_id: String,
    pub domain: String,
    pub path: PathBuf,
    pub kind: Kind,
    pub origin: Origin,
    pub device: u64,
    pub inode: u64,
    pub original: Custody,
    pub preimage: StatPreimage,
    pub project_preimage: ProjectPreimage,
    pub final_custody: Custody,
    pub size: u64,
    pub expected: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct Creator {
    pub owner_id: String,
    pub domain: String,
    pub filesystem_uuid: [u8; 16],
    pub project_id: u32,
    pub hard_limit_bytes: u64,
    pub root: PathBuf,
    pub root_device: u64,
    pub root_inode: u64,
    pub control: PathBuf,
    pub control_device: u64,
    pub control_inode: u64,
    pub coordination: PathBuf,
    pub coordination_device: u64,
    pub coordination_inode: u64,
    pub profile_identity: String,
    pub profile_algorithm: String,
    pub profile_chunk: String,
    pub profile_seed: [u8; 32],
    pub genesis: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct InitialLedger {
    pub version: u32,
    pub epoch: String,
    pub registry: claims::RegistryIdentity,
    pub phase: ProvisioningPhase,
    pub creators: Vec<Creator>,
    pub roles: Vec<RoleOwner>,
    pub entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RolePlan {
    pub version: u32,
    pub owners: Vec<RoleOwner>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::host) struct RoleOwner {
    pub owner_id: String,
    pub domain: String,
    pub publisher_uid: u32,
    pub publisher_gid: u32,
    pub content_uid: u32,
    pub content_gid: u32,
    pub cache_state_gid: u32,
    pub chunk_seed: [u8; 32],
}
