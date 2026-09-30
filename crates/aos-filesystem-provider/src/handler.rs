//! Native filesystem activation and durable ownership primitives.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{ABILITY_LIMITS_V1, MAX_SAFE_INTEGER};
use aos_contract::Sha256Digest;
use rustix::fs::{FlockOperation, Mode, OFlags, fchmod, fchown, flock, fstat, mkdirat, openat};
use rustix::process::{Gid, Uid};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{resolve_storage_view_path, validate_provider_owned_path, validate_storage_claim};

const LOCK_RETRY: Duration = Duration::from_millis(5);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct StorageOwnership {
    uid: Option<Uid>,
    gid: Option<Gid>,
}

struct StorageIdentity {
    device: u64,
    inode: u64,
}

struct RegularFileObservation {
    digest: Sha256Digest,
}

pub mod native;

mod filesystem;
use filesystem::*;
