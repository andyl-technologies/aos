//! Supplies fixed operator intent and finite project allocations for each case.
//!
//! Helper intent uses the existing administrative TOML schema:
//! ```toml
//! socket = "/fixture/positive/quota.sock"
//! epoch = "00000000000000000000000000000001"
//! tier_charge_budget_bytes = 67108864
//! owners = [] # The fixture supplies both complete explicit owners.
//! ```

use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use terrane_format::{chunking::ChunkProfile, refs::Locality};
use terrane_linux::host_quota::{NativeProject, ROOT_LABELS, open_host_path};
use terrane_sdk::{
    bucket::{FileBucketConfig, FileBucketPublicationConfig},
    store::{TokioClock, TokioLocalFs},
};

/// Bounds one ordinary positive-case owner to a finite 32 MiB project.
pub(super) const LIMIT: u64 = 32 * 1024 * 1024;
/// Fixes the registered chunk seed used by trusted fixture role intent.
pub(super) const SEED: [u8; 32] = [7; 32];
/// Orders the public and private disclosure-domain labels.
pub(super) const DOMAINS: [&str; 2] = ["public", "private:fixture"];
/// Orders the matching public and private compatible-owner identifiers.
pub(super) const OWNERS: [&str; 2] = ["fixture-public", "fixture-private"];

/// Identifies one fixed supervisor-owned case, without carrying native authority.
pub(super) struct Case {
    /// Absolute fixed fixture or allocation path.
    pub path: PathBuf,
    /// Fixed case ordinal used only to allocate distinct test projects.
    pub index: u32,
}

impl Case {
    /// Resolves one fixed case beneath the protected supervisor-supplied disk root.
    ///
    /// # Errors
    /// Refuses unknown cases, absent configuration, noncanonical paths or unsafe native parent
    /// custody.
    pub fn existing(name: &str) -> io::Result<Self> {
        let index = match name {
            "positive" => 0,
            "unknown" => 1,
            "wrong-profile" => 2,
            "incomplete" => 3,
            "preexisting" => 4,
            "reused-project" => 5,
            "partial-quota" => 6,
            "initialize-positive" => 7,
            "initialize-existing" => 8,
            "initialize-unsafe-parent" => 9,
            _ => return Err(io::Error::other("unknown case")),
        };
        let root = PathBuf::from(
            std::env::var_os("TERRANE_INITIAL_FIXTURE_ROOT")
                .ok_or_else(|| io::Error::other("requires explicit supervised disk root"))?,
        );
        if !root.is_absolute()
            || root
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(io::Error::other(
                "fixture root must be canonical and absolute",
            ));
        }
        let parent = open_host_path(&root, true)?;
        if parent.metadata()?.uid() != 0 || parent.metadata()?.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "fixture disk root lacks protected host custody",
            ));
        }
        Ok(Self {
            path: root.join(name),
            index,
        })
    }

    /// Creates one fresh protected case parent before any portable creator effects.
    ///
    /// # Errors
    /// Returns refusal for existing cases, unsafe disk roots or native creation and synchronization
    /// failures.
    pub fn create(name: &str) -> io::Result<Self> {
        let case = Self::existing(name)?;
        fs::create_dir(&case.path)?;
        fs::set_permissions(&case.path, fs::Permissions::from_mode(0o700))?;
        for owner in 0..2 {
            fs::create_dir(case.administrative(owner))?;
        }
        File::open(&case.path)?.sync_all()?;
        Ok(case)
    }

    /// Returns the fixed public or private payload root.
    pub fn root(&self, owner: usize) -> PathBuf {
        self.path
            .join(if owner == 0 { "public" } else { "private" })
    }

    /// Returns the explicit administrative allocation root for one owner.
    pub fn administrative(&self, owner: usize) -> PathBuf {
        self.path.join(if owner == 0 {
            "public-admin"
        } else {
            "private-admin"
        })
    }

    /// Returns the protected external creator-control path.
    pub fn control(&self, owner: usize) -> PathBuf {
        self.administrative(owner).join("control")
    }

    /// Returns the protected helper configuration path.
    pub fn config(&self) -> PathBuf {
        self.path.join("host.toml")
    }

    /// Returns the private explicit role-plan path.
    pub fn roles(&self) -> PathBuf {
        self.path.join("roles.toml")
    }

    /// Returns the separate administrative enrollment ledger path.
    pub fn ledger(&self) -> PathBuf {
        self.path.join("enrollment.toml")
    }

    /// Returns the actual read-only quota broker socket path.
    pub fn socket(&self) -> PathBuf {
        self.path.join("quota.sock")
    }

    /// Returns the fixed nonzero project identifier for an internal owner index.
    ///
    /// # Panics
    /// Panics if an invalid internal owner index overflows the project range.
    pub fn project(&self, owner: usize) -> u32 {
        65001 + self.index * 2 + owner as u32
    }

    /// Builds ordinary creator configuration with an explicit protected control path.
    pub fn bucket(&self, owner: usize, seed: [u8; 32]) -> FileBucketConfig {
        FileBucketConfig {
            root: self.root(owner),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: ChunkProfile::cdc_1m(seed),
            locality: Locality::default(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: 0,
                control: Some(self.control(owner)),
            }),
        }
    }

    /// Obtains a genuine single-use receipt from the actual fresh Core factory.
    ///
    /// # Errors
    /// Returns the actual creator or activation failure; existing roots never mint a receipt.
    pub async fn initial(
        &self,
        owner: usize,
        seed: [u8; 32],
    ) -> io::Result<terrane_sdk::bucket::enrollment::NativeInitialBucketEnrollment> {
        terrane_sdk::bucket::enrollment::create_initial_bucket(
            self.bucket(owner, seed),
            &TokioLocalFs,
            &TokioClock,
        )
        .await
        .map_err(super::source_error)
    }

    /// Durably writes the complete finite partition and explicit role policy.
    ///
    /// # Errors
    /// Returns bounded serialization, create-new, synchronization or native path errors.
    pub fn write_intent(&self, partial: bool) -> io::Result<()> {
        let owners = (0..2)
            .map(|owner| Owner {
                owner_id: OWNERS[owner].to_owned(),
                domain: DOMAINS[owner].to_owned(),
                project_id: self.project(owner),
                hard_limit_bytes: if partial && owner == 0 { 1024 } else { LIMIT },
                allowed_client_uids: vec![840, 841],
                roots: roots(&self.root(owner), Some(self.administrative(owner))),
            })
            .collect();
        write_toml(
            &self.config(),
            &Host {
                socket: self.socket(),
                epoch: format!("{:032x}", self.index + 1),
                tier_charge_budget_bytes: 2 * LIMIT,
                owners,
            },
            0o644,
        )?;
        write_toml(
            &self.roles(),
            &Roles {
                version: 1,
                owners: (0..2)
                    .map(|owner| Role {
                        owner_id: OWNERS[owner].to_owned(),
                        domain: DOMAINS[owner].to_owned(),
                        publisher_uid: 841,
                        publisher_gid: 841,
                        content_uid: 840,
                        content_gid: 845,
                        cache_state_gid: 844,
                        chunk_seed: SEED,
                    })
                    .collect(),
            },
            0o600,
        )
    }

    /// Checks that refusal left no enrollment ledger, host scaffold or assigned payload root.
    ///
    /// # Errors
    /// Returns native project-inspection or path errors.
    ///
    /// # Panics
    /// Panics if a required physical fixture invariant is not observed.
    pub fn assert_unassigned(&self) -> io::Result<()> {
        assert!(!self.ledger().exists());
        for owner in 0..2 {
            assert!(
                !self.root(owner).join("sealed").exists(),
                "preflight refusal must precede scaffold creation"
            );
            if self.root(owner).exists() {
                assert_eq!(
                    NativeProject::inspect(&File::open(self.root(owner))?)?.project_id,
                    0
                );
            }
        }
        Ok(())
    }
}

/// Publishes bounded fixture intent or ordinary assertion data with file and parent durability.
///
/// # Errors
/// Returns serialization, size-bound, existing-file, write or synchronization errors.
pub(super) fn write_toml<T: Serialize>(path: &Path, value: &T, mode: u32) -> io::Result<()> {
    let bytes = toml::to_string(value).map_err(super::source_error)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(io::Error::other("fixture state bound exceeded"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    output.write_all(bytes.as_bytes())?;
    output.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("fixture file has no parent"))?,
    )?
    .sync_all()
}

/// Builds the complete registered root set from explicit operator paths.
pub(super) fn roots(layout: &Path, administrative: Option<PathBuf>) -> Vec<Root> {
    ROOT_LABELS
        .iter()
        .map(|label| Root {
            role_directory: (*label).to_owned(),
            path: if *label == "layout-root" {
                layout.to_owned()
            } else {
                layout.join(label)
            },
        })
        .chain(administrative.into_iter().map(|path| Root {
            role_directory: "administrative-root".to_owned(),
            path,
        }))
        .collect()
}

/// Serializes explicit finite helper configuration as ordinary operator intent.
#[derive(Serialize)]
pub(super) struct Host {
    /// Actual helper socket path beneath the protected case parent.
    pub socket: PathBuf,
    /// Fixed lowercase administrative epoch for this case.
    pub epoch: String,
    /// Finite ceiling for the complete configured owner partition.
    pub tier_charge_budget_bytes: u64,
    /// Complete explicit owner partition, never inferred from user identifiers.
    pub owners: Vec<Owner>,
}

/// Serializes one explicitly configured compatible allocation owner.
#[derive(Serialize)]
pub(super) struct Owner {
    /// Fixed administrative compatible-owner identifier.
    pub owner_id: String,
    /// Canonical configured disclosure-domain label.
    pub domain: String,
    /// Distinct finite native project assignment selected by the case.
    pub project_id: u32,
    /// Finite aligned kernel quota limit required by this owner.
    pub hard_limit_bytes: u64,
    /// Explicit native identities permitted to query this owner.
    pub allowed_client_uids: Vec<u32>,
    /// Complete named root set for the allocation owner.
    pub roots: Vec<Root>,
}

/// Serializes one registered allocation label and its explicit path.
#[derive(Serialize)]
pub(super) struct Root {
    /// Registered allocation-class or administrative-root label.
    pub role_directory: String,
    /// Absolute fixed fixture or allocation path.
    pub path: PathBuf,
}

#[derive(Serialize)]
struct Roles {
    version: u32,
    owners: Vec<Role>,
}

#[derive(Serialize)]
struct Role {
    owner_id: String,
    domain: String,
    publisher_uid: u32,
    publisher_gid: u32,
    content_uid: u32,
    content_gid: u32,
    cache_state_gid: u32,
    chunk_seed: [u8; 32],
}

/// Carries ordinary known-present and absent path candidates for a disclosure fixture.
#[derive(Serialize, Deserialize)]
pub(super) struct PrivateHash {
    /// Actually created private snapshot path known to the supervisor.
    pub present: PathBuf,
    /// Verified absent sibling hash-path candidate supplied by the supervisor.
    pub absent: PathBuf,
}
