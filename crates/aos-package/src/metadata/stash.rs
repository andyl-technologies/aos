//! The `/run/aos-metadata` stash format.
//!
//! The stash is a child of the initrd `/run` so it survives
//! `mount --move /run /sysroot/run` during switch_root; stage-2 stages it into
//! the evaluator root `/run/aos-eval/`. Fetch writes raw user-data; only the
//! initrd authorization phase may produce evaluator-visible `host.nix` or
//! transient repart definitions.
//!
//! ```text
//! /run/aos-metadata/
//! ├── platform.env            # PLATFORM_ID=<id>  [+ METADATA_DIR=<path>]
//! ├── user-data               # exact fetched bytes
//! ├── user-data.sig           # detached whole-input SSHSIG (optional)
//! ├── host.nix                # policy-accepted operator config
//! ├── storage-plan.json       # canonical validated plan (optional)
//! ├── repart.d/               # transient rendered definitions (optional)
//! ├── facts.json              # normalized Facts (serde_json)
//! ├── network/10-aos-seed.network   # DHCP-less static seed (optional)
//! ├── .metadata-result.json   # acquisition record
//! └── .provisioning-result.json # authorization and binding record
//! ```
//!
//! `platform.env` is consumed via systemd `EnvironmentFile`, so it is rendered
//! as `KEY=value` lines. `.metadata-result.json` records acquisition.
//! `.provisioning-result.json`
//! records the later trust decision and accepted content hashes.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fetcher::Facts;

/// Default initrd stash directory.
pub const DEFAULT_STASH_DIR: &str = "/run/aos-metadata";
/// Mountpoint the config-drive mount helper uses for offline channels.
pub const DEFAULT_MEDIA_DIR: &str = "/run/aos-metadata/media";

/// The `platform.env` document (systemd `EnvironmentFile` form).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformEnv {
    /// `PLATFORM_ID` — the fetcher selector.
    pub platform_id: String,
    /// `METADATA_DIR` — the mounted offline-channel directory, if any.
    pub metadata_dir: Option<String>,
    /// Whether the platform needs network (the cloud IMDS gate). Rendered as
    /// `NEED_NETWORK=1` and mirrored by an adjacent `need-network` flag file.
    pub need_network: bool,
}

impl PlatformEnv {
    /// Render to `KEY=value` lines for a systemd `EnvironmentFile`.
    pub fn render(&self) -> String {
        let mut out = format!("PLATFORM_ID={}\n", self.platform_id);
        if let Some(dir) = &self.metadata_dir {
            out.push_str(&format!("METADATA_DIR={dir}\n"));
        }
        if self.need_network {
            out.push_str("NEED_NETWORK=1\n");
        }
        out
    }

    /// Parse a `platform.env` file's contents.
    ///
    /// Unknown keys are ignored (forward-compatible with adjacent vars).
    pub fn parse(text: &str) -> Self {
        let mut env = PlatformEnv::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k.trim() {
                "PLATFORM_ID" => env.platform_id = v.trim().to_string(),
                "METADATA_DIR" => env.metadata_dir = Some(v.trim().to_string()),
                "NEED_NETWORK" => env.need_network = v.trim() == "1",
                _ => {}
            }
        }
        env
    }
}

/// The `.metadata-result.json` acquisition record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataResult {
    /// Platform that produced this run.
    pub platform_id: String,
    /// Whether any user-data payload was fetched.
    pub fetched_user_data: bool,
    /// Where the payload came from (`imds`, `config-drive`, `fw_cfg`, …).
    pub user_data_source: String,
    /// Lowercase-hex SHA-256 of the exact fetched user-data, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data_sha256: Option<String>,
    /// Whether a detached signature was stashed.
    pub sig_present: bool,
    /// SHA-256 of the canonical `facts.json` bytes.
    pub facts_hash: String,
    /// Whether a DHCP-less static network seed was written.
    pub network_seed_written: bool,
    /// RFC 3339 timestamp of the run.
    pub timestamp: String,
}

/// The on-disk stash, rooted at a directory (default [`DEFAULT_STASH_DIR`]).
pub struct Stash {
    dir: PathBuf,
}

impl Stash {
    /// Open (creating) a stash at `dir`.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating stash dir {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// The stash root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write `platform.env`, and touch/remove the adjacent `need-network` flag
    /// the cloud-network gate keys off.
    ///
    /// # Errors
    ///
    /// Returns `Err` on any write failure.
    pub fn write_platform_env(&self, env: &PlatformEnv) -> Result<()> {
        std::fs::write(self.dir.join("platform.env"), env.render())
            .context("writing platform.env")?;
        let flag = self.dir.join("need-network");
        if env.need_network {
            std::fs::write(&flag, b"1").context("writing need-network flag")?;
        } else if flag.exists() {
            let _ = std::fs::remove_file(&flag);
        }
        Ok(())
    }

    /// Read `platform.env` from the stash.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the file is missing or unreadable.
    pub fn read_platform_env(&self) -> Result<PlatformEnv> {
        let text = std::fs::read_to_string(self.dir.join("platform.env"))
            .context("reading platform.env")?;
        Ok(PlatformEnv::parse(&text))
    }

    /// Stash exact fetched user-data bytes and optional detached signature.
    ///
    /// Returns the lowercase-hex SHA-256 of the payload for the run record.
    ///
    /// # Errors
    ///
    /// Returns `Err` on any write failure.
    pub fn write_user_data(&self, user_data: &[u8], sig: Option<&str>) -> Result<String> {
        std::fs::write(self.dir.join("user-data"), user_data).context("writing user-data")?;
        if let Some(sig) = sig {
            std::fs::write(self.dir.join("user-data.sig"), sig).context("writing user-data.sig")?;
        }
        Ok(sha256_hex(user_data))
    }

    /// Remove outputs from a previous acquisition attempt.
    ///
    /// The run marker is removed first. If the new fetch fails, authorization
    /// observes the missing marker and cannot reuse stale user-data.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing output cannot be removed.
    pub fn clear_fetch_outputs(&self) -> Result<()> {
        for file in ["user-data", "user-data.sig", ".metadata-result.json"] {
            let path = self.dir.join(file);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing {}", path.display()))?;
            }
        }
        Ok(())
    }

    /// Remove every output owned by the authorization phase.
    ///
    /// This runs before each authorization attempt so a failed re-run cannot
    /// expose stale accepted configuration or repart definitions.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing output cannot be removed.
    pub fn clear_authorized_outputs(&self) -> Result<()> {
        for file in [
            "host.nix",
            super::repart::STORAGE_PLAN_FILE,
            super::provisioning::PROVISIONING_RESULT_FILE,
        ] {
            let path = self.dir.join(file);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing {}", path.display()))?;
            }
        }
        let repart = self.dir.join(super::repart::REPART_DIR);
        if repart.exists() {
            std::fs::remove_dir_all(&repart)
                .with_context(|| format!("removing {}", repart.display()))?;
        }
        Ok(())
    }

    /// Serialize [`Facts`] to `facts.json` and return its SHA-256 (the
    /// `facts_hash`).
    ///
    /// # Errors
    ///
    /// Returns `Err` on serialization or write failure.
    pub fn write_facts(&self, facts: &Facts) -> Result<String> {
        let bytes = serde_json::to_vec_pretty(facts).context("serializing facts.json")?;
        std::fs::write(self.dir.join("facts.json"), &bytes).context("writing facts.json")?;
        Ok(sha256_hex(&bytes))
    }

    /// Write the DHCP-less static-network seed into `network/10-aos-seed.network`.
    ///
    /// # Errors
    ///
    /// Returns `Err` on any write failure.
    pub fn write_network_seed(&self, contents: &str) -> Result<PathBuf> {
        let dir = self.dir.join("network");
        std::fs::create_dir_all(&dir).context("creating stash network dir")?;
        let path = dir.join(super::staticnet::SEED_FILENAME);
        std::fs::write(&path, contents).context("writing network seed")?;
        Ok(path)
    }

    /// Write the `.metadata-result.json` run record.
    ///
    /// # Errors
    ///
    /// Returns `Err` on serialization or write failure.
    pub fn write_result(&self, result: &MetadataResult) -> Result<()> {
        let bytes =
            serde_json::to_vec_pretty(result).context("serializing .metadata-result.json")?;
        std::fs::write(self.dir.join(".metadata-result.json"), bytes)
            .context("writing .metadata-result.json")?;
        Ok(())
    }

    /// Whether the idempotency marker (`.metadata-result.json`) already exists,
    /// so a re-run within a boot is a no-op.
    pub fn already_run(&self) -> bool {
        self.dir.join(".metadata-result.json").exists()
    }
}

/// Lowercase-hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
