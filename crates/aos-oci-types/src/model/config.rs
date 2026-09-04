//! OCI image configuration and runtime defaults.
//!
//! ```text
//! {
//!   "architecture": "amd64",
//!   "os": "linux",
//!   "config": { "Entrypoint": ["/usr/bin/aos"] },
//!   "rootfs": { "type": "layers", "diff_ids": ["sha256:..."] }
//! }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Platform, validate_canonical_size, validate_printable_ascii};
use crate::annotations::Annotations;
use crate::canonical::parse_bounded;
use crate::digest::Sha256Digest;
use crate::error::{Error, Result};
use crate::limits::MAX_LAYERS_PER_IMAGE;

/// The empty object value used by OCI port and volume maps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyObject {}

/// Runtime execution defaults carried by an OCI image configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRuntimeConfig {
    /// Default user or numeric UID, optionally followed by a group or GID.
    #[serde(rename = "User", default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Port keys mapped to empty JSON objects.
    #[serde(
        rename = "ExposedPorts",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub exposed_ports: BTreeMap<String, EmptyObject>,
    /// Ordered `NAME=value` environment entries.
    #[serde(rename = "Env", default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Exec-form entrypoint argv.
    #[serde(rename = "Entrypoint", default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,
    /// Exec-form default command argv.
    #[serde(rename = "Cmd", default, skip_serializing_if = "Vec::is_empty")]
    pub cmd: Vec<String>,
    /// Writable-path hints mapped to empty JSON objects.
    #[serde(
        rename = "Volumes",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub volumes: BTreeMap<String, EmptyObject>,
    /// Default absolute working directory.
    #[serde(
        rename = "WorkingDir",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub working_dir: Option<String>,
    /// Unknown and standard runtime labels retained in key order.
    #[serde(
        rename = "Labels",
        default,
        skip_serializing_if = "Annotations::is_empty"
    )]
    pub labels: Annotations,
    /// Default stop signal spelling.
    #[serde(
        rename = "StopSignal",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_signal: Option<String>,
    /// Deprecated Docker Windows command-line escaping marker.
    #[serde(
        rename = "ArgsEscaped",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub args_escaped: Option<bool>,
}

impl ImageRuntimeConfig {
    /// Validates execution strings, environment, ports, paths, and labels.
    ///
    /// # Errors
    ///
    /// Returns an error for embedded NUL bytes, malformed environment or port
    /// entries, empty executable argv[0], a relative non-empty working directory
    /// or volume path, or invalid labels.
    pub fn validate(&self) -> Result<()> {
        if let Some(user) = &self.user {
            validate_no_nul(user, "image config User")?;
        }
        for port in self.exposed_ports.keys() {
            validate_port(port)?;
        }
        for environment in &self.env {
            validate_environment(environment)?;
        }
        validate_argv(&self.entrypoint, "image config Entrypoint")?;
        validate_argv(&self.cmd, "image config Cmd")?;
        for volume in self.volumes.keys() {
            validate_absolute_path(volume, "image config Volume")?;
        }
        if let Some(working_dir) = &self.working_dir
            && !working_dir.is_empty()
        {
            validate_absolute_path(working_dir, "image config WorkingDir")?;
        }
        self.labels.validate()?;
        if let Some(stop_signal) = &self.stop_signal {
            validate_printable_ascii(stop_signal, "image config StopSignal", false)?;
        }
        Ok(())
    }
}

/// The only root filesystem representation accepted by OCI image config v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootFsType {
    /// Ordered filesystem layers identified by uncompressed DiffIDs.
    #[serde(rename = "layers")]
    Layers,
}

/// Ordered uncompressed layer identities for an image root filesystem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootFs {
    /// Required literal root filesystem type `layers`.
    #[serde(rename = "type")]
    pub rootfs_type: RootFsType,
    /// Ordered SHA-256 digests of the uncompressed layer tar archives.
    pub diff_ids: Vec<Sha256Digest>,
}

impl RootFs {
    /// Validates the frozen runnable-layer count.
    ///
    /// # Errors
    ///
    /// Returns an error when more than 64 DiffIDs are declared.
    pub fn validate(&self) -> Result<()> {
        if self.diff_ids.len() > MAX_LAYERS_PER_IMAGE {
            return Err(Error::TooManyItems {
                field: "image config rootfs diff_ids",
                limit: MAX_LAYERS_PER_IMAGE,
                actual: self.diff_ids.len(),
            });
        }
        Ok(())
    }
}

/// One ordered image-build history record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Optional RFC 3339 creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Optional author of this build point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Optional description of the operation that created the layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional free-form comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Whether this history entry created no filesystem layer.
    #[serde(default, skip_serializing_if = "is_false")]
    pub empty_layer: bool,
}

impl HistoryEntry {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("image history created", self.created.as_deref()),
            ("image history author", self.author.as_deref()),
            ("image history created_by", self.created_by.as_deref()),
            ("image history comment", self.comment.as_deref()),
        ] {
            if let Some(value) = value {
                validate_no_nul(value, field)?;
            }
        }
        Ok(())
    }
}

/// OCI image configuration referenced by a runnable image manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
    /// Optional RFC 3339 image creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Optional image author.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Go-style target CPU architecture.
    pub architecture: String,
    /// Go-style target operating system.
    pub os: String,
    /// Optional target operating-system version.
    #[serde(
        rename = "os.version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
    /// Optional mandatory target operating-system features.
    #[serde(rename = "os.features", default, skip_serializing_if = "Vec::is_empty")]
    pub os_features: Vec<String>,
    /// Optional target CPU variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Optional execution defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ImageRuntimeConfig>,
    /// Ordered uncompressed layer identities.
    pub rootfs: RootFs,
    /// Optional ordered build history.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
}

impl ImageConfig {
    /// Parses and validates one image config within the frozen 4 MiB body cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is oversized or malformed, or when the
    /// decoded config violates [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let config: Self = parse_bounded(bytes, "OCI image config")?;
        config.validate()?;
        Ok(config)
    }

    /// Returns the platform projection carried by this config.
    #[must_use]
    pub fn platform(&self) -> Platform {
        Platform {
            architecture: self.architecture.clone(),
            os: self.os.clone(),
            os_version: self.os_version.clone(),
            os_features: self.os_features.clone(),
            variant: self.variant.clone(),
            features: Vec::new(),
        }
    }

    /// Validates platform, execution, rootfs, history, and body-size invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid platform or runtime fields, more than 64
    /// DiffIDs, a history-to-DiffID mismatch, embedded NUL bytes, or canonical
    /// JSON larger than 4 MiB.
    pub fn validate(&self) -> Result<()> {
        self.platform().validate()?;
        if let Some(created) = &self.created {
            validate_no_nul(created, "image config created")?;
        }
        if let Some(author) = &self.author {
            validate_no_nul(author, "image config author")?;
        }
        if let Some(config) = &self.config {
            config.validate()?;
        }
        self.rootfs.validate()?;
        for entry in &self.history {
            entry.validate()?;
        }
        if !self.history.is_empty() {
            let layer_history = self
                .history
                .iter()
                .filter(|entry| !entry.empty_layer)
                .count();
            if layer_history != self.rootfs.diff_ids.len() {
                return Err(Error::invalid(
                    "image config history",
                    format!(
                        "{} non-empty history entries do not match {} DiffIDs",
                        layer_history,
                        self.rootfs.diff_ids.len()
                    ),
                ));
            }
        }
        validate_canonical_size(self)
    }
}

fn validate_environment(environment: &str) -> Result<()> {
    validate_no_nul(environment, "image config Env")?;
    let Some((name, _value)) = environment.split_once('=') else {
        return Err(Error::invalid(
            "image config Env",
            "entry must use NAME=value form",
        ));
    };
    if name.is_empty() || name.contains('=') {
        return Err(Error::invalid(
            "image config Env",
            "variable name must be non-empty and contain no '='",
        ));
    }
    Ok(())
}

const fn is_false(value: &bool) -> bool {
    !*value
}

fn validate_argv(argv: &[String], field: &'static str) -> Result<()> {
    if argv.first().is_some_and(String::is_empty) {
        return Err(Error::invalid(field, "argv[0] must not be empty"));
    }
    for value in argv {
        validate_no_nul(value, field)?;
    }
    Ok(())
}

fn validate_absolute_path(path: &str, field: &'static str) -> Result<()> {
    validate_no_nul(path, field)?;
    if !path.starts_with('/') {
        return Err(Error::invalid(field, "path must be absolute"));
    }
    Ok(())
}

fn validate_no_nul(value: &str, field: &'static str) -> Result<()> {
    if value.contains('\0') {
        return Err(Error::invalid(field, "value contains a NUL byte"));
    }
    Ok(())
}

fn validate_port(value: &str) -> Result<()> {
    let (port, protocol) = value.split_once('/').map_or((value, "tcp"), |parts| parts);
    let port = port
        .parse::<u16>()
        .map_err(|error| Error::invalid("image config ExposedPorts", error.to_string()))?;
    if port == 0 {
        return Err(Error::invalid(
            "image config ExposedPorts",
            "port must be between 1 and 65535",
        ));
    }
    if !matches!(protocol, "tcp" | "udp" | "sctp") {
        return Err(Error::invalid(
            "image config ExposedPorts",
            "protocol must be tcp, udp, or sctp",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn image_config() -> ImageConfig {
        ImageConfig {
            created: None,
            author: None,
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            os_version: None,
            os_features: Vec::new(),
            variant: None,
            config: Some(ImageRuntimeConfig {
                entrypoint: vec!["/usr/bin/aos".to_string()],
                env: vec!["PATH=/usr/bin".to_string()],
                working_dir: Some("/work".to_string()),
                ..ImageRuntimeConfig::default()
            }),
            rootfs: RootFs {
                rootfs_type: RootFsType::Layers,
                diff_ids: vec![Sha256Digest::digest(b"layer")],
            },
            history: vec![HistoryEntry {
                created_by: Some("aos container layer".to_string()),
                ..HistoryEntry::default()
            }],
        }
    }

    #[test]
    fn accepts_a_bounded_exec_form_image_config() {
        image_config().validate().expect("valid image config");
    }

    #[test]
    fn rejects_bad_runtime_strings_and_paths() {
        let mut config = image_config();
        let runtime = config.config.as_mut().expect("runtime config");
        runtime.env = vec!["MISSING_EQUALS".to_string()];
        assert!(config.validate().is_err());

        let mut config = image_config();
        let runtime = config.config.as_mut().expect("runtime config");
        runtime.working_dir = Some("relative".to_string());
        assert!(config.validate().is_err());

        let mut config = image_config();
        let runtime = config.config.as_mut().expect("runtime config");
        runtime.entrypoint = vec![String::new()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_rootfs_and_history_count_mismatches() {
        let mut config = image_config();
        config.history.clear();
        config.rootfs.diff_ids = (0..=MAX_LAYERS_PER_IMAGE)
            .map(|index| Sha256Digest::digest(index.to_string().as_bytes()))
            .collect();
        assert!(config.validate().is_err());

        let mut config = image_config();
        config.history.push(HistoryEntry::default());
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_object_rejects_nonempty_map_values() {
        assert!(serde_json::from_str::<EmptyObject>("{}").is_ok());
        assert!(serde_json::from_str::<EmptyObject>(r#"{"unexpected":true}"#).is_err());
    }
}
