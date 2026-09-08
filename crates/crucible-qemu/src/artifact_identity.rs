//! Authenticated identity for one matched QEMU and plugin launch pair.
//!
//! Packaged execution uses this opaque receipt to bind a lifecycle's concrete
//! executable and plugin paths to the deployment-trusted build markers shipped
//! beside those artifacts. Callers cannot construct or relabel the receipt.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

const CONTENT_ADDRESS_PREFIX: &str = "sha256:";

/// Opaque identity of one marker-authenticated QEMU and plugin launch pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchArtifactIdentity {
    qemu: PathBuf,
    plugin: PathBuf,
    qemu_build_id: String,
    qemu_patch_series_hash: String,
    plugin_abi: String,
    shmem_abi_version: String,
}

impl QemuLaunchArtifactIdentity {
    /// Authenticates the immutable markers for one selected launch pair.
    ///
    /// The markers must name the same raw QEMU build, the compiled shmem ABI
    /// version and generated-header hash. QEMU must advertise the patched
    /// Crucible capability and plugin support. Non-content-addressed upstream
    /// build labels use the same stable normalization as reproduction
    /// artifacts.
    ///
    /// This receipt authenticates marker contents and binds their selected
    /// paths. The deployment owner must supply artifacts from an immutable
    /// store path or otherwise protect both artifacts and markers from mutation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchArtifactIdentityError`] when a selected artifact or
    /// marker is unavailable, malformed, incomplete, or inconsistent with its
    /// counterpart or this build's required shmem ABI.
    pub fn authenticate(
        qemu: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
    ) -> Result<Self, QemuLaunchArtifactIdentityError> {
        let qemu = qemu.into();
        let plugin = plugin.into();
        require_file(&qemu, "QEMU")?;
        require_file(&plugin, "plugin")?;

        let qemu_marker_path = find_marker(qemu_marker_paths(&qemu)).ok_or_else(|| {
            QemuLaunchArtifactIdentityError::MissingMarker {
                artifact: "QEMU",
                path: qemu.clone(),
            }
        })?;
        let plugin_marker_path = find_marker(plugin_marker_paths(&plugin)).ok_or_else(|| {
            QemuLaunchArtifactIdentityError::MissingMarker {
                artifact: "plugin",
                path: plugin.clone(),
            }
        })?;
        let qemu_fields = read_marker(&qemu_marker_path)?;
        let plugin_fields = read_marker(&plugin_marker_path)?;

        require_value(
            &qemu_fields,
            &qemu_marker_path,
            "qemu_sim_capability",
            "qemu-crucible",
        )?;
        require_value(
            &qemu_fields,
            &qemu_marker_path,
            "qemu_crucible_patches_applied",
            "true",
        )?;
        require_value(
            &qemu_fields,
            &qemu_marker_path,
            "qemu_plugins_enabled",
            "true",
        )?;
        let raw_build_id = field(&qemu_fields, &qemu_marker_path, "qemu_build_id")?;
        let patch_hash = field(&qemu_fields, &qemu_marker_path, "qemu_patch_series_hash")?;
        let qemu_abi_version = field(&qemu_fields, &qemu_marker_path, "qemu_shmem_abi_version")?;
        let qemu_abi = field(&qemu_fields, &qemu_marker_path, "qemu_shmem_abi")?;
        let _header = field(&qemu_fields, &qemu_marker_path, "qemu_shmem_header")?;
        let qemu_header_hash = field(&qemu_fields, &qemu_marker_path, "qemu_shmem_header_hash")?;

        let plugin_abi = field(&plugin_fields, &plugin_marker_path, "plugin_abi")?;
        let plugin_build = field(&plugin_fields, &plugin_marker_path, "qemu_build_id")?;
        let plugin_abi_version = field(&plugin_fields, &plugin_marker_path, "shmem_abi_version")?;
        let plugin_shmem_abi = field(&plugin_fields, &plugin_marker_path, "shmem_abi")?;
        let plugin_header_hash = field(
            &plugin_fields,
            &plugin_marker_path,
            "shmem_generated_header_hash",
        )?;
        let required_abi = format!("crucible-shmem-abi-v{}", crucible::SHMEM_ABI_VERSION);
        let required_abi_version = crucible::SHMEM_ABI_VERSION.to_string();

        require_same(&qemu_abi, &required_abi, "QEMU shmem ABI")?;
        require_same(&plugin_abi, &required_abi, "plugin ABI")?;
        require_same(&plugin_shmem_abi, &plugin_abi, "plugin shmem ABI")?;
        require_same(&plugin_build, &raw_build_id, "QEMU build")?;
        require_same(
            &qemu_abi_version,
            &required_abi_version,
            "QEMU shmem ABI version",
        )?;
        require_same(&qemu_abi_version, &plugin_abi_version, "shmem ABI version")?;
        require_same(&qemu_header_hash, &plugin_header_hash, "shmem header hash")?;

        Ok(Self {
            qemu,
            plugin,
            qemu_build_id: normalize_qemu_build_id(&raw_build_id),
            qemu_patch_series_hash: patch_hash,
            plugin_abi,
            shmem_abi_version: plugin_abi_version,
        })
    }

    /// Returns the exact selected QEMU executable path.
    #[must_use]
    pub fn qemu(&self) -> &Path {
        &self.qemu
    }

    /// Returns the exact selected plugin path.
    #[must_use]
    pub fn plugin(&self) -> &Path {
        &self.plugin
    }

    /// Returns the normalized QEMU build identity.
    #[must_use]
    pub fn qemu_build_id(&self) -> &str {
        &self.qemu_build_id
    }

    /// Returns the QEMU patch-series identity.
    #[must_use]
    pub fn qemu_patch_series_hash(&self) -> &str {
        &self.qemu_patch_series_hash
    }

    /// Returns the matched plugin ABI label.
    #[must_use]
    pub fn plugin_abi(&self) -> &str {
        &self.plugin_abi
    }

    /// Returns the matched shmem ABI version.
    #[must_use]
    pub fn shmem_abi_version(&self) -> &str {
        &self.shmem_abi_version
    }
}

/// Failure while authenticating one QEMU and plugin launch pair.
#[derive(Debug, Error)]
pub enum QemuLaunchArtifactIdentityError {
    /// A selected artifact is unavailable or not a regular file.
    #[error("selected {artifact} artifact `{path}` is not a regular file")]
    InvalidArtifact {
        /// Human-readable artifact kind.
        artifact: &'static str,
        /// Selected artifact path.
        path: PathBuf,
    },
    /// The selected artifact has no adjacent immutable build marker.
    #[error("selected {artifact} artifact `{path}` has no build marker")]
    MissingMarker {
        /// Human-readable artifact kind.
        artifact: &'static str,
        /// Selected artifact path.
        path: PathBuf,
    },
    /// A marker could not be read.
    #[error("read QEMU launch marker `{path}`")]
    ReadMarker {
        /// Marker path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A marker line is not a strict key/value pair.
    #[error("QEMU launch marker `{path}` line {line} is not key=value")]
    MalformedMarker {
        /// Marker path.
        path: PathBuf,
        /// One-based malformed line number.
        line: usize,
    },
    /// A marker repeats a key.
    #[error("QEMU launch marker `{path}` repeats key `{key}`")]
    DuplicateField {
        /// Marker path.
        path: PathBuf,
        /// Repeated key.
        key: String,
    },
    /// A required marker field is absent or empty.
    #[error("QEMU launch marker `{path}` has no nonempty `{field}`")]
    MissingField {
        /// Marker path.
        path: PathBuf,
        /// Required field name.
        field: &'static str,
    },
    /// A marker advertises an unsupported fixed capability value.
    #[error("QEMU launch marker `{path}` field `{field}` has an unsupported value")]
    InvalidField {
        /// Marker path.
        path: PathBuf,
        /// Invalid field name.
        field: &'static str,
    },
    /// The QEMU and plugin marker values differ.
    #[error("QEMU launch pair has mismatched {field}")]
    Mismatch {
        /// Semantic marker field that disagreed.
        field: &'static str,
    },
}

fn require_file(
    path: &Path,
    artifact: &'static str,
) -> Result<(), QemuLaunchArtifactIdentityError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(QemuLaunchArtifactIdentityError::InvalidArtifact {
            artifact,
            path: path.to_owned(),
        })
    }
}

fn find_marker(paths: Vec<PathBuf>) -> Option<PathBuf> {
    paths.into_iter().find(|path| path.is_file())
}

fn qemu_marker_paths(qemu: &Path) -> Vec<PathBuf> {
    marker_paths(
        qemu,
        "share/aos/crucible/qemu-build-identity.env",
        "qemu-build-identity.env",
    )
}

fn plugin_marker_paths(plugin: &Path) -> Vec<PathBuf> {
    marker_paths(
        plugin,
        "nix-support/crucible-qemu-plugin-build-info",
        "crucible-qemu-plugin-build-info",
    )
}

fn marker_paths(artifact: &Path, installed: &str, adjacent: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(parent) = artifact.parent() {
        if matches!(
            parent.file_name().and_then(|name| name.to_str()),
            Some("bin" | "lib")
        ) && let Some(root) = parent.parent()
        {
            paths.push(root.join(installed));
        }
        paths.push(parent.join(adjacent));
    }
    paths
}

fn read_marker(path: &Path) -> Result<BTreeMap<String, String>, QemuLaunchArtifactIdentityError> {
    let text =
        fs::read_to_string(path).map_err(|source| QemuLaunchArtifactIdentityError::ReadMarker {
            path: path.to_owned(),
            source,
        })?;
    let mut fields = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            QemuLaunchArtifactIdentityError::MalformedMarker {
                path: path.to_owned(),
                line: index + 1,
            }
        })?;
        let key = key.trim().to_owned();
        if fields
            .insert(key.clone(), value.trim().to_owned())
            .is_some()
        {
            return Err(QemuLaunchArtifactIdentityError::DuplicateField {
                path: path.to_owned(),
                key,
            });
        }
    }
    Ok(fields)
}

fn field(
    fields: &BTreeMap<String, String>,
    path: &Path,
    field: &'static str,
) -> Result<String, QemuLaunchArtifactIdentityError> {
    fields
        .get(field)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| QemuLaunchArtifactIdentityError::MissingField {
            path: path.to_owned(),
            field,
        })
}

fn require_value(
    fields: &BTreeMap<String, String>,
    path: &Path,
    field_name: &'static str,
    expected: &str,
) -> Result<(), QemuLaunchArtifactIdentityError> {
    if field(fields, path, field_name)? == expected {
        Ok(())
    } else {
        Err(QemuLaunchArtifactIdentityError::InvalidField {
            path: path.to_owned(),
            field: field_name,
        })
    }
}

fn require_same(
    left: &str,
    right: &str,
    field: &'static str,
) -> Result<(), QemuLaunchArtifactIdentityError> {
    if left == right {
        Ok(())
    } else {
        Err(QemuLaunchArtifactIdentityError::Mismatch { field })
    }
}

/// Normalizes a raw QEMU build label to its reproduction content address.
///
/// Existing SHA-256 content addresses are preserved. Other build labels use
/// the stable Crucible reproduction hash domain.
#[must_use]
pub fn normalize_qemu_build_id(raw: &str) -> String {
    if is_content_address(raw) {
        raw.to_owned()
    } else {
        format!(
            "{CONTENT_ADDRESS_PREFIX}{}",
            hex_bytes(&stable_digest(raw.as_bytes()))
        )
    }
}

fn is_content_address(value: &str) -> bool {
    value
        .strip_prefix(CONTENT_ADDRESS_PREFIX)
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn stable_digest(material: &[u8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for lane in 0..4 {
        let mut state = 0xcbf2_9ce4_8422_2325_u64 ^ lane;
        for byte in b"crucible.reproduction.hash.v1"
            .iter()
            .copied()
            .chain([0xff])
            .chain(material.iter().copied())
        {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
            state ^= state.rotate_left(17);
        }
        let offset = lane as usize * 8;
        output[offset..offset + 8].copy_from_slice(&state.to_be_bytes());
    }
    output
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixture setup and assertions fail loudly at their exact source.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    struct ArtifactFixture {
        _directory: tempfile::TempDir,
        qemu: PathBuf,
        plugin: PathBuf,
        qemu_marker: PathBuf,
        plugin_marker: PathBuf,
    }

    impl ArtifactFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("artifact fixture directory");
            let root = directory.path();
            let qemu = root.join("bin/qemu-system-x86_64");
            let plugin = root.join("lib/libcrucible-qemu-plugin.so");
            let qemu_marker = root.join("share/aos/crucible/qemu-build-identity.env");
            let plugin_marker = root.join("nix-support/crucible-qemu-plugin-build-info");

            for path in [&qemu, &plugin, &qemu_marker, &plugin_marker] {
                fs::create_dir_all(path.parent().expect("fixture path parent"))
                    .expect("create artifact fixture directory");
            }
            fs::write(&qemu, b"qemu").expect("write QEMU artifact");
            fs::write(&plugin, b"plugin").expect("write plugin artifact");

            let fixture = Self {
                _directory: directory,
                qemu,
                plugin,
                qemu_marker,
                plugin_marker,
            };
            let abi_version = required_abi_version();
            let abi = format!("crucible-shmem-abi-v{abi_version}");
            fixture.write_markers("qemu-build-v1", "qemu-build-v1", &abi_version, &abi);
            fixture
        }

        fn write_markers(
            &self,
            qemu_build: &str,
            plugin_build: &str,
            abi_version: &str,
            abi: &str,
        ) {
            fs::write(
                &self.qemu_marker,
                format!(
                    "qemu_sim_capability=qemu-crucible\n\
                     qemu_crucible_patches_applied=true\n\
                     qemu_plugins_enabled=true\n\
                     qemu_build_id={qemu_build}\n\
                     qemu_patch_series_hash=sha256:patch\n\
                     qemu_shmem_abi_version={abi_version}\n\
                     qemu_shmem_abi={abi}\n\
                     qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\n\
                     qemu_shmem_header_hash=sha256:header\n"
                ),
            )
            .expect("write QEMU marker");
            fs::write(
                &self.plugin_marker,
                format!(
                    "plugin_abi={abi}\n\
                     qemu_build_id={plugin_build}\n\
                     shmem_abi_version={abi_version}\n\
                     shmem_abi={abi}\n\
                     shmem_generated_header_hash=sha256:header\n"
                ),
            )
            .expect("write plugin marker");
        }
    }

    fn required_abi_version() -> String {
        crucible::SHMEM_ABI_VERSION.to_string()
    }

    #[test]
    fn identity_authenticates_and_binds_exact_paths() {
        let fixture = ArtifactFixture::new();

        let identity = QemuLaunchArtifactIdentity::authenticate(&fixture.qemu, &fixture.plugin)
            .expect("authenticate matched launch pair");

        assert_eq!(identity.qemu(), fixture.qemu);
        assert_eq!(identity.plugin(), fixture.plugin);
        assert_eq!(
            identity.qemu_build_id(),
            normalize_qemu_build_id("qemu-build-v1")
        );
        assert_eq!(identity.shmem_abi_version(), required_abi_version());
    }

    #[test]
    fn identity_rejects_matched_but_unsupported_abi_versions() {
        let fixture = ArtifactFixture::new();
        let required_abi = format!("crucible-shmem-abi-v{}", required_abi_version());
        fixture.write_markers("qemu-build-v1", "qemu-build-v1", "999", &required_abi);

        let error = QemuLaunchArtifactIdentity::authenticate(&fixture.qemu, &fixture.plugin)
            .expect_err("reject unsupported ABI version");

        assert!(matches!(
            error,
            QemuLaunchArtifactIdentityError::Mismatch {
                field: "QEMU shmem ABI version"
            }
        ));
    }

    #[test]
    fn identity_rejects_plugin_relabeling() {
        let fixture = ArtifactFixture::new();
        fixture.write_markers(
            "qemu-build-v1",
            "another-qemu-build",
            &required_abi_version(),
            &format!("crucible-shmem-abi-v{}", required_abi_version()),
        );

        let error = QemuLaunchArtifactIdentity::authenticate(&fixture.qemu, &fixture.plugin)
            .expect_err("reject mismatched plugin build");

        assert!(matches!(
            error,
            QemuLaunchArtifactIdentityError::Mismatch {
                field: "QEMU build"
            }
        ));
    }

    #[test]
    fn identity_rejects_missing_selected_artifacts() {
        let fixture = ArtifactFixture::new();
        let missing = fixture.qemu.with_file_name("missing-qemu");

        let error = QemuLaunchArtifactIdentity::authenticate(missing, &fixture.plugin)
            .expect_err("reject missing QEMU path");

        assert!(matches!(
            error,
            QemuLaunchArtifactIdentityError::InvalidArtifact {
                artifact: "QEMU",
                ..
            }
        ));
    }
}
