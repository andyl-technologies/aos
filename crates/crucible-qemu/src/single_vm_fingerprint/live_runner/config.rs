//! Verified immutable inputs and canonical fingerprint-observation launches.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    DeterministicLaunchProfile, QemuPreSpawnLaunchValidationError,
    validate_pre_spawn_qemu_launch_args,
};

use super::LiveRunnerArtifacts;

/// Observation-only launch kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveRunnerLaunchKind {
    /// Captures the independent definition-only preflight without guest execution.
    DefinitionPreflight,
    /// Captures one fixed-cadence run through the configured horizon.
    Observation,
}

impl LiveRunnerLaunchKind {
    pub(super) const fn expected_stopped_state(self) -> crate::QmpRunStateKind {
        match self {
            Self::DefinitionPreflight => crate::QmpRunStateKind::Prelaunch,
            Self::Observation => crate::QmpRunStateKind::Paused,
        }
    }
}

/// Exact immutable executables and guest inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRunnerImmutableInputs {
    /// Patched QEMU executable.
    pub qemu: PathBuf,
    /// Guest firmware image.
    pub firmware: PathBuf,
    /// Guest kernel image.
    pub kernel: PathBuf,
    /// Guest initial RAM filesystem.
    pub initrd: PathBuf,
    /// Materialized canonical guest-entropy seed file.
    pub seed_file: PathBuf,
    /// Observation-only trace plugin.
    pub trace_plugin: PathBuf,
}

/// Exact sampling fields layered onto the canonical launch profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveRunnerLaunchFields {
    /// Periodic fingerprint cadence.
    pub cadence_icount: u64,
    /// Fixed observation horizon.
    pub horizon_icount: u64,
}

/// Verified canonical configuration for one fresh live runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRunnerConfig {
    immutable: LiveRunnerImmutableInputs,
    profile: DeterministicLaunchProfile,
    cadence_icount: u64,
    horizon_icount: u64,
    launch_definition_digest: String,
    qemu_build_digest: String,
    trace_plugin_build_digest: String,
}

impl LiveRunnerConfig {
    /// Verifies immutable bytes and builds their canonical launch identity.
    ///
    /// The constructor hashes every executable and guest input itself. The seed
    /// file must equal the bytes derived by `profile`, so callers cannot assert
    /// provenance or bind a different seed to the canonical profile.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerConfigError`] when an input is not a normalized Nix
    /// store file, QEMU is not executable, a file cannot be read, the seed bytes
    /// differ, or sampling bounds are zero or inconsistent.
    pub fn new(
        immutable: LiveRunnerImmutableInputs,
        profile: DeterministicLaunchProfile,
        launch: LiveRunnerLaunchFields,
    ) -> Result<Self, LiveRunnerConfigError> {
        validate_sampling(launch)?;
        for (field, path) in [
            ("qemu", &immutable.qemu),
            ("firmware", &immutable.firmware),
            ("kernel", &immutable.kernel),
            ("initrd", &immutable.initrd),
            ("seed_file", &immutable.seed_file),
            ("trace_plugin", &immutable.trace_plugin),
        ] {
            validate_stable_text_path(field, path)?;
        }
        validate_embedded_option_path("seed_file", &immutable.seed_file)?;
        validate_embedded_option_path("trace_plugin", &immutable.trace_plugin)?;

        let qemu_build_digest = hash_store_file("qemu", &immutable.qemu, true)?;
        let firmware_digest = hash_store_file("firmware", &immutable.firmware, false)?;
        let kernel_digest = hash_store_file("kernel", &immutable.kernel, false)?;
        let initrd_digest = hash_store_file("initrd", &immutable.initrd, false)?;
        let seed_digest = hash_store_file("seed_file", &immutable.seed_file, false)?;
        let trace_plugin_build_digest =
            hash_store_file("trace_plugin", &immutable.trace_plugin, false)?;

        let seed_bytes =
            fs::read(&immutable.seed_file).map_err(|source| LiveRunnerConfigError::FileIo {
                field: "seed_file",
                path: immutable.seed_file.clone(),
                source,
            })?;
        if seed_bytes.as_slice() != profile.guest_entropy_seed_file().bytes() {
            return Err(LiveRunnerConfigError::SeedMismatch);
        }

        let launch_definition_digest = launch_definition_digest(
            &profile,
            launch,
            &immutable,
            LaunchDefinitionDigests {
                firmware: &firmware_digest,
                kernel: &kernel_digest,
                initrd: &initrd_digest,
                seed: &seed_digest,
                qemu: &qemu_build_digest,
                plugin: &trace_plugin_build_digest,
            },
        );

        Ok(Self {
            immutable,
            profile,
            cadence_icount: launch.cadence_icount,
            horizon_icount: launch.horizon_icount,
            launch_definition_digest,
            qemu_build_digest,
            trace_plugin_build_digest,
        })
    }

    /// Returns the verified immutable QEMU executable.
    #[must_use]
    pub fn qemu(&self) -> &Path {
        &self.immutable.qemu
    }

    /// Returns the canonical profile's exact vCPU count.
    #[must_use]
    pub fn vcpus(&self) -> u16 {
        self.profile.smp_vcpus()
    }

    /// Returns the digest computed from the complete launch definition.
    #[must_use]
    pub fn launch_definition_digest(&self) -> &str {
        &self.launch_definition_digest
    }

    /// Builds and validates the canonical executable and argv for one attempt.
    ///
    /// The base deterministic surface comes from
    /// [`DeterministicLaunchProfile::canonical_qemu_args`]. This method only
    /// replaces the canonical seed endpoint with its verified concrete path,
    /// then adds firmware, guest images, QMP, and the independent observation
    /// plugin. Serial remains disabled so a host-backed character device cannot
    /// become an input to the guest.
    ///
    /// # Errors
    ///
    /// Returns [`LiveRunnerConfigError`] when an artifact path is not stable
    /// UTF-8, a canonical option is unexpectedly absent, or the completed argv
    /// fails the crate's pre-spawn determinism validator.
    pub fn launch_spec(
        &self,
        kind: LiveRunnerLaunchKind,
        artifacts: &LiveRunnerArtifacts,
    ) -> Result<LiveRunnerLaunchSpec, LiveRunnerConfigError> {
        let qmp = path_file_name_text("qmp_socket", artifacts.qmp_socket())?;
        let trace = path_text(
            "trace",
            match kind {
                LiveRunnerLaunchKind::DefinitionPreflight => artifacts.preflight_trace(),
                LiveRunnerLaunchKind::Observation => artifacts.trace(),
            },
        )?;

        let mut argv = self.profile.canonical_qemu_args();
        replace_unique_option_value(
            &mut argv,
            "-fw_cfg",
            format!(
                "name=opt/crucible/seed,file={}",
                self.immutable.seed_file.display()
            ),
        )?;
        if kind == LiveRunnerLaunchKind::DefinitionPreflight {
            argv.push("-S".to_owned());
        }
        argv.extend([
            "-bios".to_owned(),
            path_text("firmware", &self.immutable.firmware)?.to_owned(),
            "-kernel".to_owned(),
            path_text("kernel", &self.immutable.kernel)?.to_owned(),
            "-initrd".to_owned(),
            path_text("initrd", &self.immutable.initrd)?.to_owned(),
            "-qmp".to_owned(),
            format!("unix:{qmp},server=on,wait=off"),
            "-plugin".to_owned(),
            self.plugin_argument(kind, trace),
            "-no-shutdown".to_owned(),
            "-no-reboot".to_owned(),
        ]);
        validate_pre_spawn_qemu_launch_args(&argv)
            .map_err(LiveRunnerConfigError::PreSpawnValidation)?;

        Ok(LiveRunnerLaunchSpec {
            executable: self.immutable.qemu.clone(),
            argv: argv.into_iter().map(OsString::from).collect(),
        })
    }

    fn plugin_argument(&self, kind: LiveRunnerLaunchKind, trace: &str) -> String {
        let mode = match kind {
            LiveRunnerLaunchKind::DefinitionPreflight => {
                format!("out={trace},definition_only=on,vcpus={}", self.vcpus())
            }
            LiveRunnerLaunchKind::Observation => format!(
                "out={trace},cadence={},stop_at={},extended=on,mem_events=on,rr_switch_events=on,vcpus={}",
                self.cadence_icount,
                self.horizon_icount,
                self.vcpus()
            ),
        };
        format!(
            "{},{mode},launch_digest={},qemu_build_digest={},plugin_build_digest={}",
            self.immutable.trace_plugin.display(),
            self.launch_definition_digest,
            self.qemu_build_digest,
            self.trace_plugin_build_digest
        )
    }

    #[cfg(test)]
    fn from_verified_test_inputs(
        immutable: LiveRunnerImmutableInputs,
        profile: DeterministicLaunchProfile,
        launch: LiveRunnerLaunchFields,
    ) -> Result<Self, LiveRunnerConfigError> {
        validate_sampling(launch)?;
        let launch_definition_digest = "1".repeat(64);
        Ok(Self {
            immutable,
            profile,
            cadence_icount: launch.cadence_icount,
            horizon_icount: launch.horizon_icount,
            launch_definition_digest,
            qemu_build_digest: "2".repeat(64),
            trace_plugin_build_digest: "a".repeat(64),
        })
    }
}

/// Fully constructed process invocation for one attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRunnerLaunchSpec {
    executable: PathBuf,
    argv: Vec<OsString>,
}

impl LiveRunnerLaunchSpec {
    /// Returns the exact executable.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Returns the exact argv tail.
    #[must_use]
    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }
}

/// Invalid immutable or deterministic launch configuration.
#[derive(Debug, Error)]
pub enum LiveRunnerConfigError {
    /// Immutable path is not a normalized Nix store entry descendant.
    #[error("{field} is not a normalized immutable Nix store path: {path}", path = path.display())]
    InvalidStorePath {
        /// Field name.
        field: &'static str,
        /// Rejected path.
        path: PathBuf,
    },
    /// Immutable input was not a regular file.
    #[error("{field} is not a regular file: {path}", path = path.display())]
    NotRegularFile {
        /// Field name.
        field: &'static str,
        /// Rejected path.
        path: PathBuf,
    },
    /// QEMU input was not executable.
    #[error("verified QEMU file is not executable: {path}", path = path.display())]
    NotExecutable {
        /// Rejected path.
        path: PathBuf,
    },
    /// Immutable input could not be inspected or hashed.
    #[error("cannot read {field} at {path}: {source}", path = path.display())]
    FileIo {
        /// Field name.
        field: &'static str,
        /// Input path.
        path: PathBuf,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// Seed bytes differed from the canonical launch profile.
    #[error("seed file bytes differ from the deterministic launch profile")]
    SeedMismatch,
    /// Store path cannot be embedded unambiguously in a comma-delimited option.
    #[error("{field} path contains a comma, newline, carriage return, or NUL: {path}", path = path.display())]
    InvalidEmbeddedOptionPath {
        /// Field name.
        field: &'static str,
        /// Rejected path.
        path: PathBuf,
    },
    /// Numeric field was zero.
    #[error("{field} must be non-zero")]
    Zero {
        /// Field name.
        field: &'static str,
    },
    /// Horizon precedes first cadence sample.
    #[error("horizon icount must be at least the cadence icount")]
    HorizonBeforeCadence,
    /// Canonical profile unexpectedly omitted or duplicated an option.
    #[error("canonical deterministic launch option {option} was not unique")]
    CanonicalOptionNotUnique {
        /// Required unique option.
        option: &'static str,
    },
    /// Path cannot be encoded losslessly in identity material or deterministic argv.
    #[error("{field} path is not stable UTF-8 text: {path}", path = path.display())]
    InvalidTextPath {
        /// Field name.
        field: &'static str,
        /// Rejected path.
        path: PathBuf,
    },
    /// Completed argv failed the shared deterministic validator.
    #[error("live-run argv failed pre-spawn validation: {0}")]
    PreSpawnValidation(QemuPreSpawnLaunchValidationError),
}

fn validate_sampling(launch: LiveRunnerLaunchFields) -> Result<(), LiveRunnerConfigError> {
    if launch.cadence_icount == 0 {
        return Err(LiveRunnerConfigError::Zero {
            field: "cadence_icount",
        });
    }
    if launch.horizon_icount == 0 {
        return Err(LiveRunnerConfigError::Zero {
            field: "horizon_icount",
        });
    }
    if launch.horizon_icount < launch.cadence_icount {
        return Err(LiveRunnerConfigError::HorizonBeforeCadence);
    }
    Ok(())
}

fn validate_stable_text_path(
    field: &'static str,
    path: &Path,
) -> Result<(), LiveRunnerConfigError> {
    let text = path
        .to_str()
        .ok_or_else(|| LiveRunnerConfigError::InvalidTextPath {
            field,
            path: path.to_owned(),
        })?;
    if text.bytes().any(|byte| matches!(byte, b'\n' | b'\r' | 0)) {
        return Err(LiveRunnerConfigError::InvalidTextPath {
            field,
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn validate_embedded_option_path(
    field: &'static str,
    path: &Path,
) -> Result<(), LiveRunnerConfigError> {
    if path
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|byte| matches!(byte, b',' | b'\n' | b'\r' | 0))
    {
        return Err(LiveRunnerConfigError::InvalidEmbeddedOptionPath {
            field,
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn validate_store_path(field: &'static str, path: &Path) -> Result<(), LiveRunnerConfigError> {
    let contains_dot_component = path
        .as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/')
        .any(|component| component == b"." || component == b"..");
    let mut components = path.components();
    let prefix_is_store = matches!(components.next(), Some(Component::RootDir))
        && matches!(components.next(), Some(Component::Normal(value)) if value == "nix")
        && matches!(components.next(), Some(Component::Normal(value)) if value == "store");
    let entry_is_canonical = match components.next() {
        Some(Component::Normal(entry)) => {
            let bytes = entry.as_encoded_bytes();
            bytes.len() > 33
                && bytes[32] == b'-'
                && bytes[..32].iter().all(|byte| is_nix_base32(*byte))
        }
        _ => false,
    };
    let descendants_are_normal =
        components.all(|component| matches!(component, Component::Normal(_)));
    if contains_dot_component || !prefix_is_store || !entry_is_canonical || !descendants_are_normal
    {
        return Err(LiveRunnerConfigError::InvalidStorePath {
            field,
            path: path.to_owned(),
        });
    }
    Ok(())
}

const fn is_nix_base32(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'a'..=b'd'
            | b'f'..=b'h'
            | b'i'..=b'n'
            | b'p'..=b's'
            | b'v'..=b'z'
    )
}

fn hash_store_file(
    field: &'static str,
    path: &Path,
    executable: bool,
) -> Result<String, LiveRunnerConfigError> {
    validate_store_path(field, path)?;
    let resolved = fs::canonicalize(path).map_err(|source| LiveRunnerConfigError::FileIo {
        field,
        path: path.to_owned(),
        source,
    })?;
    validate_store_path(field, &resolved)?;
    let metadata = fs::metadata(path).map_err(|source| LiveRunnerConfigError::FileIo {
        field,
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(LiveRunnerConfigError::NotRegularFile {
            field,
            path: path.to_owned(),
        });
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(LiveRunnerConfigError::NotExecutable {
            path: path.to_owned(),
        });
    }
    let mut file = File::open(path).map_err(|source| LiveRunnerConfigError::FileIo {
        field,
        path: path.to_owned(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| LiveRunnerConfigError::FileIo {
                field,
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(lower_hex(&hasher.finalize()))
}

struct LaunchDefinitionDigests<'a> {
    firmware: &'a str,
    kernel: &'a str,
    initrd: &'a str,
    seed: &'a str,
    qemu: &'a str,
    plugin: &'a str,
}

fn launch_definition_digest(
    profile: &DeterministicLaunchProfile,
    launch: LiveRunnerLaunchFields,
    immutable: &LiveRunnerImmutableInputs,
    digests: LaunchDefinitionDigests<'_>,
) -> String {
    let LaunchDefinitionDigests {
        firmware,
        kernel,
        initrd,
        seed,
        qemu,
        plugin,
    } = digests;
    let material = format!(
        "crucible.qemu.live-fingerprint-launch.v1\n{}\nqemu_path={}\nqemu_sha256={qemu}\nfirmware_path={}\nfirmware_sha256={firmware}\nkernel_path={}\nkernel_sha256={kernel}\ninitrd_path={}\ninitrd_sha256={initrd}\nseed_path={}\nseed_sha256={seed}\ntrace_plugin_path={}\ntrace_plugin_sha256={plugin}\nplugin_cadence={}\nplugin_stop_at={}\nplugin_extended=on\nplugin_mem_events=on\nplugin_rr_switch_events=on\nserial_backend=none\nqmp=unix-server-wait-off\nno_shutdown=true\nno_reboot=true",
        profile.scenario_hash_material(),
        immutable.qemu.display(),
        immutable.firmware.display(),
        immutable.kernel.display(),
        immutable.initrd.display(),
        immutable.seed_file.display(),
        immutable.trace_plugin.display(),
        launch.cadence_icount,
        launch.horizon_icount
    );
    lower_hex(&Sha256::digest(material.as_bytes()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn replace_unique_option_value(
    argv: &mut [String],
    option: &'static str,
    value: String,
) -> Result<(), LiveRunnerConfigError> {
    let indexes: Vec<usize> = argv
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == option).then_some(index))
        .collect();
    if indexes.len() != 1 || indexes[0] + 1 >= argv.len() {
        return Err(LiveRunnerConfigError::CanonicalOptionNotUnique { option });
    }
    argv[indexes[0] + 1] = value;
    Ok(())
}

fn path_text<'a>(field: &'static str, path: &'a Path) -> Result<&'a str, LiveRunnerConfigError> {
    let text = path
        .to_str()
        .ok_or_else(|| LiveRunnerConfigError::InvalidTextPath {
            field,
            path: path.to_owned(),
        })?;
    if text.contains(',') || text.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
        return Err(LiveRunnerConfigError::InvalidTextPath {
            field,
            path: path.to_owned(),
        });
    }
    Ok(text)
}

fn path_file_name_text<'a>(
    field: &'static str,
    path: &'a Path,
) -> Result<&'a str, LiveRunnerConfigError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| LiveRunnerConfigError::InvalidTextPath {
            field,
            path: path.to_owned(),
        })?;
    path_text(field, Path::new(file_name))
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStringExt;

    use super::*;
    use crate::single_vm_fingerprint::live_runner::LiveRunnerArtifactRoot;
    use crate::{IcountShiftSetting, LaunchProfileCandidate};

    fn profile() -> Result<DeterministicLaunchProfile, crate::LaunchProfileError> {
        LaunchProfileCandidate::default()
            .with_memory_mib(128)
            .with_smp_vcpus(4)
            .with_icount_shift(IcountShiftSetting::Fixed(0))
            .with_scenario_seed(0x0010_c016)
            .try_into_deterministic()
    }

    fn config() -> Result<LiveRunnerConfig, Box<dyn Error>> {
        Ok(LiveRunnerConfig::from_verified_test_inputs(
            LiveRunnerImmutableInputs {
                qemu: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-qemu/bin/qemu-system-x86_64"
                    .into(),
                firmware: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-firmware/bios.bin".into(),
                kernel: "/nix/store/cccccccccccccccccccccccccccccccc-kernel/bzImage".into(),
                initrd: "/nix/store/dddddddddddddddddddddddddddddddd-initrd/initrd".into(),
                seed_file: "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-seed/seed.bin".into(),
                trace_plugin: "/nix/store/ffffffffffffffffffffffffffffffff-plugin/lib/plugin.so"
                    .into(),
            },
            profile()?,
            LiveRunnerLaunchFields {
                cadence_icount: 100_000,
                horizon_icount: 1_000_000,
            },
        )?)
    }

    #[test]
    fn observation_argv_extends_canonical_profile() -> Result<(), Box<dyn Error>> {
        let root_path =
            std::env::temp_dir().join(format!("crucible-live-run-config-{}", std::process::id()));
        if root_path.exists() {
            std::fs::remove_dir_all(&root_path)?;
        }
        let artifacts = LiveRunnerArtifactRoot::new(&root_path)?.create_attempt(1)?;
        let config = config()?;
        let spec = config.launch_spec(LiveRunnerLaunchKind::Observation, &artifacts)?;
        let argv = spec.argv();
        let mut canonical = config.profile.canonical_qemu_args();
        replace_unique_option_value(
            &mut canonical,
            "-fw_cfg",
            format!(
                "name=opt/crucible/seed,file={}",
                config.immutable.seed_file.display()
            ),
        )?;
        let canonical: Vec<OsString> = canonical.into_iter().map(OsString::from).collect();
        assert_eq!(&argv[..canonical.len()], canonical);
        assert!(!argv.iter().any(|arg| arg == OsStr::new("-S")));
        assert!(
            argv.windows(2)
                .any(|pair| { pair[0] == OsStr::new("-serial") && pair[1] == OsStr::new("none") })
        );
        assert!(!argv.iter().any(|arg| arg == OsStr::new("-chardev")));
        assert!(argv.windows(2).any(|pair| {
            pair[0] == OsStr::new("-qmp")
                && pair[1] == OsStr::new("unix:qmp.sock,server=on,wait=off")
        }));
        assert_eq!(
            LiveRunnerLaunchKind::Observation.expected_stopped_state(),
            crate::QmpRunStateKind::Paused
        );
        let plugin = argv
            .windows(2)
            .find(|pair| pair[0] == OsStr::new("-plugin"))
            .map(|pair| pair[1].to_string_lossy().into_owned())
            .ok_or("missing plugin argument")?;
        assert!(plugin.contains("cadence=100000,stop_at=1000000"));
        assert!(plugin.contains("extended=on,mem_events=on,rr_switch_events=on,vcpus=4"));
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn preflight_waits_for_qemu_prelaunch_boundary() -> Result<(), Box<dyn Error>> {
        let root_path = std::env::temp_dir().join(format!(
            "crucible-live-preflight-config-{}",
            std::process::id()
        ));
        if root_path.exists() {
            std::fs::remove_dir_all(&root_path)?;
        }
        let artifacts = LiveRunnerArtifactRoot::new(&root_path)?.create_attempt(2)?;
        let spec = config()?.launch_spec(LiveRunnerLaunchKind::DefinitionPreflight, &artifacts)?;
        assert!(spec.argv().iter().any(|arg| arg == OsStr::new("-S")));
        assert!(spec.argv().windows(2).any(|pair| {
            pair[0] == OsStr::new("-qmp")
                && pair[1] == OsStr::new("unix:qmp.sock,server=on,wait=off")
        }));
        assert_eq!(
            LiveRunnerLaunchKind::DefinitionPreflight.expected_stopped_state(),
            crate::QmpRunStateKind::Prelaunch
        );
        assert!(
            spec.argv()
                .iter()
                .any(|arg| arg.to_string_lossy().contains("definition_only=on,vcpus=4"))
        );
        std::fs::remove_dir_all(root_path)?;
        Ok(())
    }

    #[test]
    fn store_path_escape_and_noncanonical_entry_are_rejected() {
        for path in [
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ok/../../tmp/qemu",
            "/nix/store/short-qemu/bin/qemu",
            "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-bad/./seed",
        ] {
            assert!(matches!(
                validate_store_path("input", Path::new(path)),
                Err(LiveRunnerConfigError::InvalidStorePath { .. })
            ));
        }
    }

    #[test]
    fn textual_and_embedded_paths_reject_loss_or_injection() {
        let non_utf8 = PathBuf::from(OsString::from_vec(vec![b'/', 0xff]));
        assert!(matches!(
            validate_stable_text_path("input", &non_utf8),
            Err(LiveRunnerConfigError::InvalidTextPath { .. })
        ));
        assert!(matches!(
            validate_stable_text_path(
                "input",
                Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ok/bad\npath")
            ),
            Err(LiveRunnerConfigError::InvalidTextPath { .. })
        ));
        assert!(matches!(
            validate_embedded_option_path(
                "trace_plugin",
                Path::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ok/plugin,extended=off")
            ),
            Err(LiveRunnerConfigError::InvalidEmbeddedOptionPath { .. })
        ));
    }

    #[test]
    fn sampling_accepts_a_separate_nonperiodic_horizon_boundary() {
        assert!(
            validate_sampling(LiveRunnerLaunchFields {
                cadence_icount: 10,
                horizon_icount: 21,
            })
            .is_ok()
        );
    }

    #[test]
    fn launch_identity_changes_with_immutable_path_or_digest() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let launch = LiveRunnerLaunchFields {
            cadence_icount: 100_000,
            horizon_icount: 1_000_000,
        };
        let baseline = launch_definition_digest(
            &config.profile,
            launch,
            &config.immutable,
            LaunchDefinitionDigests {
                firmware: "1",
                kernel: "2",
                initrd: "3",
                seed: "4",
                qemu: "5",
                plugin: "6",
            },
        );
        let changed_digest = launch_definition_digest(
            &config.profile,
            launch,
            &config.immutable,
            LaunchDefinitionDigests {
                firmware: "1",
                kernel: "2",
                initrd: "3",
                seed: "4",
                qemu: "different",
                plugin: "6",
            },
        );
        let mut changed_inputs = config.immutable.clone();
        changed_inputs.qemu =
            "/nix/store/99999999999999999999999999999999-qemu/bin/qemu-system-x86_64".into();
        let changed_path = launch_definition_digest(
            &config.profile,
            launch,
            &changed_inputs,
            LaunchDefinitionDigests {
                firmware: "1",
                kernel: "2",
                initrd: "3",
                seed: "4",
                qemu: "5",
                plugin: "6",
            },
        );
        assert_ne!(baseline, changed_digest);
        assert_ne!(baseline, changed_path);
        Ok(())
    }
}
