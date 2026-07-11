//! One-shot preparation of an identity-bound live QEMU invocation.
//!
//! Preparation constructs argv exactly once, hashes its raw Unix bytes, binds
//! observation control and host-visible invocation paths, and retains that same
//! [`LiveRunnerLaunchSpec`] for process spawning. There is no second argv builder
//! on the spawn path.

use thiserror::Error;

use crate::single_vm_fingerprint::{QemuTraceFingerprintImportError, QemuTraceProcessArgvContract};

use super::{
    LiveIdentityError, LiveInvocationIdentity, LiveInvocationPaths, LiveObservationControl,
    LiveObservationControlFields, LiveObservationMode, LiveRunnerArtifacts, LiveRunnerConfig,
    LiveRunnerConfigError, LiveRunnerLaunchKind, LiveRunnerLaunchSpec, RawUnixArgvIdentity,
};

/// Caller-supplied control fields not already fixed by [`LiveRunnerConfig`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePreparationRequest {
    /// Stable scenario node name.
    pub node: String,
    /// Observation mode and its typed cadence/target/ordinal fields.
    pub mode: LiveObservationMode,
    /// Definition digest, absent only while the preflight derives it.
    pub definition_digest: Option<[u8; 32]>,
}

/// Exact launch specification plus all independently computed identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePreparedLaunch {
    kind: LiveRunnerLaunchKind,
    artifacts: LiveRunnerArtifacts,
    spec: LiveRunnerLaunchSpec,
    argv_identity: RawUnixArgvIdentity,
    process_argv_contract: QemuTraceProcessArgvContract,
    control: LiveObservationControl,
    invocation: LiveInvocationIdentity,
    expected_vcpus: u16,
}

impl LivePreparedLaunch {
    /// Builds and identity-binds one exact process invocation.
    ///
    /// The launch spec is constructed once and retained. The raw argv identity,
    /// control identity, and invocation identity all refer to those exact bytes
    /// and artifact paths.
    ///
    /// # Errors
    ///
    /// Returns [`LivePreparationError`] when argv construction fails, the mode
    /// does not match the launch kind/configured cadence, or any canonical
    /// control, argv, or invocation identity is invalid.
    pub fn new(
        config: &LiveRunnerConfig,
        kind: LiveRunnerLaunchKind,
        artifacts: &LiveRunnerArtifacts,
        request: LivePreparationRequest,
    ) -> Result<Self, LivePreparationError> {
        validate_request(config, kind, &request)?;
        let spec = config.launch_spec(kind, artifacts)?;
        let argv_identity = RawUnixArgvIdentity::new(spec.executable().as_os_str(), spec.argv())?;
        let process_argv_contract = QemuTraceProcessArgvContract::new(
            argv_identity.argc(),
            argv_identity.raw_byte_count(),
            argv_identity.digest(),
        )?;
        let invocation = LiveInvocationIdentity::new(
            &argv_identity,
            LiveInvocationPaths {
                cwd: artifacts.directory().to_owned(),
                qmp_socket: artifacts.qmp_socket().to_owned(),
                stdout: artifacts.stdout_log().to_owned(),
                stderr: artifacts.stderr_log().to_owned(),
            },
        )?;
        let control = LiveObservationControl::new(LiveObservationControlFields {
            base_launch_digest: config.base_launch_digest(),
            fixed_run_digest: config.fixed_run_digest(),
            definition_digest: request.definition_digest,
            horizon_icount: config.horizon_icount(),
            node: request.node,
            attempt: artifacts.attempt(),
            actual_argv_digest: argv_identity.digest(),
            mode: request.mode,
        })?;
        Ok(Self {
            kind,
            artifacts: artifacts.clone(),
            spec,
            argv_identity,
            process_argv_contract,
            control,
            invocation,
            expected_vcpus: config.vcpus(),
        })
    }

    /// Returns the launch kind governing the expected QMP boundary.
    #[must_use]
    pub const fn kind(&self) -> LiveRunnerLaunchKind {
        self.kind
    }

    /// Returns the fresh attempt artifacts bound by this launch.
    #[must_use]
    pub const fn artifacts(&self) -> &LiveRunnerArtifacts {
        &self.artifacts
    }

    /// Returns the exact retained executable and argv.
    #[must_use]
    pub const fn spec(&self) -> &LiveRunnerLaunchSpec {
        &self.spec
    }

    /// Returns the independently computed raw argv identity.
    #[must_use]
    pub const fn argv_identity(&self) -> &RawUnixArgvIdentity {
        &self.argv_identity
    }

    /// Returns the independent expectation used to verify QEMU's self-attestation.
    #[must_use]
    pub const fn process_argv_contract(&self) -> QemuTraceProcessArgvContract {
        self.process_argv_contract
    }

    /// Returns the validated observation-control identity.
    #[must_use]
    pub const fn control(&self) -> &LiveObservationControl {
        &self.control
    }

    /// Returns the host-visible process invocation identity.
    #[must_use]
    pub const fn invocation(&self) -> &LiveInvocationIdentity {
        &self.invocation
    }

    /// Returns the exact topology count required from QMP.
    #[must_use]
    pub const fn expected_vcpus(&self) -> u16 {
        self.expected_vcpus
    }
}

fn validate_request(
    config: &LiveRunnerConfig,
    kind: LiveRunnerLaunchKind,
    request: &LivePreparationRequest,
) -> Result<(), LivePreparationError> {
    match (kind, request.mode) {
        (LiveRunnerLaunchKind::DefinitionPreflight, LiveObservationMode::DefinitionPreflight) => {
            Ok(())
        }
        (
            LiveRunnerLaunchKind::Genesis,
            LiveObservationMode::ExactTarget {
                cadence_icount,
                target_icount: 0,
                ..
            },
        ) if cadence_icount == config.cadence_icount() => Ok(()),
        (
            LiveRunnerLaunchKind::Observation,
            LiveObservationMode::ObservationHorizon { cadence_icount, .. },
        ) if cadence_icount == config.cadence_icount() => Ok(()),
        _ => Err(LivePreparationError::ModeMismatch {
            kind,
            mode: request.mode,
            configured_cadence: config.cadence_icount(),
        }),
    }
}

/// Failure while constructing an identity-bound launch.
#[derive(Debug, Error)]
pub enum LivePreparationError {
    /// Exact argv construction failed.
    #[error("live launch configuration failed: {0}")]
    Config(#[from] LiveRunnerConfigError),
    /// A canonical control, argv, or invocation identity was invalid.
    #[error("live launch identity failed: {0}")]
    Identity(#[from] LiveIdentityError),
    /// The independently computed trace-attestation contract was invalid.
    #[error("live launch trace contract failed: {0}")]
    TraceContract(#[from] QemuTraceFingerprintImportError),
    /// Requested observation semantics did not match the launch kind/config.
    #[error(
        "live launch kind {kind:?} does not admit mode {mode:?} with configured cadence {configured_cadence}"
    )]
    ModeMismatch {
        /// Requested process launch kind.
        kind: LiveRunnerLaunchKind,
        /// Requested observation mode.
        mode: LiveObservationMode,
        /// Cadence fixed by the config.
        configured_cadence: u64,
    },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::{
        DiskImageMode, GuestBackingStateMode, IcountShiftSetting, LaunchProfileCandidate,
        LiveRunnerArtifactRoot, LiveRunnerImmutableInputs, LiveRunnerLaunchFields,
        SingleVmFingerprintRunOrdinal,
    };

    fn config() -> Result<LiveRunnerConfig, Box<dyn Error>> {
        let profile = LaunchProfileCandidate::default()
            .with_memory_mib(128)
            .with_smp_vcpus(4)
            .with_icount_shift(IcountShiftSetting::Fixed(0))
            .with_disk_image_mode(DiskImageMode::NoBlockDevice)
            .with_guest_backing_state(GuestBackingStateMode::NoBlockDevice)
            .try_into_deterministic()?;
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
            profile,
            LiveRunnerLaunchFields {
                cadence_icount: 100_000,
                horizon_icount: 1_000_000,
            },
        )?)
    }

    fn artifact_root(label: &str) -> Result<LiveRunnerArtifactRoot, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!("crucible-{label}-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        Ok(LiveRunnerArtifactRoot::new(path)?)
    }

    fn observation_request() -> LivePreparationRequest {
        LivePreparationRequest {
            node: "node-a".to_owned(),
            mode: LiveObservationMode::ObservationHorizon {
                cadence_icount: 100_000,
                ordinal: SingleVmFingerprintRunOrdinal::Second,
            },
            definition_digest: Some([9; 32]),
        }
    }

    #[test]
    fn preparation_hashes_and_retains_the_exact_spawn_spec() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let root = artifact_root("prepared-launch")?;
        let artifacts = root.create_attempt(7)?;
        let prepared = LivePreparedLaunch::new(
            &config,
            LiveRunnerLaunchKind::Observation,
            &artifacts,
            observation_request(),
        )?;
        assert_eq!(
            prepared.spec().executable().as_os_str(),
            prepared.argv_identity().argv0()
        );
        assert_eq!(prepared.spec().argv(), prepared.argv_identity().argv());
        assert_eq!(
            prepared.control().fields().actual_argv_digest,
            prepared.argv_identity().digest()
        );
        assert_eq!(
            prepared.control().fields().base_launch_digest,
            config.base_launch_digest()
        );
        assert_eq!(
            prepared.control().fields().fixed_run_digest,
            config.fixed_run_digest()
        );
        assert_eq!(prepared.control().fields().attempt, 7);
        assert_eq!(prepared.invocation().paths().cwd, artifacts.directory());
        assert_eq!(
            prepared.invocation().paths().qmp_socket,
            artifacts.qmp_socket()
        );
        std::fs::remove_dir_all(root.path())?;
        Ok(())
    }

    #[test]
    fn fresh_attempt_changes_only_attempt_bound_identities() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let root = artifact_root("prepared-attempts")?;
        let first = LivePreparedLaunch::new(
            &config,
            LiveRunnerLaunchKind::Observation,
            &root.create_attempt(1)?,
            observation_request(),
        )?;
        let second = LivePreparedLaunch::new(
            &config,
            LiveRunnerLaunchKind::Observation,
            &root.create_attempt(2)?,
            observation_request(),
        )?;
        assert_eq!(
            first.control().fields().base_launch_digest,
            second.control().fields().base_launch_digest
        );
        assert_eq!(
            first.control().fields().fixed_run_digest,
            second.control().fields().fixed_run_digest
        );
        assert_ne!(
            first.argv_identity().digest(),
            second.argv_identity().digest()
        );
        assert_ne!(first.control().digest(), second.control().digest());
        assert_ne!(first.invocation().digest(), second.invocation().digest());
        std::fs::remove_dir_all(root.path())?;
        Ok(())
    }

    #[test]
    fn preflight_is_independent_and_mode_mismatches_fail_closed() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let root = artifact_root("prepared-preflight")?;
        let preflight = root.create_attempt(1)?;
        let prepared = LivePreparedLaunch::new(
            &config,
            LiveRunnerLaunchKind::DefinitionPreflight,
            &preflight,
            LivePreparationRequest {
                node: "node-a".to_owned(),
                mode: LiveObservationMode::DefinitionPreflight,
                definition_digest: None,
            },
        )?;
        assert!(prepared.control().fields().definition_digest.is_none());

        let observation = root.create_attempt(2)?;
        assert!(matches!(
            LivePreparedLaunch::new(
                &config,
                LiveRunnerLaunchKind::Observation,
                &observation,
                LivePreparationRequest {
                    node: "node-a".to_owned(),
                    mode: LiveObservationMode::ExactTarget {
                        cadence_icount: config.cadence_icount(),
                        target_icount: 500_000,
                        ordinal: SingleVmFingerprintRunOrdinal::First,
                    },
                    definition_digest: Some([9; 32]),
                },
            ),
            Err(LivePreparationError::ModeMismatch { .. })
        ));
        std::fs::remove_dir_all(root.path())?;
        Ok(())
    }

    #[test]
    fn exact_zero_prepares_an_ordinal_bound_non_running_genesis() -> Result<(), Box<dyn Error>> {
        let config = config()?;
        let root = artifact_root("prepared-genesis")?;
        let first = LivePreparedLaunch::new(
            &config,
            LiveRunnerLaunchKind::Genesis,
            &root.create_attempt(1)?,
            LivePreparationRequest {
                node: "node-a".to_owned(),
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: config.cadence_icount(),
                    target_icount: 0,
                    ordinal: SingleVmFingerprintRunOrdinal::First,
                },
                definition_digest: Some([9; 32]),
            },
        )?;
        let second = LivePreparedLaunch::new(
            &config,
            LiveRunnerLaunchKind::Genesis,
            &root.create_attempt(2)?,
            LivePreparationRequest {
                node: "node-a".to_owned(),
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: config.cadence_icount(),
                    target_icount: 0,
                    ordinal: SingleVmFingerprintRunOrdinal::Second,
                },
                definition_digest: Some([9; 32]),
            },
        )?;

        for prepared in [&first, &second] {
            let argv = prepared
                .spec()
                .argv()
                .iter()
                .map(|argument| argument.to_string_lossy())
                .collect::<Vec<_>>();
            assert!(argv.iter().any(|argument| argument == "-S"));
            assert!(argv.iter().any(|argument| {
                argument.contains("definition_only=on")
                    && !argument.contains("stop_at=")
                    && !argument.contains("cadence=")
            }));
            assert_eq!(prepared.kind(), LiveRunnerLaunchKind::Genesis);
            assert_eq!(
                prepared.kind().expected_stopped_state(),
                crate::QmpRunStateKind::Prelaunch
            );
        }
        assert_eq!(
            first.control().fields().mode.ordinal(),
            Some(SingleVmFingerprintRunOrdinal::First)
        );
        assert_eq!(
            second.control().fields().mode.ordinal(),
            Some(SingleVmFingerprintRunOrdinal::Second)
        );
        assert_ne!(
            first.argv_identity().digest(),
            second.argv_identity().digest()
        );
        assert_ne!(first.control().digest(), second.control().digest());

        for (kind, target_icount) in [
            (LiveRunnerLaunchKind::Observation, 0),
            (LiveRunnerLaunchKind::Genesis, 1),
        ] {
            assert!(matches!(
                LivePreparedLaunch::new(
                    &config,
                    kind,
                    &root.create_attempt(target_icount as u32 + 10)?,
                    LivePreparationRequest {
                        node: "node-a".to_owned(),
                        mode: LiveObservationMode::ExactTarget {
                            cadence_icount: config.cadence_icount(),
                            target_icount,
                            ordinal: SingleVmFingerprintRunOrdinal::First,
                        },
                        definition_digest: Some([9; 32]),
                    },
                ),
                Err(LivePreparationError::ModeMismatch { .. })
            ));
        }
        std::fs::remove_dir_all(root.path())?;
        Ok(())
    }
}
