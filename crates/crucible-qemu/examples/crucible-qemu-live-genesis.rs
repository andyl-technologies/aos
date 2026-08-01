//! Executes the production live definition preflight and two genesis probes.

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::ffi::OsString;
    use std::io;
    use std::path::PathBuf;

    use crucible_qemu::{
        DiskImageMode, GuestBackingStateMode, IcountShiftSetting, LaunchProfileCandidate,
        LiveDefinitionPreflightEvidence, LiveGenesisProbeExecutor, LiveGenesisProbeExecutorError,
        LiveGenesisProbeReport, LiveObservationMode, LiveObservationShutdown,
        LiveObservationShutdownPolicy, LiveRunnerArtifactRoot, LiveRunnerConfig,
        LiveRunnerImmutableInputs, LiveRunnerLaunchFields, LiveRunnerQmpPollPolicy,
        LiveRunnerQmpPoller, QemuTraceFingerprintDefinition, QmpRunStateKind,
        SingleVmFingerprintProbeRequest, SingleVmFingerprintRunOrdinal,
        SingleVmFingerprintScenario, SingleVmHostProfile, SingleVmNvcpuFingerprintContract,
        ThreadLiveRunnerSleeper, TypedLiveRunnerQmpConnector,
    };

    const CADENCE_ICOUNT: u64 = 100_000;
    const HORIZON_ICOUNT: u64 = 1_000_000;
    const MEMORY_MIB: u32 = 128;
    const NODE: &str = "live-genesis-node";
    const RR_SWITCH_QUANTUM: u64 = 4096;
    const VCPUS: u16 = 2;

    struct Arguments {
        qemu: PathBuf,
        firmware: PathBuf,
        kernel: PathBuf,
        initrd: PathBuf,
        seed: PathBuf,
        plugin: PathBuf,
        artifact_root: PathBuf,
        kernel_cmdline: String,
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let args = arguments()?;
        let profile = LaunchProfileCandidate::default()
            .with_memory_mib(MEMORY_MIB)
            .with_smp_vcpus(VCPUS)
            .with_rr_switch_quantum(RR_SWITCH_QUANTUM)
            .with_icount_shift(IcountShiftSetting::Fixed(0))
            .with_kernel_cmdline(args.kernel_cmdline)
            .with_disk_image_mode(DiskImageMode::NoBlockDevice)
            .with_guest_backing_state(GuestBackingStateMode::NoBlockDevice)
            .try_into_deterministic()?;
        let config = LiveRunnerConfig::new(
            LiveRunnerImmutableInputs {
                qemu: args.qemu,
                firmware: args.firmware,
                kernel: args.kernel,
                initrd: args.initrd,
                seed_file: args.seed,
                trace_plugin: args.plugin,
            },
            profile,
            LiveRunnerLaunchFields {
                cadence_icount: CADENCE_ICOUNT,
                horizon_icount: HORIZON_ICOUNT,
            },
        )?;

        let preflight_root = LiveRunnerArtifactRoot::new(args.artifact_root.join("preflight"))?;
        let preflight_artifacts = preflight_root.create_attempt(1)?;
        let mut preflight_poller = production_poller()?;
        let preflight = LiveDefinitionPreflightEvidence::execute(
            &config,
            &preflight_artifacts,
            NODE.to_owned(),
            &mut preflight_poller,
            LiveObservationShutdownPolicy::default(),
        )?;
        require_prelaunch(
            preflight.qmp_observation().run_state.running,
            preflight.qmp_observation().run_state.status,
            &preflight.qmp_observation().cpu_indexes,
            "definition preflight",
        )?;
        require(
            preflight.shutdown() == LiveObservationShutdown::NaturalExit { success: true },
            "definition preflight did not retain a natural successful exit",
        )?;

        let definition_digest = QemuTraceFingerprintDefinition::new(
            config.cadence_icount(),
            preflight.imported().observation(),
        )?
        .definition_digest();
        let scenario = build_scenario(&config, definition_digest, NODE)?;
        let probe_root = LiveRunnerArtifactRoot::new(args.artifact_root.join("probes"))?;
        let mut executor = LiveGenesisProbeExecutor::new(
            config.clone(),
            probe_root,
            production_poller()?,
            LiveObservationShutdownPolicy::default(),
            preflight.clone(),
            scenario.clone(),
        )?;
        require(
            executor.definition_digest() == definition_digest,
            "executor changed the independently derived definition digest",
        )?;

        let first_request = SingleVmFingerprintProbeRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::First,
            0,
        )?;
        let second_request = SingleVmFingerprintProbeRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::Second,
            0,
        )?;
        let first = executor.probe_genesis_report(&first_request)?;
        let second = executor.probe_genesis_report(&second_request)?;
        validate_report(&first, SingleVmFingerprintRunOrdinal::First, 1, &config)?;
        validate_report(&second, SingleVmFingerprintRunOrdinal::Second, 2, &config)?;

        let fingerprints_equal =
            first.probe().prefix_fingerprint() == second.probe().prefix_fingerprint();
        require(
            fingerprints_equal,
            "the two actual genesis fingerprints differed",
        )?;
        require(
            first.probe().definition_digest() == second.probe().definition_digest()
                && first.probe().run_inputs_digest() == second.probe().run_inputs_digest(),
            "the two probes did not retain the same verified immutable inputs",
        )?;

        let directories_distinct = first.prepared_launch().artifacts().directory()
            != second.prepared_launch().artifacts().directory();
        let controls_distinct = first.control().digest() != second.control().digest();
        let invocations_distinct = first.invocation().digest() != second.invocation().digest();
        let argv_distinct = first.argv_identity().digest() != second.argv_identity().digest();
        require(
            directories_distinct,
            "actual attempt directories were reused",
        )?;
        require(controls_distinct, "actual observation controls were reused")?;
        require(
            invocations_distinct,
            "actual invocation identities were reused",
        )?;
        require(argv_distinct, "actual raw argv identities were reused")?;

        let nonzero = SingleVmFingerprintProbeRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::First,
            1,
        )?;
        let nonzero_rejected = matches!(
            executor.probe_genesis_report(&nonzero),
            Err(LiveGenesisProbeExecutorError::NonGenesisTarget { target: 1 })
        );
        require(nonzero_rejected, "a nonzero genesis target was admitted")?;

        let drifted = build_scenario(&config, definition_digest, "other-node")?;
        let drifted_request =
            SingleVmFingerprintProbeRequest::new(drifted, SingleVmFingerprintRunOrdinal::First, 0)?;
        let scenario_drift_rejected = matches!(
            executor.probe_genesis_report(&drifted_request),
            Err(LiveGenesisProbeExecutorError::RequestMismatch {
                field: "fixed scenario"
            })
        );
        require(
            scenario_drift_rejected,
            "a request with scenario identity drift was admitted",
        )?;
        let no_failed_attempt = !args.artifact_root.join("probes/attempt-00000003").exists();
        require(
            no_failed_attempt,
            "a rejected request allocated a process attempt",
        )?;

        println!("PASS");
        println!("preflight_qmp_state=prelaunch");
        println!("preflight_qmp_running=false");
        println!("preflight_shutdown=natural-success");
        println!("genesis_first_qmp_state=prelaunch");
        println!("genesis_second_qmp_state=prelaunch");
        println!("genesis_first_qmp_running=false");
        println!("genesis_second_qmp_running=false");
        println!("genesis_first_shutdown=natural-success");
        println!("genesis_second_shutdown=natural-success");
        println!("genesis_fingerprints_equal={fingerprints_equal}");
        println!("fresh_attempt_directories_distinct={directories_distinct}");
        println!("fresh_control_identities_distinct={controls_distinct}");
        println!("fresh_invocation_identities_distinct={invocations_distinct}");
        println!("fresh_raw_argv_identities_distinct={argv_distinct}");
        println!("negative_nonzero_target_rejected={nonzero_rejected}");
        println!("negative_scenario_drift_rejected={scenario_drift_rejected}");
        println!("no_failed_request_attempt_allocated={no_failed_attempt}");
        println!("vcpu_count={VCPUS}");
        println!("rr_switch_quantum={RR_SWITCH_QUANTUM}");
        println!("immutable_inputs=verified-by-live-runner-config");
        println!("genesis_state=actual-all-vcpu-ram-vmstate-rr-import");
        Ok(())
    }

    fn production_poller() -> Result<
        LiveRunnerQmpPoller<TypedLiveRunnerQmpConnector, ThreadLiveRunnerSleeper>,
        Box<dyn Error>,
    > {
        Ok(LiveRunnerQmpPoller::new(
            TypedLiveRunnerQmpConnector,
            ThreadLiveRunnerSleeper,
            LiveRunnerQmpPollPolicy::default(),
        )?)
    }

    fn build_scenario(
        config: &LiveRunnerConfig,
        definition_digest: [u8; 32],
        node: &str,
    ) -> Result<SingleVmFingerprintScenario, Box<dyn Error>> {
        Ok(SingleVmFingerprintScenario::new_with_nvcpu_contract(
            node,
            definition_digest,
            config.horizon_icount(),
            SingleVmNvcpuFingerprintContract::new(
                usize::from(config.vcpus()),
                config.rr_switch_quantum(),
            )?,
            config.verified_run_inputs().to_run_inputs()?,
            SingleVmHostProfile::phase1_adversarial(),
        )?)
    }

    fn validate_report(
        report: &LiveGenesisProbeReport,
        ordinal: SingleVmFingerprintRunOrdinal,
        attempt: u32,
        config: &LiveRunnerConfig,
    ) -> Result<(), io::Error> {
        require(
            report.attempt() == attempt,
            "actual attempt sequence drifted",
        )?;
        require(
            report.probe().ordinal() == ordinal && report.probe().icount() == 0,
            "genesis probe returned the wrong ordinal or instruction target",
        )?;
        require(
            report.control().fields().mode
                == LiveObservationMode::ExactTarget {
                    cadence_icount: config.cadence_icount(),
                    target_icount: 0,
                    ordinal,
                },
            "actual completed process retained the wrong observation control",
        )?;
        require(
            report.control().fields().attempt == attempt
                && report.control().fields().actual_argv_digest == report.argv_identity().digest(),
            "actual completed process identities were not mutually bound",
        )?;
        require(
            report.invocation().paths().cwd == report.prepared_launch().artifacts().directory()
                && report.invocation().paths().qmp_socket
                    == report.prepared_launch().artifacts().qmp_socket()
                && report.invocation().argv_digest() == report.argv_identity().digest()
                && report.invocation().stdin_is_null()
                && report.invocation().environment_is_cleared(),
            "actual invocation evidence did not retain the process boundary",
        )?;
        let process_argv = report.process_argv_contract();
        require(
            process_argv.argc() == report.argv_identity().argc()
                && process_argv.raw_bytes() == report.argv_identity().raw_byte_count()
                && process_argv.digest() == report.argv_identity().digest(),
            "actual raw process argv attestation was not independently bound",
        )?;
        require_prelaunch(
            report.qmp_observation().run_state.running,
            report.qmp_observation().run_state.status,
            &report.qmp_observation().cpu_indexes,
            "genesis probe",
        )?;
        require(
            report.shutdown() == LiveObservationShutdown::NaturalExit { success: true },
            "genesis QEMU did not exit naturally with status zero after typed quit",
        )
    }

    fn require_prelaunch(
        running: bool,
        status: QmpRunStateKind,
        cpu_indexes: &[u64],
        label: &str,
    ) -> Result<(), io::Error> {
        require(
            !running && status == QmpRunStateKind::Prelaunch,
            &format!("{label} was not observed at typed non-running prelaunch"),
        )?;
        require(
            cpu_indexes == [0, 1],
            &format!("{label} did not expose the exact two-vCPU topology"),
        )
    }

    fn require(condition: bool, message: &str) -> Result<(), io::Error> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(message.to_owned()))
        }
    }

    fn arguments() -> Result<Arguments, Box<dyn Error>> {
        let mut values = std::env::args_os().skip(1);
        let qemu = next_path(&mut values, "QEMU")?;
        let firmware = next_path(&mut values, "firmware")?;
        let kernel = next_path(&mut values, "kernel")?;
        let initrd = next_path(&mut values, "initrd")?;
        let seed = next_path(&mut values, "seed")?;
        let plugin = next_path(&mut values, "trace plugin")?;
        let artifact_root = next_path(&mut values, "artifact root")?;
        let kernel_cmdline = values
            .next()
            .ok_or_else(|| io::Error::other("missing kernel command line"))?
            .into_string()
            .map_err(|_| io::Error::other("kernel command line is not UTF-8"))?;
        require(
            values.next().is_none(),
            "unexpected trailing live genesis argument",
        )?;
        Ok(Arguments {
            qemu,
            firmware,
            kernel,
            initrd,
            seed,
            plugin,
            artifact_root,
            kernel_cmdline,
        })
    }

    fn next_path(
        values: &mut impl Iterator<Item = OsString>,
        label: &str,
    ) -> Result<PathBuf, io::Error> {
        values
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other(format!("missing {label} path")))
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the live QEMU genesis executor example requires Linux");
    std::process::exit(2);
}
