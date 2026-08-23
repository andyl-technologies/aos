//! Executes two production live observations at one terminal nonzero horizon.

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::ffi::OsString;
    use std::io;
    use std::path::PathBuf;

    use crucible_qemu::{
        DiskImageMode, GuestBackingStateMode, IcountShiftSetting, LaunchProfileCandidate,
        LiveDefinitionPreflightEvidence, LiveObservationMode, LiveObservationShutdown,
        LiveObservationShutdownPolicy, LiveRunnerArtifactRoot, LiveRunnerConfig,
        LiveRunnerImmutableInputs, LiveRunnerLaunchFields, LiveRunnerQmpPollPolicy,
        LiveRunnerQmpPoller, LiveTerminalHorizonExecutor, LiveTerminalHorizonExecutorError,
        LiveTerminalHorizonReport, QemuTraceFingerprintDefinition, QmpRunStateKind,
        SingleVmFingerprintEventBoundary, SingleVmFingerprintRunOrdinal,
        SingleVmFingerprintRunRequest, SingleVmFingerprintScenario, SingleVmFingerprintTrigger,
        SingleVmHostProfile, SingleVmNvcpuFingerprintContract, ThreadLiveRunnerSleeper,
        TypedLiveRunnerQmpConnector, compare_single_vm_fingerprint_streams,
    };

    const HORIZON_ICOUNT: u64 = 100_000;
    const MEMORY_MIB: u32 = 128;
    const NODE: &str = "live-terminal-horizon-node";
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
        let immutable = LiveRunnerImmutableInputs {
            qemu: args.qemu,
            firmware: args.firmware,
            kernel: args.kernel,
            initrd: args.initrd,
            seed_file: args.seed,
            trace_plugin: args.plugin,
        };
        let config = LiveRunnerConfig::new(
            immutable.clone(),
            profile.clone(),
            LiveRunnerLaunchFields {
                cadence_icount: HORIZON_ICOUNT,
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
        require_state(
            preflight.qmp_observation().run_state.running,
            preflight.qmp_observation().run_state.status,
            &preflight.qmp_observation().cpu_indexes,
            QmpRunStateKind::Prelaunch,
            "definition preflight",
        )?;
        require(
            preflight.shutdown() == LiveObservationShutdown::NaturalExit { success: true },
            "definition preflight did not exit naturally with success",
        )?;

        let definition_digest = QemuTraceFingerprintDefinition::new(
            config.cadence_icount(),
            preflight.imported().observation(),
        )?
        .definition_digest();
        let scenario = build_scenario(&config, definition_digest, NODE)?;
        let continuing_config = LiveRunnerConfig::new(
            immutable,
            profile,
            LiveRunnerLaunchFields {
                cadence_icount: HORIZON_ICOUNT / 2,
                horizon_icount: HORIZON_ICOUNT,
            },
        )?;
        let continuing_root_path = args.artifact_root.join("continuing-rejected");
        let continuing_root = LiveRunnerArtifactRoot::new(continuing_root_path.clone())?;
        let continuing_cadence_rejected = matches!(
            LiveTerminalHorizonExecutor::new(
                continuing_config,
                continuing_root,
                production_poller()?,
                LiveObservationShutdownPolicy::default(),
                preflight.clone(),
                scenario.clone(),
            ),
            Err(LiveTerminalHorizonExecutorError::CadenceBeforeHorizon { .. })
        );
        require(
            continuing_cadence_rejected,
            "a continuing cadence was admitted by the terminal executor",
        )?;
        require(
            !continuing_root_path.join("attempt-00000001").exists(),
            "continuing-cadence rejection allocated a process attempt",
        )?;
        let run_root = LiveRunnerArtifactRoot::new(args.artifact_root.join("runs"))?;
        let mut executor = LiveTerminalHorizonExecutor::new(
            config.clone(),
            run_root,
            production_poller()?,
            LiveObservationShutdownPolicy::default(),
            preflight,
            scenario.clone(),
        )?;

        let first_request = SingleVmFingerprintRunRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::First,
        );
        let second_request = SingleVmFingerprintRunRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::Second,
        );
        let first = executor.run_report(&first_request)?;
        let second = executor.run_report(&second_request)?;
        validate_report(&first, SingleVmFingerprintRunOrdinal::First, 1, &config)?;
        validate_report(&second, SingleVmFingerprintRunOrdinal::Second, 2, &config)?;
        compare_single_vm_fingerprint_streams(first.stream(), second.stream(), HORIZON_ICOUNT)?;

        let fingerprints_equal =
            first.stream().final_fingerprint == second.stream().final_fingerprint;
        let directories_distinct = first.prepared_launch().artifacts().directory()
            != second.prepared_launch().artifacts().directory();
        let controls_distinct = first.control().digest() != second.control().digest();
        let invocations_distinct = first.invocation().digest() != second.invocation().digest();
        let argv_distinct = first.argv_identity().digest() != second.argv_identity().digest();
        require(fingerprints_equal, "terminal horizon fingerprints differed")?;
        require(directories_distinct, "attempt directories were reused")?;
        require(controls_distinct, "observation controls were reused")?;
        require(invocations_distinct, "invocation identities were reused")?;
        require(argv_distinct, "raw argv identities were reused")?;

        let drifted = build_scenario(&config, definition_digest, "other-node")?;
        let drifted_request =
            SingleVmFingerprintRunRequest::new(drifted, SingleVmFingerprintRunOrdinal::First);
        let scenario_drift_rejected = executor.run_report(&drifted_request).is_err();
        require(
            scenario_drift_rejected,
            "a request with scenario identity drift was admitted",
        )?;
        let no_failed_attempt = !args.artifact_root.join("runs/attempt-00000003").exists();
        require(
            no_failed_attempt,
            "a rejected request allocated a process attempt",
        )?;

        println!("PASS");
        println!("preflight_qmp_state=prelaunch");
        println!("preflight_qmp_running=false");
        println!("terminal_first_qmp_state=paused");
        println!("terminal_second_qmp_state=paused");
        println!("terminal_first_qmp_running=false");
        println!("terminal_second_qmp_running=false");
        println!("terminal_first_shutdown=natural-success");
        println!("terminal_second_shutdown=natural-success");
        println!("terminal_single_sample_each=true");
        println!("terminal_sample_icount={HORIZON_ICOUNT}");
        println!("terminal_fingerprints_equal={fingerprints_equal}");
        println!(
            "definition_digest={}",
            lower_hex(&executor.definition_digest())
        );
        println!("fixed_run_digest={}", lower_hex(&config.fixed_run_digest()));
        println!(
            "terminal_final_fingerprint={}",
            lower_hex(&first.stream().final_fingerprint)
        );
        let first_sample = first
            .stream()
            .samples
            .first()
            .ok_or_else(|| io::Error::other("validated terminal sample disappeared"))?;
        println!(
            "terminal_raw_ram_digest={}",
            lower_hex(first_sample.nvcpu_fingerprint.guest_memory_digest())
        );
        println!(
            "terminal_vmstate_digest={}",
            lower_hex(first_sample.nvcpu_fingerprint.device_state_digest())
        );
        println!("terminal_vmstate_export=true");
        println!("fresh_attempt_directories_distinct={directories_distinct}");
        println!("fresh_control_identities_distinct={controls_distinct}");
        println!("fresh_invocation_identities_distinct={invocations_distinct}");
        println!("fresh_raw_argv_identities_distinct={argv_distinct}");
        println!("negative_scenario_drift_rejected={scenario_drift_rejected}");
        println!("no_failed_request_attempt_allocated={no_failed_attempt}");
        println!("continuing_cadence_rejected={continuing_cadence_rejected}");
        println!("second_run_repeat=active");
        println!("vcpu_count={VCPUS}");
        println!("rr_switch_quantum={RR_SWITCH_QUANTUM}");
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
        report: &LiveTerminalHorizonReport,
        ordinal: SingleVmFingerprintRunOrdinal,
        attempt: u32,
        config: &LiveRunnerConfig,
    ) -> Result<(), io::Error> {
        require(
            report.attempt() == attempt,
            "actual attempt sequence drifted",
        )?;
        require(
            report.control().fields().mode
                == LiveObservationMode::ObservationHorizon {
                    cadence_icount: HORIZON_ICOUNT,
                    ordinal,
                },
            "completed process retained the wrong observation mode",
        )?;
        require(
            report.control().fields().attempt == attempt
                && report.control().fields().actual_argv_digest == report.argv_identity().digest(),
            "completed process identities were not mutually bound",
        )?;
        require(
            report.invocation().paths().cwd == report.prepared_launch().artifacts().directory()
                && report.invocation().paths().qmp_socket
                    == report.prepared_launch().artifacts().qmp_socket()
                && report.invocation().argv_digest() == report.argv_identity().digest()
                && report.invocation().stdin_is_null()
                && report.invocation().environment_is_cleared(),
            "invocation evidence did not retain the process boundary",
        )?;
        let process_argv = report.process_argv_contract();
        require(
            process_argv.argc() == report.argv_identity().argc()
                && process_argv.raw_bytes() == report.argv_identity().raw_byte_count()
                && process_argv.digest() == report.argv_identity().digest(),
            "raw process argv attestation was not independently bound",
        )?;
        require_state(
            report.qmp_observation().run_state.running,
            report.qmp_observation().run_state.status,
            &report.qmp_observation().cpu_indexes,
            QmpRunStateKind::Paused,
            "terminal horizon",
        )?;
        require(
            report.shutdown() == LiveObservationShutdown::NaturalExit { success: true },
            "terminal horizon QEMU did not exit naturally with status zero",
        )?;
        let samples = &report.stream().samples;
        require(
            samples.len() == 1,
            "terminal run did not emit exactly one sample",
        )?;
        let sample = samples
            .first()
            .ok_or_else(|| io::Error::other("terminal sample is absent"))?;
        require(
            sample.seq == 0
                && sample.icount == HORIZON_ICOUNT
                && sample.node == NODE
                && sample.trigger
                    == SingleVmFingerprintTrigger::Event(
                        SingleVmFingerprintEventBoundary::HorizonAdvance,
                    ),
            "terminal sample did not bind the exact horizon event",
        )?;
        require(
            sample.nvcpu_fingerprint.vcpu_registers().len() == usize::from(VCPUS)
                && sample.nvcpu_fingerprint.rr_cursor().rr_switch_quantum() == RR_SWITCH_QUANTUM
                && report.stream().final_icount == config.horizon_icount(),
            "terminal sample omitted topology, RR, or final-icount evidence",
        )
    }

    fn require_state(
        running: bool,
        status: QmpRunStateKind,
        cpu_indexes: &[u64],
        expected: QmpRunStateKind,
        label: &str,
    ) -> Result<(), io::Error> {
        require(
            !running && status == expected,
            &format!("{label} was not observed at the expected non-running state"),
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

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
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
            "unexpected trailing live terminal-horizon argument",
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
    eprintln!("the live QEMU terminal-horizon example requires Linux");
    std::process::exit(2);
}
