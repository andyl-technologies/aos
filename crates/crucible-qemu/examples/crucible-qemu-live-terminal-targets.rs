//! Exercises isolated terminal observations at several exact nonzero targets.

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::ffi::OsString;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread::{self, JoinHandle};

    use crucible_qemu::{
        DiskImageMode, GuestBackingStateMode, IcountShiftSetting, LaunchProfileCandidate,
        LiveDefinitionPreflightEvidence, LiveObservationMode, LiveObservationShutdown,
        LiveObservationShutdownPolicy, LiveRunnerArtifactRoot, LiveRunnerConfig,
        LiveRunnerImmutableInputs, LiveRunnerLaunchFields, LiveRunnerQmpPollPolicy,
        LiveRunnerQmpPoller, LiveTerminalTargetExecutor, LiveTerminalTargetExecutorError,
        LiveTerminalTargetReport, QemuTraceFingerprintDefinition, QmpRunStateKind,
        SingleVmFingerprintEventBoundary, SingleVmFingerprintProbeRequest,
        SingleVmFingerprintRunOrdinal, SingleVmFingerprintScenario, SingleVmFingerprintTrigger,
        SingleVmHostProfile, SingleVmNvcpuFingerprintContract, ThreadLiveRunnerSleeper,
        TypedLiveRunnerQmpConnector,
    };

    const CADENCE_ICOUNT: u64 = 25_000;
    const HORIZON_ICOUNT: u64 = 100_000;
    const MEMORY_MIB: u32 = 128;
    const MID_TARGET: u64 = 50_001;
    const NODE: &str = "live-terminal-targets-node";
    const RR_SWITCH_QUANTUM: u64 = 4096;
    const TARGETS: [u64; 3] = [1, MID_TARGET, HORIZON_ICOUNT];
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
        require_qmp(
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
        let scenario = build_scenario(&config, definition_digest, NODE, HORIZON_ICOUNT)?;
        let run_root = LiveRunnerArtifactRoot::new(args.artifact_root.join("runs"))?;
        let mut executor = LiveTerminalTargetExecutor::new(
            config.clone(),
            run_root,
            production_poller()?,
            LiveObservationShutdownPolicy::default(),
            preflight,
            scenario.clone(),
        )?;
        require(
            executor.definition_digest() == definition_digest,
            "executor changed the independently derived definition digest",
        )?;

        let mut first = Vec::with_capacity(TARGETS.len());
        for target in TARGETS {
            let request = SingleVmFingerprintProbeRequest::new(
                scenario.clone(),
                SingleVmFingerprintRunOrdinal::First,
                target,
            )?;
            first.push(executor.observe_report(&request)?);
        }

        let second_requests = TARGETS.map(|target| {
            SingleVmFingerprintProbeRequest::new(
                scenario.clone(),
                SingleVmFingerprintRunOrdinal::Second,
                target,
            )
        });
        let [
            second_one_request,
            second_mid_request,
            second_horizon_request,
        ] = second_requests;
        let host_load = HostLoad::start(4)?;
        let host_work_before = host_load.work_count();
        let second_one = executor.observe_report(&second_one_request?);
        let second_mid = executor.observe_report(&second_mid_request?);
        let second_horizon = executor.observe_report(&second_horizon_request?);
        let host_work_after = host_load.work_count();
        let host_load_work_observed = host_work_after > host_work_before;
        host_load.stop()?;
        require(
            host_load_work_observed,
            "host-load workers performed no measured work during the second ordinal",
        )?;
        let second = vec![second_one?, second_mid?, second_horizon?];

        for (index, target) in TARGETS.into_iter().enumerate() {
            validate_report(
                &first[index],
                SingleVmFingerprintRunOrdinal::First,
                u32::try_from(index + 1)?,
                target,
                &config,
            )?;
            validate_report(
                &second[index],
                SingleVmFingerprintRunOrdinal::Second,
                u32::try_from(index + 4)?,
                target,
                &config,
            )?;
        }

        let all_reports = first.iter().chain(second.iter()).collect::<Vec<_>>();
        let same_target_fingerprints_equal =
            first.iter().zip(second.iter()).all(|(left, right)| {
                left.observation().target_icount() == right.observation().target_icount()
                    && left.observation().state_fingerprint()
                        == right.observation().state_fingerprint()
            });
        require(
            same_target_fingerprints_equal,
            "same-target isolated state fingerprints differed across ordinals",
        )?;
        let controls = all_reports
            .iter()
            .map(|report| report.control().digest())
            .collect::<Vec<_>>();
        let invocations = all_reports
            .iter()
            .map(|report| report.invocation().digest())
            .collect::<Vec<_>>();
        let argv = all_reports
            .iter()
            .map(|report| report.argv_identity().digest())
            .collect::<Vec<_>>();
        let directories = all_reports
            .iter()
            .map(|report| report.prepared_launch().artifacts().directory())
            .collect::<Vec<_>>();
        let controls_distinct = all_unique(&controls);
        let invocations_distinct = all_unique(&invocations);
        let argv_distinct = all_unique(&argv);
        let directories_distinct = all_unique(&directories);
        let exact_targets_distinct = [&first, &second].into_iter().all(|ordinal_reports| {
            ordinal_reports
                .iter()
                .map(|report| report.observation().target_icount())
                .eq(TARGETS)
                && all_unique(
                    &ordinal_reports
                        .iter()
                        .map(|report| report.observation().target_icount())
                        .collect::<Vec<_>>(),
                )
                && all_unique(
                    &ordinal_reports
                        .iter()
                        .map(|report| report.control().digest())
                        .collect::<Vec<_>>(),
                )
                && all_unique(
                    &ordinal_reports
                        .iter()
                        .map(|report| report.argv_identity().digest())
                        .collect::<Vec<_>>(),
                )
        });
        let publication_import_all = all_reports.iter().all(|report| {
            let sample = report.observation().sample();
            report.prepared_launch().artifacts().trace().is_file()
                && sample.seq == 0
                && sample.icount == report.observation().target_icount()
                && sample.nvcpu_fingerprint.vcpu_registers().len() == usize::from(VCPUS)
        });
        let qmp_paused_all = all_reports.iter().all(|report| {
            !report.qmp_observation().run_state.running
                && report.qmp_observation().run_state.status == QmpRunStateKind::Paused
                && report.qmp_observation().cpu_indexes == [0, 1]
        });
        let shutdown_natural_all = all_reports.iter().all(|report| {
            report.shutdown() == LiveObservationShutdown::NaturalExit { success: true }
        });
        let definition_and_run_inputs_fixed = all_reports.iter().all(|report| {
            report.observation().definition_digest() == &definition_digest
                && report.observation().run_inputs_digest() == &config.fixed_run_digest()
                && report.control().fields().definition_digest == Some(definition_digest)
                && report.control().fields().fixed_run_digest == config.fixed_run_digest()
        });
        let state_fingerprints = first
            .iter()
            .map(|report| report.observation().state_fingerprint())
            .collect::<Vec<_>>();
        let ram_digests = first
            .iter()
            .map(|report| {
                report
                    .observation()
                    .sample()
                    .nvcpu_fingerprint
                    .guest_memory_digest()
            })
            .collect::<Vec<_>>();
        let vmstate_digests = first
            .iter()
            .map(|report| {
                report
                    .observation()
                    .sample()
                    .nvcpu_fingerprint
                    .device_state_digest()
            })
            .collect::<Vec<_>>();
        let target_state_fingerprints_distinct =
            all_nonzero(&state_fingerprints) && all_unique(&state_fingerprints);
        let target_guest_memory_component_digests_nonconstant =
            all_nonzero(&ram_digests) && !all_equal(&ram_digests);
        let target_device_state_component_digests_nonconstant =
            all_nonzero(&vmstate_digests) && !all_equal(&vmstate_digests);
        require(controls_distinct, "terminal controls were reused")?;
        require(invocations_distinct, "terminal invocations were reused")?;
        require(argv_distinct, "terminal raw argv identities were reused")?;
        require(
            directories_distinct,
            "terminal attempt directories were reused",
        )?;
        require(
            exact_targets_distinct,
            "distinct targets did not retain distinct target, control, and argv identities",
        )?;
        require(
            publication_import_all,
            "terminal trace publication or strict import evidence was absent",
        )?;
        require(qmp_paused_all, "terminal typed QMP evidence drifted")?;
        require(
            shutdown_natural_all,
            "terminal shutdown evidence was not natural success",
        )?;
        require(
            definition_and_run_inputs_fixed,
            "definition or verified run inputs drifted across terminal observations",
        )?;
        require(
            target_state_fingerprints_distinct,
            "isolated target state fingerprints were zero or not distinct",
        )?;
        require(
            target_guest_memory_component_digests_nonconstant,
            "target guest-memory component digests were zero or constant across targets",
        )?;
        require(
            target_device_state_component_digests_nonconstant,
            "target device-state component digests were zero or constant across targets",
        )?;

        let zero = SingleVmFingerprintProbeRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::First,
            0,
        )?;
        let zero_rejected = matches!(
            executor.observe_report(&zero),
            Err(LiveTerminalTargetExecutorError::GenesisTarget)
        );
        require(zero_rejected, "terminal executor admitted target zero")?;

        let overshoot_scenario =
            build_scenario(&config, definition_digest, NODE, HORIZON_ICOUNT + 1)?;
        let overshoot = SingleVmFingerprintProbeRequest::new(
            overshoot_scenario,
            SingleVmFingerprintRunOrdinal::First,
            HORIZON_ICOUNT + 1,
        )?;
        let overshoot_rejected = matches!(
            executor.observe_report(&overshoot),
            Err(LiveTerminalTargetExecutorError::TargetBeyondHorizon {
                target: 100_001,
                horizon: HORIZON_ICOUNT,
            })
        );
        require(
            overshoot_rejected,
            "terminal executor admitted an overshoot",
        )?;

        let drifted = build_scenario(&config, definition_digest, "other-node", HORIZON_ICOUNT)?;
        let drifted_request = SingleVmFingerprintProbeRequest::new(
            drifted,
            SingleVmFingerprintRunOrdinal::First,
            MID_TARGET,
        )?;
        let scenario_drift_rejected = matches!(
            executor.observe_report(&drifted_request),
            Err(LiveTerminalTargetExecutorError::RequestMismatch {
                field: "fixed scenario"
            })
        );
        require(
            scenario_drift_rejected,
            "terminal executor admitted scenario identity drift",
        )?;
        let no_rejected_attempt = !args.artifact_root.join("runs/attempt-00000007").exists();
        require(
            no_rejected_attempt,
            "a rejected terminal request allocated an attempt",
        )?;

        println!("PASS");
        println!("preflight_qmp_state=prelaunch");
        println!("preflight_qmp_running=false");
        println!("preflight_shutdown=natural-success");
        println!(
            "terminal_qmp_state_all={}",
            if qmp_paused_all { "paused" } else { "invalid" }
        );
        println!("terminal_qmp_running_all={}", !qmp_paused_all);
        println!(
            "terminal_shutdown_all={}",
            if shutdown_natural_all {
                "natural-success"
            } else {
                "invalid"
            }
        );
        println!("terminal_publication_import_all={publication_import_all}");
        println!(
            "terminal_sample_icounts={}",
            first
                .iter()
                .map(|report| report.observation().sample().icount.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        println!("same_target_state_fingerprints_equal={same_target_fingerprints_equal}");
        println!("exact_targets_distinct={exact_targets_distinct}");
        println!("target_state_fingerprints_distinct={target_state_fingerprints_distinct}");
        println!(
            "target_guest_memory_component_digests_nonconstant={target_guest_memory_component_digests_nonconstant}"
        );
        println!(
            "target_device_state_component_digests_nonconstant={target_device_state_component_digests_nonconstant}"
        );
        println!("fresh_attempt_directories_distinct={directories_distinct}");
        println!("fresh_control_identities_distinct={controls_distinct}");
        println!("fresh_invocation_identities_distinct={invocations_distinct}");
        println!("fresh_raw_argv_identities_distinct={argv_distinct}");
        println!("negative_zero_target_rejected={zero_rejected}");
        println!("negative_overshoot_rejected={overshoot_rejected}");
        println!("negative_scenario_drift_rejected={scenario_drift_rejected}");
        println!("no_rejected_request_attempt_allocated={no_rejected_attempt}");
        println!("definition_digest={}", lower_hex(&definition_digest));
        println!("fixed_run_digest={}", lower_hex(&config.fixed_run_digest()));
        for (label, report) in ["target_1", "target_50001", "target_100000"]
            .into_iter()
            .zip(first.iter())
        {
            let sample = report.observation().sample();
            println!(
                "{label}_state_fingerprint={}",
                lower_hex(report.observation().state_fingerprint())
            );
            println!(
                "{label}_guest_memory_component_digest={}",
                lower_hex(sample.nvcpu_fingerprint.guest_memory_digest())
            );
            println!(
                "{label}_device_state_component_digest={}",
                lower_hex(sample.nvcpu_fingerprint.device_state_digest())
            );
        }
        println!("definition_and_run_inputs_fixed={definition_and_run_inputs_fixed}");
        println!("second_ordinal_host_load_work_observed={host_load_work_observed}");
        println!(
            "second_ordinal_host_load_work_delta={}",
            host_work_after - host_work_before
        );
        println!("vcpu_count={VCPUS}");
        println!("rr_switch_quantum={RR_SWITCH_QUANTUM}");
        println!(
            "scope=isolated-current-state-target-foundation-not-cumulative-prefix-or-refinement"
        );
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
        horizon: u64,
    ) -> Result<SingleVmFingerprintScenario, Box<dyn Error>> {
        Ok(SingleVmFingerprintScenario::new_with_nvcpu_contract(
            node,
            definition_digest,
            horizon,
            SingleVmNvcpuFingerprintContract::new(
                usize::from(config.vcpus()),
                config.rr_switch_quantum(),
            )?,
            config.verified_run_inputs().to_run_inputs()?,
            SingleVmHostProfile::phase1_adversarial(),
        )?)
    }

    fn validate_report(
        report: &LiveTerminalTargetReport,
        ordinal: SingleVmFingerprintRunOrdinal,
        attempt: u32,
        target: u64,
        config: &LiveRunnerConfig,
    ) -> Result<(), io::Error> {
        require(
            report.attempt() == attempt,
            "actual terminal attempt sequence drifted",
        )?;
        require(
            report.observation().ordinal() == ordinal
                && report.observation().target_icount() == target
                && report.observation().node() == NODE
                && report.observation().definition_digest()
                    == &report.control().fields().definition_digest.ok_or_else(|| {
                        io::Error::other("terminal control omitted definition digest")
                    })?
                && report.observation().run_inputs_digest() == &config.fixed_run_digest(),
            "terminal observation changed target, ordinal, node, definition, or run inputs",
        )?;
        require(
            report.control().fields().mode
                == LiveObservationMode::ExactTarget {
                    cadence_icount: CADENCE_ICOUNT,
                    target_icount: target,
                    ordinal,
                },
            "completed process retained the wrong exact-target mode",
        )?;
        require(
            report.control().fields().attempt == attempt
                && report.control().fields().actual_argv_digest == report.argv_identity().digest(),
            "completed terminal identities were not mutually bound",
        )?;
        require(
            report.invocation().paths().cwd == report.prepared_launch().artifacts().directory()
                && report.invocation().paths().qmp_socket
                    == report.prepared_launch().artifacts().qmp_socket()
                && report.invocation().argv_digest() == report.argv_identity().digest()
                && report.invocation().stdin_is_null()
                && report.invocation().environment_is_cleared(),
            "terminal invocation did not retain the process boundary",
        )?;
        let process_argv = report.process_argv_contract();
        require(
            process_argv.argc() == report.argv_identity().argc()
                && process_argv.raw_bytes() == report.argv_identity().raw_byte_count()
                && process_argv.digest() == report.argv_identity().digest(),
            "terminal raw process argv attestation was not bound",
        )?;
        require_qmp(
            report.qmp_observation().run_state.running,
            report.qmp_observation().run_state.status,
            &report.qmp_observation().cpu_indexes,
            QmpRunStateKind::Paused,
            "terminal target",
        )?;
        require(
            report.shutdown() == LiveObservationShutdown::NaturalExit { success: true },
            "terminal QEMU did not exit naturally after typed quit",
        )?;
        let sample = report.observation().sample();
        require(
            sample.seq == 0
                && sample.icount == target
                && sample.node == NODE
                && sample.trigger
                    == SingleVmFingerprintTrigger::Event(
                        SingleVmFingerprintEventBoundary::HorizonAdvance,
                    ),
            "terminal import did not retain one exact target sample",
        )?;
        require(
            sample.nvcpu_fingerprint.vcpu_registers().len() == usize::from(VCPUS)
                && sample.nvcpu_fingerprint.rr_cursor().rr_switch_quantum() == RR_SWITCH_QUANTUM,
            "terminal sample omitted topology or RR evidence",
        )
    }

    fn require_qmp(
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

    fn all_unique<T: PartialEq>(values: &[T]) -> bool {
        values
            .iter()
            .enumerate()
            .all(|(index, value)| !values[..index].contains(value))
    }

    fn all_equal<T: PartialEq>(values: &[T]) -> bool {
        values
            .first()
            .is_some_and(|first| values.iter().all(|value| value == first))
    }

    fn all_nonzero(values: &[&[u8]]) -> bool {
        !values.is_empty()
            && values
                .iter()
                .all(|bytes| !bytes.is_empty() && bytes.iter().any(|byte| *byte != 0))
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

    struct HostLoad {
        stop: Arc<AtomicBool>,
        work: Arc<AtomicU64>,
        workers: Vec<JoinHandle<()>>,
    }

    impl HostLoad {
        fn start(worker_count: usize) -> Result<Self, io::Error> {
            let stop = Arc::new(AtomicBool::new(false));
            let work = Arc::new(AtomicU64::new(0));
            let ready = Arc::new(Barrier::new(worker_count + 1));
            let workers = (0..worker_count)
                .map(|_| {
                    let stop = Arc::clone(&stop);
                    let work = Arc::clone(&work);
                    let ready = Arc::clone(&ready);
                    thread::spawn(move || {
                        ready.wait();
                        while !stop.load(Ordering::Relaxed) {
                            work.fetch_add(1, Ordering::Relaxed);
                            std::hint::spin_loop();
                        }
                    })
                })
                .collect();
            ready.wait();
            for _ in 0..10_000 {
                if work.load(Ordering::Relaxed) >= u64::try_from(worker_count).unwrap_or(u64::MAX) {
                    return Ok(Self {
                        stop,
                        work,
                        workers,
                    });
                }
                thread::yield_now();
            }
            stop.store(true, Ordering::Relaxed);
            for worker in workers {
                let _ = worker.join();
            }
            Err(io::Error::other(
                "host-load workers did not publish readiness work",
            ))
        }

        fn work_count(&self) -> u64 {
            self.work.load(Ordering::Relaxed)
        }

        fn stop(self) -> Result<(), io::Error> {
            self.stop.store(true, Ordering::Relaxed);
            for worker in self.workers {
                worker
                    .join()
                    .map_err(|_| io::Error::other("host-load worker panicked"))?;
            }
            Ok(())
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
            "unexpected trailing live terminal-target argument",
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
    eprintln!("the live QEMU terminal-target example requires Linux");
    std::process::exit(2);
}
