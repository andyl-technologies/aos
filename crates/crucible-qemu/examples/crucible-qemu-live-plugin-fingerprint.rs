//! Runs the production live single-VM fingerprint gate with the Rust plugin.
//!
//! Boots the patched QEMU binary with the real Rust control plugin loaded and
//! `fingerprint=on`, drives the shared-memory quantum hot path to a fixed
//! ascending cadence of aggregate-icount targets, reads the black-box
//! fingerprint sample the plugin publishes at each boundary, and runs the whole
//! scenario twice (the second run under host CPU load) through
//! `run_single_vm_fingerprint_gate`. It then exercises the instruction-exact
//! probe backend at one interior icount and asserts the two fixed runs are
//! byte-identical there. Prints machine-checkable evidence the phase2 gate
//! asserts.
//!
//! ```text
//! CRUCIBLE_FP_SECOND_RUN_LOAD  "0" disables second-run host load (default on)
//! CRUCIBLE_FP_TIMEOUT_SECS     per-quantum host wait bound (default 240)
//! CRUCIBLE_FP_PROBE_ICOUNT     interior probe icount (default 6000000)
//! CRUCIBLE_FP_DIVERGENCE_DUMP  "1" enables the live mismatch/dump negative control
//! ```

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match linux::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-plugin-fingerprint: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-plugin-fingerprint runs on Linux only");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::ffi::OsString;
    use std::time::Duration;

    use crucible::ContentHash;
    use crucible_qemu::{
        PLUGIN_FINGERPRINT_TARGET_ICOUNTS, PluginFingerprintRunner, PluginFingerprintRunnerConfig,
        SingleVmFingerprintGateError, SingleVmFingerprintGateReport,
        SingleVmFingerprintProbeRequest, SingleVmFingerprintProbeRunner,
        SingleVmFingerprintRunInputs, SingleVmFingerprintRunOrdinal, SingleVmFingerprintScenario,
        SingleVmHostProfile, SingleVmNvcpuFingerprintContract, run_single_vm_fingerprint_gate,
    };

    /// Default vCPU count when `CRUCIBLE_FP_SMP_VCPUS` is unset.
    ///
    /// The single-VM (M1) gate leaves it unset and pins one vCPU. The multi-vCPU
    /// (M3) gate sets it to the launched `-smp N` so the plugin drives the
    /// aggregate-icount clock across `N` vCPUs and samples every vCPU's register
    /// file into the fingerprint.
    const DEFAULT_VCPU_COUNT: u16 = 1;
    /// Default guest memory in MiB when `CRUCIBLE_FP_MEMORY_MIB` is unset.
    const DEFAULT_MEMORY_MIB: u32 = 64;
    const RR_SWITCH_QUANTUM: u64 = 4096;
    /// Content-addressing domain for the example's synthetic run-input digests.
    const INPUT_DOMAIN: &str = "crucible.rust-plugin-fingerprint-example-inputs.v1";

    pub(super) fn run() -> Result<(), String> {
        let mut args = env::args_os();
        let program = args
            .next()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("crucible-qemu-live-plugin-fingerprint"));
        let qemu = required(&mut args, &program)?;
        let plugin = required(&mut args, &program)?;
        let kernel = required(&mut args, &program)?;
        let firmware = required(&mut args, &program)?;
        let run_directory = required(&mut args, &program)?;
        let initrd = args.next();
        let kernel_cmdline = args.next();
        if args.next().is_some() {
            return Err(usage(&program));
        }

        let second_run_host_load = env_flag("CRUCIBLE_FP_SECOND_RUN_LOAD", true)?;
        let timeout_secs = env_u64("CRUCIBLE_FP_TIMEOUT_SECS", 240)?;
        let probe_icount = env_u64("CRUCIBLE_FP_PROBE_ICOUNT", 6_000_000)?;
        let vcpu_count = env_u16("CRUCIBLE_FP_SMP_VCPUS", DEFAULT_VCPU_COUNT)?;
        let divergence_dump = env_flag("CRUCIBLE_FP_DIVERGENCE_DUMP", false)?;
        let memory_mib = u32::try_from(env_u64(
            "CRUCIBLE_FP_MEMORY_MIB",
            u64::from(DEFAULT_MEMORY_MIB),
        )?)
        .map_err(|_| String::from("CRUCIBLE_FP_MEMORY_MIB exceeds u32"))?;

        let mut config =
            PluginFingerprintRunnerConfig::new(&qemu, &plugin, &kernel, &firmware, &run_directory)
                .map_err(|error| error.to_string())?
                .with_completion_timeout(Duration::from_secs(timeout_secs))
                .with_second_run_host_load(second_run_host_load)
                .with_second_run_divergence_control(divergence_dump)
                .with_smp_vcpus(vcpu_count)
                .with_memory_mib(memory_mib);
        let kernel_cmdline_text = match &kernel_cmdline {
            Some(cmdline) => {
                let cmdline = cmdline.to_string_lossy().into_owned();
                config = config.with_kernel_cmdline(cmdline.clone());
                cmdline
            }
            None => String::new(),
        };
        if let Some(initrd) = &initrd {
            config = config.with_initrd(initrd);
        }

        let mut runner =
            PluginFingerprintRunner::new(config, RR_SWITCH_QUANTUM).map_err(|e| e.to_string())?;
        let definition_digest = runner.definition_digest();
        let definition_domain = runner.definition().domain().to_owned();
        let run_horizon_icount = runner.definition().run_horizon_icount();

        let run_inputs = build_run_inputs(&qemu, &firmware, &kernel_cmdline_text)?;
        let nvcpu_contract =
            SingleVmNvcpuFingerprintContract::new(usize::from(vcpu_count), RR_SWITCH_QUANTUM)
                .map_err(|error| error.to_string())?;
        let scenario = SingleVmFingerprintScenario::new_with_nvcpu_contract(
            "rust-plugin-fingerprint-vm",
            definition_digest.to_vec(),
            run_horizon_icount,
            nvcpu_contract,
            run_inputs,
            SingleVmHostProfile::phase1_adversarial(),
        )
        .map_err(|error| error.to_string())?;

        if divergence_dump {
            return run_divergence_dump_negative_control(&mut runner, &scenario);
        }

        let report = run_single_vm_fingerprint_gate(&mut runner, &scenario)
            .map_err(|error| error.to_string())?;

        // Instruction-exact probe attestation: both fixed runs must produce a
        // byte-identical cumulative prefix at an interior icount. Equality here
        // is the launch-identity attestation for the refinement backend.
        let probe_equal = attest_probe_equality(&mut runner, &scenario, probe_icount)?;

        let sample_targets = PLUGIN_FINGERPRINT_TARGET_ICOUNTS
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");

        // Aggregate-clock + per-component determinism evidence: every busy-window
        // boundary's aggregate node icount must equal its exact target (the
        // raw-vs-logical regression guard), and each component the fingerprint
        // folds in (per-vCPU registers, RR cursor, guest-RAM digest, device-state
        // digest) must be byte-identical across the two runs.
        let evidence = nvcpu_evidence(&report)?;

        println!("PASS");
        println!("fingerprint_authority=rust-plugin");
        println!("definition_domain={definition_domain}");
        println!("definition_digest={}", hex(&definition_digest));
        println!("scenario_id={}", report.scenario_id);
        println!("sample_count={}", report.sample_count);
        println!("sample_target_icounts={sample_targets}");
        println!("run_horizon_icount={run_horizon_icount}");
        println!("vcpu_count={vcpu_count}");
        println!("memory_mib={memory_mib}");
        println!("rr_switch_quantum={RR_SWITCH_QUANTUM}");
        println!(
            "matching_final_fingerprint={}",
            hex(&report.matching_final_fingerprint)
        );
        println!("deterministic_run_twice=true");
        println!("second_run_host_load={second_run_host_load}");
        println!("probe_prefix_equal_at_{probe_icount}={probe_equal}");
        println!("probe_count={}", runner.probe_count());
        for line in &evidence.per_sample_lines {
            println!("{line}");
        }
        println!(
            "aggregate_icount_equals_target={}",
            evidence.aggregate_icount_equals_target
        );
        println!(
            "rr_cursor_matches_run_twice={}",
            evidence.rr_cursor_matches_run_twice
        );
        println!(
            "per_vcpu_registers_match_run_twice={}",
            evidence.registers_match_run_twice
        );
        println!(
            "guest_ram_digest_matches_run_twice={}",
            evidence.ram_digest_matches_run_twice
        );
        println!(
            "device_state_digest_matches_run_twice={}",
            evidence.device_state_digest_matches_run_twice
        );
        Ok(())
    }

    fn run_divergence_dump_negative_control(
        runner: &mut PluginFingerprintRunner,
        scenario: &SingleVmFingerprintScenario,
    ) -> Result<(), String> {
        let error = run_single_vm_fingerprint_gate(runner, scenario)
            .err()
            .ok_or_else(|| String::from("divergence negative control unexpectedly matched"))?;
        let SingleVmFingerprintGateError::Mismatch { bisection, .. } = error else {
            return Err(format!(
                "divergence negative control did not produce a validated mismatch: {error}"
            ));
        };
        let dump = bisection.state_dump();
        println!("PASS");
        println!("divergence_negative_control=true");
        println!(
            "first_different_icount={}",
            bisection.first_different_icount()
        );
        println!(
            "state_dump_content_address={}",
            bisection.state_dump_content_address()
        );
        println!(
            "first_vcpu_register_files={}",
            dump.first().vcpu_registers().len()
        );
        println!(
            "second_vcpu_register_files={}",
            dump.second().vcpu_registers().len()
        );
        println!(
            "paired_differing_memory_regions={}",
            dump.first().differing_memory_regions().len()
        );
        println!(
            "first_device_state_bytes={}",
            dump.first().device_state().len()
        );
        println!(
            "second_device_state_bytes={}",
            dump.second().device_state().len()
        );
        println!("both_side_raw_state_dump=true");
        Ok(())
    }

    /// Probes both fixed runs at `icount` and returns whether the prefixes match.
    fn attest_probe_equality(
        runner: &mut PluginFingerprintRunner,
        scenario: &SingleVmFingerprintScenario,
        icount: u64,
    ) -> Result<bool, String> {
        let first_request = SingleVmFingerprintProbeRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::First,
            icount,
        )
        .map_err(|error| error.to_string())?;
        let second_request = SingleVmFingerprintProbeRequest::new(
            scenario.clone(),
            SingleVmFingerprintRunOrdinal::Second,
            icount,
        )
        .map_err(|error| error.to_string())?;
        let first = runner
            .probe_single_vm_fingerprint(&first_request)
            .map_err(|error| error.to_string())?;
        let second = runner
            .probe_single_vm_fingerprint(&second_request)
            .map_err(|error| error.to_string())?;
        Ok(first.prefix_fingerprint() == second.prefix_fingerprint())
    }

    /// Aggregate-clock and per-component determinism evidence at `-smp N`.
    struct NvcpuEvidence {
        /// One `sample[i]` line per boundary: aggregate icount + RR cursor + N.
        per_sample_lines: Vec<String>,
        /// Every boundary's aggregate node icount equals its exact busy-window
        /// target: the regression guard for the raw-vs-logical aggregation hazard
        /// (no idle-jump offset leaks into a busy-window aggregate accounting).
        aggregate_icount_equals_target: bool,
        /// The two runs produced the same round-robin cursor at every boundary.
        rr_cursor_matches_run_twice: bool,
        /// The two runs produced identical per-vCPU register digests everywhere.
        registers_match_run_twice: bool,
        /// The two runs produced identical guest-RAM digests everywhere.
        ram_digest_matches_run_twice: bool,
        /// The two runs produced identical device-state digests everywhere.
        device_state_digest_matches_run_twice: bool,
    }

    /// Extracts the M3 aggregate-clock and per-component determinism evidence.
    ///
    /// Under single-threaded RR icount QEMU keeps one global instruction counter,
    /// so there is no per-vCPU retired count to sum (the introspection stamp is a
    /// deterministic constant); the per-vCPU progress that exists is the RR cursor
    /// (`current_vcpu`, `position_in_quantum`). The raw-vs-logical regression guard
    /// is therefore that each busy-window boundary's aggregate node icount equals
    /// its exact target, and the per-vCPU evidence is the deterministic RR cursor.
    fn nvcpu_evidence(report: &SingleVmFingerprintGateReport) -> Result<NvcpuEvidence, String> {
        let first = &report.first_stream.samples;
        let second = &report.second_stream.samples;
        if first.len() != second.len() {
            return Err(format!(
                "run-twice sample counts differ: {} vs {}",
                first.len(),
                second.len()
            ));
        }
        let mut per_sample_lines = Vec::with_capacity(first.len());
        let mut aggregate_icount_equals_target = true;
        let mut rr_cursor_matches_run_twice = true;
        let mut registers_match_run_twice = true;
        let mut ram_digest_matches_run_twice = true;
        let mut device_state_digest_matches_run_twice = true;
        for (index, (first_sample, second_sample)) in first.iter().zip(second).enumerate() {
            if PLUGIN_FINGERPRINT_TARGET_ICOUNTS.get(index) != Some(&first_sample.icount) {
                aggregate_icount_equals_target = false;
            }
            let cursor = first_sample.nvcpu_fingerprint.rr_cursor();
            if cursor != second_sample.nvcpu_fingerprint.rr_cursor() {
                rr_cursor_matches_run_twice = false;
            }
            let registers = first_sample.nvcpu_fingerprint.vcpu_registers();
            if registers != second_sample.nvcpu_fingerprint.vcpu_registers() {
                registers_match_run_twice = false;
            }
            if first_sample.nvcpu_fingerprint.guest_memory_digest()
                != second_sample.nvcpu_fingerprint.guest_memory_digest()
            {
                ram_digest_matches_run_twice = false;
            }
            if first_sample.nvcpu_fingerprint.device_state_digest()
                != second_sample.nvcpu_fingerprint.device_state_digest()
            {
                device_state_digest_matches_run_twice = false;
            }
            per_sample_lines.push(format!(
                "sample[{index}]_aggregate_icount={} rr_current_vcpu={} rr_position_in_quantum={} vcpu_register_count={}",
                first_sample.icount,
                cursor.current_vcpu(),
                cursor.position_in_quantum(),
                registers.len(),
            ));
        }
        Ok(NvcpuEvidence {
            per_sample_lines,
            aggregate_icount_equals_target,
            rr_cursor_matches_run_twice,
            registers_match_run_twice,
            ram_digest_matches_run_twice,
            device_state_digest_matches_run_twice,
        })
    }

    /// Builds valid, content-addressed synthetic run inputs for the scenario.
    ///
    /// The fingerprint stream comparison is what certifies determinism; the run
    /// inputs only need to be valid canonical-width digests shared by both runs.
    fn build_run_inputs(
        qemu: &OsString,
        firmware: &OsString,
        kernel_cmdline: &str,
    ) -> Result<SingleVmFingerprintRunInputs, String> {
        let guest_image_digest = input_digest("guest-image", firmware);
        let seed_digest = input_digest("seed", qemu);
        let injected_input_sequence_digest = input_digest_str("injected", "empty-input-sequence");
        let launch_definition_digest = input_digest_str("launch", "rust-plugin-fingerprint-launch");
        SingleVmFingerprintRunInputs::new(
            guest_image_digest,
            kernel_cmdline.to_owned(),
            seed_digest,
            injected_input_sequence_digest,
            launch_definition_digest,
        )
        .map_err(|error| error.to_string())
    }

    fn input_digest(kind: &str, value: &OsString) -> Vec<u8> {
        input_digest_str(kind, &value.to_string_lossy())
    }

    fn input_digest_str(kind: &str, value: &str) -> Vec<u8> {
        ContentHash::from_canonical_material(INPUT_DOMAIN, &format!("{kind}={value}"))
            .bytes
            .to_vec()
    }

    fn required(args: &mut env::ArgsOs, program: &str) -> Result<OsString, String> {
        args.next().ok_or_else(|| usage(program))
    }

    fn usage(program: &str) -> String {
        format!(
            "usage: {program} <qemu> <plugin> <kernel> <firmware> <run-dir> [initrd] [kernel-cmdline]"
        )
    }

    fn env_flag(name: &str, default: bool) -> Result<bool, String> {
        match env::var(name) {
            Ok(value) => match value.as_str() {
                "1" | "true" => Ok(true),
                "0" | "false" => Ok(false),
                other => Err(format!("{name} must be 0/1/true/false, got `{other}`")),
            },
            Err(env::VarError::NotPresent) => Ok(default),
            Err(error) => Err(format!("cannot read {name}: {error}")),
        }
    }

    fn env_u64(name: &str, default: u64) -> Result<u64, String> {
        match env::var(name) {
            Ok(value) => value
                .parse()
                .map_err(|error| format!("{name} must be a u64: {error}")),
            Err(env::VarError::NotPresent) => Ok(default),
            Err(error) => Err(format!("cannot read {name}: {error}")),
        }
    }

    fn env_u16(name: &str, default: u16) -> Result<u16, String> {
        match env::var(name) {
            Ok(value) => value
                .parse()
                .map_err(|error| format!("{name} must be a u16: {error}")),
            Err(env::VarError::NotPresent) => Ok(default),
            Err(error) => Err(format!("cannot read {name}: {error}")),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }
}
