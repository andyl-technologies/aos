//! Local-QEMU debugger execution rejection tests.

use super::*;

#[test]
pub(super) fn cli_qemu_debug_rejects_unavailable_local_execution_before_probe()
-> Result<(), Box<dyn Error>> {
    struct ForbiddenProbe;

    impl LiveQemuProbeRunner for ForbiddenProbe {
        fn run_probe(
            &mut self,
            _backend: &ResolvedLocalBackend,
        ) -> Result<LiveQemuProbeEvidence, CliError> {
            panic!("an unavailable local debugger must not launch a generic QEMU probe");
        }
    }

    let backend = ResolvedLocalBackend::Qemu {
        qemu: PathBuf::from("/test/qemu"),
        plugin: PathBuf::from("/test/plugin"),
        qemu_build_id: String::from("test-build"),
        qemu_patch_series_hash: String::from("test-patches"),
        plugin_abi: String::from("test-plugin-abi"),
        shmem_abi_version: String::from("test-shmem-abi"),
        qemu_source: QemuDiscoverySource::Flag,
        plugin_source: QemuDiscoverySource::Flag,
    };
    let cli = Cli::parse_from([
        "crucible",
        "--backend",
        "qemu",
        "debug",
        "--session",
        "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("debug command should parse");
    };
    let plan = plan_debug_invocation(&cli, args)?;
    let error = run_local_qemu_debug_workflow_with_probe(&backend, &plan, &mut ForbiddenProbe)
        .expect_err("local debugger execution must fail instead of emitting a plan");
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(
        error
            .to_string()
            .contains("no debug operation was executed")
    );
    assert!(error.to_string().contains("requested_operation=attach-gdb"));
    assert!(error.to_string().contains("target=session:7:12:"));
    Ok(())
}
#[test]
pub(super) fn cli_qemu_debug_rejects_missing_artifact_before_live_probe()
-> Result<(), Box<dyn Error>> {
    struct ForbiddenProbe;

    impl LiveQemuProbeRunner for ForbiddenProbe {
        fn run_probe(
            &mut self,
            _backend: &ResolvedLocalBackend,
        ) -> Result<LiveQemuProbeEvidence, CliError> {
            panic!("artifact validation must precede the live QEMU probe");
        }
    }

    let backend = ResolvedLocalBackend::Qemu {
        qemu: PathBuf::from("/test/qemu"),
        plugin: PathBuf::from("/test/plugin"),
        qemu_build_id: String::from("test-build"),
        qemu_patch_series_hash: String::from("test-patches"),
        plugin_abi: String::from("test-plugin-abi"),
        shmem_abi_version: String::from("test-shmem-abi"),
        qemu_source: QemuDiscoverySource::Flag,
        plugin_source: QemuDiscoverySource::Flag,
    };
    let missing = TempDir::new()?.path().join("missing.crucible");
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("qemu"),
        String::from("debug"),
        missing.display().to_string(),
    ]);
    let Commands::Debug(args) = &cli.command else {
        panic!("debug command should parse");
    };
    let plan = plan_debug_invocation(&cli, args)?;
    let error = run_local_qemu_debug_workflow_with_probe(&backend, &plan, &mut ForbiddenProbe)
        .expect_err("a missing artifact must fail before live probing");

    assert!(matches!(error, CliError::Artifact(_)));
    Ok(())
}
