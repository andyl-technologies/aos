//! Failure-artifact reproduction footer tests.

use super::*;

#[test]
pub(super) fn cli_failure_artifact_writer_emits_replay_and_debug_commands()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("artifact dir with spaces");
    let cli = Cli::parse_from([
        "crucible",
        "--artifact-dir",
        artifact_dir.to_str().unwrap_or("."),
        "run",
        TEST_SCENARIO,
    ]);
    let artifact = mock_e2e_reproduction_artifact()?;
    let artifact_bytes = artifact.encode()?;

    let report = write_reproduction_artifact(&cli, &artifact_bytes, "Property Violation")?;

    assert!(report.path.starts_with(temp.path()));
    assert!(report.path.exists());
    assert!(report.footer.replay_command.starts_with("crucible replay "));
    assert!(
        report
            .footer
            .replay_command
            .contains("artifact dir with spaces")
    );
    assert!(report.footer.replay_command.contains('\''));
    assert!(report.footer.debug_command.starts_with("crucible debug "));
    assert!(
        report
            .footer
            .debug_command
            .contains("artifact dir with spaces")
    );
    assert!(report.footer.debug_command.contains('\''));
    assert!(report.footer.debug_command.ends_with(" --at-failure"));
    assert!(report.path.to_string_lossy().contains("property-violation"));
    assert_eq!(
        ReproductionArtifact::decode(&fs::read(&report.path)?)?,
        artifact
    );
    replay_reproduction_artifact(
        &cli,
        &ReplayArgs {
            artifact: report.path.clone(),
            to: None,
            check: None,
            bisect: None,
            bounded_scheduler_preemption: false,
        },
    )?;
    assert_eq!(report.digest, artifact.digest()?);

    Ok(())
}
