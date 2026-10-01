//! Exercises complete zero invocation reports before publication inventory succeeds.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::process::Command;

use anyhow::Result;
use tempfile::TempDir;

#[test]
fn local_inventory_errors_report_zero_without_contacting_the_hub() -> Result<()> {
    let fixture = TempDir::new()?;
    let root = fixture.path().join("surface");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("web"))?;
    std::fs::write(root.join("web/content.json"), b"changed")?;

    let malformed = fixture.path().join("malformed.json");
    std::fs::write(&malformed, b"{")?;
    let pinned = fixture.path().join("pinned.json");
    std::fs::write(
        &pinned,
        serde_json::to_vec(&serde_json::json!({
            "registry": "fixture/main",
            "generation": "a".repeat(64),
            "refsDigest": "b".repeat(64),
            "defaultCommit": "c".repeat(40),
            "parentPublicationId": "",
            "objects": []
        }))?,
    )?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let hub = format!("http://{}", listener.local_addr()?);
    let missing = fixture.path().join("missing");
    let cases = [
        (&missing, None, "publication root"),
        (&root, Some(&malformed), "decoding publication manifest"),
        (
            &root,
            Some(&pinned),
            "does not exactly match the pinned surface",
        ),
    ];

    for (root, manifest, error) in cases {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aos"));
        command.args([
            "--json",
            "hub",
            "registry",
            "publish",
            "upload",
            "fixture/main",
        ]);
        command.arg("--root").arg(root).arg("--hub").arg(&hub);
        command.args(["--token", "local-inventory-test"]);
        if let Some(manifest) = manifest {
            command.arg("--manifest").arg(manifest);
        }
        let output = command.output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;

        assert!(!output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains(error), "{stdout}\n{stderr}");
        let reports = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("Direct upload client: "))
            .collect::<Vec<_>>();
        assert_eq!(reports.len(), 1, "{stderr}");
        assert_eq!(
            reports[0],
            "caps=0 begin=0 status=0 grant=0 report=0 complete=0 abort=0 identity=0 \
             manifest_begin=0 manifest_append=0 manifest_seal=0 commit=0 metadata_read=0 \
             provider_attempts=0 provider_successes=0 acknowledged_bytes=0 max_provider_active=0"
        );
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    }
    Ok(())
}
