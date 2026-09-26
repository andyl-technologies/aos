//! Worked-network campaign recovery against the packaged local S3 service.

use super::*;

#[test]
#[ignore = "requires an exclusive HTTPS Garage service and its process control"]
fn public_worked_network_survives_live_s3_outage_and_credential_expiry()
-> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    let endpoint = std::env::var("CRUCIBLE_S3_TEST_ENDPOINT")?;
    let bucket = std::env::var("CRUCIBLE_S3_TEST_BUCKET")?;
    let prefix = std::env::var("CRUCIBLE_S3_TEST_PREFIX")?;
    let access_key = std::env::var("AWS_ACCESS_KEY_ID")?;
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")?;
    let credentials = fixture._temporary.path().join("s3-credentials.toml");
    write_credentials(&credentials, &access_key, &secret_key, None)?;
    write_store(&fixture, &endpoint, &bucket, &prefix, &credentials)?;

    let generated = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
        ])
        .arg(&fixture.fixture),
        "generate live S3 product fixture",
    )?;
    let manifest = json_path(&generated, "manifest")?;
    let lineage = json_path(&generated, "lineage")?;
    let policy = json_path(&generated, "policy")?;

    let mut service = fixture.start_service(Some(&manifest))?;
    run_json(
        connected_campaign(&fixture)
            .args(["create", CAMPAIGN, "--lineage"])
            .arg(&lineage)
            .arg("--policy")
            .arg(&policy)
            .args(["--start-command", START_COMMAND]),
        "create worked-network campaign on live S3",
    )?;
    let mut parent = (
        CAMPAIGN.to_owned(),
        json_string(&campaign_status(&fixture)?, "snapshot")?,
    );
    let mut retained = vec![(CAMPAIGN, parent.1.clone())];
    for derived in DERIVED_CAMPAIGNS {
        run_json(
            connected_campaign(&fixture).args([
                "derive",
                parent.0.as_str(),
                "--snapshot",
                parent.1.as_str(),
                derived,
            ]),
            "derive live S3 campaign",
        )?;
        let snapshot = json_string(&campaign_status_named(&fixture, derived)?, "snapshot")?;
        parent = (derived.to_owned(), snapshot.clone());
        retained.push((derived, snapshot));
    }
    service.stop()?;
    let retained_placements = json_u64(&fixture.verify_store()?, "placements")?;
    assert!(retained_placements > 0);

    let mut untrusted = command(&["--format", "jsonl", "store", "verify"]);
    untrusted.arg(&fixture.store).env(
        "SSL_CERT_FILE",
        std::env::var("CRUCIBLE_S3_TEST_UNTRUSTED_CA")?,
    );
    let untrusted = output_with_timeout(untrusted, Duration::from_secs(20))?;
    assert!(
        !untrusted.status.success(),
        "untrusted Garage certificate was accepted"
    );

    let mut unavailable = GaragePauseGuard::pause()?;
    let mut verify_during_outage = command(&["--format", "jsonl", "store", "verify"]);
    verify_during_outage.arg(&fixture.store);
    let outage = output_with_timeout(verify_during_outage, Duration::from_secs(20))?;
    assert!(
        !outage.status.success(),
        "unavailable live S3 passed verification"
    );
    unavailable.resume()?;
    assert_eq!(
        json_u64(&fixture.verify_store()?, "placements")?,
        retained_placements
    );

    write_credentials(&credentials, &access_key, &secret_key, Some(1))?;
    let expired = command(&["--format", "jsonl", "store", "credentials", "refresh"])
        .arg(&fixture.store)
        .output()?;
    assert!(!expired.status.success(), "expired credential was accepted");
    assert!(String::from_utf8_lossy(&expired.stderr).contains("S3 credential is expired"));
    let denied_read = command(&["--format", "jsonl", "store", "verify"])
        .arg(&fixture.store)
        .output()?;
    assert!(
        !denied_read.status.success(),
        "expired credential left product storage readable"
    );
    write_credentials(&credentials, &access_key, &secret_key, None)?;
    let refreshed = run_json(
        command(&["--format", "jsonl", "store", "credentials", "refresh"]).arg(&fixture.store),
        "refresh restored live S3 credential",
    )?;
    assert_eq!(
        refreshed["schema"],
        "crucible.cli.store-credential-refresh.v1"
    );
    assert_eq!(
        json_u64(&fixture.verify_store()?, "placements")?,
        retained_placements
    );

    let mut restarted = fixture.start_service(None)?;
    for (name, snapshot) in &retained {
        assert_eq!(
            campaign_status_named(&fixture, name)?["snapshot"],
            snapshot.as_str()
        );
    }
    restarted.stop()?;
    let planned = run_json(
        &mut fixture.gc_command("plan"),
        "plan recovered S3 product GC",
    )?;
    let applied = run_json(
        &mut fixture.gc_command("apply"),
        "apply recovered S3 product GC",
    )?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["apply_status"], "applied");
    let mut reopened = fixture.start_service(None)?;
    for (name, snapshot) in &retained {
        assert_eq!(
            campaign_status_named(&fixture, name)?["snapshot"],
            snapshot.as_str()
        );
    }
    reopened.stop()?;

    println!("live_s3_worked_network_outage_credentials_gc=true");
    Ok(())
}

fn write_credentials(
    path: &Path,
    access_key: &str,
    secret_key: &str,
    expiry: Option<u64>,
) -> Result<(), Box<dyn Error>> {
    let expiry = expiry
        .map(|seconds| format!("expires_at_unix_seconds = {seconds}\n"))
        .unwrap_or_default();
    fs::write(
        path,
        format!(
            "schema = \"crucible.campaign-s3-credentials\"\nversion = 1\naccess_key_id = {access_key:?}\nsecret_access_key = {secret_key:?}\n{expiry}"
        ),
    )?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_store(
    fixture: &FlightFixture,
    endpoint: &str,
    bucket: &str,
    prefix: &str,
    credentials: &Path,
) -> Result<(), Box<dyn Error>> {
    let refs = fixture._temporary.path().join("refs");
    let objects = format!("{prefix}/product-{}", std::process::id());
    fs::write(
        &fixture.store,
        format!(
            r#"schema = "crucible.campaign-repository-store"
version = 2
root = "profile"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}

[[s3_endpoints]]
id = "live-product"
region = "garage"
endpoint_url = {endpoint:?}
force_path_style = true
credential_path = {credentials:?}
maximum_queued_commands = 8
maximum_in_flight_operations = 2
maximum_retained_command_bytes = 134217728
operation_timeout_ms = 1000
strong_cas_conformance = true

[[nodes]]
id = "s3"
[nodes.spec]
kind = "s3"
endpoint = "live-product"
bucket = {bucket:?}
prefix = {objects:?}
maximum_logical_object_bytes = 67108864
multipart_part_bytes = 5242880

[[nodes]]
id = "profile"
[nodes.spec]
kind = "profile-validated"
child = "s3"
policy = "crucible.campaign.object-profile.v1"
"#,
        ),
    )?;
    fs::set_permissions(&fixture.store, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

struct GaragePauseGuard {
    pid: String,
    kill: PathBuf,
    paused: bool,
}

impl GaragePauseGuard {
    fn pause() -> Result<Self, Box<dyn Error>> {
        let mut guard = Self {
            pid: std::env::var("CRUCIBLE_S3_TEST_GARAGE_PID")?,
            kill: PathBuf::from(
                std::env::var_os("CRUCIBLE_S3_TEST_KILL").ok_or("missing kill tool")?,
            ),
            paused: false,
        };
        guard.signal("STOP")?;
        guard.paused = true;
        Ok(guard)
    }

    fn resume(&mut self) -> Result<(), Box<dyn Error>> {
        self.signal("CONT")?;
        self.paused = false;
        Ok(())
    }

    fn signal(&self, name: &str) -> Result<(), Box<dyn Error>> {
        let status = Command::new(&self.kill)
            .args([format!("-{name}"), self.pid.clone()])
            .status()?;
        if !status.success() {
            return Err(format!("cannot send {name} to live Garage service").into());
        }
        Ok(())
    }
}

impl Drop for GaragePauseGuard {
    fn drop(&mut self) {
        if self.paused {
            let _ = self.signal("CONT");
        }
    }
}
