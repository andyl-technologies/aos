//! Real issuer processes, inode ownership, explicit restart and actual UTC use.

use std::io::{BufRead as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::authority_journal::recovery::tests::policy;
use crate::authority_journal::recovery::{self, ClockRecoveryReceipt};

use super::*;

const CHILD_CONFIGURATION: &str = "AOS_TEST_CLOCK_RECOVERY_CONFIGURATION";
const CHILD_RECEIPT: &str = "AOS_TEST_CLOCK_RECOVERY_RECEIPT";

fn actual_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn private_json(path: &Path, value: &impl serde::Serialize) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn configuration(file: &Fixture) -> AuthorityConfiguration {
    let root = file.path.parent().unwrap().parent().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let publisher = root.join("publisher.key");
    let renewal = root.join("renewal.key");
    let seed = root.join("issuer.key");
    for (path, bytes) in [
        (&publisher, [11; 32]),
        (&renewal, [12; 32]),
        (&seed, [13; 32]),
    ] {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    AuthorityConfiguration {
        format_version: 2,
        listen: address,
        journal_file: file.path.clone(),
        installation: file.marker.clone(),
        hub_root: file.boundary.hub_root.clone(),
        hub_sqlite_file: None,
        policy: aos_hub_core::storage_authority::lease::BoundedLeaseRevocationPolicy {
            timing_profile: profile(),
        },
        clock_uncertainty: integer(0),
        clock_commit_latency: integer(1),
        clock_recovery: Some(policy()),
        issuance_enabled: true,
        publisher_key_file: publisher,
        renewal_key_file: renewal,
        signing_seed_file: seed,
        signing_key_id: "fixture-authority-signing-v1".into(),
        tls: None,
    }
}

struct IssuerProcess(Child);

impl IssuerProcess {
    fn start(configuration: &Path, receipt: Option<&Path>) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "authority_server::tests::clock_recovery::issuer_process_child",
                "--nocapture",
            ])
            .env(CHILD_CONFIGURATION, configuration)
            .stdout(Stdio::piped());
        if let Some(receipt) = receipt {
            command.env(CHILD_RECEIPT, receipt);
        } else {
            command.env_remove(CHILD_RECEIPT);
        }
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if line.as_ref().is_ok_and(|line| line == "ISSUER_READY") {
                    let _ = sender.send(());
                }
            }
        });
        let process = Self(child);
        receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        process
    }

    fn stop(&mut self, terminate: bool) {
        if terminate {
            rustix::process::kill_process(
                rustix::process::Pid::from_raw(self.0.id() as i32).unwrap(),
                rustix::process::Signal::TERM,
            )
            .unwrap();
        } else {
            self.0.kill().unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.0.try_wait().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "issuer process did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for IssuerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn issuer_process_child() {
    let Some(path) = std::env::var_os(CHILD_CONFIGURATION) else {
        return;
    };
    let configuration = AuthorityConfiguration::read(Path::new(&path)).unwrap();
    let receipt = std::env::var_os(CHILD_RECEIPT)
        .map(|path| super::super::recovery_operator::read_receipt(Path::new(&path)).unwrap());
    let server =
        AuthorityServer::open_with_clock_resolution(&configuration, receipt.as_ref()).unwrap();
    println!("ISSUER_READY");
    std::io::stdout().flush().unwrap();
    server.serve().await.unwrap();
}

#[tokio::test]
async fn actual_process_lock_reviewed_successor_and_sigkill_preserve_cold_refusal() {
    let file = Fixture::new();
    let configuration = configuration(&file);
    let root = file.path.parent().unwrap().parent().unwrap();
    let config_path = root.join("configuration.json");
    let publication_path = root.join("publication.json");
    let mut initial = publication();
    initial.attestation.as_mut().unwrap().valid_until = actual_now() + 600;
    private_json(&config_path, &configuration);
    private_json(&publication_path, &initial);
    let journal = configuration.initialize(&publication_path).unwrap();
    let original = journal.load().unwrap();

    let mut process = IssuerProcess::start(&config_path, None);
    assert!(journal.inspect_clock_session(&policy()).is_err());
    assert!(AuthorityServer::open(&configuration).is_err());
    process.stop(true);
    assert!(AuthorityServer::open(&configuration).is_err());
    let after_stop = journal.load().unwrap();
    assert_eq!(after_stop.publication, original.publication);
    assert_eq!(
        after_stop.journal.last_sequence,
        original.journal.last_sequence
    );

    // Wait for actual UTC to pass the retained conservative interval. There is
    // no future helper time, SQL floor rewrite or automatic session clearing.
    let inspected = journal.inspect_clock_session(&policy()).unwrap();
    let safe = inspected
        .expected_ceiling
        .get()
        .max(inspected.expected_head.journal.largest_issued_expiry.get())
        + 2;
    let wait_deadline = Instant::now() + Duration::from_secs(8);
    while actual_now() < safe {
        assert!(Instant::now() < wait_deadline);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Strict operator inputs start from this genuinely private trusted CWD,
    // including in sandboxes whose absolute filesystem root has a foreign owner.
    // TempDir returns an absolute path; preserve explicit relative aliases for
    // reads while the output API keeps its absolute descriptor-pinned parent.
    let transfer = tempfile::tempdir_in(".").unwrap();
    std::fs::set_permissions(transfer.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let relative = PathBuf::from(transfer.path().file_name().unwrap());
    let absolute = transfer.path().canonicalize().unwrap();
    let plan_path = relative.join("plan.json");
    let policy_path = relative.join("recovery-policy.json");
    let reviewer_path = relative.join("independent-reviewer.key");
    let review_path = relative.join("review.json");
    let receipt_path = relative.join("receipt.json");
    private_json(&policy_path, &policy());
    std::fs::write(&reviewer_path, [37; 32]).unwrap();
    std::fs::set_permissions(&reviewer_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    super::super::recovery_operator::inspect(&configuration, &absolute.join("plan.json")).unwrap();
    super::super::recovery_operator::sign(
        &policy_path,
        &plan_path,
        &reviewer_path,
        &absolute.join("review.json"),
    )
    .unwrap();
    let occupied_output = absolute.join("occupied-output.json");
    private_json(&occupied_output, &"retain this existing file");
    let existing_bytes = std::fs::read(&occupied_output).unwrap();
    assert!(super::super::recovery_operator::resolve(
        &configuration,
        &review_path,
        &occupied_output
    )
    .is_err());
    assert_eq!(std::fs::read(&occupied_output).unwrap(), existing_bytes);
    assert!(AuthorityServer::open(&configuration).is_err());
    super::super::recovery_operator::resolve(
        &configuration,
        &review_path,
        &absolute.join("receipt.json"),
    )
    .unwrap();
    let receipt: ClockRecoveryReceipt =
        recovery::decode(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(
        receipt.review.plan.expected_head,
        after_stop.head().unwrap()
    );
    assert!(AuthorityServer::open(&configuration).is_err());
    let mut successor = IssuerProcess::start(&config_path, Some(&receipt_path));
    assert!(journal.inspect_clock_session(&policy()).is_err());
    assert!(AuthorityServer::open_with_clock_resolution(&configuration, Some(&receipt)).is_err());

    let now = actual_now();
    let request = IssuerRequest {
        protocol_version: 1,
        installation: file.marker.clone(),
        nonce: "a".repeat(64),
        issued_at: integer(now),
        expires_at: integer(now + 30),
        operation: IssuerOperation::Issue {
            cohort: cohort(&initial),
            requested_not_after: integer(now + 30),
        },
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    let signature = sign_issuer_request(&StorageWorkKey::new([12; 32]).unwrap(), &bytes).unwrap();
    let client = reqwest::Client::new();
    let address = format!("http://{}{}", configuration.listen, ISSUER_CONTROL_PATH);
    let deadline = Instant::now() + Duration::from_secs(5);
    let response = loop {
        match client
            .post(&address)
            .header(ISSUER_SIGNATURE_HEADER, &signature)
            .body(bytes.clone())
            .send()
            .await
        {
            Ok(response) => break response,
            Err(_) => {
                assert!(Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    assert_eq!(response.status(), StatusCode::OK);
    let reply = response.bytes().await.unwrap();
    let public = ed25519_dalek::SigningKey::from_bytes(&[13; 32])
        .verifying_key()
        .to_bytes();
    let verifier =
        EpochLeaseVerifier::from_bytes(configuration.signing_key_id.clone(), &public).unwrap();
    let reply = verify_issuer_reply_at_time(&verifier, &request, &reply, || {
        Ok(LeaseClock {
            observed_at: actual_now(),
            uncertainty: 2,
        })
    })
    .unwrap();
    assert!(reply.lease.is_some());
    assert_eq!(reply.current.journal.last_sequence.get(), 1);
    let consumer_clock = LeaseClock {
        observed_at: actual_now(),
        uncertainty: 2,
    };
    let key = "managed/binding/objects/recovered";
    let floor = aos_hub_core::storage_authority::lease::EpochLeaseFloor::initialize_fresh_guard(
        initial.authority.clone(),
        file.marker.executor_identity.clone(),
        key.into(),
        &profile(),
        consumer_clock,
    )
    .unwrap();
    verifier
        .validate_lease(
            reply.lease.as_ref().unwrap().as_bytes(),
            &cohort(&initial),
            &profile(),
            &floor,
            key,
            aos_hub_core::storage_authority::lease::LeaseEffect::Put,
            consumer_clock,
        )
        .unwrap();

    successor.stop(false);
    assert!(AuthorityServer::open_with_clock_resolution(&configuration, Some(&receipt)).is_err());
    assert!(AuthorityServer::open(&configuration).is_err());
    let final_state = journal.load().unwrap();
    assert_eq!(final_state.journal.last_sequence.get(), 1);
    assert_eq!(
        final_state.journal.largest_issued_expiry,
        reply.current.journal.largest_issued_expiry
    );
    assert_eq!(final_state.publication, initial);
    let next = journal.inspect_clock_session(&policy()).unwrap();
    let review = recovery::ClockRecoveryReview::sign(next, &policy(), &[37; 32]).unwrap();
    assert!(
        journal.resolve_clock_session(&policy(), &review).is_err(),
        "old issued lease window must close before another recovery"
    );
}
