//! Exact-binary rejection tests for forged systemd descriptor activation.

use std::os::unix::process::CommandExt as _;
use std::process::{Command, Output, Stdio};

use rustix::io::{FdFlags, fcntl_setfd};

const LAUNCH_MODE: &str = "AOS_GUARDIAN_TEST_LAUNCH_MODE";
const ACTIVATION_NAMES: &str = "broker-plan-policy.cbor:broker-plan-public-key:broker-revocation-scope:ownership-lease-policy.cbor:ownership-lease-public-key:node-id:broker-plan.cbor:broker-plan-signature.cbor:ownership-lease.cbor:ownership-lease-signature.cbor";

#[test]
fn exact_binary_rejects_a_forged_complete_tuple_with_missing_descriptors() {
    if std::env::var(LAUNCH_MODE).ok().as_deref() == Some("missing") {
        exec_guardian("10", ACTIVATION_NAMES);
    }

    let output = run_launcher("missing");
    assert_rejected_activation(output);
}

#[test]
fn exact_binary_rejects_a_forged_descriptor_name_set() {
    if std::env::var(LAUNCH_MODE).ok().as_deref() == Some("names") {
        exec_guardian("10", "broker-plan-policy.cbor:wrong");
    }

    let output = run_launcher("names");
    assert_rejected_activation(output);
}

#[test]
fn exact_binary_rejects_an_extra_inherited_descriptor() {
    if std::env::var(LAUNCH_MODE).ok().as_deref() == Some("extra") {
        let inherited = (0..11)
            .map(|_| {
                let file = std::fs::File::open("/dev/null")
                    .unwrap_or_else(|error| panic!("cannot open inherited fixture: {error}"));
                fcntl_setfd(&file, FdFlags::empty())
                    .unwrap_or_else(|error| panic!("cannot preserve inherited fixture: {error}"));
                file
            })
            .collect::<Vec<_>>();
        assert_eq!(inherited.len(), 11);
        exec_guardian("10", ACTIVATION_NAMES);
    }

    let output = run_launcher("extra");
    assert_rejected_activation(output);
}

fn run_launcher(mode: &str) -> Output {
    Command::new(
        std::env::current_exe()
            .unwrap_or_else(|error| panic!("cannot locate activation test binary: {error}")),
    )
    .args([
        "--exact",
        match mode {
            "missing" => "exact_binary_rejects_a_forged_complete_tuple_with_missing_descriptors",
            "names" => "exact_binary_rejects_a_forged_descriptor_name_set",
            "extra" => "exact_binary_rejects_an_extra_inherited_descriptor",
            _ => panic!("unknown launcher mode"),
        },
        "--nocapture",
    ])
    .env(LAUNCH_MODE, mode)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .unwrap_or_else(|error| panic!("cannot run activation launcher: {error}"))
}

fn exec_guardian(listen_fds: &str, listen_fdnames: &str) -> ! {
    let guardian = env!("CARGO_BIN_EXE_aos-sandbox-guardian");
    let error = Command::new(guardian)
        .env(
            "LISTEN_PID",
            rustix::process::getpid().as_raw_nonzero().get().to_string(),
        )
        .env("LISTEN_FDS", listen_fds)
        .env("LISTEN_FDNAMES", listen_fdnames)
        .env(
            "AOS_GUARDIAN_INCARNATION",
            "01010101010101010101010101010101",
        )
        .env("STATE_DIRECTORY", "/invalid-before-state-access")
        .env("NOTIFY_SOCKET", "/invalid-before-notification")
        .exec();
    panic!("cannot exec exact Guardian binary: {error}")
}

fn assert_rejected_activation(output: Output) {
    assert!(
        !output.status.success(),
        "forged activation unexpectedly passed"
    );
    let stderr = String::from_utf8(output.stderr)
        .unwrap_or_else(|error| panic!("Guardian stderr is not UTF-8: {error}"));
    assert!(
        stderr.contains("invalid guardian descriptor activation"),
        "unexpected Guardian rejection: {stderr:?}"
    );
}
