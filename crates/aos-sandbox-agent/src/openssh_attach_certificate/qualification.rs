//! Profile and root-monitor qualification against the packaged OpenSSH daemon.
//!
//! This ignored fixture runs only in the dedicated minimal VM. It installs
//! public claims and the real gate binary. A final bounded monitor fixture
//! inspects actual authentication custody and confined native pipe transport
//! on the existing Guest socket path. Fixture descriptors are not production
//! I/O authority or qualification of the Controller/Host/Guest held consume.

use std::fs;
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};
use ssh_key::{LineEnding, PrivateKey, certificate::Builder, private::Ed25519Keypair};

use super::*;
use crate::openssh_gate::OpenSshGateBindingV1;
use crate::openssh_gate_linux::{RunningOpenSshGateV1, expected_openssh_gate_config_v1};

const DIRECTORY: &str = "/etc/aos/sandbox-attach";
const FIXTURE_DIRECTORY: &str = "/run/aos-attach-profile-qualification";
const GATE: &str = "/usr/libexec/aos-sandbox-exec-gate";

struct OwnedProcess(Child);

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn key(seed: u8) -> PrivateKey {
    PrivateKey::new(Ed25519Keypair::from_seed(&[seed; 32]).into(), "").unwrap()
}

fn protected_file(path: impl AsRef<Path>, bytes: &[u8], mode: u32) {
    fs::write(path.as_ref(), bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write_claim(claim: &OpenSshGateClaimV1) {
    protected_file(
        format!("{DIRECTORY}/gate-record.json"),
        &serde_json::to_vec(claim).unwrap(),
        0o644,
    );
}

fn process_start_ticks(pid: u32) -> u64 {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    stat.rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

fn builder(claim: &OpenSshGateClaimV1, after: u64, before: u64) -> Builder {
    let binding = &claim.binding;
    let mut builder = Builder::new(
        [16; 32],
        key(17).public_key().key_data().clone(),
        after,
        before,
    )
    .unwrap();
    builder
        .key_id(public_attach_certificate_key_id_v1(
            &binding.attach_operation_id,
            &binding.execution_id,
            &binding.incarnation_id,
            &binding.principal_id,
            &binding.audit_id,
        ))
        .unwrap();
    builder.valid_principal(&binding.user).unwrap();
    builder
}

fn with_command(mut builder: Builder, claim: &OpenSshGateClaimV1) -> Builder {
    let binding = &claim.binding;
    builder
        .critical_option(
            "force-command",
            public_attach_force_command_v1(
                &binding.attach_operation_id,
                &binding.execution_id,
                &binding.incarnation_id,
                binding.assignment_epoch,
                &binding.principal_id,
                &binding.audit_id,
            ),
        )
        .unwrap();
    builder.extension("permit-pty", "").unwrap();
    builder
}

fn certificate(builder: Builder) -> String {
    builder.sign(&key(8)).unwrap().to_openssh().unwrap()
}

fn callback(chroot: &str, encoded: &str, uid: u32, extra: Option<&str>) -> Output {
    let (kind, base64) = encoded.split_once(' ').unwrap();
    let mut command = Command::new(chroot);
    command.args([
        &format!("--userspec=+{uid}:+{uid}"),
        "--groups=",
        "/",
        GATE,
        "--authorized-principals",
        kind,
        base64,
    ]);
    if let Some(extra) = extra {
        command.arg(extra);
    }
    command.output().unwrap()
}

fn assert_callback_denial(output: Output) {
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn ssh_command(ssh: &str, certificate: &str) -> Command {
    let certificate_path = PathBuf::from(format!("{FIXTURE_DIRECTORY}/holder-cert.pub"));
    protected_file(&certificate_path, certificate.as_bytes(), 0o644);
    let mut command = Command::new(ssh);
    command
        .args([
            "-v",
            "-F",
            "/dev/null",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            &format!("-oUserKnownHostsFile={FIXTURE_DIRECTORY}/known_hosts"),
            "-oGlobalKnownHostsFile=/dev/null",
            "-oIdentitiesOnly=yes",
            "-oIdentityAgent=none",
            &format!("-oCertificateFile={}", certificate_path.display()),
            "-oConnectTimeout=5",
            "-i",
            &format!("{FIXTURE_DIRECTORY}/holder"),
            "-p",
            "2222",
            "aos_exec@127.0.0.1",
            "true",
        ])
        .stdin(Stdio::null());
    command
}

fn ssh_authentication(ssh: &str, certificate: &str, expected: bool) {
    let output = ssh_command(ssh, certificate).output().unwrap();
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    let authenticated = diagnostic.contains("Authenticated to 127.0.0.1")
        && diagnostic.contains("using \"publickey\"");
    assert_eq!(
        authenticated, expected,
        "SSH authentication outcome differs"
    );
    if !expected {
        assert!(diagnostic.contains("Permission denied (publickey)"));
    }
    // The administrator's fixed command cannot run `true` or transfer I/O:
    // this fixture deliberately has no process bridge to serve a descriptor.
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!Path::new("/run/aos-sandbox-agent/exec-gate.sock").exists());
}

#[test]
#[ignore = "requires the dedicated root-owned minimal VM and packaged OpenSSH"]
fn packaged_sshd_enforces_profile_and_confined_original_ticket_relay() {
    assert_eq!(
        std::env::var("AOS_ATTACH_PROFILE_QUALIFICATION").unwrap(),
        "1"
    );
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let gate_package = std::env::var("AOS_ATTACH_PROFILE_GATE").unwrap();
    let ssh = std::env::var("AOS_ATTACH_PROFILE_SSH").unwrap();
    let chroot = std::env::var("AOS_ATTACH_PROFILE_CHROOT").unwrap();
    let sleep = std::env::var("AOS_ATTACH_PROFILE_SLEEP").unwrap();
    let version = Command::new(&ssh).arg("-V").output().unwrap();
    assert!(
        String::from_utf8(version.stderr)
            .unwrap()
            .contains("OpenSSH_10.5p1")
    );
    assert!(!Path::new(DIRECTORY).exists());
    assert!(!Path::new(GATE).exists());

    fs::create_dir_all(DIRECTORY).unwrap();
    fs::create_dir_all(FIXTURE_DIRECTORY).unwrap();
    fs::set_permissions(FIXTURE_DIRECTORY, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all("/usr/libexec").unwrap();
    fs::copy(gate_package, GATE).unwrap();
    fs::set_permissions(GATE, fs::Permissions::from_mode(0o755)).unwrap();
    let host_key = key(7);
    protected_file(
        format!("{DIRECTORY}/host_key"),
        host_key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        0o400,
    );
    let host_public = host_key.public_key().to_openssh().unwrap();
    let ca_public = key(8).public_key().to_openssh().unwrap();
    protected_file(
        format!("{DIRECTORY}/host_key.pub"),
        format!("{host_public}\n").as_bytes(),
        0o644,
    );
    protected_file(
        format!("{DIRECTORY}/trusted_user_ca.pub"),
        format!("{ca_public}\n").as_bytes(),
        0o644,
    );
    protected_file(
        format!("{FIXTURE_DIRECTORY}/holder"),
        key(17).to_openssh(LineEnding::LF).unwrap().as_bytes(),
        0o600,
    );
    protected_file(
        format!("{FIXTURE_DIRECTORY}/known_hosts"),
        format!("[127.0.0.1]:2222 {host_public}\n").as_bytes(),
        0o600,
    );

    let mut process = OwnedProcess(
        Command::new(&chroot)
            .args(["--userspec=+1001:+1001", "--groups=", "/", &sleep, "300"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut binding = OpenSshGateBindingV1 {
        attach_operation_id: [1; 16],
        execution_id: [2; 16],
        incarnation_id: [3; 16],
        assignment_epoch: 4,
        principal_id: [5; 16],
        audit_id: [6; 16],
        user: "aos_exec".to_owned(),
        port: 2222,
        host_public_key: host_public,
        trusted_user_ca_public_key: ca_public,
        expires_at: i64::try_from(now + 240).unwrap(),
        gate_config_digest: [9; 32],
    };
    let config = expected_openssh_gate_config_v1(&binding).unwrap();
    binding.gate_config_digest = Sha256::digest(&config).into();
    protected_file(format!("{DIRECTORY}/sshd_config"), &config, 0o644);
    let mut daemon = RunningOpenSshGateV1::start(binding.clone()).unwrap();
    let (sshd_pid, sshd_start_ticks) = daemon.daemon_identity().unwrap();
    let claim = OpenSshGateClaimV1 {
        binding,
        route_digest: [10; 32],
        runtime_identity: [11; 32],
        process_pid: process.0.id(),
        process_start_ticks: process_start_ticks(process.0.id()),
        sshd_pid,
        sshd_start_ticks,
        pty: true,
    };
    write_claim(&claim);

    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", 2222)).is_err() {
        assert!(Instant::now() < deadline, "packaged sshd did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    let measured = daemon
        .physical_readback([12; 32], claim.route_digest, [13; 32])
        .unwrap();
    assert_eq!(measured.binding, claim.binding);
    let gate_digest: [u8; 32] = Sha256::digest(fs::read(GATE).unwrap()).into();
    assert_eq!(measured.physical.gate_executable_digest, gate_digest);

    let accepted = certificate(with_command(builder(&claim, now - 1, now + 120), &claim));
    let output = callback(&chroot, &accepted, 1001, None);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"aos_exec\n");
    assert!(output.stderr.is_empty());
    assert_callback_denial(callback(&chroot, &accepted, 0, None));
    assert_callback_denial(callback(&chroot, &accepted, 1001, Some("extra")));
    ssh_authentication(&ssh, &accepted, true);

    let mut missing_command = builder(&claim, now - 1, now + 120);
    missing_command.extension("permit-pty", "").unwrap();
    let missing_command = certificate(missing_command);
    assert_callback_denial(callback(&chroot, &missing_command, 1001, None));
    ssh_authentication(&ssh, &missing_command, false);
    for foreign_operation in [true, false] {
        let mut foreign = claim.clone();
        if foreign_operation {
            foreign.binding.attach_operation_id = [21; 16];
        } else {
            foreign.binding.execution_id = [22; 16];
        }
        let encoded = certificate(with_command(
            builder(&foreign, now - 1, now + 120),
            &foreign,
        ));
        assert_callback_denial(callback(&chroot, &encoded, 1001, None));
        ssh_authentication(&ssh, &encoded, false);
    }
    let mut forwarding = with_command(builder(&claim, now - 1, now + 120), &claim);
    forwarding.extension("permit-port-forwarding", "").unwrap();
    let forwarding = certificate(forwarding);
    assert_callback_denial(callback(&chroot, &forwarding, 1001, None));
    ssh_authentication(&ssh, &forwarding, false);
    let expired = certificate(with_command(builder(&claim, now - 30, now - 1), &claim));
    assert_callback_denial(callback(&chroot, &expired, 1001, None));
    ssh_authentication(&ssh, &expired, false);

    // Public readback detects changed executable and configuration custody.
    fs::set_permissions(GATE, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        daemon
            .physical_readback([12; 32], claim.route_digest, [13; 32])
            .is_err()
    );
    fs::set_permissions(GATE, fs::Permissions::from_mode(0o755)).unwrap();
    let gate_bytes = fs::read(GATE).unwrap();
    let accepted_gate = format!("{GATE}.accepted");
    fs::rename(GATE, &accepted_gate).unwrap();
    protected_file(GATE, &gate_bytes, 0o755);
    assert!(
        daemon
            .physical_readback([12; 32], claim.route_digest, [13; 32])
            .is_err()
    );
    fs::rename(&accepted_gate, GATE).unwrap();
    let mut substituted = gate_bytes.clone();
    substituted.push(0);
    protected_file(GATE, &substituted, 0o755);
    assert!(
        daemon
            .physical_readback([12; 32], claim.route_digest, [13; 32])
            .is_err()
    );
    protected_file(GATE, &gate_bytes, 0o755);
    protected_file(format!("{DIRECTORY}/sshd_config"), b"Port 2222\n", 0o644);
    assert!(
        daemon
            .physical_readback([12; 32], claim.route_digest, [13; 32])
            .is_err()
    );
    assert_callback_denial(callback(&chroot, &accepted, 1001, None));

    // Restore the exact original installation before the distinct monitor
    // fixture. That fixture measures authentication custody only, never I/O.
    protected_file(format!("{DIRECTORY}/sshd_config"), &config, 0o644);
    drop(daemon);
    monitor_qualification::qualify_root_monitor_binding(&ssh, &claim, &accepted);

    // This is profile/authentication-only evidence. Preserve the original
    // certificate and historical leader bytes after the real leader exits;
    // strict provisioning and the absent actual IO owner still deny custody.
    let mut daemon = RunningOpenSshGateV1::start(claim.binding.clone()).unwrap();
    let mut historical = claim.clone();
    (historical.sshd_pid, historical.sshd_start_ticks) = daemon.daemon_identity().unwrap();
    write_claim(&historical);
    process.0.kill().unwrap();
    process.0.wait().unwrap();
    assert!(crate::openssh_gate_linux::load_openssh_gate_claim_v1().is_err());
    assert!(
        daemon
            .physical_readback([12; 32], historical.route_digest, [13; 32])
            .is_err()
    );
    assert_eq!(
        crate::openssh_gate_linux::load_unexpired_openssh_attach_profile_v5().unwrap(),
        historical,
    );
    let output = callback(&chroot, &accepted, 1001, None);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"aos_exec\n");
    assert!(output.stderr.is_empty());
    ssh_authentication(&ssh, &accepted, true);

    let mut expired = historical.clone();
    expired.binding.expires_at = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    write_claim(&expired);
    assert!(crate::openssh_gate_linux::load_unexpired_openssh_attach_profile_v5().is_err());
    assert_callback_denial(callback(&chroot, &accepted, 1001, None));
    write_claim(&historical);
}

mod monitor_qualification;
