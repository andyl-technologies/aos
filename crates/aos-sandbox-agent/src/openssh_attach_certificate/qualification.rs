//! Profile and root-monitor qualification against the packaged OpenSSH daemon.
//!
//! This ignored fixture runs only in the dedicated minimal VM. It installs
//! public claims and the real gate binary. A final bounded monitor fixture
//! inspects actual authentication custody and confined native pipe transport
//! on the existing Guest socket path. Fixture descriptors are not production
//! I/O authority or qualification of the Controller/Host/Guest held consume.

use std::fs;
use std::io::Read as _;
use std::net::{Ipv4Addr, TcpStream};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
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
const MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy)]
enum ProfileCase {
    Accepted,
    MissingForceCommand,
    ForeignOperation,
    ForeignExecution,
    ForwardingExtension,
    ExpiredCertificate,
    AcceptedHistorical,
}

impl ProfileCase {
    fn coordinates(self) -> (&'static str, Ipv4Addr) {
        let (name, source_octet) = match self {
            Self::Accepted => ("accepted-profile", 2),
            Self::MissingForceCommand => ("missing-force-command", 3),
            Self::ForeignOperation => ("foreign-operation", 4),
            Self::ForeignExecution => ("foreign-execution", 5),
            Self::ForwardingExtension => ("forwarding-extension", 6),
            Self::ExpiredCertificate => ("expired-certificate", 7),
            Self::AcceptedHistorical => ("accepted-historical-profile", 8),
        };

        // Each case gets its own default /32 penalty bucket. Repeated hostile
        // certificates must reach authentication rather than an earlier case's
        // source penalty. The server's normal penalties remain enabled.
        (name, Ipv4Addr::new(127, 0, 0, source_octet))
    }
}

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

fn start_qualification_daemon(
    binding: OpenSshGateBindingV1,
    monitor: bool,
    diagnostic_name: &str,
) -> RunningOpenSshGateV1 {
    let diagnostic_path = Path::new(FIXTURE_DIRECTORY).join(diagnostic_name);
    let diagnostic = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&diagnostic_path)
        .unwrap();
    let mut daemon =
        RunningOpenSshGateV1::start_for_qualification(binding, monitor, diagnostic).unwrap();

    // This TCP-only probe sends no authentication or certificate. Claims and
    // all authentication/custody checks still precede the actual SSH client.
    wait_listener(|| daemon.qualification_exit_status(), &diagnostic_path);
    daemon
}

fn wait_listener(
    mut exit_status: impl FnMut() -> std::io::Result<Option<std::process::ExitStatus>>,
    diagnostic_path: &Path,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let connection_error = match TcpStream::connect(("127.0.0.1", 2222)) {
            Ok(_) => return,
            Err(error) => error,
        };

        let status = exit_status();
        if !matches!(status, Ok(None)) || Instant::now() >= deadline {
            panic!(
                "{}",
                listener_failure(&status, &connection_error, diagnostic_path)
            );
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

fn listener_failure(
    status: &std::io::Result<Option<std::process::ExitStatus>>,
    connection_error: &std::io::Error,
    diagnostic_path: &Path,
) -> String {
    format!(
        "packaged sshd listener unavailable; TCP error: {connection_error}; {}",
        owned_daemon_diagnostics(status, diagnostic_path),
    )
}

// Status and bounded stderr are observations, not a conclusion about which
// listener, process or physical readback predicate failed.
fn owned_daemon_diagnostics(
    status: &std::io::Result<Option<std::process::ExitStatus>>,
    diagnostic_path: &Path,
) -> String {
    let mut bytes = Vec::new();
    let stderr = match fs::File::open(diagnostic_path).and_then(|file| {
        file.take(MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES)
            .read_to_end(&mut bytes)
    }) {
        Ok(_) => String::from_utf8_lossy(&bytes).replace("\r\n", "\n"),
        Err(error) => format!("diagnostic read failed: {error}"),
    };

    format!(
        "original child status: {status:?}; stderr (first {MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES} bytes) \
         at {}:\n{stderr}",
        diagnostic_path.display()
    )
}

fn owned_client_diagnostics(
    status: &std::io::Result<Option<std::process::ExitStatus>>,
    stdout: Option<BorrowedFd<'_>>,
    stderr: Option<BorrowedFd<'_>>,
) -> String {
    format!(
        "original client status: {status:?}; \
         stdout (up to {MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES} available bytes):\n{}\n\
         stderr (up to {MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES} available bytes):\n{}",
        available_pipe_diagnostic(stdout),
        available_pipe_diagnostic(stderr),
    )
}

// Only the already-failed fixture reads these original client pipes. A single
// nonblocking read never waits for a live writer, EOF or a second observation.
fn available_pipe_diagnostic(pipe: Option<BorrowedFd<'_>>) -> String {
    let Some(pipe) = pipe else {
        return "original client pipe unavailable".to_owned();
    };
    let bytes = (|| -> rustix::io::Result<Vec<u8>> {
        let flags = rustix::fs::fcntl_getfl(pipe)?;
        rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK)?;

        let mut bytes = vec![0; MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES as usize];
        let length = match rustix::io::read(pipe, bytes.as_mut_slice()) {
            Ok(length) => length,
            Err(rustix::io::Errno::AGAIN) => 0,
            Err(error) => return Err(error),
        };
        bytes.truncate(length);
        Ok(bytes)
    })();

    match bytes {
        Ok(bytes) => String::from_utf8_lossy(&bytes).replace("\r\n", "\n"),
        Err(error) => format!("original client pipe observation failed: {error}"),
    }
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
    ssh_command_from(ssh, certificate, None)
}

fn ssh_command_from(ssh: &str, certificate: &str, source: Option<Ipv4Addr>) -> Command {
    let certificate_path = PathBuf::from(format!("{FIXTURE_DIRECTORY}/holder-cert.pub"));
    protected_file(&certificate_path, certificate.as_bytes(), 0o644);
    ssh_client_command(ssh, &certificate_path, source)
}

fn ssh_client_command(ssh: &str, certificate_path: &Path, source: Option<Ipv4Addr>) -> Command {
    let mut command = Command::new(ssh);
    if let Some(source) = source {
        command.args(["-b", &source.to_string()]);
    }

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

fn ssh_authentication_failure(case: &str, output: &Output) -> String {
    let maximum = MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES as usize;
    let stdout = &output.stdout[..output.stdout.len().min(maximum)];
    let stderr = &output.stderr[..output.stderr.len().min(maximum)];

    // Only the ephemeral fixture client's output is included. Certificates
    // and private-key file contents are never supplied to this diagnostic.
    format!(
        "SSH fixture case {case}; original client status: {}; \
         stdout (first {maximum} bytes):\n{}\n\
         stderr (first {maximum} bytes):\n{}",
        output.status,
        String::from_utf8_lossy(stdout).replace("\r\n", "\n"),
        String::from_utf8_lossy(stderr).replace("\r\n", "\n"),
    )
}

fn ssh_authentication(ssh: &str, certificate: &str, case: ProfileCase, expected: bool) {
    let (name, source) = case.coordinates();
    let output = ssh_command_from(ssh, certificate, Some(source))
        .output()
        .unwrap();
    let failure = ssh_authentication_failure(name, &output);
    let diagnostic = std::str::from_utf8(&output.stderr)
        .unwrap_or_else(|error| panic!("{failure}\ninvalid client diagnostic UTF-8: {error}"));
    let authenticated = diagnostic.contains("Authenticated to 127.0.0.1")
        && diagnostic.contains("using \"publickey\"");
    assert_eq!(authenticated, expected, "{failure}");
    if !expected {
        assert!(
            diagnostic.contains("Permission denied (publickey)"),
            "{failure}"
        );
    }
    // The administrator's fixed command cannot run `true` or transfer I/O:
    // this fixture deliberately has no process bridge to serve a descriptor.
    assert!(!output.status.success(), "{failure}");
    assert!(output.stdout.is_empty(), "{failure}");
    assert!(
        !Path::new("/run/aos-sandbox-agent/exec-gate.sock").exists(),
        "{failure}"
    );
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
    let mut daemon = start_qualification_daemon(binding.clone(), false, "profile.stderr");
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
    ssh_authentication(&ssh, &accepted, ProfileCase::Accepted, true);

    let mut missing_command = builder(&claim, now - 1, now + 120);
    missing_command.extension("permit-pty", "").unwrap();
    let missing_command = certificate(missing_command);
    assert_callback_denial(callback(&chroot, &missing_command, 1001, None));
    ssh_authentication(
        &ssh,
        &missing_command,
        ProfileCase::MissingForceCommand,
        false,
    );
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
        let case = if foreign_operation {
            ProfileCase::ForeignOperation
        } else {
            ProfileCase::ForeignExecution
        };
        ssh_authentication(&ssh, &encoded, case, false);
    }
    let mut forwarding = with_command(builder(&claim, now - 1, now + 120), &claim);
    forwarding.extension("permit-port-forwarding", "").unwrap();
    let forwarding = certificate(forwarding);
    assert_callback_denial(callback(&chroot, &forwarding, 1001, None));
    ssh_authentication(&ssh, &forwarding, ProfileCase::ForwardingExtension, false);
    let expired = certificate(with_command(builder(&claim, now - 30, now - 1), &claim));
    assert_callback_denial(callback(&chroot, &expired, 1001, None));
    ssh_authentication(&ssh, &expired, ProfileCase::ExpiredCertificate, false);

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
    let mut daemon = start_qualification_daemon(claim.binding.clone(), false, "historical.stderr");
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
    ssh_authentication(&ssh, &accepted, ProfileCase::AcceptedHistorical, true);

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

#[test]
fn listener_failure_retains_original_exit_and_stderr() {
    use std::os::unix::process::ExitStatusExt as _;

    let diagnostic = tempfile::NamedTempFile::new().unwrap();
    fs::write(diagnostic.path(), b"fixture daemon startup error\n").unwrap();
    let status = Ok(Some(std::process::ExitStatus::from_raw(256)));
    let connection_error = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);

    let failure = listener_failure(&status, &connection_error, diagnostic.path());

    assert!(failure.contains("packaged sshd listener unavailable; TCP error:"));
    assert!(failure.contains(&format!("original child status: {status:?}")));
    assert!(failure.contains("ConnectionRefused") || failure.contains("connection refused"));
    assert!(failure.contains("fixture daemon startup error\n"));
}

#[test]
fn listener_failure_bounds_ephemeral_stderr() {
    let diagnostic = tempfile::NamedTempFile::new().unwrap();
    let mut bytes = vec![b'x'; MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES as usize];
    bytes.extend_from_slice(b"excluded tail");
    fs::write(diagnostic.path(), &bytes).unwrap();
    let connection_error = std::io::Error::from(std::io::ErrorKind::NetworkUnreachable);

    let failure = listener_failure(&Ok(None), &connection_error, diagnostic.path());

    assert!(failure.contains("original child status: Ok(None)"));
    assert!(failure.contains("first 16384 bytes"));
    assert!(!failure.contains("excluded tail"));
}

#[test]
fn client_failure_observes_available_output_without_waiting_for_live_writers() {
    let (stdout, stdout_writer) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (stderr, stderr_writer) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let stdout_flags = rustix::fs::fcntl_getfl(&stdout).unwrap();
    let stderr_flags = rustix::fs::fcntl_getfl(&stderr).unwrap();
    assert_eq!(
        rustix::io::write(&stdout_writer, b"fixture client stdout\r\n").unwrap(),
        23,
    );
    assert_eq!(
        rustix::io::write(&stderr_writer, b"fixture client stderr\r\n").unwrap(),
        23,
    );

    let failure = owned_client_diagnostics(&Ok(None), Some(stdout.as_fd()), Some(stderr.as_fd()));

    assert!(failure.contains("original client status: Ok(None)"));
    assert!(failure.contains("stdout (up to 16384 available bytes):\nfixture client stdout\n"));
    assert!(failure.contains("stderr (up to 16384 available bytes):\nfixture client stderr\n"));
    assert!(!failure.contains('\r'));
    assert_eq!(
        rustix::fs::fcntl_getfl(&stdout).unwrap(),
        stdout_flags | rustix::fs::OFlags::NONBLOCK,
    );
    assert_eq!(
        rustix::fs::fcntl_getfl(&stderr).unwrap(),
        stderr_flags | rustix::fs::OFlags::NONBLOCK,
    );

    // Both original writers remain open. Empty pipes must report the current
    // absence of bytes rather than wait for EOF or future client output.
    assert_eq!(available_pipe_diagnostic(Some(stdout.as_fd())), "");
    assert_eq!(available_pipe_diagnostic(Some(stderr.as_fd())), "");
    drop((stdout_writer, stderr_writer));
}

#[test]
fn client_failure_bounds_both_original_output_samples_and_retains_exit_status() {
    use std::os::unix::process::ExitStatusExt as _;

    // Regular fixture files avoid making setup depend on the kernel's pipe
    // capacity; the same bounded FD read is exercised with more than 16 KiB.
    let stdout = tempfile::NamedTempFile::new().unwrap();
    let stderr = tempfile::NamedTempFile::new().unwrap();
    let maximum = MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES as usize;
    let mut stdout_bytes = vec![b'x'; maximum];
    stdout_bytes.extend_from_slice(b"excluded stdout tail");
    let mut stderr_bytes = vec![b'y'; maximum];
    stderr_bytes.extend_from_slice(b"excluded stderr tail");
    fs::write(stdout.path(), &stdout_bytes).unwrap();
    fs::write(stderr.path(), &stderr_bytes).unwrap();
    let mut original_stdout = fs::File::open(stdout.path()).unwrap();
    let mut original_stderr = fs::File::open(stderr.path()).unwrap();
    let status = Ok(Some(std::process::ExitStatus::from_raw(256)));

    let failure = owned_client_diagnostics(
        &status,
        Some(original_stdout.as_fd()),
        Some(original_stderr.as_fd()),
    );

    assert!(failure.contains(&format!("original client status: {status:?}")));
    assert!(failure.contains(&"x".repeat(maximum)));
    assert!(failure.contains(&"y".repeat(maximum)));
    assert!(!failure.contains("excluded stdout tail"));
    assert!(!failure.contains("excluded stderr tail"));
    let mut stdout_tail = String::new();
    let mut stderr_tail = String::new();
    original_stdout.read_to_string(&mut stdout_tail).unwrap();
    original_stderr.read_to_string(&mut stderr_tail).unwrap();
    assert_eq!(stdout_tail, "excluded stdout tail");
    assert_eq!(stderr_tail, "excluded stderr tail");
}

#[test]
fn client_failure_keeps_status_and_pipe_observation_errors_neutral() {
    let (_reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let status = Err(std::io::Error::from_raw_os_error(10));

    let failure = owned_client_diagnostics(&status, None, Some(writer.as_fd()));

    assert!(failure.contains(&format!("original client status: {status:?}")));
    assert!(failure.contains("original client pipe unavailable"));
    assert!(failure.contains("original client pipe observation failed:"));
    assert!(!failure.contains("TCP"));
    assert!(!failure.contains("listener unavailable"));
    assert!(!failure.contains("authentication failed"));
}

#[test]
fn ssh_authentication_failure_retains_case_status_and_bounded_output() {
    use std::os::unix::process::ExitStatusExt as _;

    let maximum = MAXIMUM_FIXTURE_DIAGNOSTIC_BYTES as usize;
    let mut stdout = vec![b'x'; maximum];
    stdout.extend_from_slice(b"excluded stdout tail");
    let mut stderr = vec![b'y'; maximum];
    stderr.extend_from_slice(b"excluded stderr tail");
    let output = Output {
        status: std::process::ExitStatus::from_raw(256),
        stdout,
        stderr,
    };

    let failure = ssh_authentication_failure("missing-force-command", &output);

    assert!(failure.contains("SSH fixture case missing-force-command"));
    assert!(failure.contains(&format!("original client status: {}", output.status)));
    assert!(failure.contains(&format!("stdout (first {maximum} bytes):\n")));
    assert!(failure.contains(&format!("stderr (first {maximum} bytes):\n")));
    assert!(failure.contains(&"x".repeat(maximum)));
    assert!(failure.contains(&"y".repeat(maximum)));
    assert!(!failure.contains("excluded stdout tail"));
    assert!(!failure.contains("excluded stderr tail"));
}

#[test]
fn profile_cases_bind_distinct_loopback_sources_without_changing_ssh_arguments() {
    use std::collections::BTreeSet;
    use std::ffi::OsString;

    let certificate_path = Path::new("/fixture/holder-cert.pub");
    let expected: Vec<OsString> = [
        "-v",
        "-F",
        "/dev/null",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        &format!("-oUserKnownHostsFile={FIXTURE_DIRECTORY}/known_hosts"),
        "-oGlobalKnownHostsFile=/dev/null",
        "-oIdentitiesOnly=yes",
        "-oIdentityAgent=none",
        "-oCertificateFile=/fixture/holder-cert.pub",
        "-oConnectTimeout=5",
        "-i",
        &format!("{FIXTURE_DIRECTORY}/holder"),
        "-p",
        "2222",
        "aos_exec@127.0.0.1",
        "true",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let baseline = ssh_client_command("/fixture/ssh", certificate_path, None);
    assert_eq!(baseline.get_program(), "/fixture/ssh");
    assert_eq!(
        baseline.get_args().map(OsString::from).collect::<Vec<_>>(),
        expected
    );

    let cases = [
        ProfileCase::Accepted,
        ProfileCase::MissingForceCommand,
        ProfileCase::ForeignOperation,
        ProfileCase::ForeignExecution,
        ProfileCase::ForwardingExtension,
        ProfileCase::ExpiredCertificate,
        ProfileCase::AcceptedHistorical,
    ];
    let mut sources = BTreeSet::new();
    let mut names = BTreeSet::new();
    for (index, case) in cases.into_iter().enumerate() {
        let (name, source) = case.coordinates();
        assert_eq!(source, Ipv4Addr::new(127, 0, 0, 2 + index as u8));
        assert!(sources.insert(source));
        assert!(names.insert(name));

        let command = ssh_client_command("/fixture/ssh", certificate_path, Some(source));
        let mut arguments = vec![OsString::from("-b"), OsString::from(source.to_string())];
        arguments.extend(expected.iter().cloned());
        assert_eq!(command.get_program(), baseline.get_program());
        assert_eq!(
            command.get_args().map(OsString::from).collect::<Vec<_>>(),
            arguments
        );
    }
}

#[test]
fn ssh_failure_normalizes_crlf_for_display_without_changing_capture() {
    use std::os::unix::process::ExitStatusExt as _;

    let output = Output {
        status: std::process::ExitStatus::from_raw(256),
        stdout: b"fixture stdout\r\n".to_vec(),
        stderr: b"fixture stderr\r\n".to_vec(),
    };

    let failure = ssh_authentication_failure("missing-force-command", &output);

    assert!(failure.contains("fixture stdout\n"));
    assert!(failure.contains("fixture stderr\n"));
    assert!(!failure.contains('\r'));
    assert_eq!(output.stdout, b"fixture stdout\r\n");
    assert_eq!(output.stderr, b"fixture stderr\r\n");
}

mod monitor_qualification;
