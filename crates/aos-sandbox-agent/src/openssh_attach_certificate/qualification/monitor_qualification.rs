//! Real pinned sshd monitor and confined relay transport qualification.
//!
//! The fixture uses the existing fixed Guest pathname only to inspect real
//! monitor records, pidfds and native pipe transport. The fixed fixture pipes
//! are not production execution authority; actual Guest/Controller/Host held
//! consume and installed continuous confinement require separate qualification.

use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use nix::libc;
use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::os::unix::process::CommandExt as _;
use std::os::unix::process::ExitStatusExt as _;

use super::*;
use crate::openssh_monitor::{
    OPENSSH_MONITOR_BINDING_ACK_V2, OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2,
    OpenSshMonitorWitnessV2,
};
use crate::openssh_session::{
    OpenSshSessionActionV4, OpenSshSessionReplyV4, OpenSshSessionRequestV4, OpenSshSessionStateV4,
    OriginalExecutionWaitStatusV4,
};
use crate::openssh_ticket::validate_original_ticket_certificate_v2;

const SOCKET: &str = "/run/aos-sandbox-agent/exec-gate.sock";

fn monitor_runtime_failure(
    error: &crate::openssh_gate_linux::OpenSshGatePhysicalErrorV1,
    status: &std::io::Result<Option<std::process::ExitStatus>>,
    diagnostic_path: &Path,
) -> String {
    format!(
        "original monitor runtime readback failed: {error:?}\n{}",
        owned_daemon_diagnostics(status, diagnostic_path),
    )
}

pub(super) fn qualify_root_monitor_binding(ssh: &str, base: &OpenSshGateClaimV1, original: &str) {
    let passwd = fs::read_to_string("/etc/passwd").unwrap();
    let shell = format!("{FIXTURE_DIRECTORY}/hostile-shell");
    let marker = "/home/aos_exec/shell-executed";
    protected_file(marker, b"", 0o666);
    let bash = std::env::var("AOS_ATTACH_PROFILE_BASH").unwrap();
    protected_file(
        &shell,
        format!("#!{bash}\nprintf shell-invoked > {marker}\nexit 99\n").as_bytes(),
        0o755,
    );
    let changed = passwd
        .lines()
        .map(|line| {
            if line.starts_with("aos_exec:") {
                format!("{}:{shell}", line.rsplit_once(':').unwrap().0)
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    protected_file("/etc/passwd", changed.as_bytes(), 0o644);
    let session_package = std::env::var("AOS_ATTACH_PROFILE_SSHD_SESSION").unwrap();
    if let Ok(existing) = fs::symlink_metadata("/usr/libexec/sshd-session") {
        assert!(existing.file_type().is_symlink());
        assert_eq!(
            fs::canonicalize("/usr/libexec/sshd-session").unwrap(),
            fs::canonicalize(&session_package).unwrap()
        );
        // Replace only this VM-local package symlink with a measured fixture
        // copy; never write through it into the retained package executable.
        fs::remove_file("/usr/libexec/sshd-session").unwrap();
    }
    fs::copy(session_package, "/usr/libexec/sshd-session").unwrap();
    fs::set_permissions(
        "/usr/libexec/sshd-session",
        fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    fs::create_dir_all("/run/aos-sandbox-agent").unwrap();
    fs::set_permissions("/run/aos-sandbox-agent", fs::Permissions::from_mode(0o755)).unwrap();
    let mut listener = RecordSubjectListener::bind(Path::new(SOCKET), 16).unwrap();
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666)).unwrap();
    let ticket = fixture_ticket(base, original);
    let original_ticket_bytes = ticket.encode().unwrap();
    protected_file(
        crate::openssh_ticket::OPENSSH_TICKET_CLAIM_PATH_V2,
        &original_ticket_bytes,
        0o444,
    );

    let mut daemon = start_qualification_daemon(base.binding.clone(), true, "monitor.stderr");
    // A new measured daemon does not change the original certificate profile.
    let mut claim = base.clone();
    (claim.sshd_pid, claim.sshd_start_ticks) = daemon.daemon_identity().unwrap();
    write_claim(&claim);
    let runtime = daemon.monitor_runtime_v2(&claim).unwrap_or_else(|error| {
        let status = daemon.qualification_exit_status();
        let diagnostic_path = Path::new(FIXTURE_DIRECTORY).join("monitor.stderr");
        panic!(
            "{}",
            monitor_runtime_failure(&error, &status, &diagnostic_path)
        );
    });
    assert!(
        runtime
            .require_monitor(
                &PidFd::open(std::num::NonZeroU32::new(std::process::id()).unwrap()).unwrap()
            )
            .is_err()
    );
    assert!(PidFd::from_owned(fs::File::open("/dev/null").unwrap().into()).is_err());

    // This exact stored-ticket/profile preflight cannot replace the actual
    // holder authentication, root-monitor custody or native relay checks.
    let installed_ticket = crate::openssh_gate_linux::load_original_ticket_claim_v2().unwrap();
    assert!(
        installed_ticket == original_ticket_bytes,
        "stored original monitor fixture ticket was substituted",
    );
    let (certificate_type, certificate_base64) = original.split_once(' ').unwrap();
    validate_original_ticket_certificate_v2(
        &claim,
        &installed_ticket,
        certificate_type,
        certificate_base64,
        now(),
    )
    .expect("original monitor ticket must retain its exact certificate profile");

    let mut client = ssh_command(ssh, original)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    client
        .stdin
        .take()
        .unwrap()
        .write_all(b"original-input\n")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connection = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                assert!(
                    Instant::now() < deadline,
                    "root monitor did not register\noriginal monitor daemon:\n{}\n{}",
                    owned_daemon_diagnostics(
                        &daemon.qualification_exit_status(),
                        &Path::new(FIXTURE_DIRECTORY).join("monitor.stderr"),
                    ),
                    owned_client_diagnostics(
                        &client.try_wait(),
                        client.stdout.as_ref().map(|pipe| pipe.as_fd()),
                        client.stderr.as_ref().map(|pipe| pipe.as_fd()),
                    ),
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("monitor accept: {error}"),
        }
    };
    runtime.require_monitor(connection.peer().pidfd()).unwrap();
    let record = loop {
        match connection.receive_with_descriptors(OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2, 1) {
            Ok(record) => break record,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("monitor receive: {error}"),
        }
    };
    let (payload, subject, child) = {
        let bound = connection.bind_received_descriptors(record).unwrap();
        let (payload, subject, mut descriptors, peer) = bound.into_parts();
        let record_credentials = subject.credentials();
        let peer_credentials = peer.credentials();
        assert_eq!(record_credentials.pid(), peer_credentials.pid());
        assert_eq!(record_credentials.uid(), peer_credentials.uid());
        assert_eq!(record_credentials.gid(), peer_credentials.gid());
        assert_eq!(peer.credentials().uid(), 0);
        let child = PidFd::from_owned(descriptors.pop().unwrap()).unwrap();
        assert!(descriptors.is_empty());
        (payload, subject, child)
    };
    runtime.require_monitor(subject.pidfd()).unwrap();
    let session_path = "/usr/libexec/sshd-session";
    let session_bytes = fs::read(session_path).unwrap();
    fs::set_permissions(session_path, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(runtime.require_monitor(subject.pidfd()).is_err());
    fs::set_permissions(session_path, fs::Permissions::from_mode(0o500)).unwrap();
    let accepted_session = "/usr/libexec/sshd-session.accepted";
    fs::rename(session_path, accepted_session).unwrap();
    protected_file(session_path, &session_bytes, 0o500);
    assert!(runtime.require_monitor(subject.pidfd()).is_err());
    fs::rename(accepted_session, session_path).unwrap();
    runtime.require_monitor(subject.pidfd()).unwrap();
    let witness = OpenSshMonitorWitnessV2::decode_confined_v3(&payload).unwrap();
    witness
        .validate_original_holder(&claim, &ticket, now())
        .unwrap();
    runtime
        .require_confined_child_v3(
            &child,
            connection.peer().credentials().pid().get(),
            witness.uid,
            witness.gid,
        )
        .unwrap();
    assert_eq!((witness.uid, witness.gid), (1001, 1001));
    assert!(
        runtime
            .require_confined_child_v3(&child, claim.sshd_pid, witness.uid, witness.gid)
            .is_err()
    );
    assert!(
        runtime
            .require_confined_child_v3(
                &child,
                connection.peer().credentials().pid().get(),
                1002,
                1002
            )
            .is_err()
    );
    connection.send(OPENSSH_MONITOR_BINDING_ACK_V2).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let record = loop {
        match connection.receive_with_descriptors(8, 1) {
            Ok(record) => break record,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                assert!(Instant::now() < deadline, "confined relay did not register");
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("relay receive: {error}"),
        }
    };
    let bound = connection.bind_received_descriptors(record).unwrap();
    let (payload, relay_sender, mut descriptors, peer) = bound.into_parts();
    assert_eq!(payload, b"AOSRLY03");
    assert_eq!(relay_sender.credentials().pid(), peer.credentials().pid());
    assert_eq!(relay_sender.credentials().uid(), peer.credentials().uid());
    assert_eq!(relay_sender.credentials().gid(), peer.credentials().gid());
    runtime.require_monitor(relay_sender.pidfd()).unwrap();
    let relay = PidFd::from_owned(descriptors.pop().unwrap()).unwrap();
    assert!(descriptors.is_empty());
    let child_pid = child.process_identity().unwrap().pid();
    runtime
        .require_confined_child_v3(&relay, child_pid, witness.uid, witness.gid)
        .unwrap();
    let relay_pid = relay.process_identity().unwrap().pid();
    qualify_same_uid_denials(child_pid, relay_pid, witness.uid, witness.gid);
    assert!(child.is_alive().unwrap() && relay.is_alive().unwrap());
    connection.send(b"AOSRAK03").unwrap();

    // These real fixed-process pipes exercise only the native relay transport.
    // They do not replace the production Guest barrier or owner authorization.
    let mut fixture = OwnedProcess(
        Command::new(&bash)
            .args(["-c", "IFS= read -r line; printf 'stdout:%s\\n' \"$line\"; printf 'stderr:%s\\n' \"$line\" >&2; exit 37"])
            .uid(1001).gid(1001)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap(),
    );
    let mut pipe_ends = Some((
        fixture.0.stdin.take().unwrap(),
        fixture.0.stdout.take().unwrap(),
        fixture.0.stderr.take().unwrap(),
    ));
    let mut original_io = None;
    let mut terminal_status = None;
    let mut terminal_replied = false;
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if client.try_wait().unwrap().is_some() {
            break;
        }
        if let Ok(mut gate) = listener.accept() {
            assert_eq!(gate.peer().credentials().uid(), 1001);
            assert_eq!(gate.peer().credentials().pid().get(), relay_pid);
            let record = loop {
                match gate.receive(8) {
                    Ok(record) => break record,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                        assert!(Instant::now() < deadline);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("relay request: {error}"),
                }
            };
            let bound = gate.bind_received(record).unwrap();
            assert_eq!(bound.payload(), b"AOSRIO03");
            assert_eq!(
                bound.subject().credentials().pid(),
                bound.peer().credentials().pid()
            );
            assert_eq!(
                bound.subject().credentials().uid(),
                bound.peer().credentials().uid()
            );
            assert_eq!(
                bound.subject().credentials().gid(),
                bound.peer().credentials().gid()
            );
            assert_eq!(bound.subject().credentials().pid().get(), relay_pid);
            drop(bound);
            let (input, output, error) = pipe_ends.take().expect("one native transport handoff");
            gate.send_with_descriptors(
                b"AOSGOS03",
                &[input.as_fd(), output.as_fd(), error.as_fd()],
            )
            .unwrap();
            drop((input, output, error));
            let receipt = loop {
                match gate.receive(8) {
                    Ok(record) => break record,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                        assert!(Instant::now() < deadline);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("native relay receipt: {error}"),
                }
            };
            let receipt = gate.bind_received(receipt).unwrap();
            assert_eq!(receipt.payload(), b"AOSRID03");
            assert_eq!(receipt.subject().credentials().pid().get(), relay_pid);
            assert_eq!(receipt.subject().credentials().uid(), 1001);
            assert_eq!(receipt.subject().credentials().gid(), 1001);
            drop(receipt);
            original_io = Some(gate);
        }
        if terminal_status.is_none() {
            if let Some(status) = fixture.0.try_wait().unwrap() {
                // This real fixture process is not a production admitted
                // execution. Its exact waitstatus proves native MM reporting
                // differs from relay exit, not Guest cgroup/authority custody.
                let status = OriginalExecutionWaitStatusV4::new(status.into_raw() as u32).unwrap();
                assert_eq!(status.exit_code(), Some(37));
                original_io
                    .as_mut()
                    .unwrap()
                    .send(&status.encode_io_terminal())
                    .unwrap();
                terminal_status = Some(status);
            }
        }
        match connection.receive(32) {
            Ok(record) => {
                assert!(!terminal_replied);
                runtime
                    .require_original_terminal_monitor_v4(connection.peer().pidfd())
                    .unwrap();
                let bound = connection.bind_received(record).unwrap();
                assert_eq!(
                    bound.subject().credentials().pid(),
                    subject.credentials().pid()
                );
                assert_eq!(bound.subject().credentials().uid(), 0);
                assert_eq!(
                    bound.subject().pidfd().process_identity().unwrap(),
                    subject.pidfd().process_identity().unwrap()
                );
                let request = OpenSshSessionRequestV4::decode(bound.payload()).unwrap();
                assert_eq!(request.sequence, 1);
                assert_eq!(request.action, OpenSshSessionActionV4::Terminal);
                drop(bound);
                connection
                    .send(
                        &OpenSshSessionReplyV4 {
                            sequence: request.sequence,
                            state: OpenSshSessionStateV4::Terminal(terminal_status.unwrap()),
                        }
                        .encode()
                        .unwrap(),
                    )
                    .unwrap();
                terminal_replied = true;
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {}
            Err(error) => panic!("original terminal request: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "native relay client did not close"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let output = client.wait_with_output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Authenticated to 127.0.0.1"));
    assert!(stderr.contains("stderr:original-input\n"));
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, b"stdout:original-input\n");
    assert!(pipe_ends.is_none());
    assert_eq!(fixture.0.wait().unwrap().code(), Some(37));
    assert!(terminal_replied);
    assert!(
        fs::read(marker).unwrap().is_empty(),
        "passwd shell was invoked"
    );
    // A retained pidfd never adopts a later numeric PID: the exited original
    // child is closed even if a future process eventually obtains that number.
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.is_alive().unwrap() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        runtime
            .require_confined_child_v3(&child, subject.credentials().pid().get(), 1001, 1001)
            .is_err()
    );
    drop(connection);
    drop(daemon);

    qualify_incomplete_authentication(&mut listener, base, original, ssh);
    protected_file("/etc/passwd", passwd.as_bytes(), 0o644);
    drop(listener);
    fs::remove_file(SOCKET).unwrap();
}

fn qualify_same_uid_denials(child: u32, relay: u32, uid: u32, gid: u32) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "openssh_attach_certificate::qualification::monitor_qualification::same_uid_actor_cannot_inject_or_steal_confined_producer", "--test-threads=1"])
        .env("AOS_ATTACH_ATTACK_TARGETS", format!("{child},{relay}"))
        .uid(uid).gid(gid).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
#[ignore = "invoked only as an unprivileged actor by the pinned monitor VM fixture"]
fn same_uid_actor_cannot_inject_or_steal_confined_producer() {
    assert_eq!(rustix::process::getuid().as_raw(), 1001);
    for pid in std::env::var("AOS_ATTACH_ATTACK_TARGETS")
        .unwrap()
        .split(',')
        .map(|pid| pid.parse::<libc::pid_t>().unwrap())
    {
        assert!(pid > 1 && pid != std::process::id() as libc::pid_t);
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
        assert!(status.lines().any(|line| line == "Seccomp:\t2"));
        assert_eq!(
            fs::read_link(format!("/proc/{pid}/exe"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        for path in [format!("/proc/{pid}/mem"), format!("/proc/{pid}/fd/0")] {
            assert_eq!(
                fs::File::open(path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        // SAFETY: These qualification syscalls target a different live task;
        // no pointer is dereferenced by Rust and every operation must be denied.
        unsafe {
            assert_eq!(
                libc::syscall(libc::SYS_ptrace, libc::PTRACE_ATTACH, pid, 0usize, 0usize),
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            let mut byte = 0u8;
            let local = libc::iovec {
                iov_base: std::ptr::addr_of_mut!(byte).cast(),
                iov_len: 1,
            };
            let remote = libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 1,
            };
            assert_eq!(libc::process_vm_readv(pid, &local, 1, &remote, 1, 0), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(libc::process_vm_writev(pid, &local, 1, &remote, 1, 0), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
    }
}

fn fixture_ticket(claim: &OpenSshGateClaimV1, original: &str) -> PublicAttachTicketBindingV2 {
    let certificate = ssh_key::Certificate::from_openssh(original).unwrap();
    let mut grant = [0; 416];
    grant[..8].copy_from_slice(b"AOSAPG01");
    grant[8..24].copy_from_slice(&claim.binding.attach_operation_id);
    grant[24..40].copy_from_slice(&claim.binding.execution_id);
    PublicAttachTicketBindingV2 {
        operation_id: claim.binding.attach_operation_id,
        execution_id: claim.binding.execution_id,
        incarnation_id: claim.binding.incarnation_id,
        principal_id: claim.binding.principal_id,
        audit_id: claim.binding.audit_id,
        assignment_epoch: claim.binding.assignment_epoch,
        valid_after: certificate.valid_after(),
        expires_at: certificate.valid_before(),
        holder_public_key: certificate.public_key().ed25519().unwrap().0,
        request_digest: [23; 32],
        decision_digest: [24; 32],
        pending_grant: grant,
        base_route_digest: claim.route_digest,
        certificate: original.as_bytes().to_vec(),
    }
}

fn qualify_incomplete_authentication(
    listener: &mut RecordSubjectListener,
    base: &OpenSshGateClaimV1,
    original: &str,
    ssh: &str,
) {
    let deny = std::env::var("AOS_ATTACH_PROFILE_PAM_DENY").unwrap();
    let permit = std::env::var("AOS_ATTACH_PROFILE_PAM_PERMIT").unwrap();
    fs::create_dir_all("/etc/pam.d").unwrap();
    for (case, auth, account, session) in [
        ("account", permit.as_str(), deny.as_str(), permit.as_str()),
        (
            "credentials",
            deny.as_str(),
            permit.as_str(),
            permit.as_str(),
        ),
        ("session", permit.as_str(), permit.as_str(), deny.as_str()),
    ] {
        protected_file(
            format!("/etc/pam.d/aos-attach-{case}"),
            format!(
                "auth required {auth}\naccount required {account}\nsession required {session}\n"
            )
            .as_bytes(),
            0o644,
        );
    }
    let cases = [
        ("nologin", Vec::new()),
        (
            "mfa",
            vec![
                "-oAuthenticationMethods=publickey,password".to_owned(),
                "-oPasswordAuthentication=yes".to_owned(),
            ],
        ),
        (
            "account",
            vec![
                "-oUsePAM=yes".to_owned(),
                "-oPAMServiceName=aos-attach-account".to_owned(),
            ],
        ),
        (
            "credentials",
            vec![
                "-oUsePAM=yes".to_owned(),
                "-oPAMServiceName=aos-attach-credentials".to_owned(),
            ],
        ),
        (
            "session",
            vec![
                "-oUsePAM=yes".to_owned(),
                "-oPAMServiceName=aos-attach-session".to_owned(),
            ],
        ),
    ];
    for (case, overrides) in cases {
        if case == "nologin" {
            assert!(!Path::new("/etc/nologin").exists());
            protected_file("/etc/nologin", b"closed\n", 0o644);
        }
        let log_path = format!("{FIXTURE_DIRECTORY}/monitor-{case}.stderr");
        protected_file(&log_path, b"", 0o600);
        let log = fs::OpenOptions::new().write(true).open(&log_path).unwrap();
        let mut command = Command::new("/usr/sbin/sshd");
        command.args([
            "-D",
            "-e",
            "-f",
            &format!("{DIRECTORY}/sshd_config"),
            "-oAosAttachMonitorV2=yes",
            "-oSshdSessionPath=/usr/libexec/sshd-session",
            "-oLogLevel=DEBUG3",
        ]);
        command
            .args(overrides)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log);
        let mut daemon = OwnedProcess(command.spawn().unwrap());
        wait_listener(|| daemon.0.try_wait(), Path::new(&log_path));
        let mut claim = base.clone();
        claim.sshd_pid = daemon.0.id();
        claim.sshd_start_ticks = process_start_ticks(daemon.0.id());
        write_claim(&claim);
        let output = ssh_command(ssh, original).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(matches!(listener.accept(), Err(SeqpacketError::WouldBlock)));
        drop(daemon);
        let log = fs::read_to_string(&log_path).unwrap();
        if case == "nologin" {
            fs::remove_file("/etc/nologin").unwrap();
        }
        // Denial must follow actual privileged certificate verification, not
        // an absent PAM file, invalid configuration or failed signature.
        assert!(
            log.lines()
                .any(|line| line.contains("mm_answer_keyverify: publickey")
                    && line.contains(" verified"))
        );
        match case {
            "nologin" => assert!(log.contains("not allowed because") && log.contains("nologin")),
            "mfa" => assert!(log.contains("method publickey: partial")),
            "account" => assert!(log.contains("pam_acct_mgmt =")),
            "credentials" | "session" => {
                assert!(log.contains("AOS attach PAM credentials/session rejected"))
            }
            _ => unreachable!(),
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn original_monitor_ticket_retains_pty_profile_and_denies_substitution() {
    let claim = crate::openssh_attach_certificate::tests::claim();
    let original = certificate(with_command(builder(&claim, 1000, 1200), &claim));
    let ticket = fixture_ticket(&claim, &original);
    let original_ticket_bytes = ticket.encode().unwrap();
    let (certificate_type, certificate_base64) = original.split_once(' ').unwrap();

    validate_original_ticket_certificate_v2(
        &claim,
        &original_ticket_bytes,
        certificate_type,
        certificate_base64,
        1100,
    )
    .unwrap();

    let mut substituted_profile = claim.clone();
    substituted_profile.pty = false;
    assert!(
        validate_original_ticket_certificate_v2(
            &substituted_profile,
            &original_ticket_bytes,
            certificate_type,
            certificate_base64,
            1100,
        )
        .is_err()
    );
    assert!(ticket.certificate == original.as_bytes());
    assert!(ticket.encode().unwrap() == original_ticket_bytes);
}

#[test]
fn monitor_readback_failure_preserves_error_without_inferred_listener_or_tcp_failure() {
    let diagnostic = tempfile::NamedTempFile::new().unwrap();
    fs::write(diagnostic.path(), b"fixture monitor stderr\r\n").unwrap();
    let error = crate::openssh_gate_linux::OpenSshGatePhysicalErrorV1::Io(
        std::io::Error::from_raw_os_error(2),
    );
    let status = Ok(Some(std::process::ExitStatus::from_raw(256)));

    let failure = monitor_runtime_failure(&error, &status, diagnostic.path());

    assert!(failure.contains(&format!(
        "original monitor runtime readback failed: {error:?}"
    )));
    assert!(failure.contains(&format!("original child status: {status:?}")));
    assert!(failure.contains("stderr (first 16384 bytes)"));
    assert!(failure.contains("fixture monitor stderr\n"));
    assert!(!failure.contains("TCP"));
    assert!(!failure.contains("listener unavailable"));
    assert_eq!(
        fs::read(diagnostic.path()).unwrap(),
        b"fixture monitor stderr\r\n"
    );
}
