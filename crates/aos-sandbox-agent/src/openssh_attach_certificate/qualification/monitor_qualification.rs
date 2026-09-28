//! Real pinned sshd monitor/authentication fixture, never an I/O authority.
//!
//! The fixture uses the existing fixed Guest pathname only to inspect real
//! monitor records and pidfds. Production registry/Controller currentness and
//! continuously confined relay/held consume still require separate qualification.

use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};

use super::*;
use crate::openssh_monitor::{
    OPENSSH_MONITOR_BINDING_ACK_V2, OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2,
    OpenSshMonitorWitnessV2,
};

const SOCKET: &str = "/run/aos-sandbox-agent/exec-gate.sock";

pub(super) fn qualify_root_monitor_binding(ssh: &str, base: &OpenSshGateClaimV1, original: &str) {
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
    protected_file(
        crate::openssh_ticket::OPENSSH_TICKET_CLAIM_PATH_V2,
        &ticket.encode().unwrap(),
        0o444,
    );

    let mut daemon = RunningOpenSshGateV1::start_with_monitor_v2(base.binding.clone()).unwrap();
    let mut claim = base.clone();
    (claim.sshd_pid, claim.sshd_start_ticks) = daemon.daemon_identity().unwrap();
    write_claim(&claim);
    wait_listener();
    let runtime = daemon.monitor_runtime_v2(&claim).unwrap();
    assert!(
        runtime
            .require_monitor(
                &PidFd::open(std::num::NonZeroU32::new(std::process::id()).unwrap()).unwrap()
            )
            .is_err()
    );
    assert!(PidFd::from_owned(fs::File::open("/dev/null").unwrap().into()).is_err());

    let mut client = ssh_command(ssh, original)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connection = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                assert!(Instant::now() < deadline, "root monitor did not register");
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
    let witness = OpenSshMonitorWitnessV2::decode(&payload).unwrap();
    witness
        .validate_original_holder(&claim, &ticket, now())
        .unwrap();
    runtime
        .require_child(
            &child,
            connection.peer().credentials().pid().get(),
            witness.uid,
            witness.gid,
        )
        .unwrap();
    assert_eq!((witness.uid, witness.gid), (1001, 1001));
    assert!(
        runtime
            .require_child(&child, claim.sshd_pid, witness.uid, witness.gid)
            .is_err()
    );
    assert!(
        runtime
            .require_child(
                &child,
                connection.peer().credentials().pid().get(),
                1002,
                1002
            )
            .is_err()
    );
    connection.send(OPENSSH_MONITOR_BINDING_ACK_V2).unwrap();

    // Refuse the later unprivileged forced command without sending any FD.
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if client.try_wait().unwrap().is_some() {
            break;
        }
        if let Ok(gate) = listener.accept() {
            assert_eq!(gate.peer().credentials().uid(), 1001);
            drop(gate);
        }
        assert!(
            Instant::now() < deadline,
            "authentication-only client did not close"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let output = client.wait_with_output().unwrap();
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Authenticated to 127.0.0.1")
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // A retained pidfd never adopts a later numeric PID: the exited original
    // child is closed even if a future process eventually obtains that number.
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.is_alive().unwrap() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        runtime
            .require_child(&child, subject.credentials().pid().get(), 1001, 1001)
            .is_err()
    );
    drop(connection);
    drop(daemon);

    qualify_incomplete_authentication(&mut listener, base, original, ssh);
    drop(listener);
    fs::remove_file(SOCKET).unwrap();
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
        let daemon = OwnedProcess(command.spawn().unwrap());
        let mut claim = base.clone();
        claim.sshd_pid = daemon.0.id();
        claim.sshd_start_ticks = process_start_ticks(daemon.0.id());
        write_claim(&claim);
        wait_listener();
        let output = ssh_command(ssh, original).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(matches!(listener.accept(), Err(SeqpacketError::WouldBlock)));
        drop(daemon);
        let log = fs::read_to_string(&log_path).unwrap();
        // Denial must follow actual privileged certificate verification, not
        // an absent PAM file, invalid configuration or failed signature.
        assert!(
            log.lines()
                .any(|line| line.contains("mm_answer_keyverify: publickey")
                    && line.contains(" verified"))
        );
        match case {
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

fn wait_listener() {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", 2222)).is_err() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
}
