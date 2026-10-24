//! Actual socket/event controls for the one-shot host sender.
//!
//! Reply values model only wire observations. These fixtures never issue a
//! native worker, request, StopOwner, page proof, or capture eligibility.

use super::*;
use crate::ram_control::{RamControlClient, RamControlRegistrar};
use crucible_qemu_protocol::ram_control::*;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
use std::io::{IoSliceMut, Read};
use std::mem::MaybeUninit;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

struct SocketRegistrar {
    client: Mutex<RamControlClient>,
}

impl RamControlRegistrar for SocketRegistrar {
    fn checkpoint_arm(
        &self,
        loan: CheckpointArmLoan<'_>,
    ) -> Result<CheckpointArmReceipt, CheckpointOriginalError> {
        self.client.lock().unwrap().checkpoint_arm(loan)
    }

    fn register(
        &self,
        _target: HostRamTarget,
        _policy: crucible_host_resources::ram_policy::HostRamPolicy,
        _resources: crucible_host_resources::ram_policy::HostResourceVector,
        _supervisor: HostOperationSupervisor,
        _client: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }
}

fn receive_arm(worker: &mut UnixStream) -> (RamControlFrame, OwnedFd) {
    let mut first = [0; 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        &*worker,
        &mut [IoSliceMut::new(&mut first)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .unwrap();
    assert_eq!(received.bytes, 1);
    let mut aliases = control
        .drain()
        .flat_map(|message| match message {
            RecvAncillaryMessage::ScmRights(descriptors) => descriptors.collect::<Vec<_>>(),
            _ => panic!("unexpected ancillary record"),
        })
        .collect::<Vec<_>>();
    assert_eq!(aliases.len(), 1);
    let mut length = [0; 4];
    length[0] = first[0];
    worker.read_exact(&mut length[1..]).unwrap();
    let size = u32::from_be_bytes(length) as usize;
    assert_eq!(size, 238);
    let mut body = [0; RAM_CONTROL_CHECKPOINT_MAX_BYTES];
    worker.read_exact(&mut body[..size]).unwrap();
    let frame = decode_ram_control(&body[..size]).unwrap();
    assert!(matches!(
        frame.message,
        RamControlMessage::Request(RamControlRequest::CheckpointArm { .. })
    ));
    (frame, aliases.remove(0))
}

fn reply(worker: &mut UnixStream, frame: RamControlFrame, wrong_digest: bool) {
    let mut digest = ram_control_request_digest(&frame).unwrap();
    if wrong_digest {
        digest[0] ^= 1;
    }
    let response = RamControlFrame {
        message: RamControlMessage::CheckpointArmReply {
            request_digest: digest,
            receipt: RamControlCheckpointArmReceipt {
                disposition: RamControlDisposition::Accepted,
                request_generation: 7,
                first_status: 0,
                post_status: 0,
            },
        },
        ..frame
    };
    write_ram_control(worker, &response).unwrap();
}

#[test]
fn arm_sends_the_same_event_once_and_reuses_the_saved_receipt() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let (signal, trigger) = std::sync::mpsc::channel();
    let pager = std::thread::spawn(move || {
        let hello = read_ram_control(&mut worker).unwrap().unwrap();
        write_ram_control(
            &mut worker,
            &crate::ram_control::checkpoint_test_response(hello),
        )
        .unwrap();
        let (arm, alias) = receive_arm(&mut worker);
        reply(&mut worker, arm, false);
        worker
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let mut byte = [0];
        assert!(
            worker.read(&mut byte).is_err(),
            "saved receipt must not resend any byte"
        );
        trigger.recv().unwrap();
        rustix::io::write(&alias, &1_u64.to_ne_bytes()).unwrap();
    });
    let supervisor = supervisor();
    let client =
        RamControlClient::connect_supervised(host, [4; 32], target(), supervisor.clone()).unwrap();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let registration = registration(
        &account,
        Arc::new(SocketRegistrar {
            client: Mutex::new(client),
        }),
    );
    let event = event();
    let mut owner = CheckpointOriginal::allocate(&supervisor, &registration).unwrap();
    owner.enter(&event).unwrap();

    let receipt = owner.prepare_receiving(&registration).unwrap();
    assert_eq!(owner.prepare_receiving(&registration).unwrap(), receipt);
    assert_eq!(
        supervisor
            .operation_statuses()
            .unwrap()
            .iter()
            .filter(|status| status.class == HostOperationClass::Quiescence)
            .count(),
        1
    );
    signal.send(()).unwrap();
    pager.join().unwrap();
    assert!(
        owner.check(target()).is_err(),
        "received kernel alias must cancel the actual original"
    );
    owner.retire_after_reap();
    assert!(account.reserve_resources(0, 2, 16384).is_ok());
}

#[test]
fn mismatched_arm_digest_poisoning_preserves_the_first_refusal() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let pager = std::thread::spawn(move || {
        let hello = read_ram_control(&mut worker).unwrap().unwrap();
        write_ram_control(
            &mut worker,
            &crate::ram_control::checkpoint_test_response(hello),
        )
        .unwrap();
        let (arm, _alias) = receive_arm(&mut worker);
        reply(&mut worker, arm, true);
    });
    let supervisor = supervisor();
    let client =
        RamControlClient::connect_supervised(host, [4; 32], target(), supervisor.clone()).unwrap();
    let registrar = Arc::new(SocketRegistrar {
        client: Mutex::new(client),
    });
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let registration = registration(&account, registrar.clone());
    let event = event();
    let mut owner = CheckpointOriginal::allocate(&supervisor, &registration).unwrap();
    owner.enter(&event).unwrap();

    let first = owner.prepare_receiving(&registration).unwrap_err();
    assert_eq!(
        first.source,
        CheckpointOriginalCause::Transport(CheckpointTransportCause::AuthorityMismatch)
    );
    assert!(matches!(
        registrar.client.lock().unwrap().status(),
        Err(RamControlError::AuthorityMismatch)
    ));
    supervisor.cancel().unwrap();
    let later = owner.prepare_receiving(&registration).unwrap_err();
    assert_eq!(later.source, first.source);
    assert!(later.original_after.is_some());
    pager.join().unwrap();
    owner.retire_after_reap();
}

#[test]
fn different_supervisor_is_refused_before_arm_bytes_or_descriptor() {
    let (host, mut worker) = UnixStream::pair().unwrap();
    let pager = std::thread::spawn(move || {
        let hello = read_ram_control(&mut worker).unwrap().unwrap();
        write_ram_control(
            &mut worker,
            &crate::ram_control::checkpoint_test_response(hello),
        )
        .unwrap();
        worker
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut byte = [0];
        assert!(worker.read(&mut byte).is_err());
    });
    let different = supervisor();
    let client = RamControlClient::connect_supervised(host, [4; 32], target(), different).unwrap();
    let supervisor = supervisor();
    let account = HostServiceAllocator::new(1, 2, 16384).unwrap();
    let registration = registration(
        &account,
        Arc::new(SocketRegistrar {
            client: Mutex::new(client),
        }),
    );
    let event = event();
    let mut owner = CheckpointOriginal::allocate(&supervisor, &registration).unwrap();
    owner.enter(&event).unwrap();

    let first = owner.prepare_receiving(&registration).unwrap_err();
    assert_eq!(
        first.source,
        CheckpointOriginalCause::Transport(CheckpointTransportCause::AuthorityMismatch)
    );
    pager.join().unwrap();
    owner.retire_after_reap();
}
