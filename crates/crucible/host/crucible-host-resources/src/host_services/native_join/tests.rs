//! Exercises actual TLS return separately from Rust body completion.

use super::*;
use std::cell::RefCell;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

struct HeldTls {
    entered: Sender<()>,
    release: Receiver<()>,
}

impl Drop for HeldTls {
    fn drop(&mut self) {
        let _ = self.entered.send(());
        let _ = self.release.recv();
    }
}

thread_local! {
    static HELD_TLS: RefCell<Option<HeldTls>> = const { RefCell::new(None) };
}

fn worker_with_held_tls() -> (NativeJoinOwner, Receiver<()>, Sender<()>) {
    let (entered, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        HELD_TLS.with(|slot| {
            *slot.borrow_mut() = Some(HeldTls {
                entered,
                release: released,
            })
        });
    });
    (NativeJoinOwner::from_worker(worker), observed, release)
}

fn require_joined(owner: &mut NativeJoinOwner) {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match owner.poll().unwrap() {
            NativeJoinObservation::Returned => return,
            NativeJoinObservation::Pending => {
                assert!(Instant::now() < end, "actual TLS task did not return");
                std::thread::yield_now();
            }
        }
    }
}

#[test]
fn body_return_cannot_retire_a_task_with_a_live_tls_destructor() {
    let (mut owner, entered, release) = worker_with_held_tls();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let identity = owner.thread_id();

    assert_eq!(owner.poll().unwrap(), NativeJoinObservation::Pending);
    assert_eq!(owner.last_status(), Some(libc::EBUSY));
    assert!(owner.native.is_some());
    release.send(()).unwrap();
    require_joined(&mut owner);

    assert_eq!(owner.thread_id(), identity);
    assert!(owner.native.is_none());
    assert_eq!(owner.last_status(), Some(0));
    assert_eq!(owner.poll().unwrap(), NativeJoinObservation::Returned);
    assert_eq!(owner.last_status(), Some(0));
}

#[test]
fn inherited_identity_refuses_before_accessing_the_actual_native_handle() {
    let (mut owner, entered, release) = worker_with_held_tls();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let creator = owner.creator_process;
    owner.creator_process = creator.wrapping_add(1);

    assert_eq!(owner.poll(), Err(NativeJoinError::ForeignProcess));
    assert_eq!(owner.last_status(), None);
    assert!(owner.native.is_some());

    owner.creator_process = creator;
    release.send(()).unwrap();
    require_joined(&mut owner);
}

#[test]
fn unexpected_result_is_permanent_and_never_overwritten_by_later_success() {
    // This pure disposition control owns no task or fabricated native receipt.
    let mut disposition = Disposition::Active;
    assert_eq!(
        disposition.observe(libc::EBUSY),
        Ok(NativeJoinObservation::Pending)
    );
    let first = NativeJoinError::Native {
        status: libc::EINVAL,
    };
    assert_eq!(disposition.observe(libc::EINVAL), Err(first));
    assert_eq!(disposition.observe(0), Err(first));
    assert_eq!(disposition.observe(libc::ESRCH), Err(first));
    assert_eq!(disposition, Disposition::Uncertain(libc::EINVAL));
}
