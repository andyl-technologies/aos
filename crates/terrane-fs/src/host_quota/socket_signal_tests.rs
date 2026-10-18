//! Isolates real signal interruptions of retained native seqpacket receives.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SIGNALS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn interrupted(_: libc::c_int) {
    SIGNALS.fetch_add(1, Ordering::Relaxed);
}

fn isolated(name: &str) -> bool {
    if std::env::var("TERRANE_QUOTA_SIGNAL_CHILD").as_deref() == Ok(name) {
        return true;
    }
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", name, "--nocapture"])
        .env("TERRANE_QUOTA_SIGNAL_CHILD", name)
        .output()
        .expect("isolated signal subprocess");
    assert!(
        output.status.success(),
        "signal subprocess failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
        "isolated exact test filter did not execute one successful case"
    );
    false
}

fn install_handler() -> libc::pthread_t {
    // SAFETY: the isolated child installs a non-restarting handler with no
    // allocation or shared non-atomic state. No unrelated tests run here.
    unsafe {
        let mut action: libc::sigaction = zeroed();
        action.sa_sigaction = interrupted as *const () as usize;
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(
            libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()),
            0
        );
        libc::pthread_self()
    }
}

#[test]
fn interrupted_receive_keeps_the_same_connection() {
    if !isolated("host_quota::socket::signal_tests::interrupted_receive_keeps_the_same_connection")
    {
        return;
    }
    let target = install_handler();
    let (sender, receiver) = super::tests::pair();
    let producer = std::thread::spawn(move || {
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(40));
            // SAFETY: the receiving test thread remains live through join.
            assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGUSR1) }, 0);
        }
        std::thread::sleep(Duration::from_millis(40));
        sender.send(b"after interruption").expect("actual packet");
        sender.send(b"same session").expect("second actual packet");
    });

    assert_eq!(
        receiver.receive().expect("interrupted receive"),
        b"after interruption"
    );
    assert_eq!(
        receiver.receive().expect("retained connection"),
        b"same session"
    );
    producer.join().expect("signal producer");
    assert!(SIGNALS.load(Ordering::Relaxed) >= 3);
}

#[test]
fn repeated_interruptions_do_not_extend_the_original_deadline() {
    if !isolated(
        "host_quota::socket::signal_tests::repeated_interruptions_do_not_extend_the_original_deadline",
    ) {
        return;
    }
    let target = install_handler();
    let (_sender, receiver) = super::tests::pair();
    let producer = std::thread::spawn(move || {
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(20));
            // SAFETY: the receiving test thread remains live through join.
            assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGUSR1) }, 0);
        }
    });

    let started = Instant::now();
    let error = receiver
        .receive_until(started + Duration::from_millis(250))
        .expect_err("finite interrupted receive must expire");
    let elapsed = started.elapsed();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        elapsed >= Duration::from_millis(200),
        "premature timeout: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(650),
        "deadline extended: {elapsed:?}"
    );
    assert!(SIGNALS.load(Ordering::Relaxed) >= 2);
    producer.join().expect("signal producer");
}
