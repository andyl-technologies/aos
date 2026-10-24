//! Exercises finite original frame progress with no Child or qualification.

// crucible-lint: allow panic-shortcut -- Pipe and writer fixtures deliberately panic on failed ownership and deadline assertions.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use super::*;

#[test]
fn unread_nonblocking_pipe_retains_partial_original_and_refuses_second_attempt() {
    let body = vec![0x5a; 1024 * 1024];
    let mut frame = OriginalLaunchFrame::reserve(&body, body.len()).unwrap();
    let original_bytes = frame.bytes.clone();
    let (mut reader, mut writer) = std::io::pipe().unwrap();
    let flags = rustix::fs::fcntl_getfl(&writer).unwrap();
    rustix::fs::fcntl_setfl(&writer, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
    frame.begin(Duration::from_secs(1)).unwrap();

    assert!(frame.write_original(&mut writer).is_err());
    let retained = frame.cursor;
    assert!(retained > 0 && retained < original_bytes.len());
    assert_eq!(frame.bytes, original_bytes);
    let mut observed = vec![0; retained];
    reader.read_exact(&mut observed).unwrap();
    assert_eq!(observed, original_bytes[..retained]);
    assert!(frame.deadline().unwrap().remaining().is_err());
    assert!(frame.begin(Duration::from_secs(3)).is_err());
    assert_eq!(frame.cursor, retained);
    assert_eq!(frame.bytes, original_bytes);
}

#[test]
fn exact_frame_is_sent_once_and_the_shared_cut_cannot_be_renewed() {
    let mut frame = OriginalLaunchFrame::reserve(b"{}", 2).unwrap();
    frame.begin(Duration::from_millis(10)).unwrap();
    let cut = frame.deadline().unwrap();
    let mut bytes = Vec::new();

    frame.write_original(&mut bytes).unwrap();
    assert_eq!(bytes, [0, 0, 0, 2, b'{', b'}']);
    assert_eq!(frame.cursor, bytes.len());
    while let Ok(remaining) = cut.remaining() {
        std::thread::park_timeout(remaining);
    }
    assert!(frame.deadline().unwrap().remaining().is_err());
    assert!(frame.begin(Duration::from_secs(3)).is_err());
    assert_eq!(frame.bytes, bytes);
    assert!(OriginalLaunchFrame::reserve(b"{}", 1).is_err());
}

struct UnwindAfterPrefix {
    calls: usize,
    original: Vec<u8>,
}

impl Write for UnwindAfterPrefix {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls > 1 {
            panic!("inert writer callback unwind");
        }
        self.original.extend_from_slice(&bytes[..2]);
        Ok(2)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_unwind_keeps_original_frame_cursor_and_attempt_fence() {
    let mut frame = OriginalLaunchFrame::reserve(b"{}", 2).unwrap();
    frame.begin(Duration::from_secs(3)).unwrap();
    let original = frame.bytes.clone();
    let mut writer = UnwindAfterPrefix {
        calls: 0,
        original: Vec::new(),
    };

    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            frame.write_original(&mut writer)
        }))
        .is_err()
    );
    assert_eq!(frame.cursor, 2);
    assert_eq!(writer.original, original[..2]);
    assert_eq!(frame.bytes, original);
    assert!(frame.begin(Duration::from_secs(3)).is_err());
}
