//! Real nonblocking socket pressure, bounded drainage, and linear release.

use std::io::Write;

use super::*;

fn callback(token: u32) -> String {
    format!(
        "CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=pending pid=153 raw_icount=5859742910 token_kind=observed token_before={token} token_after={token}\n"
    )
}

#[test]
fn interleaved_live_drains_retain_late_rows_after_actual_socket_saturation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = create_diagnostic_pair(47)?;
    let mut consumer = pair.take_consumer()?;
    consumer.bind_child_process_id(153);
    let mut expected = Vec::new();
    let mut saturated = false;

    // The same nonblocking writer cannot deliver an unlimited undrained prefix.
    for token in 0..4096 {
        let row = callback(token);
        match pair.child.write(row.as_bytes()) {
            Ok(count) => expected.extend_from_slice(&row.as_bytes()[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                saturated = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(saturated);
    assert!(!expected.is_empty());

    let initial = consumer.drain_available_bounded()?;
    assert!(initial.bytes_read() <= MAXIMUM_READ_ATTEMPTS * READ_BYTES);
    assert!(!initial.eof());
    // Terminate any partial row from the pressured prefix before later rows.
    pair.child.write_all(b"\n")?;
    expected.push(b'\n');
    for batch in 0..20 {
        for ordinal in 0..50 {
            let row = callback(4000 + batch * 50 + ordinal);
            pair.child.write_all(row.as_bytes())?;
            expected.extend_from_slice(row.as_bytes());
        }
        let drain = consumer.drain_available_bounded()?;
        assert!(drain.bytes_read() <= MAXIMUM_READ_ATTEMPTS * READ_BYTES);
        assert!(consumer.live_drain_error().is_none());
    }

    pair.child.shutdown(Shutdown::Write)?;
    consumer.mark_writer_detached(&pair.descriptor_name, pair.socket_cookie, 47)?;
    let capture = consumer.finish_detached_capture()?;
    assert_eq!(capture.stream_bytes(), expected.len() as u64);
    let tail_start = expected
        .len()
        .saturating_sub(MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES);
    assert_eq!(capture.tail(), &expected[tail_start..]);
    assert_eq!(capture.omitted_bytes(), tail_start as u64);
    assert_eq!(capture.socket_cookie(), pair.socket_cookie);
    assert_eq!(capture.descriptor_name(), &pair.descriptor_name);
    assert_eq!(capture.template_generation(), 47);
    assert!(
        capture
            .control_diagnostics_summary()
            .ends_with(callback(4999).trim_end())
    );
    assert!(consumer.finish_detached_capture().is_err());
    assert!(consumer.drain_available_bounded().is_err());
    Ok(())
}

#[test]
fn one_live_turn_leaves_available_bytes_beyond_its_64_kib_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pair = create_diagnostic_pair(51)?;
    let mut consumer = pair.take_consumer()?;
    let chunk = [0x5a; 4096];
    let mut written = 0;
    for _ in 0..256 {
        match pair.child.write(&chunk) {
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    assert!(written > MAXIMUM_READ_ATTEMPTS * READ_BYTES);

    let first = consumer.drain_available_bounded()?;
    assert_eq!(first.bytes_read(), MAXIMUM_READ_ATTEMPTS * READ_BYTES);
    assert_eq!(first.stream_bytes(), first.bytes_read() as u64);
    assert!(!first.eof());
    let remaining = consumer.drain_available()?;
    assert_eq!(remaining.stream_bytes(), written as u64);
    assert_eq!(
        consumer.retained_tail().len(),
        written.min(MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES)
    );
    assert!(consumer.retained_tail().iter().all(|byte| *byte == 0x5a));
    Ok(())
}

#[test]
fn live_read_failure_stays_sticky_and_refuses_eof_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let mut pair = create_diagnostic_pair(53)?;
    let mut consumer = pair.take_consumer()?;
    pair.child.write_all(b"before loss\n")?;
    consumer.drain_available_bounded()?;

    // A socket read from a directory descriptor fails with ENOTSOCK, a
    // deterministic error that no concurrently forked test process can mask.
    consumer.host = UnixStream::from(std::os::fd::OwnedFd::from(std::fs::File::open("/")?));

    assert!(consumer.drain_available_bounded().is_err());
    let failure = consumer
        .live_drain_error()
        .ok_or("live read failure was not retained")?
        .to_owned();
    assert!(failure.contains("read branch-private child diagnostics failed"));
    assert!(failure.len() <= MAXIMUM_ERROR_CHARS);
    consumer.mark_writer_detached(&pair.descriptor_name, pair.socket_cookie, 53)?;

    assert!(consumer.drain_available_bounded().is_err());
    assert!(consumer.drain_available().is_err());
    assert!(consumer.finish_detached_capture().is_err());
    assert_eq!(consumer.live_drain_error(), Some(failure.as_str()));
    assert_eq!(consumer.retained_tail(), b"before loss\n");
    assert!(!consumer.captured);
    Ok(())
}
