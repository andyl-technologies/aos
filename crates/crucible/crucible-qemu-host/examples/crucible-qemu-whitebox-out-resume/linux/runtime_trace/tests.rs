//! Original native row decoding and bounded raw/binary suffix controls.

use super::*;

#[test]
fn exact_opt_in_rejects_other_spellings_and_non_text_bytes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    assert!(enabled(Some(OsStr::new("1"))));
    for setting in [
        None,
        Some(OsStr::new("true")),
        Some(OsStr::new("01")),
        Some(OsStr::new("1\n")),
        Some(OsStr::from_bytes(&[0xff])),
    ] {
        assert!(!enabled(setting));
    }
}

#[test]
fn genuine_native_row_schemas_distinguish_rr_callback_entry_from_host_delivery() {
    let bytes = b"crucible_sim_determinism_timer seq=1 timer=3 list=1 scope=global owner=rr expire_ps=10 current_ps=10 raw=80\ncrucible_sim_determinism_timer seq=2 timer=4 list=2 scope=aio owner=host expire_ps=11 current_ps=12 raw=81\n";
    let summary = summarize(&mut io::Cursor::new(bytes))
        .unwrap_or_else(|error| panic!("native rows: {error}"));
    assert_eq!(
        (summary.rows, summary.timer_rows, summary.rr_timer_entries),
        (2, 2, 1)
    );
    assert_eq!(summary.malformed_rows, 0);
    assert!(summary.complete_pairs);
    assert_eq!(summary.tail.iter().copied().collect::<Vec<_>>(), bytes);
    assert_eq!(summary.bytes, bytes.len() as u64);
}

#[test]
fn partial_and_binary_overflow_remain_advisory_with_exact_raw_suffix_bounds() {
    let mut bytes = b"partial native row without LF".to_vec();
    bytes.extend(std::iter::repeat_n(0xff, 8192));
    let summary = summarize(&mut io::Cursor::new(&bytes))
        .unwrap_or_else(|error| panic!("raw bytes: {error}"));
    assert_eq!(summary.bytes, bytes.len() as u64);
    assert_eq!(summary.malformed_rows, 1);
    assert_eq!(summary.timer_rows, 0);
    assert!(!summary.complete_pairs);
    assert_eq!(summary.tail.len(), TAIL_BYTES);
    assert_eq!(
        summary.tail.iter().copied().collect::<Vec<_>>(),
        bytes[bytes.len() - TAIL_BYTES..]
    );
    let escaped = summary.escaped_tail();
    assert_eq!(escaped.len(), TAIL_BYTES * 4);
    assert_eq!(escaped, "\\xff".repeat(TAIL_BYTES));
}

#[test]
fn finite_stream_ceiling_refuses_oversize_without_unbounded_line_allocation() {
    use std::io::Read;

    let source = io::repeat(b'x').take(MAXIMUM_BYTES + 1);
    let error = summarize(&mut io::BufReader::new(source))
        .err()
        .unwrap_or_else(|| panic!("oversize trace accepted"));
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}
