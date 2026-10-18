//! Measures both actual decimal serializers in the same ordinary test binary.
//!
//! This ignored test reports every sample. It changes no test profile, process
//! supervision or allocator, and infers no VM or scenario performance from the
//! scalar measurement. The caller builds its ordinary optimized test target.

// crucible-lint: allow panic-shortcut -- This optional benchmark fails on any wire or writer mismatch.
use super::U64;
use serde::{Serialize, Serializer};
use std::{hint::black_box, io::Cursor, time::Instant};

struct PreviousU64(u64);

impl Serialize for PreviousU64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // This is the actual prior implementation, measured without changing
        // the current production branch or constructing another executable.
        serializer.serialize_str(&self.0.to_string())
    }
}

fn assert_wire_parity(value: u64) {
    let prior = serde_json::to_vec(&PreviousU64(value)).unwrap();
    let current = serde_json::to_vec(&U64::new(value)).unwrap();
    assert_eq!(current, prior);
    assert_eq!(
        serde_json::from_slice::<U64>(&current).unwrap().get(),
        value
    );
}

fn serialize_repeated<T: Serialize>(value: &T, iterations: usize) -> u128 {
    // Output storage is fixed and prefunded. Only the old formatter's actual
    // temporary String differs from the new formatter inside the timed loop.
    let mut output = Cursor::new([0u8; 22]);
    let started = Instant::now();
    for _ in 0..iterations {
        output.set_position(0);
        serde_json::to_writer(black_box(&mut output), black_box(value)).unwrap();
        black_box(output.position());
        black_box(output.get_ref());
    }
    started.elapsed().as_nanos()
}

#[test]
#[ignore = "manual measurement in the ordinary optimized Contract test binary"]
fn compare_old_and_stack_u64_serializers() {
    const WARMUP: usize = 4096;
    const ITERATIONS: usize = 200_000;
    const PAIRS: usize = 30;
    let cases = [
        ("zero", 0),
        ("instruction_time_ps", 50),
        ("common_sequence", 1024),
        ("common_time_ps", 1_000_000_000),
        ("wide_32bit", 1u64 << 32),
        ("wide_53bit", 1u64 << 53),
        ("wide_20digit", 10_000_000_000_000_000_000),
        ("maximum", u64::MAX),
    ];
    eprintln!("u64_serializer_sample,case,value,pair,first,iterations,old_ns,new_ns");
    for (name, value) in cases {
        assert_wire_parity(value);
        let previous = PreviousU64(value);
        let current = U64::new(value);
        for pair in 0..PAIRS {
            // Every pair warms both equally. Alternating both warmup and
            // measured order balances first/second position for either path.
            let (first, old_ns, new_ns) = if pair % 2 == 0 {
                black_box(serialize_repeated(&previous, WARMUP));
                black_box(serialize_repeated(&current, WARMUP));
                let old_ns = serialize_repeated(&previous, ITERATIONS);
                let new_ns = serialize_repeated(&current, ITERATIONS);
                ("old", old_ns, new_ns)
            } else {
                black_box(serialize_repeated(&current, WARMUP));
                black_box(serialize_repeated(&previous, WARMUP));
                let new_ns = serialize_repeated(&current, ITERATIONS);
                let old_ns = serialize_repeated(&previous, ITERATIONS);
                ("new", old_ns, new_ns)
            };
            eprintln!(
                "u64_serializer_sample,{name},{value},{pair},{first},{ITERATIONS},{old_ns},{new_ns}"
            );
        }
        assert_wire_parity(value);
    }
}
