//! Branch reseeding and repeatability checks for scheduling sub-nodes.

use super::*;

#[test]
fn branch_reseed_restarts_block_fault_draws_at_cursor_zero() {
    let faults = IoFaults {
        loss: Probability::ALWAYS,
        ..IoFaults::none()
    };
    let branch_seed = Seed::from_u64(0xb10c_0002);
    let mut expected = crate::device::device_rng(branch_seed, &device_id("disk"), 0);
    let expected_first_draw = expected.next_u64();
    let mut disk = fresh_disk(Seed::from_u64(0xb10c_0001), faults);
    disk.submit(0, &read_request(1, 0, 8))
        .unwrap_or_else(|error| panic!("prefix submit should succeed: {error}"));
    let _ = disk.deliver_due(u64::MAX);

    disk.reseed_future_decisions(branch_seed);
    disk.submit(2_000, &read_request(2, 0, 8))
        .unwrap_or_else(|error| panic!("branch submit should succeed: {error}"));
    let delivered = disk.deliver_due(u64::MAX);
    let actual_first_draw = delivered.iter().find_map(|delivery| {
        delivery
            .decisions
            .iter()
            .find_map(|decision| match decision {
                Decision::RngDraw(draw) => Some(draw.value),
                _ => None,
            })
    });

    assert_eq!(actual_first_draw, Some(expected_first_draw));
}

#[test]
fn branch_reseed_restarts_ninep_fault_draws_at_cursor_zero() {
    let faults = IoFaults {
        loss: Probability::ALWAYS,
        ..IoFaults::none()
    };
    let branch_seed = Seed::from_u64(0x9f50_0002);
    let mut expected = crate::device::device_rng(branch_seed, &device_id("fs"), 0);
    let expected_first_draw = expected.next_u64();
    let mut fs = fresh_ninep(Seed::from_u64(0x9f50_0001), faults);
    fs.submit_ninep_frame(0, &tversion(7, 4096, codec::PROTOCOL_VERSION))
        .unwrap_or_else(|error| panic!("prefix 9p submit should succeed: {error}"));
    let _ = fs.deliver_due(u64::MAX);

    fs.reseed_future_decisions(branch_seed);
    fs.submit_ninep_frame(2_000, &tversion(8, 4096, codec::PROTOCOL_VERSION))
        .unwrap_or_else(|error| panic!("branch 9p submit should succeed: {error}"));
    let delivered = fs.deliver_due(u64::MAX);
    let actual_first_draw = delivered.iter().find_map(|delivery| {
        delivery
            .decisions
            .iter()
            .find_map(|decision| match decision {
                Decision::RngDraw(draw) => Some(draw.value),
                _ => None,
            })
    });

    assert_eq!(actual_first_draw, Some(expected_first_draw));
}

#[test]
fn run_twice_is_byte_identical() {
    let faults = IoFaults {
        jitter_window_ns: 64,
        loss: Probability::new(1, 3),
        ..IoFaults::none()
    };
    let drive = || {
        let mut disk = fresh_disk(Seed::from_u64(0x7e57), faults.clone());
        for index in 0..4u64 {
            disk.submit(index * 50, &read_request(index as u32 + 1, 0, 8))
                .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
        }
        let mut out = Vec::new();
        while let Some(delivery) = disk.next_exact_local_event() {
            out.extend(disk.deliver_due(delivery));
        }
        out
    };
    assert_eq!(drive(), drive(), "two runs must be byte-identical");
}
