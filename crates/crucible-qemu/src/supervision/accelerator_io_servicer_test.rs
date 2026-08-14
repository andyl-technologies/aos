//! Tests extracted from the adjacent production module.

use super::*;

#[test]
fn closed_job_schemas_are_integer_only_and_strict() {
    let mut gpu = 2_u32.to_le_bytes().to_vec();
    gpu.extend_from_slice(&1_i32.to_le_bytes());
    gpu.extend_from_slice(&2_i32.to_le_bytes());
    gpu.extend_from_slice(&3_i32.to_le_bytes());
    gpu.extend_from_slice(&4_i32.to_le_bytes());
    assert_eq!(
        execute_gpu_vector_add(&gpu, 8),
        (0, [4_i32.to_le_bytes(), 6_i32.to_le_bytes()].concat())
    );
    assert_eq!(
        execute_gpu_vector_add(&gpu[..gpu.len() - 1], 8).0,
        STATUS_MALFORMED_JOB
    );

    let mut fpga = (0_u8..=255).rev().collect::<Vec<_>>();
    fpga.extend_from_slice(&[0, 1, 255]);
    assert_eq!(execute_fpga_lut(&fpga, 3), (0, vec![255, 254, 0]));

    let mut tpu = vec![1, 0, 2, 0, 1, 0, 2, 3, 4, 5];
    assert_eq!(
        execute_tpu_i8_matmul(&tpu, 4),
        (0, 23_i32.to_le_bytes().to_vec())
    );
    tpu.push(0);
    assert_eq!(execute_tpu_i8_matmul(&tpu, 4).0, STATUS_MALFORMED_JOB);
}

#[test]
fn accelerator_checkpoint_codec_round_trips_pending_completion() {
    let completion = AcceleratorEntry::new(
        2,
        3,
        [4; 32],
        AcceleratorClass::Gpu,
        1,
        0,
        0,
        true,
        10,
        8,
        &[1, 2, 3, 4],
    )
    .unwrap_or_else(|error| panic!("valid completion: {error}"));
    let checkpoint = QemuLiveAcceleratorCheckpoint {
        vm_slot: 7,
        pending: BTreeMap::from([(
            (3, 2),
            PendingAcceleratorCompletion {
                due_icount: 99,
                completion,
            },
        )]),
    };
    let bytes = checkpoint
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode checkpoint: {error}"));
    assert_eq!(
        QemuLiveAcceleratorCheckpoint::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("decode checkpoint: {error}")),
        checkpoint
    );
}
