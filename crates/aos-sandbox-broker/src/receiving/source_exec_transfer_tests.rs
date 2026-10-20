//! Projects Source's closed error onto shared fixed-service transfer custody.
//!
//! Source retains its original PID1/profile/ledger and all Source-only policy.
//! This alias only shares passive transfer decoding and physical executable
//! observations; it cannot issue an original, account or receiving loan.

#[derive(Clone, Copy, Debug, Default, thiserror::Error)]
#[error("inert Source format fixture refused")]
struct SourceReceivingClosedV1;

type SourceExecTransferReadbackV1 =
    super::fixed_service_transfer::FixedServiceExecTransferReadbackV1<
        SourceReceivingClosedV1,
    >;

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    use aos_sandbox_protocol::domain_ledger::resource_bank::{
        FIXED_SERVICE_FINAL_TRANSFER_BYTES, FIXED_SERVICE_ORIGIN_HEADER_BYTES,
    };

    // Complete new-profile comparison DATA, never a genuine Source original.
    fn packet() -> (Vec<u8>, ResourceVector, ResourceVector) {
        let ceiling = ResourceVector::new([65_536; D::COUNT])
            .with(D::MemoryBytes, 1024 * 1024)
            .with(D::CpuMicrosPerPeriod, 10_000)
            .with(D::Pids, 4)
            .with(D::OpenFiles, 128);
        let usage = ResourceVector::ZERO
            .with(D::CpuMicrosPerPeriod, 10_000)
            .with(D::MemoryBytes, 4096)
            .with(D::Pids, 1)
            .with(D::OpenFiles, 80)
            .with(D::Mounts, 12)
            .with(D::TmpfsBytes, 4096)
            .with(D::MetadataEntries, 64)
            .with(D::ConcurrentOperations, 1);
        let mut packet = vec![0; FIXED_SERVICE_FINAL_TRANSFER_BYTES];
        packet[..8].copy_from_slice(b"AOSRSO01");
        packet[8] = 3;
        packet[9] = 1;
        packet[16..32].fill(1);
        packet[32..40].copy_from_slice(&1_u64.to_be_bytes());
        packet[40..48].copy_from_slice(&42_u64.to_be_bytes());
        packet[48..56].copy_from_slice(&100_u64.to_be_bytes());
        packet[56..88].fill(7);
        packet[88..96].copy_from_slice(&64_u64.to_be_bytes());
        packet[96..104].copy_from_slice(&16_u64.to_be_bytes());
        packet[104..112].copy_from_slice(&80_u64.to_be_bytes());
        packet[112..120].copy_from_slice(&131_072_u64.to_be_bytes());
        packet[120..128].copy_from_slice(&1_u64.to_be_bytes());
        for (index, dimension) in D::ALL.into_iter().enumerate() {
            let start = FIXED_SERVICE_ORIGIN_HEADER_BYTES + index * 8;
            packet[start..start + 8].copy_from_slice(&usage.get(dimension).to_be_bytes());
        }
        (packet, ceiling, usage)
    }

    #[test]
    fn final_transfer_retains_every_sticky_dimension_without_audit_refund() {
        let (packet, ceiling, usage) = packet();
        let mut readback = SourceExecTransferReadbackV1::default();
        readback.prepare_once(&packet, ceiling, 64).unwrap();

        assert_eq!(readback.persistent_usage().unwrap(), usage);
        assert_eq!(readback.permanent_open_files().unwrap(), 80);
        assert_eq!(readback.persistent_usage().unwrap().get(D::MemoryBytes), 4096);
        assert!(!readback.complete());
        assert!(readback.prepare_once(&packet, ceiling, 64).is_err());
    }

    #[test]
    fn final_transfer_has_no_short_form_and_bounds_all_dimensions() {
        let (packet, ceiling, _) = packet();
        for length in [0, FIXED_SERVICE_ORIGIN_HEADER_BYTES, FIXED_SERVICE_FINAL_TRANSFER_BYTES - 1] {
            let mut readback = SourceExecTransferReadbackV1::default();
            assert!(readback.prepare_once(&packet[..length], ceiling, 64).is_err());
        }
        let mut trailing = packet.clone();
        trailing.push(0);
        assert!(SourceExecTransferReadbackV1::default().prepare_once(&trailing, ceiling, 64).is_err());

        for (index, dimension) in D::ALL.into_iter().enumerate() {
            let mut changed = packet.clone();
            let start = FIXED_SERVICE_ORIGIN_HEADER_BYTES + index * 8;
            changed[start..start + 8].copy_from_slice(&(ceiling.get(dimension) + 1).to_be_bytes());
            assert!(SourceExecTransferReadbackV1::default().prepare_once(&changed, ceiling, 64).is_err());
        }
    }

    #[test]
    fn final_transfer_refuses_missing_lifetime_debt_and_inexact_fd_equation() {
        let (packet, ceiling, _) = packet();
        for dimension in [D::CpuMicrosPerPeriod, D::Pids, D::ConcurrentOperations] {
            let mut changed = packet.clone();
            let index = D::ALL.iter().position(|value| *value == dimension).unwrap();
            let start = FIXED_SERVICE_ORIGIN_HEADER_BYTES + index * 8;
            changed[start..start + 8].copy_from_slice(&0_u64.to_be_bytes());
            assert!(SourceExecTransferReadbackV1::default().prepare_once(&changed, ceiling, 64).is_err());
        }
        for (offset, value) in [(88, 63_u64), (96, u64::MAX), (104, 79), (112, u64::MAX), (120, 0)] {
            let mut changed = packet.clone();
            changed[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            assert!(SourceExecTransferReadbackV1::default().prepare_once(&changed, ceiling, 64).is_err());
        }
    }
}
