//! Builds numerical ELF inputs for the real bounded artifact reader.
//!
//! These component files observe implementation declarations only. Neither the
//! bytes nor the resulting observation grants Main, Source or native authority.

use super::*;

pub(crate) fn receiver_record(source_activation: u32, checkpoint_ingress: u32) -> [u8; 40] {
    let mut bytes = [0; 40];
    bytes[..8].copy_from_slice(b"CRUCRCV1");
    for (index, value) in [1_u32, 40, 5, 8, 8, 1, source_activation, checkpoint_ingress]
        .into_iter()
        .enumerate()
    {
        bytes[8 + index * 4..12 + index * 4].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}

pub(crate) fn receiver_elf(records: &[[u8; 40]]) -> Vec<u8> {
    let names = b"\0.qemu.crucible.standing-constructor\0.qemu.crucible.preexec\0";
    let count = 3 + records.len();
    let names_offset = 64 + 64 * count;
    let body_offset = names_offset + names.len();
    let mut bytes = vec![0; body_offset + 96 + records.len() * 40];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&(count as u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());
    bytes[132..136].copy_from_slice(&3_u32.to_le_bytes());
    bytes[152..160].copy_from_slice(&(names_offset as u64).to_le_bytes());
    bytes[160..168].copy_from_slice(&(names.len() as u64).to_le_bytes());
    bytes[names_offset..body_offset].copy_from_slice(names);
    section(&mut bytes, 2, 1, body_offset, 96);
    bytes[body_offset..body_offset + 96].copy_from_slice(&super::tests::declaration());
    let receiver_name = 1 + b".qemu.crucible.standing-constructor".len() + 1;
    for (index, record) in records.iter().enumerate() {
        let offset = body_offset + 96 + index * 40;
        section(&mut bytes, 3 + index, receiver_name, offset, 40);
        bytes[offset..offset + 40].copy_from_slice(record);
    }
    bytes
}

fn section(bytes: &mut [u8], index: usize, name: usize, offset: usize, length: u64) {
    let start = 64 + index * 64;
    bytes[start..start + 4].copy_from_slice(&(name as u32).to_le_bytes());
    bytes[start + 4..start + 8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[start + 8..start + 16].copy_from_slice(&2_u64.to_le_bytes());
    bytes[start + 24..start + 32].copy_from_slice(&(offset as u64).to_le_bytes());
    bytes[start + 32..start + 40].copy_from_slice(&length.to_le_bytes());
}

pub(crate) fn observe_receiver(
    file: &File,
    original: &HostOperationGuard,
) -> Result<NativeReceiverArtifact, NativeConstructorReadError> {
    authenticate_final_elf(file, original).map(|artifact| artifact.receiver_artifact())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- component inputs never issue a native owner.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn actual_receiver_elf_observation_checks_source_activation_independently_of_ingress() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let mut file = tempfile::tempfile().unwrap();
        for (source, ingress, expected) in [
            (0, 0, NativeReceiverError::SourceActivationUnavailable),
            (0, 1, NativeReceiverError::SourceActivationUnavailable),
            (1, 0, NativeReceiverError::UnsupportedSourceActivation(1)),
            (1, 1, NativeReceiverError::UnsupportedSourceActivation(1)),
        ] {
            file.set_len(0).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&receiver_elf(&[receiver_record(source, ingress)]))
                .unwrap();
            let actual = observe_receiver(&file, &original).unwrap();
            assert_eq!(actual.check_source_activation(), Err(expected));
        }
        assert_eq!(original.status().unwrap().completed_work_units, 0);
    }

    #[test]
    fn actual_receiver_elf_observation_rejects_missing_duplicate_and_changed_transport() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let current = receiver_record(0, 0);
        let mut inputs = vec![receiver_elf(&[]), receiver_elf(&[current, current])];
        for offset in [0, 8, 12, 16, 20, 24, 28] {
            let mut changed = current;
            changed[offset] ^= 1;
            inputs.push(receiver_elf(&[changed]));
        }
        let mut file = tempfile::tempfile().unwrap();
        for bytes in inputs {
            file.set_len(0).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&bytes).unwrap();
            assert!(matches!(
                observe_receiver(&file, &original)
                    .unwrap()
                    .check_source_activation(),
                Err(NativeReceiverError::Declaration(_))
            ));
        }
    }

    #[test]
    fn retained_receiver_observation_binds_the_complete_selected_elf_and_original() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let mut first = tempfile::tempfile().unwrap();
        let mut second = tempfile::tempfile().unwrap();
        let bytes = receiver_elf(&[receiver_record(0, 0)]);
        first.write_all(&bytes).unwrap();
        second.write_all(&bytes).unwrap();
        let observed = observe_receiver(&first, &original).unwrap();
        assert!(observed.same_artifact(&observe_receiver(&second, &original).unwrap()));
        second
            .write_all(b"different retained final artifact tail")
            .unwrap();
        assert!(!observed.same_artifact(&observe_receiver(&second, &original).unwrap()));
        supervisor.cancel().unwrap();
        assert!(matches!(
            observe_receiver(&first, &original),
            Err(NativeConstructorReadError::Original(_))
        ));
    }
}
