//! GPL-local phase policy and timer-birth ABI with separately encoded public bytes.
//!
//! These native scalar layouts stay inside the QEMU process. Source registration
//! compares the complete original early pin; pointers are never process protocol
//! fields. Diagnostic birth observations do not authorize settlement or readiness.

use std::ffi::{c_int, c_void};

use crucible_protocol::node_control::{
    NativeCommandError, NativePhasePolicy, NativePhaseTimerObservation,
};

use super::abi::{NativeTimerArm, NativeTimerList};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativePhasePolicyAbi {
    pub version: u32,
    pub size: u32,
    pub mapping_id: u32,
    pub reserved: u32,
    pub maximum_microsteps: u64,
    pub prepared_scope_hash: [u8; 32],
    pub phase_preparation_commitment: [u8; 32],
    pub realize_request_digest: [u8; 32],
    pub policy_digest: [u8; 32],
}

impl NativePhasePolicyAbi {
    pub(crate) fn from_policy(policy: &NativePhasePolicy) -> Result<Self, NativeCommandError> {
        policy.validate()?;
        Ok(Self {
            version: 1,
            size: 152,
            mapping_id: policy.mapping as u32,
            reserved: 0,
            maximum_microsteps: policy.maximum_microstep.get(),
            prepared_scope_hash: policy.prepared_scope_hash,
            phase_preparation_commitment: policy.phase_preparation_commitment,
            realize_request_digest: policy.realize_request_digest,
            policy_digest: policy.policy_digest,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeTimerBirthAbi {
    pub timer: NativeTimerArm,
    pub birth_kind: u32,
    pub birth_phase: u32,
    pub birth_flags: u32,
    pub reserved: u32,
    pub birth_time_ps: u64,
    pub birth_microstep: u64,
    pub source_original_sequence: u64,
    pub parent_timer_id: u64,
    pub parent_arm_generation: u64,
    pub prepared_scope_hash: [u8; 32],
    pub source_original_digest: [u8; 32],
    pub construction_commitment: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeTimerBirthInventoryAbi {
    pub version: u32,
    pub size: u32,
    pub list_count: u32,
    pub timer_count: u32,
    pub current_ps: u64,
    pub mutation_generation: u64,
    pub gate_generation: u64,
    pub source_original_sequence: u64,
    pub prepared_scope_hash: [u8; 32],
    pub source_original_digest: [u8; 32],
}

pub(crate) type RegisterPhaseProjection = extern "C" fn(*const NativePhasePolicyAbi) -> c_int;
pub(crate) type QueryTimerBirths = extern "C" fn(
    *const u8,
    u64,
    *mut NativeTimerBirthInventoryAbi,
    *mut NativeTimerList,
    u32,
    *mut NativeTimerBirthAbi,
    u32,
) -> c_int;

pub(crate) fn resolve_register_phase() -> Option<RegisterPhaseProjection> {
    // SAFETY: The static export is source-declared with this exact scalar ABI;
    // a missing symbol is refused before registration, never guessed by edition.
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_register_crucible_node_phase_projection".as_ptr(),
        )
    };
    if pointer.is_null() {
        None
    } else {
        // SAFETY: The exact export has the verified policy152 registration type.
        Some(unsafe { std::mem::transmute::<*mut c_void, RegisterPhaseProjection>(pointer) })
    }
}

pub(crate) fn resolve_query_timer_births() -> Option<QueryTimerBirths> {
    // SAFETY: The static export selects this separately versioned GPL-native ABI.
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_query_timer_births".as_ptr(),
        )
    };
    if pointer.is_null() {
        None
    } else {
        // SAFETY: The exact export accepts bounded summary112/list16/row200 buffers.
        Some(unsafe { std::mem::transmute::<*mut c_void, QueryTimerBirths>(pointer) })
    }
}

pub(crate) fn decode_native_inventory(
    summary: &NativeTimerBirthInventoryAbi,
    lists: &[NativeTimerList],
    timers: &[NativeTimerBirthAbi],
) -> Result<NativePhaseTimerObservation, NativeCommandError> {
    if summary.version != 1
        || summary.size != 112
        || summary.list_count > 64
        || summary.timer_count > 4096
        || lists.len() != summary.list_count as usize
        || timers.len() != summary.timer_count as usize
    {
        return Err(NativeCommandError::Conflict);
    }
    let length = 112 + lists.len() * 16 + timers.len() * 200;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| NativeCommandError::ResourceLimit)?;
    for value in [
        summary.version,
        summary.size,
        summary.list_count,
        summary.timer_count,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in [
        summary.current_ps,
        summary.mutation_generation,
        summary.gate_generation,
        summary.source_original_sequence,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&summary.prepared_scope_hash);
    bytes.extend_from_slice(&summary.source_original_digest);
    for list in lists {
        bytes.extend_from_slice(&list.list_id.to_be_bytes());
        bytes.extend_from_slice(&list.timer_count.to_be_bytes());
        bytes.extend_from_slice(&list.flags.to_be_bytes());
    }
    for row in timers {
        for value in [
            row.timer.timer_id,
            row.timer.list_id,
            row.timer.arm_generation,
            row.timer.expiry_ps,
            row.timer.fifo_ordinal,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            row.timer.attributes,
            row.timer.scale,
            row.birth_kind,
            row.birth_phase,
            row.birth_flags,
            row.reserved,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            row.birth_time_ps,
            row.birth_microstep,
            row.source_original_sequence,
            row.parent_timer_id,
            row.parent_arm_generation,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&row.prepared_scope_hash);
        bytes.extend_from_slice(&row.source_original_digest);
        bytes.extend_from_slice(&row.construction_commitment);
    }
    // The closed portable decoder checks every unused native field, avoiding a
    // lossy enum conversion that might hide malformed or fabricated provenance.
    NativePhaseTimerObservation::decode(&bytes)
}

const _: () = {
    assert!(std::mem::size_of::<NativePhasePolicyAbi>() == 152);
    assert!(std::mem::offset_of!(NativePhasePolicyAbi, prepared_scope_hash) == 24);
    assert!(std::mem::size_of::<NativeTimerBirthAbi>() == 200);
    assert!(std::mem::offset_of!(NativeTimerBirthAbi, birth_kind) == 48);
    assert!(std::mem::offset_of!(NativeTimerBirthAbi, prepared_scope_hash) == 104);
    assert!(std::mem::size_of::<NativeTimerBirthInventoryAbi>() == 112);
    assert!(std::mem::offset_of!(NativeTimerBirthInventoryAbi, prepared_scope_hash) == 48);
};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn raw_unknown_fields_remain_checked_instead_of_being_lost_in_enum_conversion() {
        let summary = NativeTimerBirthInventoryAbi {
            version: 1,
            size: 112,
            list_count: 1,
            timer_count: 1,
            mutation_generation: 1,
            gate_generation: 1,
            prepared_scope_hash: [1; 32],
            ..Default::default()
        };
        let lists = [NativeTimerList {
            list_id: 1,
            timer_count: 1,
            flags: 3,
        }];
        let timer = NativeTimerBirthAbi {
            timer: NativeTimerArm {
                timer_id: 1,
                list_id: 1,
                arm_generation: 1,
                expiry_ps: 100,
                fifo_ordinal: 0,
                attributes: 0,
                scale: 1,
            },
            ..Default::default()
        };
        let original = decode_native_inventory(&summary, &lists, &[timer]).unwrap();
        assert!(matches!(
            original.timers[0].birth,
            crucible_protocol::node_control::NativeTimerBirth::Unknown { parent: None }
        ));

        for field in 0..6 {
            let mut corrupt = timer;
            match field {
                0 => corrupt.reserved = 1,
                1 => corrupt.birth_time_ps = 1,
                2 => corrupt.birth_phase = 3,
                3 => corrupt.prepared_scope_hash = [1; 32],
                4 => corrupt.source_original_digest = [1; 32],
                _ => corrupt.construction_commitment = [1; 32],
            }
            assert!(decode_native_inventory(&summary, &lists, &[corrupt]).is_err());
        }
    }
}
