//! Accelerator submit, completion, cancellation, and staged restore callbacks.
//!
//! Requests borrow the common device-I/O freeze owner and registered rings.
//! Moving these adapters does not introduce a separate hold or callback lock.

use super::*;

pub(super) const QEMU_PLUGIN_ACCELERATOR_POLL_PENDING: i64 = -2;

impl LiveDeviceCallbackState {
    // crucible-lint: allow rust-allow -- the accelerator request preserves every fixed public envelope field.
    #[allow(
        clippy::too_many_arguments,
        reason = "the public accelerator envelope has fixed fields"
    )]
    pub(super) fn submit_accelerator(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
        sequence: u64,
        device_id: [u8; 32],
        class_id: u16,
        job_kind: u16,
        queue_id: u16,
        service_units: u64,
        input: &[u8],
        output_capacity: usize,
    ) -> Result<(), LiveDeviceCallbackError> {
        if self.accelerator_pending.contains_key(&sequence)
            || self.accelerator_completed.contains_key(&sequence)
        {
            return Err(LiveDeviceCallbackError::DuplicateAcceleratorSequence { sequence });
        }
        let class = match class_id {
            1 => AcceleratorClass::Gpu,
            2 => AcceleratorClass::Tpu,
            3 => AcceleratorClass::Fpga,
            _ => return Err(LiveDeviceCallbackError::UnknownAcceleratorClass { class_id }),
        };
        let entry = AcceleratorEntry::new(
            sequence,
            self.accelerator_generation,
            device_id,
            class,
            job_kind,
            queue_id,
            0,
            false,
            service_units,
            u32::try_from(output_capacity).map_err(|_error| {
                LiveDeviceCallbackError::AcceleratorOutputTooLarge {
                    sequence,
                    len: output_capacity,
                    capacity: crucible_qemu_shmem::ACCELERATOR_ENTRY_DATA_BYTES,
                }
            })?,
            input,
        )
        .map_err(|source| LiveDeviceCallbackError::AcceleratorEntry { source })?;
        let token = self
            .freeze
            .begin_independent_submit(slot, current_icount)
            .map_err(|source| LiveDeviceCallbackError::AcceleratorFreeze { source })?;
        if let Err(source) = self.accelerator_rings.enqueue_request(entry) {
            self.freeze
                .fail_request(slot, token)
                .map_err(|source| LiveDeviceCallbackError::AcceleratorFreeze { source })?;
            return Err(LiveDeviceCallbackError::AcceleratorRing { source });
        }
        self.accelerator_pending.insert(
            sequence,
            PendingAcceleratorRequest {
                token,
                device_id,
                class_id,
                job_kind,
                queue_id,
                service_units,
                output_capacity,
            },
        );
        Ok(())
    }

    pub(super) fn poll_accelerator(
        &mut self,
        slot: &NodeSlot,
        sequence: u64,
        output: &mut [u8],
    ) -> Result<(u16, i64), LiveDeviceCallbackError> {
        while let Some(entry) = self
            .accelerator_rings
            .dequeue_completion()
            .map_err(|source| LiveDeviceCallbackError::AcceleratorRing { source })?
        {
            let completion_sequence = entry.sequence();
            if !entry.is_completion() || entry.generation() != self.accelerator_generation {
                return Err(LiveDeviceCallbackError::InvalidAcceleratorCompletion {
                    sequence: completion_sequence,
                });
            }
            if let Some(cancellation) = self.accelerator_cancelled.get(&completion_sequence) {
                if entry.status() != ACCELERATOR_STATUS_CANCELLED
                    || entry.device_id() != cancellation.device_id()
                    || entry.class() != cancellation.class()
                    || entry.job_kind() != cancellation.job_kind()
                    || entry.queue_id() != cancellation.queue_id()
                    || entry.service_units() != cancellation.service_units()
                    || entry.output_capacity() != cancellation.output_capacity()
                {
                    return Err(LiveDeviceCallbackError::InvalidAcceleratorCompletion {
                        sequence: completion_sequence,
                    });
                }
                self.accelerator_cancelled.remove(&completion_sequence);
                continue;
            }
            if self
                .accelerator_completed
                .insert(completion_sequence, entry)
                .is_some()
            {
                return Err(LiveDeviceCallbackError::DuplicateAcceleratorSequence {
                    sequence: completion_sequence,
                });
            }
        }
        if sequence == 0 {
            return Ok((0, QEMU_PLUGIN_ACCELERATOR_POLL_PENDING));
        }
        let Some(completion) = self.accelerator_completed.get(&sequence).copied() else {
            return Ok((0, QEMU_PLUGIN_ACCELERATOR_POLL_PENDING));
        };
        let pending = self
            .accelerator_pending
            .get(&sequence)
            .ok_or(LiveDeviceCallbackError::UnknownAcceleratorSequence { sequence })?;
        if completion.device_id() != pending.device_id
            || completion.class() != pending.class_id
            || completion.job_kind() != pending.job_kind
            || completion.queue_id() != pending.queue_id
            || completion.service_units() != pending.service_units
            || completion.output_capacity() as usize != pending.output_capacity
        {
            return Err(LiveDeviceCallbackError::InvalidAcceleratorCompletion { sequence });
        }
        let data = completion
            .data()
            .map_err(|source| LiveDeviceCallbackError::AcceleratorEntry { source })?;
        if data.len() > output.len() || data.len() > pending.output_capacity {
            return Err(LiveDeviceCallbackError::AcceleratorOutputTooLarge {
                sequence,
                len: data.len(),
                capacity: output.len(),
            });
        }
        output[..data.len()].copy_from_slice(data);
        let pending = self
            .accelerator_pending
            .remove(&sequence)
            .ok_or(LiveDeviceCallbackError::UnknownAcceleratorSequence { sequence })?;
        self.accelerator_completed.remove(&sequence);
        self.freeze
            .complete_request(slot, pending.token)
            .map_err(|source| LiveDeviceCallbackError::AcceleratorFreeze { source })?;
        let len = i64::try_from(data.len()).map_err(|_error| {
            LiveDeviceCallbackError::ResponseLengthOverflow {
                family: "accelerator",
                len: data.len(),
            }
        })?;
        Ok((completion.status(), len))
    }

    pub(super) fn cancel_accelerator(
        &mut self,
        slot: &NodeSlot,
        sequence: u64,
    ) -> Result<(), LiveDeviceCallbackError> {
        let pending = self
            .accelerator_pending
            .get(&sequence)
            .ok_or(LiveDeviceCallbackError::UnknownAcceleratorSequence { sequence })?;
        let class = match pending.class_id {
            1 => AcceleratorClass::Gpu,
            2 => AcceleratorClass::Tpu,
            3 => AcceleratorClass::Fpga,
            class_id => return Err(LiveDeviceCallbackError::UnknownAcceleratorClass { class_id }),
        };
        let cancellation = AcceleratorEntry::cancellation(
            sequence,
            self.accelerator_generation,
            pending.device_id,
            class,
            pending.job_kind,
            pending.queue_id,
            pending.service_units,
            u32::try_from(pending.output_capacity).map_err(|_error| {
                LiveDeviceCallbackError::AcceleratorOutputTooLarge {
                    sequence,
                    len: pending.output_capacity,
                    capacity: crucible_qemu_shmem::ACCELERATOR_ENTRY_DATA_BYTES,
                }
            })?,
        )
        .map_err(|source| LiveDeviceCallbackError::AcceleratorEntry { source })?;
        self.accelerator_rings
            .enqueue_request(cancellation)
            .map_err(|source| LiveDeviceCallbackError::AcceleratorRing { source })?;
        let pending = self
            .accelerator_pending
            .remove(&sequence)
            .ok_or(LiveDeviceCallbackError::UnknownAcceleratorSequence { sequence })?;
        self.accelerator_completed.remove(&sequence);
        self.accelerator_cancelled.insert(sequence, cancellation);
        self.freeze
            .fail_request(slot, pending.token)
            .map(|_release| ())
            .map_err(|source| LiveDeviceCallbackError::AcceleratorFreeze { source })
    }

    pub(super) fn begin_accelerator_restore(
        &mut self,
        count: u32,
    ) -> Result<(), LiveDeviceCallbackError> {
        if self.accelerator_restore_staging.is_some() {
            return Err(LiveDeviceCallbackError::AcceleratorRestoreAlreadyActive);
        }
        self.accelerator_restore_staging = Some((count, BTreeMap::new()));
        Ok(())
    }

    // crucible-lint: allow rust-allow -- restore preserves every fixed accelerator continuation field.
    #[allow(
        clippy::too_many_arguments,
        reason = "the public accelerator envelope has fixed fields"
    )]
    pub(super) fn stage_accelerator_restore(
        &mut self,
        sequence: u64,
        device_id: [u8; 32],
        class_id: u16,
        job_kind: u16,
        queue_id: u16,
        service_units: u64,
        output_capacity: usize,
    ) -> Result<(), LiveDeviceCallbackError> {
        if !matches!(class_id, 1..=3)
            || sequence == 0
            || device_id.iter().all(|byte| *byte == 0)
            || job_kind == 0
            || queue_id != 0
            || service_units == 0
            || output_capacity == 0
            || output_capacity > crucible_qemu_shmem::ACCELERATOR_ENTRY_DATA_BYTES
            || self.accelerator_pending.contains_key(&sequence)
            || self.accelerator_completed.contains_key(&sequence)
            || self.accelerator_cancelled.contains_key(&sequence)
        {
            return Err(LiveDeviceCallbackError::InvalidAcceleratorRestore { sequence });
        }
        let Some((expected, staged)) = self.accelerator_restore_staging.as_mut() else {
            return Err(LiveDeviceCallbackError::AcceleratorRestoreNotActive);
        };
        if staged.len() >= *expected as usize
            || staged
                .insert(
                    sequence,
                    PendingAcceleratorEnvelope {
                        device_id,
                        class_id,
                        job_kind,
                        queue_id,
                        service_units,
                        output_capacity,
                    },
                )
                .is_some()
        {
            return Err(LiveDeviceCallbackError::InvalidAcceleratorRestore { sequence });
        }
        Ok(())
    }

    pub(super) fn commit_accelerator_restore(
        &mut self,
        slot: &NodeSlot,
        current_icount: u64,
    ) -> Result<(), LiveDeviceCallbackError> {
        let Some((expected, staged)) = self.accelerator_restore_staging.take() else {
            return Err(LiveDeviceCallbackError::AcceleratorRestoreNotActive);
        };
        if staged.len() != expected as usize {
            return Err(LiveDeviceCallbackError::AcceleratorRestoreCountMismatch {
                expected,
                observed: staged.len(),
            });
        }
        if staged.keys().any(|sequence| {
            self.accelerator_pending.contains_key(sequence)
                || self.accelerator_completed.contains_key(sequence)
                || self.accelerator_cancelled.contains_key(sequence)
        }) {
            return Err(LiveDeviceCallbackError::AcceleratorRestoreConflict);
        }
        let tokens = self
            .freeze
            .begin_independent_batch(slot, current_icount, expected)
            .map_err(|source| LiveDeviceCallbackError::AcceleratorFreeze { source })?;
        for ((sequence, envelope), token) in staged.into_iter().zip(tokens) {
            self.accelerator_pending.insert(
                sequence,
                PendingAcceleratorRequest {
                    token,
                    device_id: envelope.device_id,
                    class_id: envelope.class_id,
                    job_kind: envelope.job_kind,
                    queue_id: envelope.queue_id,
                    service_units: envelope.service_units,
                    output_capacity: envelope.output_capacity,
                },
            );
        }
        Ok(())
    }

    pub(super) fn abort_accelerator_restore(&mut self) {
        self.accelerator_restore_staging = None;
    }
}

impl LiveVcpuTimeCallbackState {
    // crucible-lint: allow rust-allow -- the callback mirrors every fixed field in QEMU's accelerator ABI.
    #[allow(
        clippy::too_many_arguments,
        reason = "the QEMU accelerator ABI has fixed fields"
    )]
    pub(super) fn accelerator_submit(
        &self,
        sequence: u64,
        device_id: [u8; 32],
        class_id: u16,
        job_kind: u16,
        queue_id: u16,
        service_units: u64,
        input: &[u8],
        output_capacity: usize,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let current_icount = self.device_callback_icount()?;
        self.lock_devices()?
            .submit_accelerator(
                self.slot.get(),
                current_icount,
                sequence,
                device_id,
                class_id,
                job_kind,
                queue_id,
                service_units,
                input,
                output_capacity,
            )
            .map_err(LiveVcpuTimeCallbackError::live_device)?;
        (self.force_vcpu_exit)();
        Ok(())
    }

    pub(super) fn accelerator_poll(
        &self,
        sequence: u64,
        output: &mut [u8],
    ) -> Result<(u16, i64), LiveVcpuTimeCallbackError> {
        if self.idle_advance_is_pending() {
            return Ok((0, QEMU_PLUGIN_ACCELERATOR_POLL_PENDING));
        }
        let result = self
            .lock_devices()?
            .poll_accelerator(self.slot.get(), sequence, output)
            .map_err(LiveVcpuTimeCallbackError::live_device)?;
        self.publish_device_completion_pause_if_quiesced("accelerator-poll")?;
        Ok(result)
    }
}

// crucible-lint: allow rust-allow -- the callback mirrors every fixed field in QEMU's accelerator ABI.
#[allow(
    clippy::too_many_arguments,
    reason = "the QEMU accelerator ABI has fixed fields"
)]
pub(in crate::runtime::live_callbacks) extern "C" fn crucible_qemu_plugin_live_accelerator_submit_cb(
    sequence: u64,
    device_id: *const u8,
    class_id: u16,
    job_kind: u16,
    queue_id: u16,
    service_units: u64,
    data: *const u8,
    len: usize,
    output_capacity: usize,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    let Some(device_id) = std::ptr::NonNull::new(device_id.cast_mut()) else {
        return -1;
    };
    // SAFETY: QEMU supplies a readable fixed 32-byte identity for this call.
    let identity = unsafe { core::slice::from_raw_parts(device_id.as_ptr(), 32) };
    let mut identity_bytes = [0_u8; 32];
    identity_bytes.copy_from_slice(identity);
    // SAFETY: QEMU keeps the input readable for `len` bytes for this call.
    let input = unsafe { input_payload(data, len) }
        .ok_or(LiveDeviceCallbackError::NullPayload {
            family: "accelerator",
            len,
        })
        .unwrap_or_else(|source| {
            abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
        });
    match state.accelerator_submit(
        sequence,
        identity_bytes,
        class_id,
        job_kind,
        queue_id,
        service_units,
        input,
        output_capacity,
    ) {
        Ok(()) => 0,
        Err(error) => abort_live_callback(error),
    }
}

pub(in crate::runtime::live_callbacks) extern "C" fn crucible_qemu_plugin_live_accelerator_restore_cb(
    sequence: u64,
    device_id: *const u8,
    class_id: u16,
    job_kind: u16,
    queue_id: u16,
    service_units: u64,
    output_capacity: usize,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    let Some(device_id) = std::ptr::NonNull::new(device_id.cast_mut()) else {
        return -1;
    };
    // SAFETY: QEMU supplies a readable fixed identity for this call.
    let identity = unsafe { core::slice::from_raw_parts(device_id.as_ptr(), 32) };
    let mut identity_bytes = [0_u8; 32];
    identity_bytes.copy_from_slice(identity);
    let mut devices = match state.lock_devices() {
        Ok(value) => value,
        Err(error) => abort_live_callback(error),
    };
    match devices.stage_accelerator_restore(
        sequence,
        identity_bytes,
        class_id,
        job_kind,
        queue_id,
        service_units,
        output_capacity,
    ) {
        Ok(()) => 0,
        Err(_error) => -1,
    }
}

pub(in crate::runtime::live_callbacks) extern "C" fn crucible_qemu_plugin_live_accelerator_restore_begin_cb(
    count: u32,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    match state.lock_devices().and_then(|mut devices| {
        devices
            .begin_accelerator_restore(count)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }) {
        Ok(()) => 0,
        Err(_error) => -1,
    }
}

pub(in crate::runtime::live_callbacks) extern "C" fn crucible_qemu_plugin_live_accelerator_restore_commit_cb(
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    let current_icount = match state.callback_current_icount() {
        Ok(value) => value,
        Err(_error) => return -1,
    };
    match state.lock_devices().and_then(|mut devices| {
        devices
            .commit_accelerator_restore(state.slot.get(), current_icount)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }) {
        Ok(()) => 0,
        Err(_error) => -1,
    }
}

pub(in crate::runtime::live_callbacks) extern "C" fn crucible_qemu_plugin_live_accelerator_restore_abort_cb(
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    if let Ok(mut devices) = state.lock_devices() {
        devices.abort_accelerator_restore();
    }
}

pub(in crate::runtime::live_callbacks) extern "C" fn crucible_qemu_plugin_live_accelerator_poll_cb(
    sequence: u64,
    status: *mut u16,
    output: *mut u8,
    capacity: usize,
    userdata: *mut c_void,
) -> i64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    let Some(mut status) = std::ptr::NonNull::new(status) else {
        return -1;
    };
    let output =
        // SAFETY: QEMU grants exclusive output access for this callback.
        unsafe { output_buffer(output, capacity, "accelerator") }.unwrap_or_else(|source| {
            abort_live_callback(LiveVcpuTimeCallbackError::live_device(source))
        });
    match state.accelerator_poll(sequence, output) {
        Ok((completion_status, len)) => {
            // SAFETY: QEMU supplies a writable status word for this callback.
            unsafe { *status.as_mut() = completion_status };
            len
        }
        Err(error) => abort_live_callback(error),
    }
}

pub(in crate::runtime::live_callbacks) extern "C" fn crucible_qemu_plugin_live_accelerator_wait_cb(
    _sequence: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    (state.force_vcpu_exit)();
}

pub(in crate::runtime::live_callbacks) extern "C" fn crucible_qemu_plugin_live_accelerator_cancel_cb(
    sequence: u64,
    userdata: *mut c_void,
) -> c_int {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return -1;
    };
    match state.lock_devices().and_then(|mut devices| {
        devices
            .cancel_accelerator(state.slot.get(), sequence)
            .map_err(LiveVcpuTimeCallbackError::live_device)
    }) {
        Ok(()) => 0,
        Err(error) => abort_live_callback(error),
    }
}
