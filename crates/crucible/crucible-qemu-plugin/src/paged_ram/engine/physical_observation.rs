//! Samples actual kernel residency during the existing physical placement cut.
//!
//! This producer reuses reclaim's page scratch and the same original operation.
//! The retained result is an interval observation, not current RSS, private page
//! classification, or permission to reduce a reservation after execution resumes.

// SPDX-License-Identifier: GPL-2.0-or-later

use crucible_qemu_protocol::ram_control::{
    RAM_OBSERVATION_TOTAL_RESIDENT, RamControlResidentObservation,
};

use super::placement::PhysicalPlacement;
use super::*;

/// Owns a distinct fixed result allocation and its same-inventory credit.
///
/// The existing enclosing service header covers this inline holder; admission
/// checks that unchanged header bound before creating the service allocation.
pub(super) struct ResidentObservationState {
    body: Option<Box<Mutex<Option<RamControlResidentObservation>>>>,
    reservation: Option<MetadataReservation>,
}

impl ResidentObservationState {
    /// Charges the fixed result body before its allocation, using the same bank.
    ///
    /// # Errors
    /// Refuses unavailable original metadata; no replacement account is created.
    pub(super) fn prepare(budget: &crucible_ram::MetadataBudget) -> Result<Self, RamError> {
        let reservation = budget.reserve_bytes(Self::required_metadata_bytes()?)?;
        let body = Box::new(Mutex::new(None));
        Ok(Self {
            body: Some(body),
            reservation: Some(reservation),
        })
    }

    /// Reports this body's fixed declared extent before native allowance partition.
    ///
    /// # Errors
    /// Refuses an unrepresentable target allocation extent.
    pub(super) fn required_metadata_bytes() -> Result<u64, RamError> {
        u64::try_from(size_of::<Mutex<Option<RamControlResidentObservation>>>())
            .map_err(|_| RamError::Invariant("resident observation extent overflow"))
    }

    /// Borrows the fixed result without waiting or admitting another allocation.
    ///
    /// # Errors
    /// Refuses an absent, poisoned or contended result owner.
    pub(super) fn try_lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<RamControlResidentObservation>>, RamError> {
        self.body
            .as_ref()
            .ok_or("resident observation body absent")?
            .try_lock()
            .map_err(|_| RamError::Invariant("resident observation ownership unavailable"))
    }
}

impl Drop for ResidentObservationState {
    fn drop(&mut self) {
        // No guard can outlive its borrow of this sole body owner. Free the
        // actual allocation before returning its separate original credit.
        drop(self.body.take());
        drop(self.reservation.take());
    }
}

impl PhysicalPlacement<'_> {
    /// Borrows the existing page scratch under the same complete certificate.
    ///
    /// # Errors
    /// Refuses lost mapping/policy/writer identity, expired original, unavailable
    /// kernel residency evidence, incomplete coverage or checked count overflow.
    pub(super) fn sample_residency(
        &self,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<RamControlResidentObservation, RamError> {
        self.check_budget()?;
        self.check_policy_generation()?;
        let writer_generation = self.writer_generation()?;
        let started_ns = super::super::supervision::monotonic_ns()?;
        let mut covered_bytes = 0_u64;
        let mut total_resident_bytes = 0_u64;
        for arena in &self.service.arenas {
            let span = arena.native;
            if span.topology_generation != self.generation
                || span.host_address == 0
                || !span.host_address.is_multiple_of(PAGE_BYTES as u64)
                || span.logical_length == 0
                || span.mapping_length < span.logical_length
                || !span.mapping_length.is_multiple_of(PAGE_BYTES as u64)
            {
                return Err(RamError::Invariant("resident sample mapping changed"));
            }
            let mut offset = 0_u64;
            while offset < span.logical_length {
                self.check_budget()?;
                self.check_policy_generation()?;
                let logical =
                    (span.logical_length - offset).min((scratch.len() * PAGE_BYTES) as u64);
                let address = span
                    .host_address
                    .checked_add(offset)
                    .ok_or("resident sample address overflow")?;
                let resident = sample_resident_chunk(address, logical, scratch)?;
                self.check_budget()?;
                self.check_policy_generation()?;
                total_resident_bytes = total_resident_bytes
                    .checked_add(resident)
                    .ok_or("resident sample total overflow")?;
                covered_bytes = covered_bytes
                    .checked_add(logical)
                    .ok_or("resident sample coverage overflow")?;
                offset = offset
                    .checked_add(logical)
                    .ok_or("resident sample offset overflow")?;
                self.progress_work()?;
            }
        }
        self.check_policy_generation()?;
        if covered_bytes != self.owner.logical_bytes.load(Ordering::Acquire)
            || self.writer_generation()? != writer_generation
        {
            return Err(RamError::Invariant("resident sample identity changed"));
        }
        let completed_ns = super::super::supervision::monotonic_ns()?;
        self.check_budget()?;
        let policy = self
            .owner
            .policy
            .try_lock()
            .map_err(|_| "resident sample policy ownership unavailable")?
            .ok_or("resident sample policy absent")?;
        let effective_target_bytes = policy
            .resident_target_bytes
            .max(self.owner.permanent_resident_bytes.load(Ordering::Acquire));
        let observation = RamControlResidentObservation {
            availability: RAM_OBSERVATION_TOTAL_RESIDENT,
            topology_generation: self.generation,
            policy_revision: self.policy_revision,
            policy_generation: self.policy_generation,
            worker_generation: self.service.worker_generation,
            writer_generation,
            covered_bytes,
            total_resident_bytes,
            effective_target_bytes,
            started_ns,
            completed_ns,
        };
        observation
            .validate()
            .map_err(|_| "invalid resident observation")?;
        Ok(observation)
    }
}

/// Observes one fixed-size kernel chunk without dereferencing its address.
///
/// The production caller separately holds the exact native mapping certificate.
/// An unmapped address is a kernel refusal; this helper creates no Rust reference
/// to guest memory and cannot issue a mapping loan from numeric coordinates.
///
/// # Errors
/// Refuses invalid geometry, an unrepresentable address or a kernel failure.
fn sample_resident_chunk(address: u64, logical: u64, scratch: &mut [u8]) -> Result<u64, RamError> {
    let pages = usize::try_from(logical.div_ceil(PAGE_BYTES as u64))
        .map_err(|_| "resident sample page count overflow")?;
    if logical == 0
        || address == 0
        || !address.is_multiple_of(PAGE_BYTES as u64)
        || pages > scratch.len()
        || pages > PAGE_BYTES
    {
        return Err(RamError::Invariant(
            "resident sample chunk geometry is invalid",
        ));
    }
    let address = usize::try_from(address).map_err(|_| "resident sample address overflow")?;
    let length = pages
        .checked_mul(PAGE_BYTES)
        .ok_or("resident sample mapping extent overflow")?;
    address
        .checked_add(length)
        .ok_or("resident sample address extent overflow")?;
    scratch[..pages].fill(0);
    // SAFETY: the output slice has one initialized writable byte per kernel
    // page. mincore interprets the numeric address without a Rust dereference,
    // returns an error for absent mappings and retains neither input nor output.
    if unsafe { libc::mincore(address as *mut c_void, length, scratch.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    resident_logical_bytes(&scratch[..pages], logical)
}

/// Counts only logical guest bytes; the last page may extend past logical RAM.
fn resident_logical_bytes(bitmap: &[u8], logical: u64) -> Result<u64, RamError> {
    if logical == 0 || bitmap.len() as u64 != logical.div_ceil(PAGE_BYTES as u64) {
        return Err(RamError::Invariant("resident bitmap coverage is invalid"));
    }
    bitmap
        .iter()
        .enumerate()
        .try_fold(0_u64, |total, (index, byte)| {
            let valid = (logical - index as u64 * PAGE_BYTES as u64).min(PAGE_BYTES as u64);
            total
                .checked_add(if byte & 1 != 0 { valid } else { 0 })
                .ok_or(RamError::Invariant("resident bitmap count overflow"))
        })
}

#[cfg(test)]
mod tests;
