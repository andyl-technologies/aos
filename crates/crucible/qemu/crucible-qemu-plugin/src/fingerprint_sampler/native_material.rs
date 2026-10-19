//! Digests Source-owned detached bytes using actual native read receipts.
//!
//! Native Material retains its descriptor and finite operation through queue,
//! read, publication, acknowledgement and Main cleanup. Rust owns only movable
//! opaque projections and a non-replayable hash transcript.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::fingerprint_native::{Api, Material, MaterialRead, Work, Worker};

/// Retains only the actual native Material and its borrowed descriptor identity.
#[derive(Debug)]
pub(super) struct NativeCapturedMaterial {
    pub(super) owner: *mut Material,
    pub(super) descriptor: i32,
}

// SAFETY: native Material is retained in Source for this process. Only the born
// worker reads through its exact work loan; physical return stays on Main.
unsafe impl Send for NativeCapturedMaterial {}

impl CapturedFingerprintSample {
    /// Projects the actual retained Material for Source's genuine work constructor.
    pub(crate) fn native_material(&self) -> *mut Material {
        self.device.native.owner
    }

    /// Returns only physical Material custody, independently of semantic expiry.
    ///
    /// # Errors
    /// Retains the exact native return refusal and any unconsumed owner projection.
    pub(crate) fn return_material(
        &mut self,
        id: u64,
        api: Api,
    ) -> Result<(), FingerprintSamplerError> {
        if self.device.native.owner.is_null() {
            return Ok(());
        }
        let status = (api.material_return)(id, &mut self.device.native.owner);
        // A consumed output is not replayed, even if a trailing refusal exists.
        if self.device.native.owner.is_null() {
            self.device.native.descriptor = -1;
        }
        if status != 0 {
            return Err(FingerprintSamplerError::NativeMaterial { status });
        }
        if !self.device.native.owner.is_null() {
            return Err(FingerprintSamplerError::NativeMaterial {
                status: -libc::EPROTO,
            });
        }
        Ok(())
    }

    /// Hashes actual returned prefixes, preserving every consumed byte on failure.
    ///
    /// # Errors
    /// Preserves native read/post failure, invalid receipts or the same expired
    /// Material Original. A failed transcript never reissues consumed reads.
    pub(crate) fn digest_native(
        &mut self,
        workspace: &mut [u8; 65_536],
        api: Api,
        worker: *mut Worker,
        work: *mut Work,
    ) -> Result<FingerprintSample, FingerprintSamplerError> {
        let material_length = self.device.material_length;
        let progress = &mut self.device.progress;
        if let Some(failure) = &progress.failure {
            return Err(failure.clone());
        }
        if let Some(completed) = progress.completed {
            self.sample.device_state_digest = completed;
            return Ok(self.sample);
        }
        while progress.consumed < material_length {
            let requested =
                (material_length - progress.consumed).min(workspace.len() as u64) as usize;
            let mut receipt = MaterialRead::default();
            let status = (api.read)(worker, work, requested, &mut receipt);
            read_receipt::consume(
                progress,
                receipt,
                status,
                workspace,
                requested,
                material_length,
                false,
            )?;
        }
        // Counted length is not physical EOF. Native completion requires an
        // actual zero-byte pread after the final positive prefix.
        let mut eof = MaterialRead::default();
        let eof_status = (api.read)(worker, work, 1, &mut eof);
        read_receipt::consume(
            progress,
            eof,
            eof_status,
            workspace,
            1,
            material_length,
            true,
        )?;
        let mut bounded_ns = 0;
        let status = (api.worker_material_current)(worker, work, &mut bounded_ns);
        if status != 0 || bounded_ns == 0 {
            return Err(read_receipt::retain_failure(
                progress,
                if status != 0 {
                    status
                } else {
                    -libc::ETIMEDOUT
                },
            ));
        }
        let completed = progress.hasher.clone().finalize().into();
        progress.completed = Some(completed);
        self.sample.device_state_digest = completed;
        Ok(self.sample)
    }
}
