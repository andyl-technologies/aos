//! Authenticates once-only execution receiving against the original enrollment.
//!
//! This row is a spent-origin latch in the existing Host snapshot. It creates
//! no receiving original: only the already captured Parent/profile/recipient
//! owner supplies its binding, and only its prepaid atomic commit can seal the
//! private execution subdivision. An unknown write is never retried as fresh.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{HostState, MAXIMUM_REQUESTS, MAXIMUM_STATE_BYTES, HEADER_BYTES};
use crate::{HostError, Result, authorization::HostAuthorityV1};

const DOMAIN: &[u8] = b"aos.host.execution-receiving-origin.v2\0";

/// Comparison fields copied only after the same actual enrollment observer joins.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionOriginBindingV2 {
    pub(crate) node: [u8; 16],
    pub(crate) epoch: [u8; 16],
    pub(crate) boot: [u8; 16],
    pub(crate) producer: [u8; 16],
    pub(crate) manifest: [u8; 32],
    pub(crate) account: [u8; 16],
    pub(crate) prepare_claim: [u8; 16],
    pub(crate) accept_claim: [u8; 16],
    pub(crate) recipient: [u8; 16],
    pub(crate) profile: [u8; 32],
}

impl ExecutionOriginBindingV2 {
    fn origin(&self) -> [u8; 32] {
        // Delivery/process/profile changes cannot create a fresh financial
        // origin. Permanent coissuance identity is the actual account+claim
        // conjunction; full native enrollment fields remain MAC-bound below.
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        for bytes in [&self.node, &self.epoch, &self.account,
            &self.prepare_claim, &self.accept_claim] {
            hash.update(bytes);
        }
        hash.finalize().into()
    }

    fn payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 208);
        bytes.extend_from_slice(DOMAIN);
        for value in [&self.node, &self.epoch, &self.boot, &self.producer] {
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&self.manifest);
        for value in [&self.account, &self.prepare_claim, &self.accept_claim, &self.recipient] {
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&self.profile);
        bytes
    }

    fn validate(&self) -> Result<()> {
        if [&self.node, &self.epoch, &self.boot, &self.producer, &self.account,
            &self.prepare_claim, &self.accept_claim, &self.recipient].contains(&&[0; 16])
            || self.manifest == [0; 32] || self.profile == [0; 32]
            || self.prepare_claim == self.accept_claim
        {
            return Err(HostError::Fence("execution receiving origin is malformed"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableExecutionOriginV2 {
    binding: ExecutionOriginBindingV2,
    authentication: Vec<u8>,
}

impl DurableExecutionOriginV2 {
    pub(super) fn receiving_dynamic_bytes_v3(&self) -> usize { self.authentication.capacity() }
}

pub(super) fn validate_rows_v2(rows: &[DurableExecutionOriginV2]) -> Result<()> {
    if rows.len() > MAXIMUM_REQUESTS {
        return Err(HostError::Fence("execution receiving origin table is full"));
    }
    for (index, row) in rows.iter().enumerate() {
        row.binding.validate()?;
        if row.authentication.is_empty() || row.authentication.len() > super::MAXIMUM_EXECUTION_AUTHENTICATION_BYTES
            || rows[..index].iter().any(|earlier| earlier.binding.origin() == row.binding.origin())
        {
            return Err(HostError::Fence("execution receiving origin table conflicts"));
        }
    }
    Ok(())
}

impl HostState {
    pub(super) fn contains_execution_origin_v2(&self, binding: ExecutionOriginBindingV2) -> bool {
        self.execution_origins.iter().any(|row| row.binding == binding && !row.authentication.is_empty())
    }


    pub(super) fn validate_execution_origins_v2(&self, authority: &HostAuthorityV1) -> Result<()> {
        validate_rows_v2(&self.execution_origins)?;
        for row in &self.execution_origins {
            let origin = row.binding.origin();
            let mut location = [0; 16];
            location.copy_from_slice(&origin[..16]);
            if authority.open_execution_record(&location, &row.authentication)? != row.binding.payload() {
                return Err(HostError::Fence("execution receiving origin authentication changed"));
            }
        }
        Ok(())
    }

    pub(crate) fn execution_origin_preparation_demand_v2(&self) -> Option<ResourceVector> {
        // The loaded snapshot is mutated in place. The selected serializer
        // borrows its tables and retains only a bounded body and envelope;
        // it never clones the complete snapshot or its request payloads.
        let rows = self.execution_origins.len().checked_add(1)?;
        let vector = self.execution_origins.capacity().checked_add(rows)?
            .checked_mul(std::mem::size_of::<DurableExecutionOriginV2>())?;
        let memory = (2 * MAXIMUM_STATE_BYTES).checked_add(HEADER_BYTES)?
            .checked_add(vector)?
            .checked_add(2 * super::MAXIMUM_EXECUTION_AUTHENTICATION_BYTES)?
            .checked_add(2 * std::mem::size_of::<super::HostStateWriteAttemptV2>())?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 1)
            // Actual snapshot/temporary names plus the durable origin index.
            .with(D::MetadataEntries, u64::try_from(rows.checked_add(2)?).ok()?)
            .with(D::StorageBytes, u64::try_from(MAXIMUM_STATE_BYTES.checked_add(HEADER_BYTES)?).ok()?))
    }

    pub(crate) fn spend_execution_origin_v2(&mut self, binding: ExecutionOriginBindingV2,
        authority: &HostAuthorityV1) -> Result<()> {
        binding.validate()?;
        if self.execution_origins.len() >= MAXIMUM_REQUESTS
            || self.execution_origins.iter().any(|row| row.binding.origin() == binding.origin())
        {
            return Err(HostError::Fence("execution receiving original was already spent"));
        }
        let origin = binding.origin();
        let mut location = [0; 16];
        location.copy_from_slice(&origin[..16]);
        let authentication = authority.seal_execution_record(&location, &binding.payload())?;
        self.execution_origins.try_reserve_exact(1)
            .map_err(|error| HostError::State(error.to_string()))?;
        self.execution_origins.push(DurableExecutionOriginV2 { binding, authentication });
        Ok(())
    }
}
