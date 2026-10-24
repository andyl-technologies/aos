//! Complete same-original queue-plan acknowledgement bytes.
//!
//! ```text
//! ACK128: version1:u32, size128:u32, scope[32], epoch/process/barrier:u64,
//!         queue_plan_digest[32], staged_profile_digest[32]
//! All integers are big endian. Correlation bytes supply no native authority.
//! ```

use super::{StagedControlProfile, queue_plan::QueuePlan};
use crate::whole_control::{
    WHOLE_ACK_BYTES, WholeControlError, put_u32, put_u64, read_u32, read_u64,
};

/// Correlates the entire original queue plan and selected constructor profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuePlanAcknowledgement {
    /// Retains the exact original constructor scope.
    pub scope: [u8; 32],
    /// Correlates the original native epoch.
    pub native_epoch: u64,
    /// Correlates the original source process generation.
    pub process_generation: u64,
    /// Correlates the original source barrier generation.
    pub barrier_generation: u64,
    /// Commits the whole original queue plan body.
    pub queue_plan_digest: [u8; 32],
    /// Commits the whole original staged constructor profile.
    pub profile_digest: [u8; 32],
}

impl QueuePlanAcknowledgement {
    /// Builds a plan acknowledgement for the complete original selected profile.
    ///
    /// # Errors
    /// Rejects another scope or malformed constructor profile. The resulting
    /// correlation does not confer source readiness or execution authority.
    pub fn for_plan(
        plan: &QueuePlan<'_>,
        profile: &StagedControlProfile,
    ) -> Result<Self, WholeControlError> {
        if plan.scope != profile.compute.scope {
            return Err(WholeControlError::Correlation);
        }
        Ok(Self {
            scope: plan.scope,
            native_epoch: plan.native_epoch,
            process_generation: plan.process_generation,
            barrier_generation: plan.barrier_generation,
            queue_plan_digest: plan.digest(),
            profile_digest: profile.digest()?,
        })
    }

    /// Encodes the complete plan acknowledgement into explicit portable bytes.
    ///
    /// # Errors
    /// Rejects absent original correlations.
    pub fn encode(&self) -> Result<[u8; WHOLE_ACK_BYTES], WholeControlError> {
        self.validate()?;
        let mut body = [0; WHOLE_ACK_BYTES];
        put_u32(&mut body, 0, 1);
        put_u32(&mut body, 4, WHOLE_ACK_BYTES as u32);
        body[8..40].copy_from_slice(&self.scope);
        put_u64(&mut body, 40, self.native_epoch);
        put_u64(&mut body, 48, self.process_generation);
        put_u64(&mut body, 56, self.barrier_generation);
        body[64..96].copy_from_slice(&self.queue_plan_digest);
        body[96..128].copy_from_slice(&self.profile_digest);
        Ok(body)
    }

    /// Decodes one complete original plan acknowledgement.
    ///
    /// # Errors
    /// Rejects malformed extents or absent original correlations.
    pub fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        if body.len() != WHOLE_ACK_BYTES
            || read_u32(body, 0) != 1
            || read_u32(body, 4) as usize != WHOLE_ACK_BYTES
        {
            return Err(WholeControlError::Body);
        }
        let acknowledgement = Self {
            scope: array32(body, 8),
            native_epoch: read_u64(body, 40),
            process_generation: read_u64(body, 48),
            barrier_generation: read_u64(body, 56),
            queue_plan_digest: array32(body, 64),
            profile_digest: array32(body, 96),
        };
        acknowledgement.validate()?;
        Ok(acknowledgement)
    }

    /// Checks both full original plan and profile correlations.
    ///
    /// # Errors
    /// Rejects any changed original constructor, plan or source generation.
    pub fn validate_against(
        &self,
        plan: &QueuePlan<'_>,
        profile: &StagedControlProfile,
    ) -> Result<(), WholeControlError> {
        if self != &Self::for_plan(plan, profile)? {
            return Err(WholeControlError::Correlation);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), WholeControlError> {
        if self.scope == [0; 32]
            || self.native_epoch == 0
            || self.process_generation == 0
            || self.barrier_generation == 0
            || self.queue_plan_digest == [0; 32]
            || self.profile_digest == [0; 32]
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

fn array32(body: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&body[offset..offset + 32]);
    value
}
