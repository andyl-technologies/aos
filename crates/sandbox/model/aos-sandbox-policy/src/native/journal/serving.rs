//! Binds the actual fixed owner to a completed same-instance serving cut.
//!
//! These private-field identities compare the original allocation and next
//! sequence. They create no writer, role loan or native completion and cannot
//! refresh an old sequence. The real terminal producer owes its native posts.

use std::sync::Arc;

use aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::super::PolicyNativeJournalErrorV1 as ErrorV1;
use super::{PolicyJournalInstanceV1, PolicyJournalStorageV1, RootPolicyJournalV1};

/// Keeps the actual opened instance and its captured native next sequence.
///
/// Construction requires the original healthy fixed owner. This opaque
/// comparison identity cannot issue authority or stand in for a role lender.
#[must_use]
pub struct RootPolicyJournalServingIdentityV1 {
    instance: Arc<PolicyJournalInstanceV1>,
    next: u64,
}

impl RootPolicyJournalServingIdentityV1 {
    /// Compares the same actual allocation and unchanged captured sequence.
    ///
    /// # Errors
    /// Refuses a foreign opened owner or a different captured native cut.
    pub fn require_same_captured_cut_v2(&self, other: &Self) -> Result<(), ErrorV1> {
        if !Arc::ptr_eq(&self.instance, &other.instance) || self.next != other.next {
            return Err(ErrorV1::boundary());
        }
        Ok(())
    }

    /// Prices the original two identities and capture/return carriers.
    ///
    /// # Errors
    /// Refuses checked representation overflow without allocating or funding.
    pub fn pair_demand_v1() -> Result<ResourceVector, ErrorV1> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(8)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }
}

impl RootPolicyJournalV1 {
    /// Captures the genuine opened instance and its current next sequence.
    ///
    /// No native IO, mutation, debit or role authority is issued. The caller
    /// prepays the identity carrier and completes its actual terminal checks.
    ///
    /// # Errors
    /// Refuses native uncertainty or a refused/ended same-original invocation.
    pub fn serving_identity_v1(&self) -> Result<RootPolicyJournalServingIdentityV1, ErrorV1> {
        self.require_selected_serving_native_v1()?;
        Ok(RootPolicyJournalServingIdentityV1 {
            instance: Arc::clone(&self.instance),
            next: self.next_sequence(),
        })
    }

    /// Compares the same live opened owner with its unchanged captured cut.
    ///
    /// # Errors
    /// Refuses unhealthy custody, owner substitution or any sequence advance.
    pub fn require_serving_identity_v1(
        &self,
        identity: &RootPolicyJournalServingIdentityV1,
    ) -> Result<(), ErrorV1> {
        self.require_selected_serving_native_v1()?;
        if !Arc::ptr_eq(&identity.instance, &self.instance)
            || identity.next != self.next_sequence()
        {
            return Err(ErrorV1::boundary());
        }
        Ok(())
    }

    /// Requires the actual same financial allocation and genuine native link.
    ///
    /// This performs no native IO, debit, reset, release or role admission. The
    /// real listener retains Initial while its same fixed pair moves.
    ///
    /// # Errors
    /// Preserves actual stable financial refusal or unhealthy native custody.
    pub fn require_serving_financial_v1(
        &self,
        expected: &RootJournalFinancialOriginalV1,
    ) -> Result<(), ErrorV1> {
        self.require_selected_serving_native_v1()?;
        let PolicyJournalStorageV1::Selected { financial, .. } = &self.storage else {
            return Err(ErrorV1::boundary());
        };
        financial.require_same_v1(expected)
            .map_err(|_| ErrorV1::Financial(financial.clone()))?;
        self.require_native_original()
    }

    fn require_selected_serving_native_v1(&self) -> Result<(), ErrorV1> {
        self.require_healthy_native()?;
        match &self.storage {
            PolicyJournalStorageV1::Selected { .. } => Ok(()),
            PolicyJournalStorageV1::Ordinary { .. } => Err(ErrorV1::boundary()),
        }
    }
}

impl RootPolicyJournalV1 {
    /// Measures this same genuine Root writer's independent native names post.
    ///
    /// # Errors
    /// Refuses ordinary storage or preserves the actual Root native refusal.
    pub fn root_names_post_demand_v1(
        &self,
    ) -> Result<aos_sandbox_model::ResourceVector, ErrorV1> {
        match &self.storage {
            crate::native::journal::PolicyJournalStorageV1::Selected { writer, .. } => {
                let native = writer.native_post_demand_v1()?;
                // The common journal and concrete role each return one owning
                // post/result lane. The lower supplier already pays the post
                // original and native names storage; these are only the two
                // new typed forwarding interfaces and their return planes.
                let controls = std::mem::size_of::<Result<
                    aos_sandbox_broker::receiving::RootWriterPostOriginalV1, ErrorV1,
                >>()
                    .checked_add(std::mem::size_of::<Result<(), ErrorV1>>())
                    .and_then(|bytes| bytes.checked_add(
                        std::mem::size_of::<Result<ResourceVector, ErrorV1>>(),
                    ))
                    .and_then(|bytes| bytes.checked_mul(2))
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or_else(ErrorV1::geometry)?;
                native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))
                    .map_err(|_| ErrorV1::geometry())
            }
            crate::native::journal::PolicyJournalStorageV1::Ordinary { .. } => {
                Err(ErrorV1::boundary())
            }
        }
    }

    /// Arms the same actual Root writer's independently owed native names post.
    ///
    /// The existing serving receiver pays the complete post demand before this
    /// call and retains its returned original before entering native observation.
    ///
    /// # Errors
    /// Refuses ordinary storage or preserves the original Root invocation cause.
    pub fn arm_root_names_post_once_v1(
        &self,
    ) -> Result<aos_sandbox_broker::receiving::RootWriterPostOriginalV1, ErrorV1>
    {
        match &self.storage {
            crate::native::journal::PolicyJournalStorageV1::Selected { writer, .. } => {
                writer.arm_native_post_once_v1().map_err(Into::into)
            }
            crate::native::journal::PolicyJournalStorageV1::Ordinary { .. } => {
                Err(ErrorV1::boundary())
            }
        }
    }

    /// Completes the original armed names post on this same genuine Root writer.
    ///
    /// # Errors
    /// Refuses a foreign post, ordinary storage, failed original observation or
    /// ended actual invocation; the caller keeps the post original resident.
    pub fn finish_root_names_post_once_v1(
        &self,
        post: &mut aos_sandbox_broker::receiving::RootWriterPostOriginalV1,
    ) -> Result<(), ErrorV1> {
        match &self.storage {
            crate::native::journal::PolicyJournalStorageV1::Selected { writer, .. } => {
                writer.finish_native_post_once_v1(post).map_err(Into::into)
            }
            crate::native::journal::PolicyJournalStorageV1::Ordinary { .. } => {
                Err(ErrorV1::boundary())
            }
        }
    }
}
