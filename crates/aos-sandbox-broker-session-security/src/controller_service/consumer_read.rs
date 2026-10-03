//! Adapts the sole Controller worker's actual prepared resource to PRE-ROOT STATE.
//!
//! This has no public/admin/Attach trigger. A genuine later kernel-request and
//! original Ready-worker ingress is still missing. The actual Root daemon does
//! dispatch this wire mode, but this private client seam is not an end-to-end
//! ConsumerRead path and cannot perform a positive effect or retire quarantine.

use aos_sandbox::attachment_effect_owner::CurrentControllerConsumerResourceV1;
use aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::policy_compiler::consumer_read_flight::{
    ConsumerReadFlightErrorV1, ConsumerReadPolicyStateV1, with_consumer_read_policy_state_v1,
};
use aos_sandbox_core::RawPairedClockSample;

pub(super) fn with_pre_root_state<T>(
    resource: &mut CurrentControllerConsumerResourceV1<'_>,
    profile: &ProductionControllerNormalRootProfileV1,
    clock: &mut T,
    action: impl for<'state> FnOnce(&ConsumerReadPolicyStateV1<'state>),
) -> Result<(), ConsumerReadFlightErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    with_consumer_read_policy_state_v1(resource, profile, clock, action)
}
