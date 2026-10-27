//! Uses the sole closed credential DATA recipe at the real Root receiving stage.

pub use aos_sandbox_policy::signed_inputs::RootStartupCredentialMemberV1;
use aos_sandbox_model::ResourceVector;
use crate::controller_resource_reservation::ResourceReservationErrorV1;

pub(crate) fn fixed_root_credential_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
    aos_sandbox_policy::signed_inputs::startup_credentials::fixed_root_credential_demand_v1()
        .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
}
