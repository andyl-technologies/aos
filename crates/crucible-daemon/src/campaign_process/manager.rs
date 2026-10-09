//! Connects the immutable campaign policy to shared service-birth ownership.

use super::CampaignProcessAdmissionError;
use super::policy::ProcessPolicy;
use crucible_linux_resource::host_services::process_birth::{
    self, ServiceBirthContract, VerifiedServiceBirth,
};

pub(super) async fn verify(
    policy: &ProcessPolicy,
) -> Result<VerifiedServiceBirth, CampaignProcessAdmissionError> {
    process_birth::authenticate(&ServiceBirthContract {
        unit: &policy.unit,
        executable: &policy.executable,
        memory_max_bytes: policy.memory_max_bytes,
        tasks_max: policy.tasks_max,
        file_descriptors: policy.file_descriptors,
        runtime_seconds: policy.runtime_seconds,
        startup_timeout_seconds: policy.startup_timeout_seconds,
        main_thread_stack_bytes: policy.main_thread_stack_bytes,
        cpu_quota_percent: policy.cpu_quota_percent,
        baseline_resident_bytes: policy.baseline_resident_bytes,
        metadata_bytes: policy.metadata_bytes,
    })
    .await
    .map_err(message)
}

fn message(error: impl std::fmt::Display) -> CampaignProcessAdmissionError {
    CampaignProcessAdmissionError::policy(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_diagnostics_retain_policy_classification_and_original_text() {
        let original = std::io::Error::other("original manager refusal");
        let expected = original.to_string();
        let classified = message(original);

        assert!(matches!(
            &classified,
            CampaignProcessAdmissionError::Policy(_)
        ));
        assert_eq!(classified.to_string(), expected);
    }
}
