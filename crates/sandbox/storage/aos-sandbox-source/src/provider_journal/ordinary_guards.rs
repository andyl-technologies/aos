//! Preserves the complete ordinary no-original Git comparisons.
//!
//! These closed private bindings instantiate the same canonical DATA recipes
//! as the existing Controller callers. They grant no role, signer, writer,
//! financial original or exception. Actual Source claims, challenge custody,
//! currentness and native append stay with their real Source owners.

use super::{JournalError, JournalTransaction, RecordNamespace};

mod provider_policy_data {
    use aos_sandbox_model::RecordNamespace;
    use aos_sandbox_model::{ObjectDigest, ProjectId, ResourceDimension, ResourceVector};
    use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
    use aos_sandbox_protocol::publisher_project_authorization::commitment;

    type PublisherPolicyError = super::JournalError;

    aos_sandbox_protocol::define_provider_record_helpers_data_recipe_v1!(
        PublisherPolicyError::ProtectedBoundary
    );

    mod account_coverage {
        aos_sandbox_protocol::define_provider_account_coverage_data_recipe_v1!(
            super::PublisherPolicyError::ProtectedBoundary
        );
    }

    mod native_account {
        use super::*;

        aos_sandbox_protocol::define_provider_native_account_data_recipe_v1!(
            PublisherPolicyError::ProtectedBoundary
        );
    }

    pub(super) use native_account::{
        require_complete_coverage_read_state_data_v1, require_coverage_native_account_transaction,
    };
}

mod provider_cli_floor_data {
    use std::collections::BTreeMap;

    use aos_sandbox_model::{
        CLOCK_PAIR_TOLERANCE_NANOSECONDS, ObjectDigest, RawPairedClockSample, RecordNamespace,
    };
    use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
    use sha2::{Digest as _, Sha256};

    type CliAuthorizationAdapterError = super::JournalError;

    aos_sandbox_ledger_replay::define_provider_time_floor_data_recipe_v1!(
        CliAuthorizationAdapterError::ProtectedBoundary
    );
}

mod capabilities {
    use std::io;

    use aos_sandbox_model::bounded_codec::{BoundedAppendError, append_with_capped_doubling};
    use aos_sandbox_model::{CapabilityId, CapabilityRecord};
    use serde::{Deserialize, Serialize};

    type PublisherAuthorityError = super::JournalError;

    mod issuance {
        use std::io;

        use aos_sandbox_model::{
            AuditId, CapabilityRecord, ObjectDigest, Operation, OperationSet, ResourceId,
            ResourceKind, ResourceVector, Selector,
        };
        use serde::{Deserialize, Serialize};
        use sha2::{Digest as _, Sha256};

        use super::{MAXIMUM_RECORD_BYTES, PublisherAuthorityError};

        aos_sandbox_ledger_replay::define_provider_issuance_data_recipe_v1! {
            invalid_metadata: PublisherAuthorityError::ProtectedBoundary,
            crosslink: PublisherAuthorityError::ProtectedBoundary,
            malformed: PublisherAuthorityError::ProtectedBoundary
        }
    }

    mod runtime_issuance {
        use aos_sandbox_model::{CapabilityRecord, ObjectDigest};
        use serde::{Deserialize, Serialize};

        use super::{IssuanceDecisionMetadataV1, PublisherAuthorityError};

        aos_sandbox_ledger_replay::define_provider_runtime_issuance_data_recipe_v1! {
            invalid_metadata: PublisherAuthorityError::ProtectedBoundary,
            crosslink: PublisherAuthorityError::ProtectedBoundary
        }
    }

    use issuance::IssuanceDecisionMetadataV1;
    use runtime_issuance::RuntimeIssuanceEvidenceV1;

    aos_sandbox_ledger_replay::define_provider_capability_record_data_recipe_v1! {
        malformed: PublisherAuthorityError::ProtectedBoundary,
        invalid_parent: PublisherAuthorityError::ProtectedBoundary,
        invalid_handle: PublisherAuthorityError::ProtectedBoundary,
        key_mismatch: PublisherAuthorityError::ProtectedBoundary,
        crosslink: PublisherAuthorityError::ProtectedBoundary,
        unsupported: PublisherAuthorityError::UnsupportedVersion,
        limit: PublisherAuthorityError::LimitExceeded
    }
}

mod provider_initial_issuance_data {
    use aos_sandbox_model::{CapabilityId, ObjectDigest, PrincipalId, ProjectId, RecordNamespace};
    use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};

    use super::capabilities as provider_capability_record_data;
    type InitialPublicCapabilityErrorV1 = super::JournalError;

    aos_sandbox_ledger_replay::define_provider_initial_issuance_data_recipe_v1!(
        InitialPublicCapabilityErrorV1::ProtectedBoundary
    );
}

fn has_durable_owner_fence_v1(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> bool {
    aos_sandbox_ledger_replay::git_coverage_prefix::has_durable_owner_fence_v1(state)
}

aos_sandbox_ledger_replay::define_provider_git_ordinary_data_recipe_v1!();
