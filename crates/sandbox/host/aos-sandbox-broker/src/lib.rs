//! Shared privileged-broker authority admission and durable records.
//!
//! Audience-specific brokers canonicalize their own request and catalog
//! semantics. This crate verifies the common signed plan and ownership lease,
//! intersects them with protected local time and fencing state, and emits
//! location-authenticated durable records that remain non-authorizing until
//! committed by the caller.
//!
//! Admission owns the common signature/lease intersection, configuration owns
//! descriptor-relative protected credential loading, and records own the private
//! location-bound MAC engine. Domain brokers retain semantic admission and effects.

/// Shares passive immutable measurement and retained native DATA for purpose owners.
pub mod immutable_image;

/// Measures closed compiled TPM-helper purposes without granting role authority.
pub mod fixed_tpm_helper_image;

/// Shares bounded nonzero kernel entropy DATA and retained partial fills.
#[cfg(target_os = "linux")]
pub mod bounded_entropy;

/// Samples raw ownership-clock DATA without effect or lease authority.
#[cfg(target_os = "linux")]
pub mod ownership_clock;

/// Shares fixed native entropy for protected Root protocol challenges.
#[cfg(target_os = "linux")]
pub mod root_nonce;

/// Owns the existing fixed Root settlement peer-checked client.
#[cfg(target_os = "linux")]
pub mod root_settlement;

/// Shares mechanical prepared-plan, expanded-key and signing-message custody.
pub mod prepared_plan_signing;

mod admission;
mod config;
mod record;
pub use record::{MAXIMUM_AUTHENTICATED_RECORD_BYTES_V3, local_record_sealing_bytes_v1, storage_admission_sealing_bytes_v1,
    storage_effect_completion_sealing_bytes_v1, MountAttachmentAnchorRecordShapeDataV4,
    mount_attachment_anchor_record_shape_v4};

pub use admission::{StorageCaptureStopInspectionErrorV4,
    StorageCaptureStopInspectionOriginalV4, VerifiedStorageCaptureStopCleanupV4};
pub use admission::{
    AdmissionRequest, BrokerAdmissionError, BrokerSignedAdmissionOriginalV4, BrokerAuthority, NetworkPublicVerifierV2, BrokerEffectClockDispositionV1, BrokerEffectClockComparisonV3,
    VerifiedBrokerAdmission, VerifiedStorageCaptureLifetimeV3, StoragePrepareNativeClockLoanV1,
    StorageHostLaunchExportInspectionErrorV2, VerifiedStorageHostLaunchExportV2,
};
pub use aos_sandbox_model::RecordNamespace;
pub use config::{
    BrokerAuthorityConfigError, ProtectedBrokerAuthorityConfiguration,
    ProtectedBrokerPublicCredentialRole, ProtectedBrokerPublicCredentialSnapshot,
    ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    ProtectedBrokerPublicCredentials, ProtectedStorageBrokerConfigurationOriginalV1,
    NetworkPublicCredentialsOriginalV2,
    ProtectedNetworkBrokerConfigurationOriginalV4, ProtectedMountBrokerConfigurationOriginalV4,
};
pub use record::{
    AuthorizationRecordError, BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV1,
    BrokerEffectStatusV1, BrokerLocalRecordDomain,
};

#[doc(hidden)]
pub mod receiving;

#[doc(hidden)]
pub mod writer_currentness;

#[doc(hidden)]
pub mod canonical_journal;

#[doc(hidden)]
pub mod cross_owner_readonly;

#[doc(hidden)]
pub mod ownership_record_io;

#[doc(hidden)]
pub mod paired_clock;

/// Shares the boot-bookended kernel sampler and retained native observations.
#[cfg(target_os = "linux")]
pub mod kernel_clock;

/// Owns the unchanged fixed Controller clock and retained native sampler.
#[cfg(target_os = "linux")]
pub mod controller_clock;

/// Retains fixed continuation samplers and strict original comparison bounds.
#[cfg(target_os = "linux")]
pub mod continuation_clock;

/// Shares passive transaction and capacity custody recipes for private role adapters.
pub mod domain_transaction_custody;

/// Shares the fixed Cache signer socket connection and native failure custody.
pub mod cache_signer_connection;

/// Retains the fixed Root-first Cache CurrentProofs native transport.
pub mod cache_current_signer_exchange;

/// Fixed native credential snapshots, batches, and readback custody.
pub mod systemd_credentials;

/// Shares strict profile comparison DATA and original image observations.
pub mod profile_data;

/// Retains the original Controller first table, C ledger and private native scopes.
pub mod controller_receiving;

/// Owns the fixed native Source seed issuer read and recheck adapter.
#[cfg(target_os = "linux")]
pub mod source_seed_credential;

/// Shares fixed service native observations without role or payment authority.
pub mod fixed_service_identity;

/// Shares the installed non-MLS Cache task-context comparison DATA.
pub mod cache_signer_context;

/// Shares retained native readiness and absolute-deadline observations.
pub mod fixed_stream_readiness;

/// Shares native fixed-task subject observations without role authority.
pub mod fixed_task_subject;

/// Fixed Source native custody and its genuine construction boundary.
#[cfg(target_os = "linux")]
pub mod source_receiving;

/// Shares existing physical Cache native observation DATA without effect authority.
#[cfg(target_os = "linux")]
pub mod physical_cache_observation;

/// Shares the fixed Source socket native pathname custody recipe.
pub mod source_signer_connection;

/// Owns native protected endpoint descriptors without endpoint or signing authority.
pub mod endpoint_native_files;

/// Provides the existing fixed and variable byte engine with retained deadlines.
pub mod bounded_stream_io;

/// Retains the existing fixed Source signer socket transport without role grants.
pub mod source_signer_transport;
