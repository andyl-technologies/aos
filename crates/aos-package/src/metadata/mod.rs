//! Generic authorization, plan normalization, and configuration evaluation.
//!
//! Platform detection and metadata acquisition are owned by the selected
//! `aos-metadata-provider` package. This module consumes its typed result and
//! applies package-manager trust and configuration policy.

pub mod provider;
pub mod provisioning;
pub mod repart;

pub use aos_metadata::{
    AcquiredMetadata, DetectedPlatform, Facts, StaticNetwork, canonicalize_host_facts,
    facts_render, fetcher, normalize_host_facts, now_rfc3339,
};
pub use provisioning::{AuthorizeOptions, EvalProvisioningOptions, ProvisioningTrust};
