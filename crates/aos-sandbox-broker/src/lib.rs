//! Shared privileged-broker authority admission and durable records.
//!
//! Audience-specific brokers canonicalize their own request and catalog
//! semantics. This crate verifies the common signed plan and ownership lease,
//! intersects them with protected local time and fencing state, and emits
//! location-authenticated durable records that remain non-authorizing until
//! committed by the caller.

mod admission;
mod config;
mod record;

pub use admission::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, VerifiedBrokerAdmission,
};
pub use config::BrokerAuthorityConfigError;
pub use record::{
    AuthorizationRecordError, BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV2,
    BrokerEffectStatusV2,
};
