//! Encodes sealed delegation corroboration for future local Cleanup entry.
//!
//! ```text
//! purpose[736] = CRUCPSP3 | schema=3 | bytes=736 | physical publisher[176] |
//!                dormant selectors[32] | CRUCDPU1 delegation[512]
//! ```
//!
//! Decoding cannot select an authenticated carrier or create its retained
//! issuer, outer right, resource child or recipient. The actual constructor
//! authenticates those owners before comparing this sealed corroboration.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    DeferredCleanupCapability, DeferredCleanupDecodeError, DeferredCleanupIdentity, array32,
    generation, get32, get64, identity, put32, put64,
};
use crate::publisher_subscription::{PUBLISHER_PURPOSE_BYTES, PublisherPurpose};

/// Fixed extent of the schema-three physical purpose and entry delegation.
pub const DEFERRED_CLEANUP_PURPOSE_BYTES: usize = 736;

const DELEGATION_OFFSET: usize = 224;

/// Describes the independently retained outer right's temporal constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferredCleanupOuterPolicy {
    /// Explicitly describes a retained right without a temporal endpoint.
    NoEndpoint,
    /// Describes an immutable positive endpoint in the authenticated domain.
    FiniteEndpoint {
        /// Absolute CLOCK_MONOTONIC endpoint, at most `i64::MAX`.
        endpoint_ns: u64,
    },
}

/// Correlates the actual assigned Source and retained future-entry parents.
///
/// The carrier identity names an independently retained owner; it cannot be a
/// digest of the record containing that identity. Device and inode values only
/// corroborate the actual carrier selected before reading nominated bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupDelegation {
    /// Actual assigned Source capability identity.
    pub source_capability: [u8; 32],
    /// Actual assigned Source reservation identity.
    pub source_reservation: [u8; 32],
    /// Assigned local account incarnation.
    pub account_incarnation: u64,
    /// Assigned process incarnation.
    pub process_incarnation: u64,
    /// Assigned Source issuer incarnation.
    pub source_issuer_incarnation: u64,
    /// Independently retained authenticated carrier.
    pub carrier: DeferredCleanupIdentity,
    /// Actual carrier device corroboration; zero is a valid witness.
    pub carrier_device: u64,
    /// Actual carrier inode corroboration; zero is a valid witness.
    pub carrier_inode: u64,
    /// Positive extent of the actual carrier.
    pub carrier_extent: u64,
    /// Explicit constraint of the independently retained outer entry right.
    pub outer_policy: DeferredCleanupOuterPolicy,
    /// Actual authenticated CLOCK_MONOTONIC domain identity.
    pub clock_domain: [u8; 32],
    /// Positive maximum future duration, at most `i64::MAX` nanoseconds.
    pub maximum_duration_ns: u64,
    /// Positive nonexhausted maximum canonical cleanup-work inventory.
    pub maximum_units: u64,
    /// Independently retained outer entry right.
    pub outer: DeferredCleanupIdentity,
    /// Actual same-account resource parent of the dedicated physical child.
    pub resource: DeferredCleanupIdentity,
    /// Actual retained recipient parent.
    pub recipient: DeferredCleanupIdentity,
    /// Complete concrete profile identity.
    pub profile: [u8; 32],
    /// Exact extent of the already debited physical child.
    pub physical_extent: u64,
    /// Actual delegated issuer of future entry authority.
    pub issuer: DeferredCleanupIdentity,
}

impl DeferredCleanupDelegation {
    fn validate(&self) -> Result<(), DeferredCleanupDecodeError> {
        for owner in [
            self.carrier,
            self.outer,
            self.resource,
            self.recipient,
            self.issuer,
        ] {
            owner.validate()?;
        }
        if [
            self.source_capability,
            self.source_reservation,
            self.clock_domain,
            self.profile,
        ]
        .contains(&[0; 32])
            || !generation(self.account_incarnation)
            || !generation(self.process_incarnation)
            || !generation(self.source_issuer_incarnation)
            || self.carrier_extent == 0
            || self.physical_extent == 0
            || self.maximum_duration_ns == 0
            || self.maximum_duration_ns > i64::MAX as u64
            || !generation(self.maximum_units)
        {
            return Err(DeferredCleanupDecodeError);
        }
        if let DeferredCleanupOuterPolicy::FiniteEndpoint { endpoint_ns } = self.outer_policy
            && (endpoint_ns == 0 || endpoint_ns > i64::MAX as u64)
        {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Checks a dormant observation against the exact delegated parents.
    ///
    /// This comparison grants no authority. The real issuer must retain and
    /// authenticate every parent and derive entry units from its own inventory.
    ///
    /// # Errors
    /// Refuses invalid observations, changed parents, extent or profile, or
    /// future limits exceeding the immutable delegation.
    pub fn validate_capability(
        &self,
        capability: &DeferredCleanupCapability,
    ) -> Result<(), DeferredCleanupDecodeError> {
        self.validate()?;
        capability.validate()?;
        if capability.issuer != self.issuer
            || capability.resource != self.resource
            || capability.outer != self.outer
            || capability.recipient != self.recipient
            || capability.profile != self.profile
            || capability.funding.total()? != self.physical_extent
            || capability.duration_ns > self.maximum_duration_ns
            || capability.required_units > self.maximum_units
        {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    fn encode_into(&self, bytes: &mut [u8]) {
        bytes[..8].copy_from_slice(b"CRUCDPU1");
        for (offset, value) in [
            (8, 1),
            (12, 512),
            (16, 9),
            (20, 12),
            (24, 7),
            (28, 3),
            (184, 1),
            (188, 13),
            (192, 1),
            (196, 1),
            (204, 1),
            (464, 1),
        ] {
            put32(bytes, offset, value);
        }
        for (offset, value) in [
            (32, self.source_capability),
            (64, self.source_reservation),
            (128, self.carrier.identity),
            (216, self.clock_domain),
            (264, self.outer.identity),
            (304, self.resource.identity),
            (344, self.recipient.identity),
            (384, self.profile),
            (424, self.issuer.identity),
        ] {
            bytes[offset..offset + 32].copy_from_slice(&value);
        }
        for (offset, value) in [
            (96, self.account_incarnation),
            (104, self.process_incarnation),
            (112, self.source_issuer_incarnation),
            (120, self.carrier.incarnation),
            (160, self.carrier_device),
            (168, self.carrier_inode),
            (176, self.carrier_extent),
            (248, self.maximum_duration_ns),
            (256, self.maximum_units),
            (296, self.outer.incarnation),
            (336, self.resource.incarnation),
            (376, self.recipient.incarnation),
            (416, self.physical_extent),
            (456, self.issuer.incarnation),
        ] {
            put64(bytes, offset, value);
        }
        let (policy, endpoint) = match self.outer_policy {
            DeferredCleanupOuterPolicy::NoEndpoint => (1, 0),
            DeferredCleanupOuterPolicy::FiniteEndpoint { endpoint_ns } => (2, endpoint_ns),
        };
        put32(bytes, 200, policy);
        put64(bytes, 208, endpoint);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DeferredCleanupDecodeError> {
        if bytes[..8] != *b"CRUCDPU1"
            || [
                (8, 1),
                (12, 512),
                (16, 9),
                (20, 12),
                (24, 7),
                (28, 3),
                (184, 1),
                (188, 13),
                (192, 1),
                (196, 1),
                (204, 1),
                (464, 1),
            ]
            .into_iter()
            .any(|(offset, value)| get32(bytes, offset) != value)
            || bytes[468..].iter().any(|value| *value != 0)
        {
            return Err(DeferredCleanupDecodeError);
        }
        let outer_policy = match (get32(bytes, 200), get64(bytes, 208)) {
            (1, 0) => DeferredCleanupOuterPolicy::NoEndpoint,
            (2, endpoint_ns) => DeferredCleanupOuterPolicy::FiniteEndpoint { endpoint_ns },
            _ => return Err(DeferredCleanupDecodeError),
        };
        let delegation = Self {
            source_capability: array32(bytes, 32),
            source_reservation: array32(bytes, 64),
            account_incarnation: get64(bytes, 96),
            process_incarnation: get64(bytes, 104),
            source_issuer_incarnation: get64(bytes, 112),
            carrier: DeferredCleanupIdentity {
                identity: array32(bytes, 128),
                incarnation: get64(bytes, 120),
            },
            carrier_device: get64(bytes, 160),
            carrier_inode: get64(bytes, 168),
            carrier_extent: get64(bytes, 176),
            outer_policy,
            clock_domain: array32(bytes, 216),
            maximum_duration_ns: get64(bytes, 248),
            maximum_units: get64(bytes, 256),
            outer: identity(bytes, 264),
            resource: identity(bytes, 304),
            recipient: identity(bytes, 344),
            profile: array32(bytes, 384),
            physical_extent: get64(bytes, 416),
            issuer: identity(bytes, 424),
        };
        delegation.validate()?;
        Ok(delegation)
    }
}

/// Describes physical publisher roles and a dormant future-entry delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupPurpose {
    /// Actual physical publisher session's independently paid roles.
    pub publisher: PublisherPurpose,
    /// Corroboration of the actual retained future-entry owners.
    pub delegation: DeferredCleanupDelegation,
}

impl DeferredCleanupPurpose {
    fn validate_assignment(&self) -> Result<(), DeferredCleanupDecodeError> {
        self.delegation.validate()?;
        if self.publisher.account_generation != self.delegation.account_incarnation
            || self.publisher.process_generation != self.delegation.process_incarnation
        {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Encodes the distinct schema-three purpose without installing it.
    ///
    /// # Errors
    /// Refuses malformed physical roles, invalid delegation or mismatched
    /// account and process assignments.
    pub fn encode(
        &self,
    ) -> Result<[u8; DEFERRED_CLEANUP_PURPOSE_BYTES], DeferredCleanupDecodeError> {
        self.validate_assignment()?;
        let physical = self
            .publisher
            .encode()
            .map_err(|_| DeferredCleanupDecodeError)?;
        let mut bytes = [0; DEFERRED_CLEANUP_PURPOSE_BYTES];
        bytes[..PUBLISHER_PURPOSE_BYTES].copy_from_slice(&physical);
        bytes[..8].copy_from_slice(b"CRUCPSP3");
        put32(&mut bytes, 8, 3);
        put32(&mut bytes, 12, DEFERRED_CLEANUP_PURPOSE_BYTES as u32);
        for (offset, value) in [(192, 3), (196, 2), (200, 2)] {
            put32(&mut bytes, offset, value);
        }
        put64(&mut bytes, 208, 1);
        self.delegation.encode_into(&mut bytes[DELEGATION_OFFSET..]);
        Ok(bytes)
    }

    /// Decodes the exact new purpose without accepting earlier editions.
    ///
    /// # Errors
    /// Refuses noncanonical framing, selectors, padding, physical geometry,
    /// delegation constraints or account/process correlation.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeferredCleanupDecodeError> {
        if bytes.len() != DEFERRED_CLEANUP_PURPOSE_BYTES
            || bytes[..8] != *b"CRUCPSP3"
            || [
                (8, 3),
                (12, DEFERRED_CLEANUP_PURPOSE_BYTES as u32),
                (192, 3),
                (196, 2),
                (200, 2),
                (204, 0),
            ]
            .into_iter()
            .any(|(offset, value)| get32(bytes, offset) != value)
            || get64(bytes, 208) != 1
            || bytes[216..224].iter().any(|value| *value != 0)
        {
            return Err(DeferredCleanupDecodeError);
        }

        // Reuse the physical-role validator, while keeping edition negotiation
        // exact: an old decoder never receives or accepts the new record.
        let mut physical = [0; PUBLISHER_PURPOSE_BYTES];
        physical.copy_from_slice(&bytes[..PUBLISHER_PURPOSE_BYTES]);
        physical[..8].copy_from_slice(b"CRUCPSP1");
        put32(&mut physical, 8, 1);
        put32(&mut physical, 12, PUBLISHER_PURPOSE_BYTES as u32);
        physical[192..].fill(0);
        let purpose = Self {
            publisher: PublisherPurpose::decode(&physical)
                .map_err(|_| DeferredCleanupDecodeError)?,
            delegation: DeferredCleanupDelegation::decode(&bytes[DELEGATION_OFFSET..])?,
        };
        purpose.validate_assignment()?;
        Ok(purpose)
    }
}
