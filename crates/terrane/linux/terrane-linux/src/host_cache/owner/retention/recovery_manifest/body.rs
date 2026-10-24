//! Pairs registered adopted-body handles with lifetime-free metadata custody.
//!
//! These values describe retained resources, not same-response lifecycle
//! correlation, serving authorization or a completed recovery. Failed pairs may
//! be unresolved; the physical owner retains them until genuine reconciliation.

use super::*;
use crate::publisher_local::client::PeerPublishedObject;

struct RegisteredBodyCustody {
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    backing: RecoveryManifestBackingRetention,
}

/// Retains an actual adopted body and its durable metadata custody by value.
///
/// The physical executor stores a clone before any response. Cloning shares the
/// genuine resources; it supplies no constructor, consumer pin or serving proof.
/// Read-only accessors take no embedded-state lock. Actual same-response inode
/// and lifecycle correlation remains the downstream IPC owner's obligation.
#[derive(Clone)]
pub(crate) struct RecoveryManifestBodyRetention {
    custody: Arc<RegisteredBodyCustody>,
}

impl RecoveryManifestBodyRetention {
    /// Pairs only privately registered native body and consumed metadata custody.
    pub(super) fn pair(
        body: Arc<PeerPublishedObject<HostDomainLocation>>,
        backing: RecoveryManifestBackingRetention,
    ) -> Self {
        Self {
            custody: Arc::new(RegisteredBodyCustody { body, backing }),
        }
    }

    /// Borrows the actual registered native body without a state lock.
    pub(crate) fn body(&self) -> &PeerPublishedObject<HostDomainLocation> {
        &self.custody.body
    }

    /// Shares the original registered descriptor without reopening its private namespace.
    pub(in crate::host_cache) fn body_arc(&self) -> Arc<PeerPublishedObject<HostDomainLocation>> {
        Arc::clone(&self.custody.body)
    }

    /// Borrows lifetime-free durable metadata custody without a state lock.
    pub(crate) fn backing(&self) -> &RecoveryManifestBackingRetention {
        &self.custody.backing
    }
}

/// Retains registered body and metadata resources after unsuccessful completion.
pub(crate) struct RecoveryManifestBodyFailure {
    error: io::Error,
    retained: RecoveryManifestBodyRetention,
}

impl RecoveryManifestBodyFailure {
    /// Keeps a failed registered pair with its original typed cause.
    pub(super) fn new(error: io::Error, retained: RecoveryManifestBodyRetention) -> Self {
        Self { error, retained }
    }

    /// Returns the actual failure and its still-registered native resources.
    pub(crate) fn into_parts(self) -> (io::Error, RecoveryManifestBodyRetention) {
        (self.error, self.retained)
    }
}
