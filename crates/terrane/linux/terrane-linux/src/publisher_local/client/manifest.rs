//! Retains verified manifest-backed bytes with their reconstruction pin.
//!
//! Read accessors borrow immutable fields without consulting embedded state.
//! The reconstruction pin remains owned for the backing lifetime.

use std::{fs::File, sync::Arc};

use terrane_sdk::host::{
    cache::HostDomainLocation,
    publication::{PublicationClaim, VerityBinding},
};

use super::PeerPublishedObject;
use crate::host_cache::{NativeHostLayout, RetainedManifest};

/// Keeps verified manifest-backed bytes and their genuine durable pin together.
///
/// Read accessors take no embedded-state lock. The retained metadata receipt is
/// private, cannot be extracted and remains owned for the complete backing
/// lifetime. No raw file, retention identifier or boolean constructor exists.
pub struct PeerManifestPublishedObject {
    object: PeerPublishedObject<HostDomainLocation>,
    _retention: RetainedManifest,
}

impl PeerManifestPublishedObject {
    /// Borrows verified sealed bytes without consulting embedded metadata state.
    pub fn handle(&self) -> &File {
        self.object.handle()
    }

    /// Borrows the actual independently measured kernel binding without locking.
    pub fn binding(&self) -> &VerityBinding {
        self.object.binding()
    }

    /// Borrows the canonical reconstruction claim already verified for these bytes.
    pub fn claim(&self) -> &PublicationClaim {
        self.object.claim()
    }

    /// Borrows the retained root guard without consulting pin state.
    pub fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        self.object.layout()
    }

    /// Borrows the publisher-issued inode token without acquiring a state lock.
    pub fn incarnation(&self) -> &[u8; 32] {
        self.object.incarnation()
    }
}
