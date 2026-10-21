//! Receives opaque quarantine descriptors without manufacturing body authority.

use super::{Client, Error, RequestPayload};
use crate::publisher_local::wire::{BodyKey, BodyKind, Operation};
use std::fs::File;
use terrane_format::identity::Descriptor;
use terrane_sdk::host::cache::HostReadLocation;

impl<L: HostReadLocation> Client<L> {
    /// Obtains one unverified quarantine inode under the original drain epoch.
    pub(crate) fn inspect_quarantined_sealed(
        &self,
        descriptor: &Descriptor,
        incarnation: Option<[u8; 32]>,
    ) -> Result<File, Error> {
        let mut state = self.lock()?;
        self.require_drained(&state)?;
        let mut received = self.exchange_payload(
            &mut state,
            Operation::InspectQuarantine,
            RequestPayload {
                incarnation: incarnation.map_or_else(Vec::new, |tag| tag.to_vec()),
                body: Some(BodyKey {
                    kind: BodyKind::Sealed as i32,
                    descriptor: descriptor.encode(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )?;
        received
            .files
            .pop()
            .ok_or(Error::Invalid("quarantine descriptor absent"))
    }
}
