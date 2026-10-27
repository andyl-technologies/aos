//! Admits complete data pairs through the sole funded physical owner.
//!
//! Data and metadata receipts remain distinct. Both use the same durable pair
//! publication and measured resource custody, but data admission verifies each
//! encoded chunk and its dictionary graph before native allocation or eviction.

use super::{Input, NativeDataPackAdmissionError, backing::PackAdmission};
use crate::host_cache::owner::{
    NativeMetadataOwner,
    retention::{Command, NativeOwnerExecutor},
};
use std::{io, sync::Arc};
use terrane_sdk::pack::PackId;
use tokio::sync::oneshot;

/// Owns a fully verified and synchronized data pack and its original index.
///
/// This receipt grants no consumer lease. The pair remains one physical cache
/// allocation; admission does not extract standalone copies of its members.
pub struct NativeDataPackAdmission {
    pair: PackAdmission,
}

impl NativeDataPackAdmission {
    /// Transfers the complete original pair into this owner's cache.
    ///
    /// # Errors
    /// Returns the original admission if submission fails. Accepted failures
    /// retain physical resources and durable funding in the actual owner.
    pub async fn into_cache(
        self,
        owner: &NativeMetadataOwner,
    ) -> Result<super::NativeAdmissionHandoffReport, super::NativeAdmissionHandoffError<Self>> {
        super::handoff::submit(owner, Arc::clone(&self.pair._job), self).await
    }

    /// Returns the canonical identifier selecting both synchronized members.
    pub fn pack_id(&self) -> PackId {
        self.pair.id
    }

    /// Returns deduplicated synchronized allocation for the pair's two inodes.
    pub fn synchronized_pair_bytes(&self) -> u64 {
        self.pair.allocated
    }

    /// Returns the separate fresh full-project charged-and-reserved observation.
    pub fn charged_reserved_bytes(&self) -> u64 {
        self.pair.charged
    }

    /// Returns the distinct retained future policy hold at acknowledgment.
    pub fn future_hold_bytes(&self) -> u64 {
        self.pair.future_hold
    }

    /// Returns synchronized allocation of the touched content directories.
    pub fn synchronized_directory_bytes(&self) -> u64 {
        self.pair.directory_allocated
    }
}

impl NativeMetadataOwner {
    /// Submits a bounded untrusted data pack and its exact detached index.
    ///
    /// Every chunk and dictionary chain must verify before bounded eviction,
    /// reservation or namespace writes. External dictionaries require genuine
    /// completed standalone admissions in this owner, retained with the pair.
    /// Dropping the accepted waiter cannot cancel the physical command.
    ///
    /// # Errors
    /// Returns untouched inputs on local or queue refusal. Invalid content,
    /// unavailable external dictionaries, insufficient capacity, and failed
    /// native durability return accepted errors. Started work remains owned;
    /// verification refusal before reservation creates no files or funding.
    pub async fn admit_data_pack(
        &self,
        expected_id: PackId,
        pack: Vec<u8>,
        detached_index: Vec<u8>,
    ) -> Result<NativeDataPackAdmission, NativeDataPackAdmissionError> {
        let (response, receive) = oneshot::channel();
        let refusal = self
            .admission_bounds
            .check(pack.len(), detached_index.len())
            .and_then(|()| {
                self.admission_bounds
                    .check(pack.capacity(), detached_index.capacity())
            })
            .err();
        let command = Command::AdmitDataPack {
            expected_id,
            pack,
            index: detached_index,
            response,
        };
        let result = match (refusal, self.commands.as_ref()) {
            (Some(error), _) => Err((error, command)),
            (None, None) => Err((io::Error::other("native admission owner stopped"), command)),
            (None, Some(commands)) => commands.try_send(command).map_err(super::submission_error),
        };
        if let Err((
            error,
            Command::AdmitDataPack {
                expected_id,
                pack,
                index,
                ..
            },
        )) = result
        {
            return Err(NativeDataPackAdmissionError::Unsubmitted {
                error,
                expected_id,
                pack,
                detached_index: index,
            });
        }
        receive
            .await
            .map_err(|_| {
                NativeDataPackAdmissionError::Accepted(io::Error::other(
                    "native data-pack admission worker stopped before reply",
                ))
            })?
            .map_err(NativeDataPackAdmissionError::Accepted)
    }
}

/// Verifies, funds and publishes the offered pair without exposing raw authority.
///
/// # Errors
/// Refuses stale Running custody, invalid data, exhausted bounds or failed durability.
pub(in crate::host_cache::owner) async fn run(
    executor: &mut NativeOwnerExecutor,
    expected_id: PackId,
    pack: Vec<u8>,
    index: Vec<u8>,
) -> io::Result<NativeDataPackAdmission> {
    super::pair(
        executor,
        Input::DataPack {
            expected_id,
            pack: Arc::new(pack),
            index: Arc::new(index),
        },
    )
    .await
    .map(|pair| NativeDataPackAdmission { pair })
}
