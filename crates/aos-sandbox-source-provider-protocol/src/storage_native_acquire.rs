//! Inert native held-snapshot Acquire and cleanup contract.
//!
//! The version-two positive exchange is distinct from negative-only
//! `AOSZHQ01`. Provider signs the original RootMount request and native claims;
//! Storage independently verifies them and durably accepts an exact receipt
//! and original descriptor before returning one SourceRoot descriptor.
//!
//! ```text
//! AOSZNQ02 | version:u16be=2 | reserved[6]=0 |
//! native-claims-length:u32be | AOSZHQ01-claims[.length] |
//! root-request-length:u32be | signed-RootMount-Acquire[.length] |
//! ProviderOutcome-signer[120] | signature[64]
//! AOSZNA02 | version:u16be=2 | reserved[6]=0 | issuance-id[16] |
//! signed-native-request-digest[32] | signed-AOSZHR01-digest[32] |
//! original-boot[16] | device:u64be | inode:u64be | mount-id:u64be
//! AOSZNP02 | version:u16be=2 | reserved[6]=0 | descriptor-count:u16be=1 |
//! descriptor-role:u8=SourceRoot | reserved[5]=0 |
//! signed-acceptance[288] | signed-AOSZHR01[800]
//! ```
//!
//! Acceptance commits no issuance-journal head: its stable unsigned digest is
//! journaled in a separate Storage issuance owner. AOSZHR01 names the primary
//! Storage observation, not the acceptance journal, avoiding a head/digest
//! cycle. Both signatures use the independently pinned dedicated ZFS receipt
//! role; generic backend ZfsHold attestation is not interchangeable.
//!
//! Exact retry requires the original boot/device/inode/unique-mount identity
//! under retained live custody. A cold remount is never exact replay. Total
//! custody loss withholds success and resolves only through authenticated
//! cleanup or absence. These public scalar models grant no journal, kernel,
//! release, descriptor-send, or production Acquire authority.
//!
//! The signed claim sequence is the original request sequence. A future owner
//! must durably admit its first use and allow retry only for the exact saved
//! signed bytes and original live custody; it must not apply the negative-only
//! carrier's strictly-next rule as an implicit positive retry migration.

mod acceptance;
mod cleanup;
mod request;

pub use acceptance::{
    SignedStorageNativeAcceptanceV2, StorageNativeAcceptanceV2, StorageNativeAcquireReplyV2,
    StorageNativeAcquireVerificationV2, StorageNativeDescriptorCustodyV2,
    VerifiedStorageNativeAcquireV2,
};
pub use cleanup::{
    SignedStorageNativeCleanupReceiptV2, SignedStorageNativeCleanupRequestV2,
    StorageNativeCleanupDispositionV2, StorageNativeCleanupReasonV2, StorageNativeCleanupReceiptV2,
    StorageNativeCleanupRequestV2,
};
pub use request::{
    MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2, SignedStorageNativeAcquireRequestV2,
    StorageNativeAcquireRequestV2,
};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

/// Rejects malformed, unauthenticated, or mismatched native contract evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageNativeAcquireErrorV2 {
    /// Framing, a nested record, role, interval, or sentinel is invalid.
    #[error("native Storage Acquire record is noncanonical")]
    Noncanonical,
    /// An independently pinned signature or signer does not match.
    #[error("native Storage Acquire authority does not match")]
    Authority,
    /// The exact request, receipt, acceptance, or original descriptor differs.
    #[error("native Storage Acquire evidence does not match")]
    Mismatch,
    /// Original live descriptor custody has been lost.
    #[error("native Storage Acquire original descriptor custody is lost")]
    CustodyLost,
    /// The same acquisition identity names different signed request bytes.
    #[error("native Storage Acquire request replay conflicts")]
    ReplayConflict,
}

const VERSION: u16 = 2;

fn header(bytes: &mut Vec<u8>, magic: &[u8; 8]) {
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
}

fn digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn nonzero(digest: ObjectDigest) -> bool {
    digest.as_bytes() != &[0; 32]
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 8]) -> Result<Self, StorageNativeAcquireErrorV2> {
        let mut reader = Self { remaining: bytes };
        if reader.take::<8>()? != *magic
            || reader.take::<2>()? != VERSION.to_be_bytes()
            || reader.take::<6>()? != [0; 6]
        {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        Ok(reader)
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], StorageNativeAcquireErrorV2> {
        if count > self.remaining.len() {
            return Err(StorageNativeAcquireErrorV2::Noncanonical);
        }
        let (head, tail) = self.remaining.split_at(count);
        self.remaining = tail;
        Ok(head)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], StorageNativeAcquireErrorV2> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| StorageNativeAcquireErrorV2::Noncanonical)
    }

    fn digest(&mut self) -> Result<ObjectDigest, StorageNativeAcquireErrorV2> {
        Ok(ObjectDigest::from_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, StorageNativeAcquireErrorV2> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn done(&self) -> Result<(), StorageNativeAcquireErrorV2> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(StorageNativeAcquireErrorV2::Noncanonical)
        }
    }
}

#[cfg(test)]
mod tests;
