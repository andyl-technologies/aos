//! Runtime-only durable admission and replay authority brands.

use aos_sandbox::ProtectedJournalSnapshot;
use aos_sandbox_core::ObjectDigest;

use crate::ProviderRecoveryWorkV1;

/// Classifies owner admission without exposing sequence or signing authority.
#[derive(Debug)]
pub enum ProviderAdmissionDispositionV1 {
    /// The exact response is durably retained and safe to replay.
    Cached(DurableCachedResponseV1),
    /// A cached nonterminal response and separate recovery observation coexist.
    CachedRecovery {
        /// Preserves the immutable original response disposition.
        cached: DurableCachedResponseV1,
        /// Names observation-only work that may later produce a fresh outcome.
        work: ProviderRecoveryWorkV1,
    },
    /// A completed Acquire requires exact source reopen before replay send.
    AcquireReplay(DurableAcquireReplayV1),
    /// A superseding session durably reserved an exact active-acquisition rebind.
    AcquireRebind(DurableAcquireRebindPermitV1),
    /// The exact reservation exists and must enter recovery observation.
    Recover(ProviderRecoveryWorkV1),
    /// A fresh request carries one move-only durable acquire permit.
    Acquire(crate::backend::DurableAcquireEffectPermitV1),
    /// A fresh release carries one move-only durable release permit.
    Release(crate::backend::DurableReleaseEffectPermitV1),
    /// Inventory awaits authoritative revalidation after durable reservation.
    Inventory(crate::inventory::DurableInventoryPermitV1),
}

/// Grants one exact active-acquisition reopen and response rebind.
pub struct DurableAcquireRebindPermitV1 {
    pub(crate) holder_id: [u8; 16],
    pub(crate) session_binding: ObjectDigest,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) attempt_digest: ObjectDigest,
    pub(crate) pending_claim: bool,
    pub(crate) reservation_digest: ObjectDigest,
    pub(crate) journal_snapshot: ProtectedJournalSnapshot,
    pub(crate) completion_capacity: crate::transaction::CompletionCapacityV1,
    pub(crate) signing_authorization:
        aos_sandbox_source_provider_security::ProviderOutcomeAuthorizationV1,
}

impl core::fmt::Debug for DurableAcquireRebindPermitV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableAcquireRebindPermitV1([redacted])")
    }
}

/// Binds a retained Acquire response to a current journal snapshot.
pub struct DurableAcquireReplayV1 {
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) attempt_key: Vec<u8>,
    pub(crate) response: Vec<u8>,
    pub(crate) journal_snapshot: ProtectedJournalSnapshot,
}

impl core::fmt::Debug for DurableAcquireReplayV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableAcquireReplayV1([redacted])")
    }
}

/// Contains exact response bytes retained at a current journal snapshot.
pub struct DurableCachedResponseV1 {
    pub(crate) attempt_key: Vec<u8>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) journal_snapshot: ProtectedJournalSnapshot,
}

impl core::fmt::Debug for DurableCachedResponseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableCachedResponseV1([redacted])")
    }
}
