//! Purpose-separated commitments used by lifecycle records.

use aos_sandbox_core::{ObjectDigest, ResourceId, Revision, SnapshotId};
use sha2::{Digest as _, Sha256};

use super::evidence::LifecycleRetentionLedgerDigestV1;
use super::projection::LifecycleModelError;

pub(super) fn snapshot_release_digest(
    snapshot: SnapshotId,
    holder: ResourceId,
    predecessor_revision: Revision,
    successor_revision: Revision,
    predecessor_ledger: LifecycleRetentionLedgerDigestV1,
    successor_ledger: LifecycleRetentionLedgerDigestV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.snapshot-retention-release.v1\0")
            .chain_update(snapshot.as_bytes())
            .chain_update(holder.as_bytes())
            .chain_update(predecessor_revision.get().to_be_bytes())
            .chain_update(successor_revision.get().to_be_bytes())
            .chain_update(predecessor_ledger.digest().as_bytes())
            .chain_update(successor_ledger.digest().as_bytes())
            .finalize()
            .into(),
    )
}

macro_rules! define_commitment {
    ($name:ident, $summary:literal, $domain:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(ObjectDigest);

        impl $name {
            /// Commits exact bytes with this value's purpose-specific domain.
            #[must_use]
            pub fn commit(bytes: &[u8]) -> Self {
                Self(ObjectDigest::from_bytes(
                    Sha256::new()
                        .chain_update($domain)
                        .chain_update(bytes)
                        .finalize()
                        .into(),
                ))
            }

            /// Returns the underlying SHA-256 commitment.
            #[must_use]
            pub const fn digest(self) -> ObjectDigest {
                self.0
            }

            pub(super) fn from_stored(digest: ObjectDigest) -> Result<Self, LifecycleModelError> {
                if digest.as_bytes() == &[0; 32] {
                    Err(LifecycleModelError::CorruptEncoding)
                } else {
                    Ok(Self(digest))
                }
            }
        }
    };
}

define_commitment!(
    LifecycleIdempotencyDigestV1,
    "Commits an idempotency key independently of request semantics.",
    b"aos.sandbox.lifecycle.idempotency.v1\0"
);
define_commitment!(
    LifecycleNormalizedRequestDigestV1,
    "Commits the complete normalized lifecycle request.",
    b"aos.sandbox.lifecycle.normalized-request.v1\0"
);
define_commitment!(
    LifecycleResourceStateDigestV1,
    "Commits the exact durable state named by a resource expectation.",
    b"aos.sandbox.lifecycle.resource-state.v1\0"
);
define_commitment!(
    DesiredStateDocumentDigestV1,
    "Commits the canonical desired-state document selected by a mutation.",
    b"aos.sandbox.lifecycle.desired-state-document.v1\0"
);
define_commitment!(
    DesiredStateCasDigestV1,
    "Commits the exact desired-state compare-and-swap mutation.",
    b"aos.sandbox.lifecycle.desired-state-cas.v1\0"
);
define_commitment!(
    LifecycleStepRequestDigestV1,
    "Commits the stable logical request for one lifecycle step.",
    b"aos.sandbox.lifecycle.step-request.v1\0"
);
define_commitment!(
    LifecycleStepBodyDigestV1,
    "Commits the exact broker request body selected for one step.",
    b"aos.sandbox.lifecycle.step-body.v1\0"
);
define_commitment!(
    LifecycleStepPlanDigestV1,
    "Commits the exact non-authorizing broker plan selected for one step.",
    b"aos.sandbox.lifecycle.step-plan.v1\0"
);
define_commitment!(
    LifecycleStepAdmissionDigestV1,
    "Commits the exact fresh broker admission used by one effect attempt.",
    b"aos.sandbox.lifecycle.step-admission.v1\0"
);
define_commitment!(
    LifecycleStepResultDigestV1,
    "Commits the exact broker result retained for one step.",
    b"aos.sandbox.lifecycle.step-result.v1\0"
);
define_commitment!(
    LifecycleInventoryDigestV1,
    "Commits the exact inventory used to classify an ambiguous step.",
    b"aos.sandbox.lifecycle.inventory.v1\0"
);
define_commitment!(
    LifecycleFailureDigestV1,
    "Commits bounded failure detail without embedding diagnostics.",
    b"aos.sandbox.lifecycle.failure.v1\0"
);
define_commitment!(
    LifecycleSemanticCommitDigestV1,
    "Commits the complete semantic-commit witness.",
    b"aos.sandbox.lifecycle.semantic-commit.v1\0"
);
define_commitment!(
    LifecycleRecordDigestV1,
    "Commits one exact canonical lifecycle operation record.",
    b"aos.sandbox.lifecycle.operation-record.v1\0"
);
define_commitment!(
    LifecycleJournalCommitDigestV1,
    "Commits the atomic journal transaction containing semantic commit.",
    b"aos.sandbox.lifecycle.journal-commit.v1\0"
);
