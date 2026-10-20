//! Publishes finite metadata-only checkpoints from authenticated side records.
//!
//! [`crate::repository::Repository::backfill_index_inputs`] prepares ordinary
//! canonical bytes and measurements from the selected native catalog. Actual
//! authorization, producer revalidation, signing and durable publication remain
//! exclusively in the repository's normal commit path. Unresolved evidence is
//! reported as a gap and cannot establish complete coverage.

mod edits;
mod records;

#[cfg(all(test, feature = "tokio", feature = "surface-sdk", unix))]
mod tests;

#[cfg(all(test, feature = "tokio", feature = "surface-sdk", unix))]
/// Shares the native backfill fixture with independent index contracts.
pub(super) use tests::native::fixture as native_fixture;

use terrane_format::identity::{Digest, Identity};
use terrane_format::indexing::{completion, maintenance};
use terrane_format::refs::RefRecord;

use super::IndexPublicationWork;
use crate::repository::PreparedTree;

/// Identifies an unresolved input without treating missing evidence as a value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexBackfillGapReason {
    /// No checked supported side record supplies the required input.
    MissingEvidence,
    /// The selected ordinary record fails independent producer verification.
    InvalidEvidence,
    /// A producer is not currently readable or trusted.
    ProducerDenied,
    /// Actual producer evidence is unavailable.
    UnavailableEvidence,
    /// The registered implementation cannot interpret the required input.
    UnsupportedInput,
    /// Same-version serving side values disagree with the inline value.
    ValueDisagreement,
    /// Conditional applicability lacks authenticated classifier evidence.
    UnknownApplicability,
    /// Another required input prevents an atomic whole-file edit.
    DeferredFile,
    /// This occurrence cannot be addressed by the supported namespace editor.
    UnsupportedOccurrence,
}

/// Reports one exact occurrence whose required input remains unresolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexBackfillGap {
    /// Actual namespace owner containing this occurrence.
    pub owner: Digest,
    /// Absolute file or unresolved occurrence path.
    pub path: Vec<u8>,
    /// Required inline attribute name, without an invented sentinel value.
    pub attribute: String,
    /// Explicit reason this input cannot count as completed work.
    pub reason: IndexBackfillGapReason,
}

/// Records a copied value and its independently authenticated side producer.
#[derive(Clone, Debug)]
pub struct IndexBackfillCopy {
    /// Exact immutable selected Attribute record identity.
    pub record: Identity,
    /// Independently verified actual producing commit.
    pub producer: Digest,
    /// Real producing occurrence that passed current Read and trust checks.
    pub producer_path: Vec<u8>,
    /// ContentRef identity to which the record's value applies.
    pub object: Digest,
    /// Registered attribute name whose canonical bytes were copied.
    pub attribute: String,
    /// Original exact function name and version, without relabeling.
    pub function: terrane_format::derived::Function,
    /// Canonical inline value bytes copied from the checked record.
    pub value: Vec<u8>,
    /// Actual consuming paths sharing this physical file edit.
    pub paths: Vec<Vec<u8>>,
}

/// Separates full missing-owner construction from valid-bound incremental work.
#[derive(Clone, Debug)]
pub struct IndexBackfillInitialization {
    /// Source owner immediately before its new binding was installed.
    pub owner: Digest,
    /// Registered attribute whose genuinely absent binding was initialized.
    pub attribute: String,
    /// Actual common owning initialization work.
    pub construction: maintenance::ConstructionWork,
    /// Actual complete reachable index closure export.
    pub export: maintenance::ExportWork,
}

/// Counts actual examined occurrences and newly materialized inline inputs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexBackfillCoverage {
    /// Root occurrences examined, retaining repeated graft policy uses.
    pub root_occurrences: usize,
    /// Regular-file occurrences examined under their actual effective policies.
    pub file_occurrences: usize,
    /// Required inputs considered, including unresolved conditional applicability.
    pub required_inputs: usize,
    /// Required inputs newly copied across their actual consuming occurrences.
    pub materialized_inputs: usize,
    /// Raw missing inline index rows before editing, independent of applicability.
    pub raw_missing_index_inputs: usize,
}

/// Reports ordinary preparation and an optional actually published checkpoint.
///
/// A report grants no serving, lineage, retention or producer authority. Raw
/// missing G rows and current applicable coverage are deliberately distinct.
#[derive(Clone, Debug, Default)]
pub struct IndexBackfillReport {
    /// Actual acknowledged winning record, filled only by normal publication.
    pub record: Option<RefRecord>,
    /// Signed immutable source view used by this finite preparation.
    pub source_view: Digest,
    /// Actual examined occurrence and materialization counts.
    pub coverage: IndexBackfillCoverage,
    /// Checked source records and exact copied canonical bytes.
    pub copied: Vec<IndexBackfillCopy>,
    /// Explicit unresolved applicable inputs or occurrence coverage.
    pub gaps: Vec<IndexBackfillGap>,
    /// Full construction only for genuinely absent required bindings.
    pub initialization: Vec<IndexBackfillInitialization>,
    /// Independently measured owner completion during preparation.
    pub completion: Vec<completion::Work>,
    /// Actual containing-root and file edits performed by preparation.
    pub edits: Vec<terrane_format::tree_builder::Work>,
    /// Actual normal writer work of the successfully published candidate.
    pub index_work: IndexPublicationWork,
}

impl IndexBackfillReport {
    /// Reports applicable coverage after all actual owning checks succeeded.
    ///
    /// This ordinary diagnostic is not a checked carrier. A prepared complete
    /// report is not a published checkpoint until `record` contains its real
    /// acknowledged result. Raw G absences may remain for proved exclusions.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty() && self.index_work.gaps.is_empty()
    }
}

/// Owns canonical proposed bytes without granting publication authority.
pub(crate) struct PreparedIndexBackfill {
    tree: Option<PreparedTree>,
    #[cfg(unix)]
    references: Option<super::read::ExistingOwnerReferences>,
    uploads: Vec<super::StagedUpload>,
    report: IndexBackfillReport,
}

impl PreparedIndexBackfill {
    /// Transfers owned proposal data and the independent closed owner carrier.
    #[cfg(unix)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<PreparedTree>,
        Vec<super::StagedUpload>,
        IndexBackfillReport,
        Option<super::read::ExistingOwnerReferences>,
    ) {
        (self.tree, self.uploads, self.report, self.references)
    }
}

#[cfg(unix)]
impl<F, B, V, C> super::Guard<crate::bucket::FileBucket<F, B, V>, C>
where
    F: crate::store::LocalFs + crate::bucket::BucketBinding + Sync,
    B: crate::store::Clock + crate::bucket::BucketBinding + Sync,
    V: crate::store::ContentValidator + crate::bucket::BucketBinding + Sync,
    C: crate::store::Clock + Sync,
{
    /// Prepares a metadata-only proposal through actual namespace and producer owners.
    ///
    /// # Errors
    /// Preserves current source, Original, selected catalog and storage failures;
    /// rejects caller-supplied uploads/evidence, signed or stale templates,
    /// mismatched selected/authoring profiles and unsupported native semantics.
    /// Optional unqualified records leave explicit gaps rather than permission.
    pub(crate) async fn prepare_index_backfill(
        &self,
        session: &crate::ref_advance::WriterSession,
        request: &super::CommitRequest,
    ) -> Result<PreparedIndexBackfill, crate::store::StoreFailure> {
        let source = session.record().ok_or_else(super::invalid)?;
        if request.commit.signature.is_some()
            || !request.uploads.is_empty()
            || !request.reference_records.is_empty()
            || !request.disclosures.is_empty()
            || request.commit.parents != [source.commit]
            || request.commit.profile_pair.recipe.is_some()
            || request.commit.profile_pair.entry_receipts.is_some()
            || request.commit.profile_pair.commit_context.is_some()
            || request.commit.profile_pair.required_properties.is_some()
            || request.commit.profile_pair.lease.is_some()
            || request.commit.packs.is_some()
            || request.commit.profile_pair.tree_format != 1
            || request.commit.profile_pair.chunk_profile != self.config().chunk_profile_name
        {
            return Err(super::invalid());
        }
        let snapshot = self
            .read_snapshot(session.reference(), &request.token, b"/", &request.surface)
            .await?;
        if snapshot.commit.identity() != source.commit
            || request.commit.tree != snapshot.evidence.root
        {
            return Err(super::invalid());
        }
        let profile = super::history::completion::profile_inputs(
            self,
            &snapshot.commit,
            &snapshot.interpretation,
        )?;
        if profile != self.configured_authoring_registries()?
            || profile.property_revision != 3
            || profile.attribute_revision != 2
            || profile.tree_revision != 1
        {
            return Err(crate::store::StoreFailure::new(
                crate::store::StoreErrorKind::Unsupported,
            ));
        }

        let records = records::acquire(self, &request.token, &request.surface).await?;
        // All borrowed entry/tree/arena work ends inside execute. Native
        // publication receives owned canonical bytes, never a self-reference.
        let mut prepared = edits::execute(self, &snapshot, &records)?;
        if let Some(tree) = &mut prepared.tree {
            prepared.references = Some(
                self.existing_owner_references(snapshot, tree, &prepared.uploads)
                    .await?,
            );
        }
        Ok(prepared)
    }
}

#[cfg(all(feature = "std", unix))]
impl<F, B, V, C> crate::repository::Repository<crate::bucket::FileBucket<F, B, V>, C, F>
where
    crate::bucket::FileBucket<F, B, V>: Sync,
    F: crate::store::LocalFs + crate::bucket::BucketBinding + Sync,
    B: crate::store::Clock + crate::bucket::BucketBinding + Sync,
    V: crate::store::ContentValidator + crate::bucket::BucketBinding + Sync,
    C: crate::store::Clock + Sync,
{
    /// Publishes a finite metadata-only checkpoint from genuinely checked side records.
    ///
    /// The request supplies unsigned commit metadata and credentials, not attribute
    /// values or completed evidence. Preparation chooses exact records from the
    /// configured native catalog. The ordinary commit path repeats current checks.
    /// An unchanged tree returns no new published record. Initializing an absent
    /// required index binding can publish a checkpoint with explicit coverage
    /// gaps; unqualified side values remain uncopied.
    ///
    /// # Errors
    /// Preserves invalid metadata templates, current source denial, Original and
    /// catalog failures, unsupported interpretation, stale sessions, and ordinary
    /// admission or durable publication failures. Evidence gaps never count as
    /// copied inputs or grant permission to publish another value.
    pub async fn backfill_index_inputs(
        &self,
        session: &mut crate::ref_advance::WriterSession,
        mut request: super::CommitRequest,
    ) -> Result<IndexBackfillReport, crate::repository::Error> {
        let prepared = self
            .coordinator()
            .guard()
            .prepare_index_backfill(session, &request)
            .await?;
        let (tree, uploads, mut report, references) = prepared.into_parts();

        if let Some(tree) = tree {
            request.commit.tree = tree.root();
            request.uploads.extend(uploads);
            let references = references.ok_or_else(super::invalid)?;
            let committed = self
                .commit_with_existing_owner_report(session, tree, request, references)
                .await?;
            report.record = Some(committed.record);
            report.index_work = committed.index_work;
        }

        Ok(report)
    }
}
