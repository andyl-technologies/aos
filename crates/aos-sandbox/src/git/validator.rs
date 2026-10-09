//! Opaque validator-issued Git graph and ancestry evidence admission.
//!
//! The verifier constructs a [`GitTrustedValidatorV1`] only after validating
//! protected reports. Canonical decoders can then rehydrate only the exact
//! graph, ancestry, and report commitments present in its bounded acceptance
//! sets.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    GitAncestryReportV1, GitDescriptorV1, GitGraphCompletenessV1, GitGraphProofDigestV1,
    GitModelError, GitObjectDatabaseDigestV1, GitObjectFormatV1, GitObjectGraphEvidenceV1,
    GitObjectIdV1, GitRefNameV1, GitTrustedValidatorV1, GitValidationPolicyDigestV1,
    GitValidatorTrustDigestV1,
};

impl GitTrustedValidatorV1 {
    /// Returns the attestation selected by the trusted validator boundary.
    #[must_use]
    pub const fn attestation(&self) -> GitValidatorTrustDigestV1 {
        self.attestation
    }

    /// Brands an attestation only after crate-internal validator verification.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::CorruptEncoding`] for sentinel or oversized
    /// acceptance sets.
    pub(crate) fn from_verified_digest(
        value: ObjectDigest,
        accepted_graphs: Vec<ObjectDigest>,
        accepted_ancestry: Vec<ObjectDigest>,
        accepted_validation_reports: Vec<ObjectDigest>,
    ) -> Result<Self, GitModelError> {
        const MAXIMUM_ACCEPTED_EVIDENCE: usize = 262_144;
        if accepted_graphs.len() > MAXIMUM_ACCEPTED_EVIDENCE
            || accepted_ancestry.len() > MAXIMUM_ACCEPTED_EVIDENCE
            || accepted_validation_reports.len() > MAXIMUM_ACCEPTED_EVIDENCE
            || accepted_graphs
                .iter()
                .chain(&accepted_ancestry)
                .chain(&accepted_validation_reports)
                .any(|digest| digest.as_bytes() == &[0; 32])
            || !accepted_graphs.windows(2).all(|pair| pair[0] < pair[1])
            || !accepted_ancestry.windows(2).all(|pair| pair[0] < pair[1])
            || !accepted_validation_reports
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(GitModelError::CorruptEncoding);
        }
        Ok(Self {
            attestation: GitValidatorTrustDigestV1::from_stored(value)?,
            accepted_graphs,
            accepted_ancestry,
            accepted_validation_reports,
        })
    }

    /// Accepts complete object-graph evidence produced by this validator.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidObjectGraph`] unless every exact graph
    /// input is in the verifier-issued acceptance set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accept_object_graph(
        &self,
        format: GitObjectFormatV1,
        completeness: GitGraphCompletenessV1,
        object_count: u64,
        total_object_bytes: u64,
        roots: Vec<GitObjectIdV1>,
        object_database: GitObjectDatabaseDigestV1,
        graph_proof: GitGraphProofDigestV1,
    ) -> Result<GitObjectGraphEvidenceV1, GitModelError> {
        let commitment = graph_evidence_commitment(
            format,
            completeness,
            object_count,
            total_object_bytes,
            &roots,
            object_database,
            graph_proof,
        );
        if self.accepted_graphs.binary_search(&commitment).is_err() {
            return Err(GitModelError::InvalidObjectGraph);
        }
        GitObjectGraphEvidenceV1::new(
            format,
            completeness,
            object_count,
            total_object_bytes,
            roots,
            object_database,
            graph_proof,
        )
    }

    /// Accepts an opaque ancestry report produced by this exact validator.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] unless every exact ancestry
    /// input and the opaque report are in the verifier-issued acceptance set.
    pub(crate) fn accept_ancestry_report(
        &self,
        reference: GitRefNameV1,
        old: GitObjectIdV1,
        new: GitObjectIdV1,
        object_database: GitObjectDatabaseDigestV1,
        report: ObjectDigest,
    ) -> Result<GitAncestryReportV1, GitModelError> {
        let commitment = ancestry_evidence_commitment(
            self.attestation,
            &reference,
            old,
            new,
            object_database,
            report,
        );
        if self.accepted_ancestry.binary_search(&commitment).is_err() {
            return Err(GitModelError::InvalidModel);
        }
        GitAncestryReportV1::from_validator(self, reference, old, new, object_database, report)
    }

    pub(super) fn accepts_validation_report(
        &self,
        report: &GitDescriptorV1,
        graph_proof: GitGraphProofDigestV1,
        policy: GitValidationPolicyDigestV1,
    ) -> bool {
        self.accepted_validation_reports
            .binary_search(&validation_report_commitment(
                self.attestation,
                report,
                graph_proof,
                policy,
            ))
            .is_ok()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn graph_evidence_commitment(
    format: GitObjectFormatV1,
    completeness: GitGraphCompletenessV1,
    object_count: u64,
    total_object_bytes: u64,
    roots: &[GitObjectIdV1],
    object_database: GitObjectDatabaseDigestV1,
    graph_proof: GitGraphProofDigestV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.validator-accepted-graph.v1\0")
        .chain_update([format as u8, completeness as u8])
        .chain_update(object_count.to_be_bytes())
        .chain_update(total_object_bytes.to_be_bytes())
        .chain_update(object_database.digest().as_bytes())
        .chain_update(graph_proof.digest().as_bytes())
        .chain_update((roots.len() as u64).to_be_bytes());
    for root in roots {
        hasher = hasher.chain_update(root.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(crate) fn ancestry_evidence_commitment(
    trust: GitValidatorTrustDigestV1,
    reference: &GitRefNameV1,
    old: GitObjectIdV1,
    new: GitObjectIdV1,
    object_database: GitObjectDatabaseDigestV1,
    report: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.validator-accepted-ancestry.v1\0")
            .chain_update(trust.digest().as_bytes())
            .chain_update((reference.as_bytes().len() as u64).to_be_bytes())
            .chain_update(reference.as_bytes())
            .chain_update(old.as_bytes())
            .chain_update(new.as_bytes())
            .chain_update(object_database.digest().as_bytes())
            .chain_update(report.as_bytes())
            .finalize()
            .into(),
    )
}

pub(crate) fn validation_report_commitment(
    trust: GitValidatorTrustDigestV1,
    report: &GitDescriptorV1,
    graph_proof: GitGraphProofDigestV1,
    policy: GitValidationPolicyDigestV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.validator-accepted-report.v1\0")
            .chain_update(trust.digest().as_bytes())
            .chain_update([report.role() as u8])
            .chain_update(report.descriptor().digest().as_bytes())
            .chain_update(report.descriptor().encoded_size().to_be_bytes())
            .chain_update(graph_proof.digest().as_bytes())
            .chain_update(policy.digest().as_bytes())
            .finalize()
            .into(),
    )
}
