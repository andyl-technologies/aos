//! Retains privately collected original CPU and storage cases in one report.

use std::{collections::BTreeSet, rc::Rc};

use super::{native_oracle::OriginalGem5Case, storage_oracle::OriginalBlockCase};
use crate::node_qualification::{CaseVerdict, QualificationError, requirement_catalog};
use crucible_node_format::{ContentRef, HashRef};

pub(super) enum OriginalCase {
    Cpu(Rc<OriginalGem5Case>),
    Storage(Rc<OriginalBlockCase>),
}

impl OriginalCase {
    pub(super) fn id(&self) -> &str {
        match self {
            Self::Cpu(case) => case.id(),
            Self::Storage(case) => case.id(),
        }
    }

    pub(super) fn verdict(&self) -> CaseVerdict {
        match self {
            Self::Cpu(case) => case.verdict(),
            Self::Storage(case) => case.verdict(),
        }
    }

    pub(super) fn result(&self) -> (&ContentRef, &[u8]) {
        match self {
            Self::Cpu(case) => case.result(),
            Self::Storage(case) => case.result(),
        }
    }

    pub(super) fn oracle(&self) -> (&ContentRef, &[u8]) {
        match self {
            Self::Cpu(case) => case.oracle(),
            Self::Storage(case) => case.oracle(),
        }
    }

    pub(super) fn objects(&self) -> &[(ContentRef, Vec<u8>)] {
        match self {
            Self::Cpu(case) => case.objects(),
            Self::Storage(case) => case.objects(),
        }
    }

    pub(super) fn world_binding_hash(&self) -> &HashRef {
        match self {
            Self::Cpu(case) => case.world_binding_hash(),
            Self::Storage(case) => case.world_binding_hash(),
        }
    }

    pub(super) fn covers(&self, requirement: &str) -> bool {
        match self {
            Self::Cpu(case) => case.covers(requirement),
            Self::Storage(case) => case.covers(requirement),
        }
    }

    pub(super) fn observed_lcg_output(&self) -> bool {
        matches!(self, Self::Cpu(case) if case.observed_lcg_output())
    }
}

/// Privately retains immutable report evidence while runtime tokens stay in the run.
///
/// This type cannot reconstruct a runtime, grant, native owner or case. Its only
/// constructor borrows a genuinely collected original after whole-report credit.
pub(super) struct ReportCase {
    id: String,
    verdict: CaseVerdict,
    result: ContentRef,
    oracle: ContentRef,
    world: HashRef,
    covered: BTreeSet<String>,
    result_index: usize,
    oracle_index: usize,
    objects: Vec<(ContentRef, Vec<u8>)>,
}

impl ReportCase {
    pub(super) fn from_original(original: &OriginalCase) -> Result<Self, QualificationError> {
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(original.objects().len())
            .map_err(evidence)?;
        for (reference, body) in original.objects() {
            reference.verify(body)?;
            let mut retained = Vec::new();
            retained.try_reserve_exact(body.len()).map_err(evidence)?;
            retained.extend_from_slice(body);
            objects.push((reference.clone(), retained));
        }
        let result_index = objects
            .iter()
            .position(|(reference, _)| reference == original.result().0)
            .ok_or(QualificationError::Refused("original result body absent"))?;
        let oracle_index = objects
            .iter()
            .position(|(reference, _)| reference == original.oracle().0)
            .ok_or(QualificationError::Refused("original oracle body absent"))?;
        let covered = requirement_catalog()?
            .1
            .into_iter()
            .filter(|id| original.covers(id))
            .map(str::to_owned)
            .collect();
        Ok(Self {
            id: original.id().into(),
            verdict: original.verdict(),
            result: original.result().0.clone(),
            oracle: original.oracle().0.clone(),
            world: original.world_binding_hash().clone(),
            covered,
            result_index,
            oracle_index,
            objects,
        })
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) fn verdict(&self) -> CaseVerdict {
        self.verdict
    }

    pub(super) fn result(&self) -> (&ContentRef, &[u8]) {
        // The private constructor verifies this index before issuing the immutable record.
        (&self.result, &self.objects[self.result_index].1)
    }

    pub(super) fn oracle(&self) -> (&ContentRef, &[u8]) {
        (&self.oracle, &self.objects[self.oracle_index].1)
    }

    pub(super) fn objects(&self) -> &[(ContentRef, Vec<u8>)] {
        &self.objects
    }

    pub(super) fn world_binding_hash(&self) -> &HashRef {
        &self.world
    }

    pub(super) fn covers(&self, requirement: &str) -> bool {
        self.covered.contains(requirement)
    }
}

fn evidence(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
