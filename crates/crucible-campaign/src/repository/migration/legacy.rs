//! Historical campaign bodies admitted only by the offline migration owner.

use crucible_cas::content_envelope::ContentChild;
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::*;

#[derive(Clone, Copy)]
pub(super) struct LegacyCampaignSnapshot {
    pub(super) parent: Option<CampaignMigrationHead>,
    pub(super) lineage: CampaignLineageId,
    pub(super) active_policy: CampaignPolicyId,
    pub(super) roots: CampaignRoots,
    pub(super) transition: Option<CampaignFactId>,
}

#[derive(Clone, Copy)]
pub(super) struct LegacyAttemptAdmissionFact {
    pub(super) admission: ContentId,
}

impl Canonical for LegacyAttemptAdmissionFact {
    fn encode(&self, encoder: &mut Encoder) {
        2_u32.encode(encoder);
        encoder.u8(4);
        encoder.string("crucible.campaign.attempt-admission");
        Canonical::encode(&self.admission, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != 2 || decoder.u8()? != 4 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "not a base-schema attempt-admission fact",
            });
        }
        if decoder.string_bounded(
            "crucible.campaign.attempt-admission".len(),
            "legacy-attempt-admission-id-tag-bytes",
        )? != "crucible.campaign.attempt-admission"
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "legacy attempt-admission fact has the wrong typed identity",
            });
        }
        let admission = ContentId::decode(decoder)?;
        if admission.kind() != ObjectKind::CampaignFact
            || !matches!(admission.schema_version(), 1 | 2)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "legacy attempt-admission fact references an unsupported schema",
            });
        }
        Ok(Self { admission })
    }
}

impl LegacyAttemptAdmissionFact {
    pub(super) fn validate_envelope(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let children = crate::object::content_children([("attempt-admission", self.admission)])?;
        if children != *envelope.children() {
            return Err(integrity(
                "legacy-attempt-admission-fact-child-table-mismatch",
            ));
        }
        Ok(())
    }
}

impl LegacyCampaignSnapshot {
    fn children(&self) -> Result<BTreeSet<ContentChild>, CampaignCodecError> {
        let mut children = vec![
            ("lineage", self.lineage.content_id()),
            ("active-policy", self.active_policy.content_id()),
            ("root.graph", self.roots.graph),
            ("root.exploration", self.roots.exploration),
            ("root.observations", self.roots.observations),
            ("root.corpus", self.roots.corpus),
            ("root.coverage", self.roots.coverage),
            ("root.findings", self.roots.findings),
            ("root.pins", self.roots.pins),
            ("root.accounting", self.roots.accounting),
            ("root.coordination", self.roots.coordination),
        ];
        if let Some(parent) = self.parent {
            children.push(("parent", parent.content_id()));
        }
        if let Some(transition) = self.transition {
            children.push(("transition", transition.content_id()));
        }
        crate::object::content_children(children)
    }

    pub(super) fn validate_envelope(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        if self.children()? != *envelope.children() {
            return Err(integrity("legacy-snapshot-child-table-mismatch"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn envelope(&self) -> Result<ObjectEnvelope, CampaignCodecError> {
        ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::Snapshot,
            2,
            self.children()?,
            crate::codec::encode(self),
        )
    }
}

impl Canonical for LegacyCampaignSnapshot {
    fn encode(&self, encoder: &mut Encoder) {
        2_u32.encode(encoder);
        self.parent.encode(encoder);
        self.lineage.encode(encoder);
        self.active_policy.encode(encoder);
        self.roots.encode(encoder);
        self.transition.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != 2 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported legacy snapshot schema version",
            });
        }
        let value = Self {
            parent: Option::decode(decoder)?,
            lineage: CampaignLineageId::decode(decoder)?,
            active_policy: CampaignPolicyId::decode(decoder)?,
            roots: CampaignRoots::decode(decoder)?,
            transition: Option::decode(decoder)?,
        };
        if value.parent.is_some() != value.transition.is_some() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "legacy snapshot parent and transition presence disagree",
            });
        }
        Ok(value)
    }
}

#[derive(Clone, Copy)]
pub(super) struct LegacyAttemptAdmission {
    schema_version: u32,
    pub(super) attempt: AttemptId,
    pub(super) role: AttemptAdmissionRole,
}

impl LegacyAttemptAdmission {
    pub(super) fn validate_envelope(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let mut children = vec![("attempt".to_owned(), self.attempt.content_id())];
        add_role_children(&mut children, self.role);
        if crate::object::content_children(children)? != *envelope.children() {
            return Err(integrity("legacy-attempt-admission-child-table-mismatch"));
        }
        Ok(())
    }
}

fn add_role_children(children: &mut Vec<(String, ContentId)>, role: AttemptAdmissionRole) {
    match role {
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposal),
            cause,
            ..
        } => {
            children.push(("proposal".to_owned(), proposal.content_id()));
            add_cause_child(children, cause);
        }
        AttemptAdmissionRole::ExecutionBasis {
            proposal: None,
            cause,
            ..
        } => add_cause_child(children, cause),
        AttemptAdmissionRole::AdditionalCause { proposal } => {
            children.push(("proposal".to_owned(), proposal.content_id()));
        }
    }
}

impl Canonical for LegacyAttemptAdmission {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.attempt.encode(encoder);
        self.role.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        let attempt = AttemptId::decode(decoder)?;
        let role = AttemptAdmissionRole::decode(decoder)?;
        let scenario_default = matches!(
            role,
            AttemptAdmissionRole::ExecutionBasis {
                cause: BranchRequestCause::ScenarioDefault(_),
                ..
            }
        );
        if (schema_version == 1 && scenario_default) || (schema_version == 2 && !scenario_default) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "legacy attempt-admission schema and role disagree",
            });
        }
        if !matches!(schema_version, 1 | 2) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported legacy attempt-admission schema version",
            });
        }
        Ok(Self {
            schema_version,
            attempt,
            role,
        })
    }
}

fn add_cause_child(children: &mut Vec<(String, ContentId)>, cause: BranchRequestCause) {
    let child = match cause {
        BranchRequestCause::Planner(id) => Some(("planner-invocation", id.content_id())),
        BranchRequestCause::ExhaustivePolicy(id) | BranchRequestCause::ScenarioDefault(id) => {
            Some(("policy", id.content_id()))
        }
        BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => None,
    };
    if let Some((role, id)) = child {
        children.push((role.to_owned(), id));
    }
}

#[cfg(test)]
mod tests {
    use crucible_cas::content_store::ObjectKind;

    use super::*;
    use crate::CampaignCommandId;

    fn attempt() -> AttemptId {
        AttemptId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"legacy migration attempt",
        ))
        .expect("attempt ID")
    }

    fn policy() -> CampaignPolicyId {
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"legacy migration policy",
        ))
        .expect("policy ID")
    }

    #[test]
    fn decoder_admits_only_the_two_historical_role_shapes() {
        let v1 = LegacyAttemptAdmission {
            schema_version: 1,
            attempt: attempt(),
            role: AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause: BranchRequestCause::Operator(CampaignCommandId::from_hash(
                    CampaignHash::derive("test.legacy-migration-command", b"v1"),
                )),
                admission_ordinal: AdmissionOrdinal::new(1),
            },
        };
        let v2 = LegacyAttemptAdmission {
            schema_version: 2,
            attempt: attempt(),
            role: AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause: BranchRequestCause::ScenarioDefault(policy()),
                admission_ordinal: AdmissionOrdinal::new(1),
            },
        };

        for value in [v1, v2] {
            let decoded: LegacyAttemptAdmission =
                crate::codec::decode(&crate::codec::encode(&value)).expect("legacy admission");
            assert_eq!(decoded.schema_version, value.schema_version);
            assert_eq!(decoded.attempt, value.attempt);
            assert_eq!(decoded.role, value.role);
        }

        let mismatched = LegacyAttemptAdmission {
            schema_version: 1,
            ..v2
        };
        assert!(
            crate::codec::decode::<LegacyAttemptAdmission>(&crate::codec::encode(&mismatched))
                .is_err()
        );
    }

    #[test]
    fn admission_fact_decoder_admits_only_historical_admission_identities() {
        for schema_version in [1, 2] {
            let admission = ContentId::for_bytes(
                ObjectKind::CampaignFact,
                schema_version,
                b"historical admission",
            );
            let fact = LegacyAttemptAdmissionFact { admission };

            let decoded: LegacyAttemptAdmissionFact =
                crate::codec::decode(&crate::codec::encode(&fact)).expect("legacy fact");
            assert_eq!(decoded.admission, admission);
        }

        let current = LegacyAttemptAdmissionFact {
            admission: ContentId::for_bytes(ObjectKind::CampaignFact, 3, b"current admission"),
        };
        assert!(
            crate::codec::decode::<LegacyAttemptAdmissionFact>(&crate::codec::encode(&current))
                .is_err()
        );
    }
}
