//! Authenticates complete class coverage before admission or release acceptance.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, Validate, canonical};

use super::{
    catalog::{normative_specification, requirement_catalog},
    schema::*,
};

/// Supplies exact applicability from independently installed profile policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Applicability {
    /// Requires authenticated successful coverage for every listed class.
    Applicable {
        /// Enumerates the exact classes to which the obligation applies.
        classes: BTreeSet<QualificationClass>,
    },
    /// Excludes a requirement under a precise source-owned scope restriction.
    NotApplicable {
        /// Contains the immutable policy's exact reason, never provider prose.
        reason: String,
    },
}

/// Applies trusted installation policy independently of provider claim authors.
///
/// Implementations belong to the host trust boundary. A successful return must
/// authenticate actual original artifacts and measured observations, not merely
/// validate report syntax, hashes, signatures, or provider-supplied pass flags.
/// They must preserve the complete case population and difficult-state scope.
pub trait InstalledQualificationAuthority {
    /// Authenticates the exact immutable claim and independently installed policy.
    ///
    /// # Errors
    /// Rejects untrusted issuers, changed source roots, unsupported report
    /// revisions, expiry, rewritten case populations or unverifiable provenance.
    fn authenticate_claim(
        &self,
        reference: &ContentRef,
        original_bytes: &[u8],
        claim: &QualificationClaim,
    ) -> Result<(), QualificationError>;

    /// Determines every obligation's applicability for the measured unit/classes.
    ///
    /// # Errors
    /// Rejects unknown policy, configuration, required class or specification.
    /// The returned map must cover the compiled catalog exactly. An exclusion
    /// must follow installed semantics rather than a claimant's missing evidence.
    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError>;

    /// Measures one object and enumerates its complete authenticated dependencies.
    ///
    /// # Errors
    /// Rejects unavailable, corrupt or unsupported objects and unknown dependency
    /// semantics. Streaming verification must enforce the byte ceiling before
    /// allocation and the dependency ceiling before collecting references.
    /// Syntax-only validation or accepting a digest without actual bytes fails.
    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError>;

    /// Authenticates the original observation and independent oracle for a case.
    ///
    /// # Errors
    /// Rejects changed units, classifications, case populations or native
    /// guarantees unsupported by the actual original harness observations.
    /// A protocol-only report cannot cover behavioral or native classes.
    fn authenticate_case(
        &self,
        unit: &QualificationUnit,
        requirement: &str,
        case: &CaseEvidence,
    ) -> Result<(), QualificationError>;
}

/// Retains authenticated behavioral scope without granting execution authority.
#[derive(Debug)]
pub struct AcceptedQualification {
    unit: QualificationUnit,
    classes: BTreeSet<QualificationClass>,
    claim: ContentRef,
}

impl AcceptedQualification {
    /// Returns the exact immutable accepted claim identity for retention.
    pub fn claim(&self) -> &ContentRef {
        &self.claim
    }

    /// Checks the accepted scope against independently measured current identity.
    ///
    /// # Errors
    /// Rejects a changed implementation, environment, contract or required class.
    /// Fresh evidence availability and authority checks are performed by
    /// [`accept_claim`] at each admission or release, not inferred from this
    /// retained scope check. Native readiness remains a separate obligation.
    pub fn require_scope(
        &self,
        current: &QualificationUnit,
        required: &BTreeSet<QualificationClass>,
    ) -> Result<(), QualificationError> {
        if current != &self.unit || !required.is_subset(&self.classes) {
            return Err(QualificationError::Refused(
                "outside accepted qualification scope",
            ));
        }
        Ok(())
    }
}

/// Selects one independently installed release profile and its original claim.
pub struct RequiredProfile<'a> {
    /// Supplies canonical immutable original report bytes, not a rewritten view.
    pub bytes: &'a [u8],
    /// Commits to those exact bytes and their media type.
    pub claim: &'a ContentRef,
    /// Contains the independently measured current complete qualification unit.
    pub unit: &'a QualificationUnit,
    /// Enumerates exactly the classes this release profile advertises.
    pub classes: &'a BTreeSet<QualificationClass>,
}

/// Accepts an original complete report under independent installed authority.
///
/// # Errors
/// Rejects malformed, over-budget, unavailable or untrusted content; changed
/// units; missing or duplicate obligations; forged exclusions; unresolved case
/// failures; unexecuted coverage; and model-only claimed native classes.
pub fn accept_claim(
    bytes: &[u8],
    reference: &ContentRef,
    current: &QualificationUnit,
    required: &BTreeSet<QualificationClass>,
    authority: &dyn InstalledQualificationAuthority,
    limits: QualificationLimits,
) -> Result<AcceptedQualification, QualificationError> {
    reference.validate()?;
    current.validate()?;
    if bytes.len() > limits.maximum_claim_bytes
        || reference.length.get() != bytes.len() as u64
        || canonical::content_ref(bytes, &reference.media_type)? != *reference
    {
        return Err(QualificationError::Refused(
            "original claim integrity or byte budget",
        ));
    }
    let value = canonical::parse_json(bytes, limits.maximum_claim_bytes)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(QualificationError::Refused("noncanonical original claim"));
    }
    let claim: QualificationClaim =
        serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
    validate_claim(&claim, current, required, limits)?;
    authority.authenticate_claim(reference, bytes, &claim)?;

    let applicability =
        authority.applicability(&claim.unit, &claim.classes, &claim.applicability_policy)?;
    authenticate_closure(&claim, reference, authority, limits)?;
    validate_coverage(&claim, &applicability, authority)?;
    Ok(AcceptedQualification {
        unit: claim.unit,
        classes: claim.classes,
        claim: reference.clone(),
    })
}

/// Verifies every advertised release profile through the admission ledger gate.
///
/// # Errors
/// Refuses an empty or over-budget inventory and any missing, failed, unavailable
/// or incompatible member. Returns no partial acceptance on failure.
pub fn verify_release_inventory(
    profiles: &[RequiredProfile<'_>],
    authority: &dyn InstalledQualificationAuthority,
    limits: QualificationLimits,
) -> Result<Vec<AcceptedQualification>, QualificationError> {
    if profiles.is_empty() || profiles.len() > 1024 {
        return Err(QualificationError::Refused(
            "invalid release qualification inventory",
        ));
    }
    let mut accepted = Vec::new();
    accepted
        .try_reserve_exact(profiles.len())
        .map_err(|_| QualificationError::Refused("release qualification allocation"))?;
    let mut total = 0usize;
    for profile in profiles {
        total = total
            .checked_add(profile.bytes.len())
            .ok_or(QualificationError::Refused(
                "release inventory byte overflow",
            ))?;
        if total > limits.maximum_claim_bytes {
            return Err(QualificationError::Refused("release inventory byte budget"));
        }
        accepted.push(accept_claim(
            profile.bytes,
            profile.claim,
            profile.unit,
            profile.classes,
            authority,
            limits,
        )?);
    }
    Ok(accepted)
}

fn validate_claim(
    claim: &QualificationClaim,
    current: &QualificationUnit,
    required: &BTreeSet<QualificationClass>,
    limits: QualificationLimits,
) -> Result<(), QualificationError> {
    use QualificationClass::*;
    claim.applicability_policy.validate()?;
    claim.limitations.validate()?;
    if let Some(reference) = &claim.supersedes {
        reference.validate()?;
    }
    let (catalog, ids) = requirement_catalog()?;
    let (specification, _) = normative_specification()?;
    if claim.format != "crucible.node-qualification"
        || claim.version != 1
        || claim.unit != *current
        || claim.unit.specification != specification
        || claim.catalog != catalog
        || claim.classes.is_empty()
        || required.is_empty()
        || !required.is_subset(&claim.classes)
        || !claim.classes.contains(&BaseProvider)
        || (claim.classes.contains(&BranchIsolated)
            && ![
                CaptureArchitectural,
                CaptureModeledLive,
                CaptureModeledDurable,
            ]
            .iter()
            .any(|class| claim.classes.contains(class)))
        || claim.requirements.len() != ids.len()
        || claim
            .requirements
            .iter()
            .zip(ids)
            .any(|(row, id)| row.requirement != id)
    {
        return Err(QualificationError::Refused(
            "claim unit, classes or complete catalog differs",
        ));
    }
    let mut cases = 0usize;
    for row in &claim.requirements {
        cases = cases
            .checked_add(row.cases.len())
            .ok_or(QualificationError::Refused("case population overflow"))?;
        if cases > limits.maximum_cases
            || row
                .not_applicable_reason
                .as_ref()
                .is_some_and(|reason| reason.is_empty() || reason.len() > 4096)
        {
            return Err(QualificationError::Refused("case or rationale budget"));
        }
        let mut ids = BTreeSet::new();
        for case in &row.cases {
            case.result.validate()?;
            case.oracle.validate()?;
            if case.case.is_empty()
                || case.case.len() > 256
                || !ids.insert(&case.case)
                || case.classes.is_empty()
                || !case.classes.is_subset(&claim.classes)
            {
                return Err(QualificationError::Refused(
                    "invalid original case identity or class",
                ));
            }
        }
    }
    Ok(())
}

fn validate_coverage(
    claim: &QualificationClaim,
    policy: &BTreeMap<String, Applicability>,
    authority: &dyn InstalledQualificationAuthority,
) -> Result<(), QualificationError> {
    if policy.len() != claim.requirements.len() {
        return Err(QualificationError::Refused(
            "incomplete installed applicability policy",
        ));
    }
    let mut native_classes = BTreeSet::new();
    let mut originals: BTreeMap<&str, &CaseEvidence> = BTreeMap::new();
    for row in &claim.requirements {
        match policy.get(&row.requirement) {
            Some(Applicability::NotApplicable { reason }) => {
                if reason.is_empty()
                    || reason.len() > 4096
                    || row.disposition != RequirementDisposition::NotApplicable
                    || row.not_applicable_reason.as_ref() != Some(reason)
                    || !row.cases.is_empty()
                {
                    return Err(QualificationError::Refused(
                        "untrusted requirement exclusion",
                    ));
                }
            }
            Some(Applicability::Applicable { classes }) => {
                if classes.is_empty()
                    || !classes.is_subset(&claim.classes)
                    || row.disposition != RequirementDisposition::Passed
                    || row.not_applicable_reason.is_some()
                    || row.cases.is_empty()
                {
                    return Err(QualificationError::Refused(
                        "unresolved applicable requirement",
                    ));
                }
                let mut covered = BTreeSet::new();
                for case in &row.cases {
                    if case.verdict != CaseVerdict::Passed
                        || !case.classes.is_subset(classes)
                        || originals
                            .insert(&case.case, case)
                            .is_some_and(|old| old != case)
                    {
                        return Err(QualificationError::Refused(
                            "failed or rewritten original case",
                        ));
                    }
                    authority.authenticate_case(&claim.unit, &row.requirement, case)?;
                    covered.extend(&case.classes);
                    if case.kind == CaseKind::RealizedProvider {
                        native_classes.extend(&case.classes);
                    }
                }
                if &covered != classes {
                    return Err(QualificationError::Refused(
                        "missing applicable class coverage",
                    ));
                }
            }
            None => {
                return Err(QualificationError::Refused(
                    "unknown requirement applicability",
                ));
            }
        }
    }
    if native_classes != claim.classes {
        return Err(QualificationError::Refused(
            "class lacks actual realized-provider evidence",
        ));
    }
    Ok(())
}

fn authenticate_closure(
    claim: &QualificationClaim,
    reference: &ContentRef,
    authority: &dyn InstalledQualificationAuthority,
    limits: QualificationLimits,
) -> Result<(), QualificationError> {
    let mut pending = Vec::new();
    for reference in claim
        .unit
        .references()
        .into_iter()
        .chain([
            reference,
            &claim.catalog,
            &claim.applicability_policy,
            &claim.limitations,
        ])
        .chain(claim.supersedes.iter())
    {
        enqueue(&mut pending, reference, limits)?;
    }
    for row in &claim.requirements {
        for case in &row.cases {
            enqueue(&mut pending, &case.result, limits)?;
            enqueue(&mut pending, &case.oracle, limits)?;
        }
    }
    let maximum_objects = limits.maximum_evidence_objects;
    if pending.len() > maximum_objects {
        return Err(QualificationError::Refused("evidence reference budget"));
    }
    let mut verified: BTreeMap<(String, String), ContentRef> = BTreeMap::new();
    let mut total = 0u64;
    while let Some(reference) = pending.pop() {
        reference.validate()?;
        let key = (reference.hash.domain.clone(), reference.hash.digest.clone());
        if let Some(original) = verified.get(&key) {
            if original != &reference {
                return Err(QualificationError::Refused(
                    "conflicting evidence hash metadata",
                ));
            }
            continue;
        }
        total = total
            .checked_add(reference.length.get())
            .ok_or(QualificationError::Refused("evidence byte overflow"))?;
        if verified.len() >= maximum_objects
            || reference.length.get() > limits.maximum_evidence_bytes
            || total > limits.maximum_total_evidence_bytes
        {
            return Err(QualificationError::Refused("evidence closure budget"));
        }
        let remaining = maximum_objects.saturating_sub(verified.len() + pending.len() + 1);
        let dependencies =
            authority.verify_evidence(&reference, limits.maximum_evidence_bytes, remaining)?;
        if dependencies.len() > remaining {
            return Err(QualificationError::Refused("evidence dependency budget"));
        }
        for dependency in dependencies {
            enqueue(&mut pending, &dependency, limits)?;
        }
        verified.insert(key, reference);
    }
    Ok(())
}

fn enqueue(
    pending: &mut Vec<ContentRef>,
    reference: &ContentRef,
    limits: QualificationLimits,
) -> Result<(), QualificationError> {
    reference.validate()?;
    if pending.len() >= limits.maximum_evidence_objects
        || reference.length.get() > limits.maximum_evidence_bytes
    {
        return Err(QualificationError::Refused("evidence reference budget"));
    }
    pending
        .try_reserve(1)
        .map_err(|_| QualificationError::Refused("evidence reference allocation"))?;
    pending.push(reference.clone());
    Ok(())
}
