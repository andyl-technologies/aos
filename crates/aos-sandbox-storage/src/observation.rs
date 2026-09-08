//! Closed OpenZFS observation plans and machine-output validation.
//!
//! Observation is separate from mutation execution. A plan is derived only
//! from a validated [`ZfsTransaction`](crate::ZfsTransaction), compiles exact
//! read-only `zfs` argument vectors, and accepts output only from commands that
//! completed successfully within the process boundary. In particular, absence
//! is proved by a successful parent inventory that omits the exact object; a
//! failed direct lookup is never interpreted as absence.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::{
    CatalogObjectKind, HoldId, PostconditionPolicyV1, ProjectAncestorPolicyV1, ReservationPolicy,
    WorkspaceSpacePolicyV1, ZfsPrecondition, ZfsTransaction,
};

const OBSERVATION_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.zfs-observation.v1\0";

/// Selects one closed observation phase around a durable mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ZfsObservationPhase {
    /// Revalidates every physical precondition before ambiguity is recorded.
    Preconditions,
    /// Determines whether the exact typed postcondition is now present.
    Postcondition,
}

impl ZfsObservationPhase {
    pub(crate) const fn wire_code(self) -> u8 {
        match self {
            Self::Preconditions => 1,
            Self::Postcondition => 2,
        }
    }
}

/// Classifies an authoritative observation without authorizing another effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ZfsObservationState {
    /// Every requested physical fact matched the closed plan.
    Matched,
    /// The mutation's expected state is not complete yet.
    Incomplete,
    /// A name, GUID, kind, or other identity conflicts with the closed plan.
    Mismatch,
}

/// Reports one completely evaluated observation plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ZfsObservationResult {
    pub(crate) state: ZfsObservationState,
    pub(crate) object_guid: Option<u64>,
    pub(crate) digest: Option<ObjectDigest>,
}

/// Reports a malformed plan derivation or machine-readable ZFS response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ZfsObservationError {
    /// A validated catalog unexpectedly could not produce a closed query.
    #[error("validated ZFS semantics could not produce a closed observation plan")]
    InvalidPlan,
    /// Successful command output violated its exact bounded machine schema.
    #[error("successful ZFS observation output was malformed or incomplete")]
    InvalidOutput,
}

/// Holds the exact read-only commands for one transaction observation.
pub(crate) struct ZfsObservationPlan {
    phase: ZfsObservationPhase,
    commands: Vec<ZfsObservationCommand>,
}

impl ZfsObservationPlan {
    /// Compiles physical precondition checks from a validated transaction.
    pub(crate) fn preconditions(transaction: &ZfsTransaction) -> Result<Self, ZfsObservationError> {
        let mut commands = Vec::new();
        for precondition in transaction.preconditions() {
            append_precondition(&mut commands, precondition)?;
        }
        if let Some(ancestor) = transaction.ancestor_transaction() {
            append_precondition(&mut commands, ancestor.precondition())?;
        }
        if commands.is_empty() {
            return Err(ZfsObservationError::InvalidPlan);
        }

        Ok(Self {
            phase: ZfsObservationPhase::Preconditions,
            commands,
        })
    }

    /// Compiles physical postcondition checks from a validated transaction.
    pub(crate) fn postcondition(transaction: &ZfsTransaction) -> Result<Self, ZfsObservationError> {
        let mut commands = Vec::new();
        append_postcondition(&mut commands, transaction.postcondition())?;
        if let Some(ancestor) = transaction.ancestor_transaction() {
            append_ancestor_postcondition(&mut commands, ancestor.postcondition())?;
        }
        if commands.is_empty() {
            return Err(ZfsObservationError::InvalidPlan);
        }

        Ok(Self {
            phase: ZfsObservationPhase::Postcondition,
            commands,
        })
    }

    pub(crate) fn commands(&self) -> &[ZfsObservationCommand] {
        &self.commands
    }

    /// Begins an evaluator that owns command order and captured identity.
    pub(crate) fn evaluation(&self) -> ZfsObservationEvaluation<'_> {
        ZfsObservationEvaluation {
            plan: self,
            outputs: Vec::with_capacity(self.commands.len()),
            object_guid: None,
            finished: false,
        }
    }

    fn matched(
        &self,
        outputs: &[Vec<u8>],
        object_guid: Option<u64>,
    ) -> Result<ZfsObservationResult, ZfsObservationError> {
        if outputs.len() != self.commands.len() {
            return Err(ZfsObservationError::InvalidOutput);
        }

        let mut hash = Sha256::new();
        hash.update(OBSERVATION_DIGEST_DOMAIN);
        hash.update([self.phase.wire_code()]);
        for (command, output) in self.commands.iter().zip(outputs) {
            hash.update(
                u32::try_from(command.arguments.len())
                    .map_err(|_| ZfsObservationError::InvalidPlan)?
                    .to_be_bytes(),
            );
            for argument in &command.arguments {
                let bytes = argument.as_encoded_bytes();
                hash.update(
                    u32::try_from(bytes.len())
                        .map_err(|_| ZfsObservationError::InvalidPlan)?
                        .to_be_bytes(),
                );
                hash.update(bytes);
            }
            hash.update(
                u32::try_from(output.len())
                    .map_err(|_| ZfsObservationError::InvalidOutput)?
                    .to_be_bytes(),
            );
            hash.update(output);
        }
        let digest = ObjectDigest::from_bytes(hash.finalize().into());
        if digest.as_bytes() == &[0; 32] {
            return Err(ZfsObservationError::InvalidOutput);
        }

        Ok(ZfsObservationResult {
            state: ZfsObservationState::Matched,
            object_guid,
            digest: Some(digest),
        })
    }

    const fn terminal(state: ZfsObservationState) -> ZfsObservationResult {
        ZfsObservationResult {
            state,
            object_guid: None,
            digest: None,
        }
    }
}

/// Evaluates each successful command exactly once in plan order.
pub(crate) struct ZfsObservationEvaluation<'a> {
    plan: &'a ZfsObservationPlan,
    outputs: Vec<Vec<u8>>,
    object_guid: Option<u64>,
    finished: bool,
}

impl ZfsObservationEvaluation<'_> {
    /// Accepts the output of the next successfully completed command.
    pub(crate) fn accept(
        &mut self,
        output: Vec<u8>,
    ) -> Result<Option<ZfsObservationResult>, ZfsObservationError> {
        if self.finished {
            return Err(ZfsObservationError::InvalidOutput);
        }
        let command = self
            .plan
            .commands
            .get(self.outputs.len())
            .ok_or(ZfsObservationError::InvalidOutput)?;
        match command.evaluate(&output)? {
            ObservationStep::Continue {
                object_guid: captured,
            } => {
                if let Some(captured) = captured
                    && self.object_guid.replace(captured).is_some()
                {
                    return Err(ZfsObservationError::InvalidPlan);
                }
                self.outputs.push(output);
                if self.outputs.len() == self.plan.commands.len() {
                    self.finished = true;
                    return self.plan.matched(&self.outputs, self.object_guid).map(Some);
                }
                Ok(None)
            }
            ObservationStep::Terminal(state) => {
                self.finished = true;
                Ok(Some(ZfsObservationPlan::terminal(state)))
            }
        }
    }
}

/// Carries one fixed read-only argv and its expected output shape.
pub(crate) struct ZfsObservationCommand {
    arguments: Vec<OsString>,
    check: ObservationCheck,
}

impl ZfsObservationCommand {
    pub(crate) fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub(crate) fn evaluate(&self, output: &[u8]) -> Result<ObservationStep, ZfsObservationError> {
        match &self.check {
            ObservationCheck::Object {
                parent,
                name,
                kind,
                expectation,
            } => {
                let inventory = parse_inventory(output)?;
                if !inventory.contains_key(parent) {
                    return Err(ZfsObservationError::InvalidOutput);
                }
                evaluate_object(inventory.get(name), *kind, *expectation)
            }
            ObservationCheck::Properties { name, expected } => {
                let properties = parse_properties(output, name, expected)?;
                let matches = expected
                    .iter()
                    .all(|(property, value)| properties.get(property) == Some(value));
                Ok(if matches {
                    ObservationStep::Continue { object_guid: None }
                } else {
                    ObservationStep::Terminal(ZfsObservationState::Incomplete)
                })
            }
            ObservationCheck::Hold {
                snapshot,
                hold_id,
                present,
                mismatch_is_incomplete,
            } => {
                let holds = parse_holds(output, snapshot)?;
                let observed = holds.contains(&hold_tag(*hold_id));
                Ok(if observed == *present {
                    ObservationStep::Continue { object_guid: None }
                } else if *mismatch_is_incomplete {
                    ObservationStep::Terminal(ZfsObservationState::Incomplete)
                } else {
                    ObservationStep::Terminal(ZfsObservationState::Mismatch)
                })
            }
        }
    }
}

/// Directs the worker to continue or return a fail-closed semantic result.
pub(crate) enum ObservationStep {
    Continue { object_guid: Option<u64> },
    Terminal(ZfsObservationState),
}

enum ObservationCheck {
    Object {
        parent: String,
        name: String,
        kind: CatalogObjectKind,
        expectation: ObjectExpectation,
    },
    Properties {
        name: String,
        expected: Vec<(String, String)>,
    },
    Hold {
        snapshot: String,
        hold_id: HoldId,
        present: bool,
        mismatch_is_incomplete: bool,
    },
}

#[derive(Clone, Copy)]
enum ObjectExpectation {
    PreconditionPresent(u64),
    PreconditionAbsent,
    PostconditionCapture,
    PostconditionPresent(u64),
    PostconditionAbsent(u64),
}

#[derive(Clone, Copy)]
struct InventoryObject {
    kind: ObservedObjectKind,
    guid: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedObjectKind {
    Filesystem,
    Snapshot,
    Volume,
}

fn append_precondition(
    commands: &mut Vec<ZfsObservationCommand>,
    precondition: &ZfsPrecondition,
) -> Result<(), ZfsObservationError> {
    match precondition {
        // The protected broker lock authenticates this binding. ZFS cannot.
        ZfsPrecondition::Catalog(_) => {}
        ZfsPrecondition::Guid { name, guid } => commands.push(object_command(
            name,
            object_kind(name),
            ObjectExpectation::PreconditionPresent(*guid),
        )?),
        ZfsPrecondition::ActiveHold {
            snapshot,
            guid,
            hold_id,
        } => {
            // Keep the GUID check intrinsic to the hold plan even though the
            // transaction compiler currently emits a preceding Guid guard.
            commands.push(object_command(
                snapshot,
                CatalogObjectKind::Snapshot,
                ObjectExpectation::PreconditionPresent(*guid),
            )?);
            commands.push(hold_command(snapshot, *hold_id, true, false));
        }
        ZfsPrecondition::Absent { name } => commands.push(object_command(
            name,
            object_kind(name),
            ObjectExpectation::PreconditionAbsent,
        )?),
    }
    Ok(())
}

fn append_postcondition(
    commands: &mut Vec<ZfsObservationCommand>,
    postcondition: &PostconditionPolicyV1,
) -> Result<(), ZfsObservationError> {
    match postcondition {
        PostconditionPolicyV1::CaptureDataset {
            name,
            space,
            origin_name,
            origin_guid,
            origin_hold,
        } => {
            commands.push(object_command(
                name,
                CatalogObjectKind::Dataset,
                ObjectExpectation::PostconditionCapture,
            )?);
            commands.push(property_command(
                name,
                created_dataset_properties(*space, origin_name),
            ));
            match (origin_name, origin_guid, origin_hold) {
                (Some(origin), guid @ 1.., Some(hold_id)) => {
                    commands.push(object_command(
                        origin,
                        CatalogObjectKind::Snapshot,
                        ObjectExpectation::PostconditionPresent(*guid),
                    )?);
                    commands.push(hold_command(origin, *hold_id, true, true));
                }
                (None, 0, None) => {}
                _ => return Err(ZfsObservationError::InvalidPlan),
            }
        }
        PostconditionPolicyV1::CaptureSnapshot { name, source_guid } => {
            commands.push(object_command(
                name,
                CatalogObjectKind::Snapshot,
                ObjectExpectation::PostconditionCapture,
            )?);
            commands.push(object_command(
                object_parent(name)?,
                CatalogObjectKind::Dataset,
                ObjectExpectation::PostconditionPresent(*source_guid),
            )?);
        }
        PostconditionPolicyV1::HoldState {
            name,
            guid,
            hold_id,
            present,
        } => {
            commands.push(object_command(
                name,
                CatalogObjectKind::Snapshot,
                ObjectExpectation::PostconditionPresent(*guid),
            )?);
            commands.push(hold_command(name, *hold_id, *present, true));
        }
        PostconditionPolicyV1::DatasetProperties { name, guid, space } => {
            commands.push(object_command(
                name,
                CatalogObjectKind::Dataset,
                ObjectExpectation::PostconditionPresent(*guid),
            )?);
            commands.push(property_command(name, dataset_space_properties(*space)));
        }
        PostconditionPolicyV1::Absent { name, kind, guid } => commands.push(object_command(
            name,
            *kind,
            ObjectExpectation::PostconditionAbsent(*guid),
        )?),
    }
    Ok(())
}

fn append_ancestor_postcondition(
    commands: &mut Vec<ZfsObservationCommand>,
    ancestor: &ProjectAncestorPolicyV1,
) -> Result<(), ZfsObservationError> {
    commands.push(object_command(
        ancestor.dataset().name(),
        CatalogObjectKind::Dataset,
        ObjectExpectation::PostconditionPresent(ancestor.dataset().guid()),
    )?);
    commands.push(property_command(
        ancestor.dataset().name(),
        vec![
            ("quota".to_owned(), ancestor.quota_bytes().to_string()),
            (
                "filesystem_limit".to_owned(),
                ancestor.filesystem_limit().to_string(),
            ),
            (
                "snapshot_limit".to_owned(),
                ancestor.snapshot_limit().to_string(),
            ),
        ],
    ));
    Ok(())
}

fn object_command(
    name: &str,
    kind: CatalogObjectKind,
    expectation: ObjectExpectation,
) -> Result<ZfsObservationCommand, ZfsObservationError> {
    let parent = object_parent(name)?.to_owned();
    Ok(ZfsObservationCommand {
        arguments: vec![
            "list".into(),
            "-H".into(),
            "-p".into(),
            "-d".into(),
            "1".into(),
            "-t".into(),
            "filesystem,volume,snapshot".into(),
            "-o".into(),
            "name,type,guid".into(),
            parent.clone().into(),
        ],
        check: ObservationCheck::Object {
            parent,
            name: name.to_owned(),
            kind,
            expectation,
        },
    })
}

fn property_command(name: &str, expected: Vec<(String, String)>) -> ZfsObservationCommand {
    let property_names = expected
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    ZfsObservationCommand {
        arguments: vec![
            "get".into(),
            "-H".into(),
            "-p".into(),
            "-o".into(),
            "name,property,value".into(),
            property_names.into(),
            name.into(),
        ],
        check: ObservationCheck::Properties {
            name: name.to_owned(),
            expected,
        },
    }
}

fn hold_command(
    snapshot: &str,
    hold_id: HoldId,
    present: bool,
    mismatch_is_incomplete: bool,
) -> ZfsObservationCommand {
    ZfsObservationCommand {
        arguments: vec!["holds".into(), "-H".into(), "-p".into(), snapshot.into()],
        check: ObservationCheck::Hold {
            snapshot: snapshot.to_owned(),
            hold_id,
            present,
            mismatch_is_incomplete,
        },
    }
}

fn created_dataset_properties(
    space: WorkspaceSpacePolicyV1,
    origin: &Option<String>,
) -> Vec<(String, String)> {
    let mut properties = dataset_space_properties(space);
    properties.push((
        "origin".to_owned(),
        origin.clone().unwrap_or_else(|| "-".to_owned()),
    ));
    properties
}

fn dataset_space_properties(space: WorkspaceSpacePolicyV1) -> Vec<(String, String)> {
    let reservation = match space.reservation() {
        ReservationPolicy::None => 0,
        ReservationPolicy::Exact(bytes) => bytes,
    };
    vec![
        ("type".to_owned(), "filesystem".to_owned()),
        ("mountpoint".to_owned(), "none".to_owned()),
        ("canmount".to_owned(), "off".to_owned()),
        ("refquota".to_owned(), space.refquota_bytes().to_string()),
        ("reservation".to_owned(), reservation.to_string()),
    ]
}

fn evaluate_object(
    observed: Option<&InventoryObject>,
    expected_kind: CatalogObjectKind,
    expectation: ObjectExpectation,
) -> Result<ObservationStep, ZfsObservationError> {
    let result = match (expectation, observed) {
        (ObjectExpectation::PreconditionAbsent, None) => {
            ObservationStep::Continue { object_guid: None }
        }
        (ObjectExpectation::PreconditionAbsent, Some(_)) => {
            ObservationStep::Terminal(ZfsObservationState::Mismatch)
        }
        (ObjectExpectation::PreconditionPresent(expected), Some(actual))
            if actual.kind == observed_kind(expected_kind) && actual.guid == expected =>
        {
            ObservationStep::Continue { object_guid: None }
        }
        (ObjectExpectation::PreconditionPresent(_), _) => {
            ObservationStep::Terminal(ZfsObservationState::Mismatch)
        }
        (ObjectExpectation::PostconditionCapture, None) => {
            ObservationStep::Terminal(ZfsObservationState::Incomplete)
        }
        (ObjectExpectation::PostconditionCapture, Some(actual))
            if actual.kind == observed_kind(expected_kind) =>
        {
            ObservationStep::Continue {
                object_guid: Some(actual.guid),
            }
        }
        (ObjectExpectation::PostconditionCapture, Some(_)) => {
            ObservationStep::Terminal(ZfsObservationState::Mismatch)
        }
        (ObjectExpectation::PostconditionPresent(_), None) => {
            ObservationStep::Terminal(ZfsObservationState::Incomplete)
        }
        (ObjectExpectation::PostconditionPresent(expected), Some(actual))
            if actual.kind == observed_kind(expected_kind) && actual.guid == expected =>
        {
            ObservationStep::Continue { object_guid: None }
        }
        (ObjectExpectation::PostconditionPresent(_), Some(_)) => {
            ObservationStep::Terminal(ZfsObservationState::Mismatch)
        }
        (ObjectExpectation::PostconditionAbsent(_), None) => {
            ObservationStep::Continue { object_guid: None }
        }
        (ObjectExpectation::PostconditionAbsent(expected), Some(actual))
            if actual.kind == observed_kind(expected_kind) && actual.guid == expected =>
        {
            ObservationStep::Terminal(ZfsObservationState::Incomplete)
        }
        (ObjectExpectation::PostconditionAbsent(_), Some(_)) => {
            ObservationStep::Terminal(ZfsObservationState::Mismatch)
        }
    };
    Ok(result)
}

fn parse_inventory(
    output: &[u8],
) -> Result<BTreeMap<String, InventoryObject>, ZfsObservationError> {
    let lines = complete_lines(output, false)?;
    let mut objects = BTreeMap::new();
    for line in lines {
        let fields = exact_fields(line, 3)?;
        let name = text_field(fields[0])?.to_owned();
        let kind = match fields[1] {
            b"filesystem" => ObservedObjectKind::Filesystem,
            b"snapshot" => ObservedObjectKind::Snapshot,
            b"volume" => ObservedObjectKind::Volume,
            _ => return Err(ZfsObservationError::InvalidOutput),
        };
        let guid = decimal_u64(fields[2])?;
        if guid == 0
            || objects
                .insert(name, InventoryObject { kind, guid })
                .is_some()
        {
            return Err(ZfsObservationError::InvalidOutput);
        }
    }
    Ok(objects)
}

fn parse_properties(
    output: &[u8],
    expected_name: &str,
    expected: &[(String, String)],
) -> Result<BTreeMap<String, String>, ZfsObservationError> {
    let allowed = expected
        .iter()
        .map(|(property, _)| property.as_str())
        .collect::<BTreeSet<_>>();
    let mut properties = BTreeMap::new();
    for line in complete_lines(output, false)? {
        let fields = exact_fields(line, 3)?;
        if text_field(fields[0])? != expected_name {
            return Err(ZfsObservationError::InvalidOutput);
        }
        let property = text_field(fields[1])?;
        let value = text_field(fields[2])?;
        if !allowed.contains(property)
            || properties
                .insert(property.to_owned(), value.to_owned())
                .is_some()
        {
            return Err(ZfsObservationError::InvalidOutput);
        }
    }
    if properties.len() != expected.len() {
        return Err(ZfsObservationError::InvalidOutput);
    }
    Ok(properties)
}

fn parse_holds(
    output: &[u8],
    expected_snapshot: &str,
) -> Result<BTreeSet<String>, ZfsObservationError> {
    let mut holds = BTreeSet::new();
    for line in complete_lines(output, true)? {
        let fields = exact_fields(line, 3)?;
        if text_field(fields[0])? != expected_snapshot || decimal_u64(fields[2]).is_err() {
            return Err(ZfsObservationError::InvalidOutput);
        }
        let tag = text_field(fields[1])?.to_owned();
        if !holds.insert(tag) {
            return Err(ZfsObservationError::InvalidOutput);
        }
    }
    Ok(holds)
}

fn complete_lines(output: &[u8], empty_allowed: bool) -> Result<Vec<&[u8]>, ZfsObservationError> {
    if output.is_empty() {
        return if empty_allowed {
            Ok(Vec::new())
        } else {
            Err(ZfsObservationError::InvalidOutput)
        };
    }
    if !output.ends_with(b"\n") || output.contains(&0) || output.contains(&b'\r') {
        return Err(ZfsObservationError::InvalidOutput);
    }
    let lines = output[..output.len() - 1]
        .split(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    if lines.iter().any(|line| line.is_empty()) {
        return Err(ZfsObservationError::InvalidOutput);
    }
    Ok(lines)
}

fn exact_fields(line: &[u8], count: usize) -> Result<Vec<&[u8]>, ZfsObservationError> {
    let fields = line.split(|byte| *byte == b'\t').collect::<Vec<_>>();
    if fields.len() != count || fields.iter().any(|field| field.is_empty()) {
        return Err(ZfsObservationError::InvalidOutput);
    }
    Ok(fields)
}

fn text_field(field: &[u8]) -> Result<&str, ZfsObservationError> {
    std::str::from_utf8(field).map_err(|_| ZfsObservationError::InvalidOutput)
}

fn decimal_u64(field: &[u8]) -> Result<u64, ZfsObservationError> {
    if field.is_empty()
        || field.iter().any(|byte| !byte.is_ascii_digit())
        || (field.len() > 1 && field[0] == b'0')
    {
        return Err(ZfsObservationError::InvalidOutput);
    }
    text_field(field)?
        .parse()
        .map_err(|_| ZfsObservationError::InvalidOutput)
}

const fn observed_kind(kind: CatalogObjectKind) -> ObservedObjectKind {
    match kind {
        CatalogObjectKind::Dataset => ObservedObjectKind::Filesystem,
        CatalogObjectKind::Snapshot => ObservedObjectKind::Snapshot,
    }
}

fn object_parent(name: &str) -> Result<&str, ZfsObservationError> {
    if let Some((dataset, _)) = name.rsplit_once('@') {
        return (!dataset.is_empty())
            .then_some(dataset)
            .ok_or(ZfsObservationError::InvalidPlan);
    }
    name.rsplit_once('/')
        .map(|(parent, _)| parent)
        .filter(|parent| !parent.is_empty())
        .ok_or(ZfsObservationError::InvalidPlan)
}

fn object_kind(name: &str) -> CatalogObjectKind {
    if name.contains('@') {
        CatalogObjectKind::Snapshot
    } else {
        CatalogObjectKind::Dataset
    }
}

fn hold_tag(hold_id: HoldId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tag = String::with_capacity(36);
    tag.push_str("aos:");
    for byte in hold_id.as_bytes() {
        tag.push(char::from(HEX[usize::from(byte >> 4)]));
        tag.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    tag
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::ObjectDigest;

    use super::*;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ResolvedCatalogCommitmentV1, ResolvedDataset, StorageDomainsV1, StorageOperation,
    };

    fn transaction() -> ZfsTransaction {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains)
                .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let destination =
            PlannedDataset::from_catalog(root, "tank/aos/project/work", domains).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
        let catalog = ResolvedCatalogCommitmentV1::new(
            7,
            domains,
            CatalogPlanV1::CreateWorkspace {
                destination,
                space,
                ancestor,
            },
        )
        .unwrap();
        ZfsTransaction::from_catalog(
            StorageOperation::CreateWorkspace { quota_bytes: 4096 },
            &catalog,
        )
        .unwrap()
    }

    #[test]
    fn plans_compile_only_closed_machine_queries() {
        let transaction = transaction();
        let preconditions = ZfsObservationPlan::preconditions(&transaction).unwrap();
        let postcondition = ZfsObservationPlan::postcondition(&transaction).unwrap();

        assert_eq!(preconditions.commands.len(), 2);
        assert_eq!(postcondition.commands.len(), 4);
        for command in preconditions.commands.iter().chain(&postcondition.commands) {
            let arguments = command
                .arguments()
                .iter()
                .map(|argument| argument.to_str().unwrap())
                .collect::<Vec<_>>();
            assert!(matches!(arguments[0], "list" | "get" | "holds"));
            assert!(
                arguments
                    .iter()
                    .any(|argument| argument.starts_with("tank/"))
            );
            assert!(!arguments.iter().any(|argument| argument.contains(' ')));
        }
    }

    #[test]
    fn successful_parent_inventory_proves_absence_without_failed_lookup() {
        let command = object_command(
            "tank/aos/project/future",
            CatalogObjectKind::Dataset,
            ObjectExpectation::PreconditionAbsent,
        )
        .unwrap();
        let output = b"tank/aos/project\tfilesystem\t15\n";

        assert!(matches!(
            command.evaluate(output).unwrap(),
            ObservationStep::Continue { object_guid: None }
        ));
        assert_eq!(command.arguments.last().unwrap(), "tank/aos/project");
        assert_eq!(command.arguments[6], "filesystem,volume,snapshot");
        assert!(matches!(
            command
                .evaluate(
                    b"tank/aos/project\tfilesystem\t15\ntank/aos/project/future\tvolume\t44\n"
                )
                .unwrap(),
            ObservationStep::Terminal(ZfsObservationState::Mismatch)
        ));
    }

    #[test]
    fn incomplete_and_conflicting_postconditions_are_distinct() {
        let command = object_command(
            "tank/aos/project/work",
            CatalogObjectKind::Dataset,
            ObjectExpectation::PostconditionAbsent(44),
        )
        .unwrap();

        assert!(matches!(
            command
                .evaluate(
                    b"tank/aos/project\tfilesystem\t15\ntank/aos/project/work\tfilesystem\t44\n"
                )
                .unwrap(),
            ObservationStep::Terminal(ZfsObservationState::Incomplete)
        ));
        assert!(matches!(
            command
                .evaluate(
                    b"tank/aos/project\tfilesystem\t15\ntank/aos/project/work\tfilesystem\t45\n"
                )
                .unwrap(),
            ObservationStep::Terminal(ZfsObservationState::Mismatch)
        ));
        assert!(matches!(
            command
                .evaluate(b"tank/aos/project\tfilesystem\t15\ntank/aos/project/work\tvolume\t44\n")
                .unwrap(),
            ObservationStep::Terminal(ZfsObservationState::Mismatch)
        ));
    }

    #[test]
    fn parsers_reject_partial_duplicate_and_extra_machine_fields() {
        assert!(parse_inventory(b"tank/aos\tfilesystem\t10").is_err());
        assert!(parse_inventory(b"tank/aos\tfilesystem\t10\ntank/aos\tfilesystem\t10\n").is_err());
        let expected = vec![("quota".to_owned(), "10".to_owned())];
        assert!(parse_properties(b"tank/aos\tquota\t10\textra\n", "tank/aos", &expected).is_err());
        assert!(parse_properties(b"tank/aos\tquota\t10", "tank/aos", &expected).is_err());
        assert!(parse_holds(b"tank/aos@s\taos:x\tnot-a-time\n", "tank/aos@s").is_err());
        for value in [b"+1".as_slice(), b"01", b" 1", b"1 "] {
            assert!(decimal_u64(value).is_err());
        }
        assert_eq!(decimal_u64(b"0").unwrap(), 0);
        assert_eq!(decimal_u64(b"18446744073709551615").unwrap(), u64::MAX);
    }

    #[test]
    fn set_quota_plan_does_not_assert_an_unchanged_clone_origin() {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let clone = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/clone",
            44,
            [2; 32],
            domains,
        )
        .unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root, "tank/aos/project", 15, [1; 32], domains).unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::None).unwrap();
        let catalog = ResolvedCatalogCommitmentV1::new(
            8,
            domains,
            CatalogPlanV1::SetQuota {
                dataset: clone,
                space,
                ancestor,
            },
        )
        .unwrap();
        let transaction = ZfsTransaction::from_catalog(
            StorageOperation::SetQuota {
                storage_handle: [2; 32],
                quota_bytes: 4096,
            },
            &catalog,
        )
        .unwrap();
        let plan = ZfsObservationPlan::postcondition(&transaction).unwrap();
        let property_command = &plan.commands()[1];
        let properties = property_command.arguments()[5].to_str().unwrap();

        assert_eq!(properties, "type,mountpoint,canmount,refquota,reservation");
        assert!(!properties.contains("origin"));
        assert!(matches!(
            property_command
                .evaluate(
                    b"tank/aos/project/clone\ttype\tfilesystem\n\
                      tank/aos/project/clone\tmountpoint\tnone\n\
                      tank/aos/project/clone\tcanmount\toff\n\
                      tank/aos/project/clone\trefquota\t4096\n\
                      tank/aos/project/clone\treservation\t0\n"
                )
                .unwrap(),
            ObservationStep::Continue { object_guid: None }
        ));
    }

    #[test]
    fn holds_accept_empty_authoritative_output_and_reject_other_snapshots() {
        assert!(parse_holds(b"", "tank/aos@s").unwrap().is_empty());
        assert!(parse_holds(b"tank/aos@other\taos:x\t1\n", "tank/aos@s").is_err());
    }

    #[test]
    fn evaluator_cannot_finalize_a_prefix_or_accept_after_terminal_state() {
        let plan = ZfsObservationPlan::postcondition(&transaction()).unwrap();
        let mut evaluation = plan.evaluation();

        let incomplete = evaluation
            .accept(b"tank/aos/project\tfilesystem\t15\n".to_vec())
            .unwrap();
        assert!(matches!(
            incomplete,
            Some(ZfsObservationResult {
                state: ZfsObservationState::Incomplete,
                object_guid: None,
                digest: None,
            })
        ));
        assert!(
            evaluation
                .accept(b"tank/aos/project\tfilesystem\t15\n".to_vec())
                .is_err()
        );

        let single = ZfsObservationPlan {
            phase: ZfsObservationPhase::Preconditions,
            commands: vec![
                object_command(
                    "tank/aos/project/future",
                    CatalogObjectKind::Dataset,
                    ObjectExpectation::PreconditionAbsent,
                )
                .unwrap(),
            ],
        };
        let mut evaluation = single.evaluation();
        assert!(matches!(
            evaluation
                .accept(b"tank/aos/project\tfilesystem\t15\n".to_vec())
                .unwrap(),
            Some(ZfsObservationResult {
                state: ZfsObservationState::Matched,
                ..
            })
        ));
        assert!(
            evaluation
                .accept(b"tank/aos/project\tfilesystem\t15\n".to_vec())
                .is_err()
        );
    }

    #[test]
    fn evaluator_rejects_multiple_captured_object_guids() {
        let plan = ZfsObservationPlan {
            phase: ZfsObservationPhase::Postcondition,
            commands: vec![
                object_command(
                    "tank/aos/project/one",
                    CatalogObjectKind::Dataset,
                    ObjectExpectation::PostconditionCapture,
                )
                .unwrap(),
                object_command(
                    "tank/aos/project/two",
                    CatalogObjectKind::Dataset,
                    ObjectExpectation::PostconditionCapture,
                )
                .unwrap(),
            ],
        };
        let mut evaluation = plan.evaluation();
        assert!(
            evaluation
                .accept(
                    b"tank/aos/project\tfilesystem\t15\ntank/aos/project/one\tfilesystem\t44\n"
                        .to_vec()
                )
                .unwrap()
                .is_none()
        );
        assert!(
            evaluation
                .accept(
                    b"tank/aos/project\tfilesystem\t15\ntank/aos/project/two\tfilesystem\t45\n"
                        .to_vec()
                )
                .is_err()
        );
    }
}
