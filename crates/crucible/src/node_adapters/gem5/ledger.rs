//! Bounded original gem5 operations and immutable native receipt custody.

use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use crucible_node_contract::{ContentRef, Id, canonical};
use crucible_node_provider::gem5::Gem5Completion;

use crate::{
    node_contract::{OperationAdmission, OperationFailure, OperationOutcome, OperationToken},
    node_scheduling::InputPayload,
};

use super::refusal;

// A native frame bounds every original string and number token. JCS can expand
// a short exponent into a decimal spelling; 32 bytes per original byte safely
// covers every finite binary64 spelling, quotes and escaped string bytes. The
// selected closed guest contributes at most one separately retained 64KiB write.
pub(super) const PREFIX_STORAGE_CREDIT: usize =
    32 * crucible_node_provider::gem5::GEM5_NATIVE_FRAME_BYTES + 65_536;

/// Preserves the original native command lineage across fresh local rebinding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrefixScope {
    pub activation: crate::node_contract::SavedRuntimeActivation,
    pub route: crate::node_contract::NodeRoute,
}

/// Retains original scope and every already executed prefix before publication.
pub(super) struct OriginalOperation {
    pub original: OperationAdmission,
    pub prefixes: Vec<Gem5Completion>,
    pub prefix_scopes: Vec<PrefixScope>,
    pub outcome: Option<OperationOutcome>,
    pub evidence: Vec<InputPayload>,
    pub acknowledged: bool,
    pub failure: Option<OperationFailure>,
}

#[cfg(test)]
mod tests {
    use crucible_node_contract::{HashRef, Phase, Position};

    use crate::node_contract::{
        ActivationRecord, NodeRoute, OperationRequest, OwnerIdentity, WorldActivation,
    };

    use super::*;

    // Model-only scope handles exercise ledger isolation. They neither prove
    // installed native qualification nor construct a runnable gem5 adapter.
    fn original() -> OperationAdmission {
        let authority = Rc::new(());
        let owner = OwnerIdentity {
            owner: Id::new("owner").unwrap(),
            incarnation: Id::new("native/first").unwrap(),
            generation: 1.into(),
        };
        OperationAdmission {
            token: OperationToken {
                authority: Rc::clone(&authority),
                operation: Id::new("original").unwrap(),
                route: NodeRoute {
                    node: Id::new("node").unwrap(),
                    owners: vec![owner.clone()],
                },
            },
            request: OperationRequest::Observe,
            activation: WorldActivation {
                authority,
                record: ActivationRecord {
                    generation: 1.into(),
                    activation_id: Id::new("world").unwrap(),
                    world_binding_hash: HashRef {
                        algorithm: "blake3-256".to_owned(),
                        domain: "model-only".to_owned(),
                        digest: "1".repeat(64),
                    },
                    owners: vec![owner],
                    boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
                },
            },
            inputs: None,
        }
    }

    #[test]
    fn identical_ids_do_not_replace_original_live_token_authority() {
        let admitted = original();
        let mut ledger = OperationLedger::new(1, 2, 1024).unwrap();
        ledger.reserve(&admitted).unwrap();
        assert!(ledger.original(admitted.token()).is_ok());

        let mut foreign = admitted.token().clone();
        foreign.authority = Rc::new(());
        assert!(ledger.original(&foreign).is_err());
        assert!(ledger.original(admitted.token()).is_ok());
    }

    #[test]
    fn original_incarnation_is_not_replaced_by_matching_owner_name() {
        let admitted = original();
        let mut ledger = OperationLedger::new(1, 2, 1024).unwrap();
        ledger.reserve(&admitted).unwrap();

        let mut foreign = admitted.token().clone();
        foreign.route.owners[0].incarnation = Id::new("native/replaced").unwrap();
        assert!(ledger.original(&foreign).is_err());
    }

    #[test]
    fn repeated_submission_never_resets_retained_original_state() {
        let admitted = original();
        let mut ledger = OperationLedger::new(1, 2, 1024).unwrap();
        ledger.reserve(&admitted).unwrap();
        ledger.original_mut(admitted.token()).unwrap().acknowledged = true;

        assert!(ledger.reserve(&admitted).is_err());
        assert!(ledger.original(admitted.token()).unwrap().acknowledged);
    }

    #[test]
    fn frame_credit_is_reserved_before_requesting_native_progress() {
        let ledger = OperationLedger::new(1, 2, 1024).unwrap();
        assert!(ledger.can_run_prefix(1024).is_ok());
        assert!(ledger.can_run_prefix(1025).is_err());
        assert!(ledger.can_run_prefix(usize::MAX).is_err());
    }

    #[test]
    fn invalid_class_limits_are_refused_before_ledger_allocation() {
        assert!(OperationLedger::new(0, 1, 1024).is_err());
        assert!(OperationLedger::new(1, 0, 1024).is_err());
        assert!(OperationLedger::new(1, 1, 0).is_err());
        assert!(OperationLedger::new(65_537, 1, 1024).is_err());
        assert!(OperationLedger::new(1, 65_537, 1024).is_err());
        assert!(OperationLedger::new(1, 1, 256 * 1024 * 1024 + 1).is_err());
    }
}

/// Keeps finite native receipt and operation credit until authentic reclamation.
pub(super) struct OperationLedger {
    operations: BTreeMap<Id, OriginalOperation>,
    maximum_operations: usize,
    maximum_prefixes: usize,
    maximum_bytes: usize,
    retained_bytes: usize,
    retained_prefixes: usize,
}

impl OperationLedger {
    pub fn operations(&self) -> impl ExactSizeIterator<Item = (&Id, &OriginalOperation)> {
        self.operations.iter()
    }

    pub fn new(
        maximum_operations: usize,
        maximum_prefixes: usize,
        maximum_bytes: usize,
    ) -> Result<Self, OperationFailure> {
        if maximum_operations == 0
            || maximum_operations > 65_536
            || maximum_prefixes == 0
            || maximum_prefixes > 65_536
            || maximum_bytes == 0
            || maximum_bytes > 256 * 1024 * 1024
        {
            return Err(refusal("gem5 original operation credit is invalid"));
        }

        Ok(Self {
            operations: BTreeMap::new(),
            maximum_operations,
            maximum_prefixes,
            maximum_bytes,
            retained_bytes: 0,
            retained_prefixes: 0,
        })
    }

    pub fn reserve(&mut self, original: &OperationAdmission) -> Result<(), OperationFailure> {
        if self.operations.contains_key(original.token().operation())
            || self.operations.len() >= self.maximum_operations
        {
            return Err(refusal(
                "gem5 original operation is repeated or exceeds credit",
            ));
        }

        self.operations.insert(
            original.token().operation().clone(),
            OriginalOperation {
                original: original.clone(),
                prefixes: Vec::new(),
                prefix_scopes: Vec::new(),
                outcome: None,
                evidence: Vec::new(),
                acknowledged: false,
                failure: None,
            },
        );
        Ok(())
    }

    pub fn original(&self, token: &OperationToken) -> Result<&OriginalOperation, OperationFailure> {
        let original = self
            .operations
            .get(token.operation())
            .ok_or_else(|| refusal("gem5 original operation custody is absent"))?;
        if !Rc::ptr_eq(&token.authority, &original.original.token().authority)
            || token.route() != original.original.token().route()
        {
            return Err(refusal(
                "gem5 operation token belongs to another native scope",
            ));
        }
        Ok(original)
    }

    pub fn original_mut(
        &mut self,
        token: &OperationToken,
    ) -> Result<&mut OriginalOperation, OperationFailure> {
        self.original(token)?;
        self.operations
            .get_mut(token.operation())
            .ok_or_else(|| refusal("gem5 original operation custody disappeared"))
    }

    /// Reserves worst-case private frame credit before another native callback.
    pub fn can_run_prefix(&self, maximum_frame_bytes: usize) -> Result<(), OperationFailure> {
        if self.retained_prefixes >= self.maximum_prefixes
            || self
                .retained_bytes
                .checked_add(maximum_frame_bytes)
                .is_none_or(|size| size > self.maximum_bytes)
        {
            return Err(refusal("gem5 native continuation receipt credit exhausted"));
        }
        Ok(())
    }

    /// Reserves complete selected-profile receipt credit and slots before effects.
    pub fn prepare_prefix(&mut self, token: &OperationToken) -> Result<(), OperationFailure> {
        self.can_run_prefix(PREFIX_STORAGE_CREDIT)?;
        let original = self.original_mut(token)?;
        original
            .prefixes
            .try_reserve(1)
            .map_err(|_| refusal("gem5 native prefix slot allocation refused"))?;
        original
            .prefix_scopes
            .try_reserve(1)
            .map_err(|_| refusal("gem5 native prefix lineage slot allocation refused"))?;
        original
            .evidence
            .try_reserve(2)
            .map_err(|_| refusal("gem5 native prefix evidence slot allocation refused"))?;
        Ok(())
    }

    /// Copies an authenticated native receipt before any administrative ACK.
    pub fn retain_prefix(
        &mut self,
        token: &OperationToken,
        receipt: Gem5Completion,
    ) -> Result<ContentRef, OperationFailure> {
        self.original(token)?;
        self.can_run_prefix(0)?;
        let value = serde_json::to_value(&receipt).map_err(|error| refusal(&error.to_string()))?;
        let bytes =
            canonical::canonical_json(&value).map_err(|error| refusal(&error.to_string()))?;
        let total = self
            .retained_bytes
            .checked_add(bytes.len())
            .filter(|size| *size <= self.maximum_bytes)
            .ok_or_else(|| refusal("gem5 native receipt exceeds retained credit"))?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;

        let original = self.original_mut(token)?;
        original.prefix_scopes.push(PrefixScope {
            activation: crate::node_contract::SavedRuntimeActivation::from(
                original.original.activation.record(),
            ),
            route: original.original.token().route().clone(),
        });
        original.prefixes.push(receipt);
        original.evidence.push(InputPayload {
            reference: reference.clone(),
            bytes,
        });
        self.retained_bytes = total;
        self.retained_prefixes += 1;
        Ok(reference)
    }

    pub fn evidence(
        &self,
        token: &OperationToken,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        let original = self.original(token)?;
        if references.len() > original.evidence.len() {
            return Err(refusal(
                "gem5 evidence request exceeds original object custody",
            ));
        }
        let mut unique = BTreeSet::new();
        let mut total = 0u64;
        for reference in references {
            if !unique.insert(reference) {
                return Err(refusal("gem5 evidence request repeats an original object"));
            }
            total = total
                .checked_add(reference.length.get())
                .filter(|size| *size <= self.maximum_bytes as u64)
                .ok_or_else(|| refusal("gem5 evidence response exceeds retained byte credit"))?;
        }
        references
            .iter()
            .map(|reference| {
                original
                    .evidence
                    .iter()
                    .find(|object| &object.reference == reference)
                    .cloned()
                    .ok_or_else(|| refusal("gem5 evidence is foreign to the original operation"))
            })
            .collect()
    }

    pub fn retain_objects(
        &mut self,
        token: &OperationToken,
        objects: Vec<InputPayload>,
    ) -> Result<(), OperationFailure> {
        self.original(token)?;
        if objects.len() > 65_536 {
            return Err(refusal(
                "gem5 original evidence object count exceeds credit",
            ));
        }
        let additional = objects.iter().try_fold(0usize, |total, object| {
            object
                .reference
                .verify(&object.bytes)
                .map_err(|error| refusal(&error.to_string()))?;
            total
                .checked_add(object.bytes.len())
                .ok_or_else(|| refusal("gem5 evidence byte credit overflow"))
        })?;
        let total = self
            .retained_bytes
            .checked_add(additional)
            .filter(|total| *total <= self.maximum_bytes)
            .ok_or_else(|| refusal("gem5 original evidence byte credit exhausted"))?;
        let original = self.original_mut(token)?;
        if original
            .evidence
            .len()
            .checked_add(objects.len())
            .is_none_or(|count| count > 65_536)
        {
            return Err(refusal("gem5 original evidence object credit exhausted"));
        }
        for object in objects {
            if let Some(old) = original
                .evidence
                .iter()
                .find(|old| old.reference == object.reference)
            {
                if old.bytes != object.bytes {
                    return Err(refusal("gem5 immutable evidence object changed"));
                }
            } else {
                original.evidence.push(object);
            }
        }
        self.retained_bytes = total;
        Ok(())
    }
}
