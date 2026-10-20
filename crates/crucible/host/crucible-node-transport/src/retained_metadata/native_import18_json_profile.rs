//! Scopes actual retained SDK18 JSON partials to their funded expansion profile.
//!
//! The ordinary observer remains depth64 and work131072. Actual SDK18
//! constructors retain their own raw/generated/expanded population profile
//! before each partial. Cumulative facts include every ordinary and child visit.
//! These DATA profiles establish no admission, completion or currentness.

use super::*;
use crate::protocol_snapshot::raw_value_reparse::JsonValueReparseConstructionData;

/// Retains actual constructor populations without granting work or admission.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18JsonMetadataProfileData {
    maximum_depth: usize,
    // Each scope owns this closed response forest plus its actual syntax
    // population. Keeping the terms separate also retains a raw frame before
    // any fallible addition of its work bound.
    dynamic_work: usize,
    raw_work: usize,
}

// These are direct observer calls of the retained response forest, excluding
// syntax descendants counted independently below: Envelope13 with seven
// Nullable/Option pairs, ResponseShape/ErrorRecord5, PrepareRestoreResult7,
// PrepareReceipt11, and the actual optional outer output slots. Three Envelope
// prefixes cover response plus ReceivedFrame and a conservative cache copy.
const ENVELOPE_PREFIX: usize = 2 + 13 + 2 * 7;
const RESPONSE_PREFIX: usize = 2 + 3 + 5 + 7;
const RECEIPT_PREFIX: usize = 2 + 11;
// Blob originals contain Begin3/Chunk4/Finish2 fields plus ContentRef3 and
// HashRef3 descendants. Each JSON field needs at most three metadata visits
// (key, Value, scalar/container wrapper). Sum all alternatives independently.
const BLOB_ORIGINAL_PREFIX: usize = ENVELOPE_PREFIX + 3 * (3 + 4 + 2 + 3 + 3);
const FIXED_RESPONSE_WORK: usize =
    3 * ENVELOPE_PREFIX + 2 * RESPONSE_PREFIX + RECEIPT_PREFIX + BLOB_ORIGINAL_PREFIX + 5;

impl NativeImport18JsonMetadataProfileData {
    /// Covers the uninitialized response slots before any raw frame exists.
    pub(crate) const fn strict_raw_data() -> Self {
        Self {
            maximum_depth: 65,
            dynamic_work: 0,
            raw_work: 0,
        }
    }

    /// Retains actual strict transport syntax population before later guards.
    ///
    /// Every Value visit, String/Vec wrapper and map key consumes at least one
    /// byte of its own strict JSON syntax. Thus actual encoded bytes bound the
    /// raw tree's metadata visits and records; this is a lexical population,
    /// not the negotiated frame ceiling or a byte-to-heap estimate.
    pub(crate) fn retain_strict_raw_population_data(&mut self, encoded_bytes: usize) {
        self.raw_work = self.raw_work.max(encoded_bytes);
    }

    /// Derives depth and work from the actual expanded constructor populations.
    ///
    /// A Value needs at most two visits per value plus one per object key.
    /// Nullable/Option wrappers in the closed typed response forest add at most
    /// one further visit per syntax node. Every container record is bounded by
    /// these visits; direct outer/boxed records belong to the fixed roster.
    /// Each actual separately owned response tree is charged independently.
    ///
    /// # Errors
    /// Refuses overflow in the actual expanded depth or population arithmetic.
    pub(crate) fn from_reparse_population_data(
        extra: &JsonValueReparseConstructionData,
        raw_values: usize,
        raw_members: usize,
    ) -> Result<Self, ProviderError> {
        let maximum_depth = extra
            .maximum_parser_layers_data()
            .checked_mul(128)
            .and_then(|layers| layers.checked_add(65))
            .ok_or_else(overflow)?;
        let expanded = extra.expanded_json_extents_data();
        let values = raw_values.checked_add(expanded.0).ok_or_else(overflow)?;
        let members = raw_members.checked_add(expanded.1).ok_or_else(overflow)?;
        let tree = values
            .checked_mul(3)
            .and_then(|visits| visits.checked_add(members))
            .ok_or_else(overflow)?;

        // These are the eight actual possible response ownership populations.
        let raw = tree;
        let response_envelope = tree;
        let received_envelope = tree;
        let received_shape = tree;
        let received_typed_result = tree;
        let capsule_shape = tree;
        let capsule_typed_result = tree;
        let receipt = tree;
        let dynamic_work = [
            raw,
            response_envelope,
            received_envelope,
            received_shape,
            received_typed_result,
            capsule_shape,
            capsule_typed_result,
            receipt,
        ]
        .into_iter()
        .try_fold(0usize, |total, work| {
            total.checked_add(work).ok_or_else(overflow)
        })?;
        let profile = Self {
            maximum_depth,
            dynamic_work,
            raw_work: 0,
        };
        profile.maximum_work_data()?;
        Ok(profile)
    }

    /// Covers two real populations without renewing protocol or native credit.
    pub(crate) const fn covering_data(self, other: Self) -> Self {
        Self {
            maximum_depth: if self.maximum_depth > other.maximum_depth {
                self.maximum_depth
            } else {
                other.maximum_depth
            },
            dynamic_work: if self.dynamic_work > other.dynamic_work {
                self.dynamic_work
            } else {
                other.dynamic_work
            },
            raw_work: if self.raw_work > other.raw_work {
                self.raw_work
            } else {
                other.raw_work
            },
        }
    }

    /// Adds independently retained constructor populations to this same owner.
    ///
    /// # Errors
    /// Refuses a checked population sum that cannot be represented.
    pub(crate) fn including_data(self, other: Self) -> Result<Self, ProviderError> {
        let mut profile = self.covering_data(other);
        profile.dynamic_work = self
            .dynamic_work
            .checked_add(other.dynamic_work)
            .and_then(|work| work.checked_add(other.raw_work))
            .ok_or_else(overflow)?;
        profile.raw_work = self.raw_work;
        profile.maximum_work_data()?;
        Ok(profile)
    }

    /// Quotes the actual assignment's typed inputs and generated JSON forests.
    ///
    /// # Errors
    /// Refuses overflow in independently counted real constructor populations.
    pub(crate) fn assignment_data(
        input_nodes: usize,
        serialized_nodes: usize,
        serialized_records: usize,
    ) -> Result<Self, ProviderError> {
        // Eight named potential forests: typed request/baseline, body, payload,
        // binding, proof, proof Value, and the final assigned Envelope. Each
        // independently borrowed typed/JSON wrapper has at most three visits
        // per actual serialized value/key. Input facts cover the retained typed
        // graph even when a missing/default field serializes differently.
        let tree = serialized_nodes
            .checked_mul(3)
            .and_then(|work| work.checked_add(serialized_records))
            .ok_or_else(overflow)?;
        let dynamic_work = tree
            .checked_mul(8)
            .and_then(|work| work.checked_add(input_nodes))
            .ok_or_else(overflow)?;
        let profile = Self {
            maximum_depth: 65,
            dynamic_work,
            raw_work: 0,
        };
        profile.maximum_work_data()?;
        Ok(profile)
    }

    /// Reports only whether a real constructor supplied nonempty populations.
    pub(crate) const fn has_constructed_population_data(self) -> bool {
        self.dynamic_work != 0
    }

    pub(crate) const fn maximum_depth_data(self) -> usize {
        self.maximum_depth
    }

    /// Returns the actual fixed and constructor population sum as DATA.
    ///
    /// # Errors
    /// Refuses checked population overflow.
    pub(crate) fn maximum_work_data(self) -> Result<usize, ProviderError> {
        self.dynamic_work
            .checked_add(self.raw_work)
            .and_then(|work| work.checked_add(FIXED_RESPONSE_WORK))
            .ok_or_else(overflow)
    }
}

#[derive(Clone, Copy, Default)]
struct WorkCounts {
    nodes: usize,
    records: usize,
}

#[derive(Clone, Copy)]
struct ActiveWork {
    counts: WorkCounts,
    maximum: usize,
}

/// Keeps delegated child work separate from the unchanged ordinary budget.
///
/// Global facts never decrease. Completed and refused child visits remain in
/// `charged`; the ordinary budget is exactly total minus charged child work.
/// Announced work is the checked sum of the actual scopes encountered in this
/// finite owner traversal. Nodes and capacity records are independently bounded,
/// just as the two ordinary categories are. This is no CPU time allowance,
/// protocol original credit or native debit reset.
pub(super) struct ScopedWorkAccounting {
    charged: WorkCounts,
    announced: usize,
    active: Option<ActiveWork>,
}

impl ScopedWorkAccounting {
    pub(super) const fn new() -> Self {
        Self {
            charged: WorkCounts {
                nodes: 0,
                records: 0,
            },
            announced: 0,
            active: None,
        }
    }
}

#[derive(Clone, Copy)]
struct PreviousProfile {
    depth: usize,
    limit: usize,
    active: Option<ActiveWork>,
}

#[allow(dead_code)]
struct PopulationControls {
    raw_values: usize,
    raw_members: usize,
    input_nodes: usize,
    serialized_nodes: usize,
    serialized_records: usize,
    maximum_depth: usize,
    expanded: (usize, usize, usize),
    values: usize,
    members: usize,
    tree: usize,
    response_forests: [usize; 8],
    forest_cursor: std::array::IntoIter<usize, 8>,
    total: usize,
    work: usize,
    dynamic_work: usize,
    encoded_bytes: usize,
    maximum: usize,
    node: bool,
    charged: &'static mut usize,
    current: &'static mut usize,
    profile: NativeImport18JsonMetadataProfileData,
    other: NativeImport18JsonMetadataProfileData,
    result: Result<(), ProviderError>,
    checked: Option<usize>,
}

impl MetadataObserver<'_> {
    /// Names actual borrowed scope/profile/closure-result controls.
    pub(crate) fn native_import18_json_profile_counter_scratch_data() -> usize {
        size_of::<NativeImport18JsonMetadataProfileData>()
            + size_of::<Result<NativeImport18JsonMetadataProfileData, ProviderError>>()
            + size_of::<PreviousProfile>()
            + size_of::<Option<&crate::client::OriginalNativeImport18Assignment>>()
            + size_of::<EnvelopeFieldLoans<'static>>()
            + size_of::<Option<NativeImport18JsonMetadataProfileData>>()
            + size_of::<Result<Option<NativeImport18JsonMetadataProfileData>, ProviderError>>()
            + size_of::<ScopedWorkAccounting>()
            + size_of::<WorkCounts>()
            + size_of::<ActiveWork>()
            + size_of::<Option<ActiveWork>>()
            + size_of::<&mut usize>()
            + size_of::<&usize>()
            + size_of::<bool>()
            + size_of::<Option<usize>>()
            + size_of::<[usize; 8]>()
            + size_of::<std::array::IntoIter<usize, 8>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<&mut Self>()
            + size_of::<&NativeImport18JsonMetadataProfileData>()
            + size_of::<&mut NativeImport18JsonMetadataProfileData>()
            + size_of::<&mut Option<crate::transport::RetainedFrame>>()
            + size_of::<&crate::transport::RetainedFrame>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<&JsonValueReparseConstructionData>()
            + size_of::<PopulationControls>()
    }

    /// Names one actual recursive Value metadata visit and container control.
    pub(crate) fn native_import18_json_metadata_frame_counter_scratch_data() -> usize {
        size_of::<&Value>()
            + size_of::<&mut Self>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<std::slice::Iter<'static, Value>>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<(&String, &Value)>()
            + size_of::<Option<(&String, &Value)>>()
            + size_of::<Option<&Value>>()
            + size_of::<usize>()
    }

    /// Charges one actual visit after its global fact was monotonically added.
    pub(super) fn charge_native_import18_metadata_work_data(
        &mut self,
        node: bool,
    ) -> Result<(), ProviderError> {
        let total = if node {
            self.facts.observed_nodes
        } else {
            self.facts.capacity_records
        };
        let charged = if node {
            &mut self.scoped_work.charged.nodes
        } else {
            &mut self.scoped_work.charged.records
        };
        if let Some(active) = &mut self.scoped_work.active {
            add(charged, 1)?;
            let current = if node {
                &mut active.counts.nodes
            } else {
                &mut active.counts.records
            };
            add(current, 1)?;
            if *current > active.maximum || *charged > self.scoped_work.announced {
                return Err(overflow());
            }
        } else if total.checked_sub(*charged).ok_or_else(overflow)? > 131_072 {
            return Err(if node {
                ProviderError::ResourceExhausted("retained metadata traversal rows")
            } else {
                overflow()
            });
        }
        Ok(())
    }

    /// Observes one genuinely funded SDK response forest under its own profile.
    ///
    /// Ordinary work remains131072 and ordinary depth remains64. Child visits
    /// add to the same cumulative facts but consume their own actual population
    /// bound. Restoring an outer scope never refunds visits or loses its partial
    /// counters; nested scopes delegate only their separately announced work.
    /// The closure is a private metadata walk, never an external callback.
    ///
    /// # Errors
    /// Refuses overflow, an exhausted actual population or a failed field walk.
    /// Both Result outcomes restore the previous active scope without refunds.
    pub(crate) fn with_native_import18_json_profile_data(
        &mut self,
        profile: NativeImport18JsonMetadataProfileData,
        observe: impl FnOnce(&mut Self) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let maximum = profile.maximum_work_data()?;
        self.scoped_work.announced = self
            .scoped_work
            .announced
            .checked_add(maximum)
            .ok_or_else(overflow)?;
        let previous = PreviousProfile {
            depth: self.json_depth,
            limit: self.json_depth_limit,
            active: self.scoped_work.active,
        };
        self.json_depth = 0;
        self.json_depth_limit = profile.maximum_depth;
        self.scoped_work.active = Some(ActiveWork {
            counts: WorkCounts::default(),
            maximum,
        });

        let result = observe(self);

        self.json_depth = previous.depth;
        self.json_depth_limit = previous.limit;
        self.scoped_work.active = previous.active;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::raw_value_reparse::quote_value_data;

    #[test]
    fn actual_reparse_profile_censuses_expanded_partial_without_widening_default() {
        let text = format!("{}null{}", "[".repeat(70), "]".repeat(70));
        let raw = serde_json::json!({"$serde_json::private::RawValue": text.clone()});
        let extra = quote_value_data(&raw, usize::MAX).unwrap();
        let profile =
            NativeImport18JsonMetadataProfileData::from_reparse_population_data(&extra, 3, 1)
                .unwrap();
        let expanded: Value = serde_json::from_str(&text).unwrap();
        let mut ordinary = MetadataObserver::new();
        let mut scoped = MetadataObserver::new();

        assert!(ordinary.observe(&expanded).is_err());
        scoped
            .with_native_import18_json_profile_data(profile, |observer| observer.observe(&expanded))
            .unwrap();

        assert!(scoped.finish().vector_capacity_bytes > 0);
        let mut restored = MetadataObserver::new();
        restored
            .with_native_import18_json_profile_data(profile, |observer| observer.observe(&expanded))
            .unwrap();
        assert_eq!(restored.json_depth_limit, 64);
        assert_eq!(restored.json_depth, 0);
        assert!(restored.observe(&expanded).is_err());
    }

    #[test]
    fn scope_restores_profile_on_refusal_without_refunding_observed_rows() {
        let mut observer = MetadataObserver::new();
        let before = observer.facts.observed_nodes;
        let result = observer.with_native_import18_json_profile_data(
            NativeImport18JsonMetadataProfileData::strict_raw_data(),
            |observer| {
                observer.observe(&Value::Bool(true))?;
                Err(overflow())
            },
        );

        assert!(result.is_err());
        assert_eq!(observer.json_depth_limit, 64);
        assert_eq!(observer.json_depth, 0);
        assert!(observer.facts.observed_nodes > before);
    }
    #[test]
    fn actual_large_raw_child_does_not_spend_or_refund_the_ordinary_budget() {
        let value = Value::Array(vec![
            Value::Array(vec![Value::Bool(true); 40_000]),
            Value::Array(vec![Value::Bool(false); 40_000]),
        ]);
        let raw = serde_json::to_vec(&value).unwrap();
        let mut profile = NativeImport18JsonMetadataProfileData::strict_raw_data();
        profile.retain_strict_raw_population_data(raw.len());
        let mut observer = MetadataObserver::new();
        observer.facts.observed_nodes = 131_071;

        observer
            .with_native_import18_json_profile_data(profile, |observer| observer.observe(&value))
            .unwrap();
        let after_child = observer.facts.observed_nodes;
        assert!(after_child > 131_072);
        observer.observe(&true).unwrap();
        assert_eq!(observer.facts.observed_nodes, after_child + 1);
        assert!(observer.observe(&true).is_err());
        assert_eq!(observer.facts.observed_nodes, after_child + 2);
        assert_eq!(observer.scoped_work.charged.nodes, after_child - 131_071);
    }

    #[test]
    fn nested_and_refused_scopes_preserve_charged_facts_and_outer_progress() {
        let profile = NativeImport18JsonMetadataProfileData::strict_raw_data();
        let mut observer = MetadataObserver::new();
        observer
            .with_native_import18_json_profile_data(profile, |observer| {
                observer.observe(&true)?;
                let result = observer.with_native_import18_json_profile_data(profile, |observer| {
                    observer.observe(&false)?;
                    Err(overflow())
                });
                assert!(result.is_err());
                assert_eq!(observer.scoped_work.active.unwrap().counts.nodes, 1);
                observer.observe(&true)
            })
            .unwrap();

        assert_eq!(observer.facts.observed_nodes, 3);
        assert_eq!(observer.scoped_work.charged.nodes, 3);
        assert!(observer.scoped_work.active.is_none());
        assert_eq!(observer.json_depth_limit, 64);
        observer.observe(&true).unwrap();
        assert_eq!(observer.facts.observed_nodes, 4);
        assert_eq!(observer.scoped_work.charged.nodes, 3);
    }
}

// Only the explicit same-Controller capsule adapter installs this loan. Ordinary
// constructors retain None and execute the exact previous Envelope field walk.
impl<'a> MetadataObserver<'a> {
    pub(crate) fn native_import18_capsule_data(
        capsule: &'a crate::client::OriginalNativeImport18Assignment,
    ) -> Self {
        let mut observer = Self::new();
        observer.native_import18_capsule = Some(capsule);
        observer
    }
}

type EnvelopeFieldLoans<'a> = (
    &'a String,
    &'a crate::envelope::MessageKind,
    &'a crate::envelope::Nullable<Id>,
    &'a crate::envelope::Nullable<Id>,
    &'a crate::envelope::Nullable<Id>,
    &'a crate::envelope::Nullable<Id>,
    &'a crate::envelope::Nullable<Id>,
    &'a crate::envelope::Nullable<Id>,
    &'a crate::envelope::Nullable<Id>,
    &'a U64,
    &'a crate::envelope::Method,
    &'a serde_json::Map<String, Value>,
    &'a Extensions,
);

impl ObserveMetadata for crate::envelope::Envelope {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let profile = match observer.native_import18_capsule {
            Some(capsule) => capsule.metadata_profile_for_envelope_data(self)?,
            None => None,
        };
        let observe_fields = |observer: &mut MetadataObserver<'_>| {
            let Self {
                protocol,
                message,
                session_id,
                incarnation_id,
                node_id,
                execution_owner_id,
                capture_owner_id,
                request_id,
                operation_id,
                sequence,
                method,
                body,
                extensions,
            } = self;
            observer.observe(protocol)?;
            observer.observe(message)?;
            observer.observe(session_id)?;
            observer.observe(incarnation_id)?;
            observer.observe(node_id)?;
            observer.observe(execution_owner_id)?;
            observer.observe(capture_owner_id)?;
            observer.observe(request_id)?;
            observer.observe(operation_id)?;
            observer.observe(sequence)?;
            observer.observe(method)?;
            observer.observe(body)?;
            observer.observe(extensions)
        };
        match profile {
            Some(profile) => {
                observer.with_native_import18_json_profile_data(profile, observe_fields)
            }
            None => observe_fields(observer),
        }
    }
}
