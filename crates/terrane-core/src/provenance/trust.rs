//! Evaluates trust only from verified commit and immutable tree evidence.
//!
//! Selector traversal uses explicit work stacks. Missing provenance never
//! becomes true through negation. Memos bind the disclosure domain, signed
//! view, verified receipt context, configuration, and effective root selectors.
//!
//! ```text
//! legacy context = [1, view, domain, selector, baseline-or-null, min-chunk-size]
//! side context = [2, view, domain, selector, baseline-or-null, min-chunk-size,
//!                 canonical selected-evidence byte string]
//! recorded context = [3, view, domain, selector, baseline-or-null, min-chunk-size,
//!                     selected-evidence-or-null, [original-root, revision,
//!                                                behavioral-names, later-names]]
//! ```

use super::selector::Node;
use super::{EntryLocation, Preset, Rejected, Selector, VerifiedHistory};
use crate::{cbor, identity::Digest, tree_format::Entry};
use alloc::{
    collections::BTreeMap,
    rc::Rc,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::cell::RefCell;

mod context;
mod encoding;
mod recorded;

use recorded::{OwnedRecorded, PolicyInputs};

#[cfg(test)]
mod recorded_evaluation_tests;

/// Names a private content fingerprint, never a registered store identity.
type MemoKey = Digest;

// Private framing binds complete immutable configuration and evidence; these
// bytes are neither a serialized trust context nor a store object preimage.
fn memo_fingerprint(
    evidence: &[u8],
    configured: &crate::properties::selected::Selection,
    occurrence: &crate::properties::selected::Selection,
) -> MemoKey {
    let mut content = Vec::new();
    cbor::write_array(&mut content, 3);
    cbor::write_bytes(&mut content, evidence);
    encode_memo_selection(&mut content, configured);
    encode_memo_selection(&mut content, occurrence);
    *blake3::hash(&content).as_bytes()
}

fn encode_memo_selection(output: &mut Vec<u8>, selection: &crate::properties::selected::Selection) {
    use crate::properties::selected::Selection;

    match selection {
        Selection::Legacy => {
            cbor::write_array(output, 1);
            cbor::write_uint(output, 0);
        }
        Selection::Active => {
            cbor::write_array(output, 1);
            cbor::write_uint(output, 1);
        }
        Selection::Recorded(context) => {
            cbor::write_array(output, 5);
            cbor::write_uint(output, 2);
            cbor::write_uint(output, context.revision());
            cbor::write_uint(output, context.current_revision());
            let behavioral: Vec<_> = context.behavioral_names().collect();
            cbor::write_array(output, behavioral.len());
            for name in behavioral {
                cbor::write_text(output, name);
            }
            cbor::write_array(output, context.later_registered().len());
            for name in context.later_registered() {
                cbor::write_text(output, name);
            }
        }
    }
}

/// Evaluates a view's trust using authenticated commits and canonical witnesses.
///
/// This type grants no read authority. Repository guards must authorize reads
/// before calling it and map false to absence on every surface (PROV-15/23).
#[derive(Clone, Debug)]
pub struct TrustContext {
    history: Rc<VerifiedHistory>,
    view: Digest,
    root: Digest,
    selector: Selector,
    baseline: Option<String>,
    domain: String,
    canonical: Vec<u8>,
    selection: crate::properties::selected::Selection,
    recorded: Option<OwnedRecorded>,
    memo: RefCell<BTreeMap<MemoKey, bool>>,
}

/// Validates serialized trust configuration without granting runtime authority.
///
/// The canonical tuple is `[1, view, domain, selector, baseline-or-null,
/// min-chunk-size]`. A version-2 tuple appends canonical selected side evidence
/// as a byte string. Version 3 also binds the exact historical property
/// vocabulary and original view root, with optional selected side evidence.
/// It does not authenticate registrations or choose a current revision.
/// Evaluator constructors independently check the selected view and its
/// interpretation against verified history before constructing an evaluator.
///
/// # Errors
/// Returns [`Rejected`] for malformed/noncanonical context bytes, unknown
/// versions, mismatched historical revision/name fences, invalid digest widths
/// or selectors, malformed selected evidence,
/// inconsistent view/domain/name bindings, duplicate or unordered selections,
/// invalid complete entry paths, noncanonical selected values or trailing bytes.
pub fn validate_canonical_context(bytes: &[u8]) -> Result<(), Rejected> {
    context::validate(bytes)
}

impl TrustContext {
    /// Constructs an evaluator from a verified view and canonical configuration.
    ///
    /// Copies the history into an immutable snapshot. [`Self::from_shared`]
    /// shares one snapshot across multiple views without copying witnesses.
    /// Baseline configuration is part of the immutable memo context; signed
    /// root `baseline` properties override it as the entry path is traversed.
    /// The disclosure domain is supplied by the trusted repository guard.
    ///
    /// # Errors
    /// Returns [`Rejected`] if the view is absent or its disclosure batch has
    /// not completed all certificate, entry and attribute validation.
    pub fn new(
        history: &VerifiedHistory,
        view: Digest,
        selector: Selector,
        domain: &str,
        baseline: Option<&str>,
    ) -> Result<Self, Rejected> {
        Self::from_shared(Rc::new(history.clone()), view, selector, domain, baseline)
    }

    /// Constructs an evaluator sharing an immutable verified history snapshot.
    ///
    /// Sharing evidence avoids cloning complete Merkle witnesses for each
    /// policy. Configuration and memo state remain local to this evaluator.
    ///
    /// # Errors
    /// Returns [`Rejected`] if the view is absent or its disclosure batch has
    /// not completed all certificate, entry and attribute validation.
    pub fn from_shared(
        history: Rc<VerifiedHistory>,
        view: Digest,
        selector: Selector,
        domain: &str,
        baseline: Option<&str>,
    ) -> Result<Self, Rejected> {
        history.require_verified_context(view)?;
        let root = history.commit(&view).ok_or(Rejected)?.commit().tree;
        let side_context = history.side_context(view, domain);
        let selection = history.view_selection(view)?;
        let recorded = match &selection {
            crate::properties::selected::Selection::Recorded(context) => {
                Some(OwnedRecorded::new(context))
            }
            _ => None,
        };
        let fields = encoding::ContextFields {
            view: &view,
            domain,
            selector: selector.encode(),
            baseline,
            minimum: history.min_chunk_size(),
            selected: &side_context,
        };
        let canonical = if let Some(context) = &recorded {
            context.encode(fields, &root)?
        } else {
            encoding::encode(fields)
        };

        Ok(Self {
            history,
            view,
            root,
            selector,
            baseline: baseline.map(ToString::to_string),
            domain: domain.to_string(),
            canonical,
            selection,
            recorded,
            memo: RefCell::new(BTreeMap::new()),
        })
    }

    /// Constructs an evaluator only when the supplied exact association is installed.
    ///
    /// # Errors
    /// Rejects absent or mismatched view, original root or complete selection,
    /// and preserves genuine history/evaluator construction failures.
    pub fn new_with_recorded(
        history: &VerifiedHistory,
        view: Digest,
        selector: Selector,
        domain: &str,
        baseline: Option<&str>,
        association: Option<(
            Digest,
            Digest,
            crate::properties::semantics::RecordedContext,
        )>,
    ) -> Result<Self, Rejected> {
        Self::from_shared_with_recorded(
            Rc::new(history.clone()),
            view,
            selector,
            domain,
            baseline,
            association,
        )
    }

    /// Constructs a shared evaluator without replacing independently installed trust.
    ///
    /// # Errors
    /// Rejects any association mismatch or incomplete authenticated history.
    pub fn from_shared_with_recorded(
        history: Rc<VerifiedHistory>,
        view: Digest,
        selector: Selector,
        domain: &str,
        baseline: Option<&str>,
        association: Option<(
            Digest,
            Digest,
            crate::properties::semantics::RecordedContext,
        )>,
    ) -> Result<Self, Rejected> {
        let (selected, root, context) = association.ok_or(Rejected)?;
        if selected != view
            || history.commit(&view).ok_or(Rejected)?.commit().tree != root
            || history.view_selection(view)?
                != crate::properties::selected::Selection::Recorded(context)
        {
            return Err(Rejected);
        }
        Self::from_shared(history, view, selector, domain, baseline)
    }

    fn policy_inputs(&self, path: &[u8]) -> Result<(EntryLocation, PolicyInputs<'_>), Rejected> {
        match &self.selection {
            crate::properties::selected::Selection::Legacy => {
                let (location, layers) = self.history.locate_policies(self.view, path)?;
                Ok((location, PolicyInputs::Legacy(layers)))
            }
            _ => {
                let (location, layers) = self.history.locate_policy_layers(self.view, path)?;
                for layer in &layers {
                    self.selection
                        .validate_layer(
                            &layer.properties,
                            layer.overrides.as_deref().unwrap_or(&[]),
                        )
                        .map_err(|_| Rejected)?;
                }
                Ok((location, PolicyInputs::Recorded(layers)))
            }
        }
    }

    fn checked_prefixes(&self, properties: &PolicyInputs<'_>) -> Result<(), Rejected> {
        for prefix in 1..=properties.len() {
            properties.resolve_prefix(prefix, self.recorded.as_ref(), &self.selection)?;
        }
        Ok(())
    }

    /// Returns the top root of the authenticated immutable input view.
    pub const fn view_root(&self) -> Digest {
        self.root
    }

    /// Returns the registered immutable configuration used by audited merge recipes.
    ///
    /// Recorded version 3 retains the original view root and exact historical
    /// revision/name fences. The current revision remains an independently
    /// selected runtime input, not an added field in this registered tuple.
    pub fn canonical_context(&self) -> &[u8] {
        &self.canonical
    }

    /// Evaluates a full view-relative path including every traversed root policy.
    pub fn accepts_path(&self, path: &[u8]) -> bool {
        let Ok((location, properties)) = self.policy_inputs(path) else {
            return false;
        };
        self.evaluate(&location, &properties).unwrap_or(false)
    }

    /// Evaluates an entry only when its root has an unambiguous view policy path.
    ///
    /// The current view root is accepted directly. For grafted roots callers
    /// must use [`Self::accepts_path`] so inherited trust cannot be bypassed.
    pub fn accepts(&self, root: Digest, path: &[u8]) -> bool {
        let Some(view) = self.history.commit(&self.view) else {
            return false;
        };
        if root != view.commit().tree {
            return false;
        }
        self.accepts_path(path)
    }

    /// Evaluates a candidate only when it exactly matches its signed input entry.
    ///
    /// This binds filtered or otherwise derived algebra inputs back to the
    /// retained signed view. Metadata, attributes, and provenance must match,
    /// and every graft policy on the original full path still applies.
    pub fn accepts_entry(&self, root: Digest, path: &[u8], candidate: &Entry<'_>) -> bool {
        let Ok((location, properties)) = self.candidate_location(root, path, candidate) else {
            return false;
        };
        self.evaluate(&location, &properties).unwrap_or(false)
    }

    /// Returns producer time only for a candidate matched to signed input evidence.
    pub fn producer_time_entry(
        &self,
        root: Digest,
        path: &[u8],
        candidate: &Entry<'_>,
    ) -> Option<u64> {
        let (location, properties) = self.candidate_location(root, path, candidate).ok()?;
        self.checked_prefixes(&properties).ok()?;
        let introducing = self.history.introducing_commit(&location).ok()?;
        Some(self.history.commit(&introducing)?.commit().timestamp)
    }

    fn candidate_location(
        &self,
        root: Digest,
        path: &[u8],
        candidate: &Entry<'_>,
    ) -> Result<(EntryLocation, PolicyInputs<'_>), Rejected> {
        if root != self.root {
            return Err(Rejected);
        }
        let (location, properties) = self.policy_inputs(path)?;
        if self.history.entry(&location)? != *candidate {
            return Err(Rejected);
        }
        Ok((location, properties))
    }

    /// Returns the verified content producer's advisory timestamp for merge policy.
    pub fn producer_time(&self, root: Digest, path: &[u8]) -> Option<u64> {
        let view = self.history.commit(&self.view)?;
        if root != view.commit().tree {
            return None;
        }
        let (location, properties) = self.policy_inputs(path).ok()?;
        self.checked_prefixes(&properties).ok()?;
        let introducing = self.history.introducing_commit(&location).ok()?;
        Some(self.history.commit(&introducing)?.commit().timestamp)
    }

    fn evaluate(
        &self,
        location: &EntryLocation,
        properties: &PolicyInputs<'_>,
    ) -> Result<bool, Rejected> {
        let introducing = self.history.introducing_commit(location)?;
        let mut baseline = self.baseline.clone();
        let mut selectors = Vec::new();
        let mut key = self.canonical.clone();
        cbor::write_bytes(&mut key, &introducing);
        cbor::write_array(&mut key, properties.len());
        for prefix in 1..=properties.len() {
            let occurrence = self.history.view_selection(location.commit)?;
            let effective =
                properties.resolve_prefix(prefix, self.recorded.as_ref(), &occurrence)?;
            baseline = match effective.get(crate::properties::PropertyName::Baseline) {
                Some(crate::properties::Value::Text(value)) => Some((*value).to_string()),
                Some(crate::properties::Value::Unset) => self.baseline.clone(),
                _ => return Err(Rejected),
            };
            let root_selector = match effective.get(crate::properties::PropertyName::Trust) {
                Some(crate::properties::Value::Selector(bytes)) => {
                    Selector::decode(bytes).map_err(|_| Rejected)?
                }
                Some(crate::properties::Value::Text(value)) => {
                    let mut encoded = Vec::new();
                    cbor::write_text(&mut encoded, value);
                    Selector::from_property(&encoded).map_err(|_| Rejected)?
                }
                _ => return Err(Rejected),
            };
            properties.write_layer(prefix - 1, &mut key)?;
            selectors.push((root_selector.clone(), baseline.clone()));
        }
        selectors.push((self.selector.clone(), baseline));
        let mut content_acceptance = false;
        let mut attribute_acceptance = BTreeMap::<&str, bool>::new();
        for (selector, _) in &selectors {
            let dependencies = selector.acceptance_dependencies();
            content_acceptance |= *dependencies.get(selector.root).ok_or(Rejected)?;
            for node in &selector.nodes {
                if let Node::AttributeBy(name, child) = node {
                    let required = *dependencies.get(*child).ok_or(Rejected)?;
                    attribute_acceptance
                        .entry(name.as_str())
                        .and_modify(|previous| *previous |= required)
                        .or_insert(required);
                }
            }
        }

        // Entries with identical verified receipt contexts share evaluations;
        // root/path alone would turn the memo into a cache per individual file.
        // Unused ancestry is not required evidence for introduction-only atoms.
        // Effective root constraints participate in the same dependency check.
        let acceptance = if content_acceptance {
            self.history.acceptance_commits(location, introducing)?
        } else {
            Vec::new()
        };
        cbor::write_array(&mut key, acceptance.len());
        for commit in &acceptance {
            cbor::write_bytes(&mut key, commit);
        }
        let mut producers = BTreeMap::new();
        for (name, required) in &attribute_acceptance {
            let context =
                self.history
                    .attribute_context(location, name, &self.domain, *required)?;
            producers.insert(name, context);
        }
        cbor::write_array(&mut key, producers.len());
        for (name, (producer, acceptance, side)) in producers {
            cbor::write_array(&mut key, 4);
            cbor::write_text(&mut key, name);
            cbor::write_bytes(&mut key, &producer);
            cbor::write_array(&mut key, acceptance.len());
            for commit in acceptance {
                cbor::write_bytes(&mut key, &commit);
            }
            if let Some(side) = side {
                side.encode_context(&mut key);
            } else {
                key.push(0xf6);
            }
        }
        // Registered context bytes retain historical execution. The private
        // fingerprint additionally binds exact captured current selection and
        // occurrence interpretation without changing any registered bytes.
        let occurrence = self.history.view_selection(location.commit)?;
        let key = memo_fingerprint(&key, &self.selection, &occurrence);
        if let Some(result) = self.memo.borrow().get(&key) {
            return Ok(*result);
        }

        let result = selectors
            .iter()
            .try_fold(true, |accepted, (selector, baseline)| {
                Ok::<_, Rejected>(
                    accepted
                        && self.evaluate_selector(
                            selector,
                            location,
                            introducing,
                            baseline.as_deref(),
                            &acceptance,
                            &attribute_acceptance,
                        )?,
                )
            })?;
        self.memo.borrow_mut().insert(key, result);
        Ok(result)
    }

    fn evaluate_selector(
        &self,
        selector: &Selector,
        location: &EntryLocation,
        introducing: Digest,
        baseline: Option<&str>,
        acceptance: &[Digest],
        attribute_acceptance: &BTreeMap<&str, bool>,
    ) -> Result<bool, Rejected> {
        let mut values = BTreeMap::<(usize, Digest, Option<usize>), bool>::new();
        let mut attributes = BTreeMap::<usize, (Digest, Vec<Digest>)>::new();
        let mut pending = vec![(selector.root, introducing, None, false)];
        while let Some((index, principal, context, finishing)) = pending.pop() {
            if values.contains_key(&(index, principal, context)) {
                continue;
            }
            let record = self.history.commit(&principal).ok_or(Rejected)?;
            let node = selector.nodes.get(index).ok_or(Rejected)?;
            let dependencies: Vec<(usize, Digest, Option<usize>)> = match node {
                Node::All(children) | Node::Any(children) => children
                    .iter()
                    .map(|child| (*child, principal, context))
                    .collect(),
                Node::Not(child) => vec![(*child, principal, context)],
                Node::AcceptedBy(child) => {
                    let carried = match context {
                        Some(context) => attributes.get(&context).ok_or(Rejected)?.1.as_slice(),
                        None => acceptance,
                    };
                    carried
                        .iter()
                        .map(|commit| (*child, *commit, context))
                        .collect()
                }
                Node::AttributeBy(name, child) => {
                    let required = *attribute_acceptance.get(name.as_str()).ok_or(Rejected)?;
                    let (producer, carried, _) =
                        self.history
                            .attribute_context(location, name, &self.domain, required)?;
                    attributes.insert(index, (producer, carried));
                    vec![(*child, producer, Some(index))]
                }
                _ => Vec::new(),
            };
            if !finishing && !dependencies.is_empty() {
                pending.push((index, principal, context, true));
                for (child, commit, context) in dependencies.into_iter().rev() {
                    pending.push((child, commit, context, false));
                }
                continue;
            }

            // Attribute evaluation never borrows acceptance from content. The
            // arena node identifies the immutable attribute receipt context.
            let carried = match context {
                Some(context) => attributes.get(&context).ok_or(Rejected)?.1.as_slice(),
                None => acceptance,
            };
            let result = match node {
                Node::Issuer(issuer) => record.authority().issuer == *issuer,
                Node::Subject(pattern) => pattern.matches(&record.authority().subject),
                Node::Kind(kind) => record.authority().kind == *kind,
                Node::Group(group) => record.authority().groups.contains(group),
                Node::Source(source) => record.commit().provenance.source == *source,
                Node::SignedByKey(key) => record.signing_public_key() == *key,
                Node::Preset(Preset::Any) => true,
                Node::Preset(Preset::Attested) => false,
                Node::Preset(Preset::Strict) => baseline.is_some_and(|group| {
                    record
                        .authority()
                        .groups
                        .iter()
                        .any(|candidate| candidate == group)
                }),
                Node::Preset(Preset::SignedBaseline) => baseline.is_some_and(|group| {
                    record
                        .authority()
                        .groups
                        .iter()
                        .any(|candidate| candidate == group)
                        || carried
                            .iter()
                            .filter_map(|commit| self.history.commit(commit))
                            .any(|record| {
                                record
                                    .authority()
                                    .groups
                                    .iter()
                                    .any(|candidate| candidate == group)
                            })
                }),
                Node::All(_) => dependencies
                    .iter()
                    .all(|dependency| values.get(dependency) == Some(&true)),
                Node::Any(_) | Node::AcceptedBy(_) => dependencies
                    .iter()
                    .any(|dependency| values.get(dependency) == Some(&true)),
                Node::Not(_) => !*values
                    .get(dependencies.first().ok_or(Rejected)?)
                    .ok_or(Rejected)?,
                Node::AttributeBy(_, _) => *values
                    .get(dependencies.first().ok_or(Rejected)?)
                    .ok_or(Rejected)?,
            };
            values.insert((index, principal, context), result);
        }
        values
            .get(&(selector.root, introducing, None))
            .copied()
            .ok_or(Rejected)
    }
}
