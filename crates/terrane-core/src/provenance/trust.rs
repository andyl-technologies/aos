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
//! ```

use super::selector::Node;
use super::{EntryLocation, Preset, Rejected, Selector, VerifiedHistory};
use crate::{
    cbor,
    identity::Digest,
    tree_format::{Entry, Property},
};
use alloc::{
    collections::BTreeMap,
    rc::Rc,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::cell::RefCell;

mod context;

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
    memo: RefCell<BTreeMap<Vec<u8>, bool>>,
}

/// Validates serialized trust configuration without granting runtime authority.
///
/// The canonical tuple is `[1, view, domain, selector, baseline-or-null,
/// min-chunk-size]`. A version-2 tuple appends canonical selected side evidence
/// as a byte string. Only [`TrustContext::new`] creates an evaluator, after
/// checking that its view is present in a verified history.
///
/// # Errors
/// Returns [`Rejected`] for malformed/noncanonical context bytes, unknown
/// versions, invalid digest widths or selectors, malformed selected evidence,
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
        let mut canonical = Vec::new();
        let side_context = history.side_context(view, domain);
        let has_side_evidence = !side_context.is_empty();
        cbor::write_array(&mut canonical, if has_side_evidence { 7 } else { 6 });
        cbor::write_uint(&mut canonical, if has_side_evidence { 2 } else { 1 });
        cbor::write_bytes(&mut canonical, &view);
        cbor::write_text(&mut canonical, domain);
        cbor::write_bytes(&mut canonical, selector.encode());
        if let Some(baseline) = baseline {
            cbor::write_text(&mut canonical, baseline);
        } else {
            canonical.push(0xf6);
        }
        cbor::write_uint(&mut canonical, history.min_chunk_size());
        if has_side_evidence {
            cbor::write_bytes(&mut canonical, &side_context);
        }

        Ok(Self {
            history,
            view,
            root,
            selector,
            baseline: baseline.map(ToString::to_string),
            domain: domain.to_string(),
            canonical,
            memo: RefCell::new(BTreeMap::new()),
        })
    }

    /// Returns the top root of the authenticated immutable input view.
    pub const fn view_root(&self) -> Digest {
        self.root
    }

    /// Returns the immutable configuration encoding used by audited merge recipes.
    pub fn canonical_context(&self) -> &[u8] {
        &self.canonical
    }

    /// Evaluates a full view-relative path including every traversed root policy.
    pub fn accepts_path(&self, path: &[u8]) -> bool {
        let Ok((location, properties)) = self.history.locate_policies(self.view, path) else {
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
        let (location, _) = self.candidate_location(root, path, candidate).ok()?;
        let introducing = self.history.introducing_commit(&location).ok()?;
        Some(self.history.commit(&introducing)?.commit().timestamp)
    }

    fn candidate_location(
        &self,
        root: Digest,
        path: &[u8],
        candidate: &Entry<'_>,
    ) -> Result<(EntryLocation, Vec<Vec<Property<'_>>>), Rejected> {
        if root != self.root {
            return Err(Rejected);
        }
        let (location, properties) = self.history.locate_policies(self.view, path)?;
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
        let (location, _) = self.history.locate(self.view, path).ok()?;
        let introducing = self.history.introducing_commit(&location).ok()?;
        Some(self.history.commit(&introducing)?.commit().timestamp)
    }

    fn evaluate(
        &self,
        location: &EntryLocation,
        properties: &[Vec<Property<'_>>],
    ) -> Result<bool, Rejected> {
        let introducing = self.history.introducing_commit(location)?;
        let mut baseline = self.baseline.clone();
        let mut selectors = Vec::new();
        let mut layers = Vec::new();
        let mut key = self.canonical.clone();
        cbor::write_bytes(&mut key, &introducing);
        cbor::write_array(&mut key, properties.len());
        for root_properties in properties {
            layers.push(crate::properties::RootLayer {
                properties: root_properties,
                overrides: &[],
            });
            // Resolve each prefix independently: non-inheriting bindings apply
            // locally, while ancestor trust constraints remain conjoined.
            let effective = self
                .history
                .view_selection(location.commit)?
                .resolve(
                    &layers,
                    crate::properties::Defaults {
                        store: "provenance",
                        private_domain: "private:provenance",
                        home: "provenance",
                    },
                )
                .map_err(|_| Rejected)?;
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
            cbor::write_array(&mut key, root_properties.len());
            for property in root_properties {
                cbor::write_array(&mut key, 2);
                cbor::write_text(&mut key, property.name);
                cbor::write_bytes(&mut key, property.value);
            }
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
