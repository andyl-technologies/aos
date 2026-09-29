//! Evaluates trust only from verified commit and immutable tree evidence.
//!
//! Selector traversal uses explicit work stacks. Missing provenance never
//! becomes true through negation. Memos bind the disclosure domain, signed
//! view, verified receipt context, configuration, and effective root selectors.

use super::selector::Node;
use super::{EntryLocation, Preset, Rejected, Selector, VerifiedHistory};
use crate::{
    cbor::{self, Decoder},
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
    canonical: Vec<u8>,
    memo: RefCell<BTreeMap<Vec<u8>, bool>>,
}

fn nullable_text(decoder: &mut Decoder<'_>) -> Result<Option<String>, Rejected> {
    if decoder.peek_major().map_err(|_| Rejected)? == 7 {
        if decoder.simple().map_err(|_| Rejected)? != 0xf6 {
            return Err(Rejected);
        }
        Ok(None)
    } else {
        Ok(Some(
            decoder
                .text(decoder.remaining().len())
                .map_err(|_| Rejected)?
                .to_string(),
        ))
    }
}

/// Validates serialized trust configuration without granting runtime authority.
///
/// The canonical tuple is `[1, view, domain, selector, baseline-or-null,
/// min-chunk-size]`. Only [`TrustContext::new`] creates an evaluator, after
/// checking that its view is present in a verified history.
///
/// # Errors
/// Returns [`Rejected`] for malformed/noncanonical context bytes, unknown
/// versions, invalid digest width, invalid selectors, or trailing bytes.
pub fn validate_canonical_context(bytes: &[u8]) -> Result<(), Rejected> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array(6).map_err(|_| Rejected)? != 6 || decoder.uint().map_err(|_| Rejected)? != 1 {
        return Err(Rejected);
    }
    if decoder.bytes(32).map_err(|_| Rejected)?.len() != 32 {
        return Err(Rejected);
    }
    decoder
        .text(decoder.remaining().len())
        .map_err(|_| Rejected)?;
    let selector = decoder
        .bytes(decoder.remaining().len())
        .map_err(|_| Rejected)?;
    Selector::decode(selector).map_err(|_| Rejected)?;
    nullable_text(&mut decoder)?;
    decoder.uint().map_err(|_| Rejected)?;
    decoder.finish().map_err(|_| Rejected)
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
    /// Returns [`Rejected`] if the view is absent from the verified history.
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
    /// Returns [`Rejected`] if the view is absent from the verified history.
    pub fn from_shared(
        history: Rc<VerifiedHistory>,
        view: Digest,
        selector: Selector,
        domain: &str,
        baseline: Option<&str>,
    ) -> Result<Self, Rejected> {
        let root = history.commit(&view).ok_or(Rejected)?.commit().tree;
        let mut canonical = Vec::new();
        cbor::write_array(&mut canonical, 6);
        cbor::write_uint(&mut canonical, 1);
        cbor::write_bytes(&mut canonical, &view);
        cbor::write_text(&mut canonical, domain);
        cbor::write_bytes(&mut canonical, selector.encode());
        if let Some(baseline) = baseline {
            cbor::write_text(&mut canonical, baseline);
        } else {
            canonical.push(0xf6);
        }
        cbor::write_uint(&mut canonical, history.min_chunk_size());

        Ok(Self {
            history,
            view,
            root,
            selector,
            baseline: baseline.map(ToString::to_string),
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
        let mut root_selector = Selector::preset(Preset::Any);
        let mut key = self.canonical.clone();
        cbor::write_bytes(&mut key, &introducing);
        cbor::write_array(&mut key, properties.len());
        for root_properties in properties {
            // Bind each root's selector to that root's effective baseline.
            // A descendant override must not widen an ancestor's requirement.
            if let Some(property) = root_properties
                .iter()
                .find(|property| property.name == "baseline")
            {
                let mut decoder = Decoder::new(property.value);
                baseline = Some(
                    decoder
                        .text(decoder.remaining().len())
                        .map_err(|_| Rejected)?
                        .to_string(),
                );
                decoder.finish().map_err(|_| Rejected)?;
            }
            cbor::write_array(&mut key, root_properties.len());
            for property in root_properties {
                cbor::write_array(&mut key, 2);
                if property.name == "trust" {
                    root_selector =
                        Selector::from_property(property.value).map_err(|_| Rejected)?;
                }
                cbor::write_text(&mut key, property.name);
                cbor::write_bytes(&mut key, property.value);
            }
            selectors.push((root_selector.clone(), baseline.clone()));
        }
        selectors.push((self.selector.clone(), baseline));
        // Entries with identical verified receipt contexts share evaluations;
        // root/path alone would turn the memo into a cache per individual file.
        let acceptance = self.history.acceptance_commits(location, introducing);
        cbor::write_array(&mut key, acceptance.len());
        for commit in &acceptance {
            cbor::write_bytes(&mut key, commit);
        }
        let mut producers = BTreeMap::new();
        for (selector, _) in &selectors {
            for node in &selector.nodes {
                if let Node::AttributeBy(name, _) = node {
                    let producer = self.history.attribute_producer(location, name)?;
                    let acceptance = self
                        .history
                        .attribute_acceptance_commits(location, name, producer);
                    producers.insert(name, (producer, acceptance));
                }
            }
        }
        cbor::write_array(&mut key, producers.len());
        for (name, (producer, acceptance)) in producers {
            cbor::write_array(&mut key, 3);
            cbor::write_text(&mut key, name);
            cbor::write_bytes(&mut key, &producer);
            cbor::write_array(&mut key, acceptance.len());
            for commit in acceptance {
                cbor::write_bytes(&mut key, &commit);
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
                    let producer = self.history.attribute_producer(location, name)?;
                    let carried = self
                        .history
                        .attribute_acceptance_commits(location, name, producer);
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
