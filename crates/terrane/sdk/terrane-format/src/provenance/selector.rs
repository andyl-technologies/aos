//! Parses the registered selector CBOR AST into a flat, input-bounded arena.
//!
//! Recursive selectors use explicit stacks, including during destruction.
//! There is no arbitrary nesting cap and no unregistered selector atom.
//!
//! ```text
//! ["all", [["kind", "workload"], ["group", "baseline"]]]
//! ```

use crate::{
    auth::SubjectPattern,
    cbor::{self, Decoder},
    refs::{CommitSource, PrincipalKind},
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

/// Reports a malformed, noncanonical, or unregistered trust selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectorError;

impl fmt::Display for SelectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid trust selector")
    }
}

impl core::error::Error for SelectorError {}

/// Names the closed initial trust preset registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preset {
    /// Accepts every entry with available verified provenance.
    Any,
    /// Accepts baseline introductions or baseline acceptance receipts.
    SignedBaseline,
    /// Requires a direct baseline introduction.
    Strict,
    /// Requires a registered introducing-workload attestation.
    Attested,
}

impl Preset {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::SignedBaseline => "signed-baseline",
            Self::Strict => "strict",
            Self::Attested => "attested",
        }
    }

    fn parse(name: &str) -> Result<Self, SelectorError> {
        match name {
            "any" => Ok(Self::Any),
            "signed-baseline" => Ok(Self::SignedBaseline),
            "strict" => Ok(Self::Strict),
            "attested" => Ok(Self::Attested),
            _ => Err(SelectorError),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Node {
    Issuer(String),
    Subject(SubjectPattern),
    Kind(PrincipalKind),
    Group(String),
    Source(CommitSource),
    SignedByKey([u8; 32]),
    Preset(Preset),
    AcceptedBy(usize),
    AttributeBy(String, usize),
    All(Vec<usize>),
    Any(Vec<usize>),
    Not(usize),
}

enum Pending {
    Accepted,
    Attribute(String),
    All(usize, Vec<usize>),
    Any(usize, Vec<usize>),
    Not,
}

/// Holds a validated selector and its exact canonical content representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selector {
    pub(super) nodes: Vec<Node>,
    pub(super) root: usize,
    bytes: Vec<u8>,
}

fn text(decoder: &mut Decoder<'_>) -> Result<String, SelectorError> {
    decoder
        .text(decoder.remaining().len())
        .map(ToString::to_string)
        .map_err(|_| SelectorError)
}

fn signing_key(text: &str) -> Result<[u8; 32], SelectorError> {
    if text.len() != 64 {
        return Err(SelectorError);
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(SelectorError),
    };
    let mut key = [0; 32];
    for (output, pair) in key.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *output = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(key)
}

impl Selector {
    /// Identifies acceptance dependencies within each node's principal context.
    ///
    /// Children precede parents in the validated arena. An attribute selector
    /// switches principal context, so its ancestry dependency belongs to its
    /// own child subtree rather than the enclosing content or attribute.
    pub(super) fn acceptance_dependencies(&self) -> Vec<bool> {
        let mut required = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let acceptance = match node {
                Node::AcceptedBy(_) | Node::Preset(Preset::SignedBaseline) => true,
                Node::All(children) | Node::Any(children) => {
                    children.iter().any(|child| required[*child])
                }
                Node::Not(child) => required[*child],
                _ => false,
            };
            required.push(acceptance);
        }
        required
    }

    /// Parses a root trust property as a selector AST or registered preset text.
    ///
    /// # Errors
    /// Returns [`SelectorError`] for invalid selector syntax or an unknown preset.
    pub fn from_property(bytes: &[u8]) -> Result<Self, SelectorError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.peek_major().map_err(|_| SelectorError)? == 3 {
            let preset = Preset::parse(&text(&mut decoder)?)?;
            decoder.finish().map_err(|_| SelectorError)?;
            Ok(Self::preset(preset))
        } else {
            Self::decode(bytes)
        }
    }

    /// Parses canonical CBOR using the closed v1 selector vocabulary.
    ///
    /// Traversal and allocation are bounded by the supplied byte length,
    /// rather than a fixed nesting limit. Attestation claims are rejected
    /// because the initial registry contains no registered claims.
    ///
    /// # Errors
    /// Returns [`SelectorError`] for malformed/noncanonical CBOR, unknown
    /// atoms, attributes or presets, invalid arguments, empty combinators, or
    /// trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SelectorError> {
        let mut decoder = Decoder::new(bytes);
        let mut nodes = Vec::new();
        let mut pending = Vec::new();

        let root = loop {
            let count = decoder.array(bytes.len()).map_err(|_| SelectorError)?;
            let operator = text(&mut decoder)?;
            let expected = if operator == "attr-by" { 3 } else { 2 };
            if count != expected {
                return Err(SelectorError);
            }

            let atom = match operator.as_str() {
                "issuer" => Node::Issuer(text(&mut decoder)?),
                "subject" => Node::Subject(SubjectPattern::new(text(&mut decoder)?)),
                "kind" => Node::Kind(match text(&mut decoder)?.as_str() {
                    "human" => PrincipalKind::Human,
                    "workload" => PrincipalKind::Workload,
                    "service" => PrincipalKind::Service,
                    _ => return Err(SelectorError),
                }),
                "group" => Node::Group(text(&mut decoder)?),
                "source" => Node::Source(match text(&mut decoder)?.as_str() {
                    "built" => CommitSource::Built,
                    "uploaded" => CommitSource::Uploaded,
                    "imported" => CommitSource::Imported,
                    "merged" => CommitSource::Merged,
                    "derived" => CommitSource::Derived,
                    "migrated" => CommitSource::Migrated,
                    _ => return Err(SelectorError),
                }),
                "signed-by-key" => Node::SignedByKey(signing_key(&text(&mut decoder)?)?),
                // No attestation claim is registered in v1. Rejecting the
                // atom prevents negation from admitting unsupported evidence.
                "attested" => return Err(SelectorError),
                "preset" => Node::Preset(Preset::parse(&text(&mut decoder)?)?),
                "accepted-by" => {
                    pending.push(Pending::Accepted);
                    continue;
                }
                "attr-by" => {
                    let name = text(&mut decoder)?;
                    if !crate::properties::registered_attribute(&name) {
                        return Err(SelectorError);
                    }
                    pending.push(Pending::Attribute(name));
                    continue;
                }
                "not" => {
                    pending.push(Pending::Not);
                    continue;
                }
                "all" | "any" => {
                    let count = decoder.array(bytes.len()).map_err(|_| SelectorError)?;
                    if count == 0 {
                        return Err(SelectorError);
                    }
                    pending.push(if operator == "all" {
                        Pending::All(count, Vec::new())
                    } else {
                        Pending::Any(count, Vec::new())
                    });
                    continue;
                }
                _ => return Err(SelectorError),
            };

            nodes.push(atom);
            let mut child = nodes.len() - 1;
            let completed = loop {
                let Some(parent) = pending.pop() else {
                    break Some(child);
                };
                let parent = match parent {
                    Pending::Accepted => Node::AcceptedBy(child),
                    Pending::Attribute(name) => Node::AttributeBy(name, child),
                    Pending::Not => Node::Not(child),
                    Pending::All(count, mut children) => {
                        children.push(child);
                        if children.len() != count {
                            pending.push(Pending::All(count, children));
                            break None;
                        }
                        Node::All(children)
                    }
                    Pending::Any(count, mut children) => {
                        children.push(child);
                        if children.len() != count {
                            pending.push(Pending::Any(count, children));
                            break None;
                        }
                        Node::Any(children)
                    }
                };
                nodes.push(parent);
                child = nodes.len() - 1;
            };
            if let Some(root) = completed {
                break root;
            }
        };

        decoder.finish().map_err(|_| SelectorError)?;
        Ok(Self {
            nodes,
            root,
            bytes: bytes.to_vec(),
        })
    }

    /// Constructs one registered named preset without fallible decoding.
    pub fn preset(preset: Preset) -> Self {
        let mut bytes = Vec::new();
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, "preset");
        cbor::write_text(&mut bytes, preset.name());
        Self {
            nodes: alloc::vec![Node::Preset(preset)],
            root: 0,
            bytes,
        }
    }

    /// Returns the selector's canonical content bytes for memo identity keys.
    pub fn encode(&self) -> &[u8] {
        &self.bytes
    }
}
