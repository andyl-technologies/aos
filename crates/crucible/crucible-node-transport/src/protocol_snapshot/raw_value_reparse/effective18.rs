//! Retains an iterative, grant-free effective JSON text-pass attempt.
//!
//! The flat arena preserves the locked Value visitor's first-key RawValue
//! branch and duplicate last-wins object semantics. Every text/work bank is
//! installed and independently quoted before decoding. Arena children are
//! indices, so even refused deep intermediate shapes have constant-stack Drop.
//! This is one text-to-Value normalization pass, not an Envelope decoder or a
//! proof that subsequent owned-Value/ResponseShape adapter passes are safe.
//!
//! Compatibility is pinned to the workspace's locked serde_json1.0.150 feature
//! closure: ordinary Number and BTreeMap objects, without arbitrary_precision
//! or preserve_order. The shallow probe selects RawValue behavior only; it
//! does not prove compatibility with a different Number or object-map profile.

use super::{RAW_VALUE_KEY, geometry};
use crate::ProviderError;
use crate::protocol_snapshot::owned11::json_value::{
    NativeImport18JsonLexicalCursorData as Cursor, NativeImport18JsonLexicalTokenData as Token,
    native_import18_json_lexical_counter_scratch_data,
};
use serde_json::{Number, Value};
use std::collections::BTreeMap;
use std::mem::{align_of, size_of};

mod storage;
pub(crate) use storage::NativeImport18EffectiveTextConstructionData;

// Locked serde_json starts at128 and refuses the decrement that reaches zero.
const TEXT_CONTAINER_LIMIT: usize = 127;
const RAW_PROBE: &str = r#"{"$serde_json::private::RawValue":"null"}"#;

#[derive(Clone, Copy)]
enum RawMode {
    Ordinary,
    Reparse,
}

struct Node {
    kind: Kind,
}

enum Kind {
    Null,
    Bool(bool),
    Number(Number),
    String(usize),
    Array {
        first: Option<usize>,
        last: Option<usize>,
    },
    Object(BTreeMap<String, usize>),
    Alias(Option<usize>),
}

struct Edge {
    value: usize,
    next: Option<usize>,
}

#[derive(Clone, Copy)]
struct Job {
    text: usize,
    position: usize,
    local_depth: usize,
    expanded_depth: usize,
}

#[derive(Clone, Copy)]
struct Returned {
    value: usize,
    text: usize,
    position: usize,
}

enum Frame {
    Array { node: usize, job: Job },
    Object { node: usize, key: usize, job: Job },
    Raw { node: usize, outer: Returned },
}

#[derive(Clone, Copy)]
enum Lexical {
    Null,
    Bool(bool),
    Number {
        start: usize,
        end: usize,
    },
    String {
        start: usize,
        end: usize,
        decoded: usize,
    },
    Array,
    ArrayEnd,
    Object,
    ObjectEnd,
    Colon,
    Comma,
    End,
}

/// Owns every initialized flat/text/work prefix through success or refusal.
///
/// No field contains a recursive Value. Completed views are inert normalization
/// DATA only and cannot issue SDK slots, native phases, memory or currentness.
pub(crate) struct NativeImport18EffectiveTextAttemptData {
    started: bool,
    failed: bool,
    complete: bool,
    mode: Option<RawMode>,
    row: NativeImport18EffectiveTextConstructionData,
    texts: Vec<String>,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    frames: Vec<Frame>,
    requested_text: usize,
    inserted_members: usize,
    maximum_intermediate_depth: usize,
    root: Option<usize>,
}

impl NativeImport18EffectiveTextAttemptData {
    /// Installs a spent partial before any reserve, probe, decode or node work.
    ///
    /// The caller independently admits the row beside all prior owners first.
    /// Literal/Raw semantics are derived from the actual locked serde build,
    /// never from a caller-selected feature Boolean or a protocol grant.
    ///
    /// # Errors
    /// Refuses a used slot, foreign row/input, capacity, lexical/parser semantics
    /// or depth/workspace exhaustion. Every initialized owning prefix remains.
    pub(crate) fn read_into_data(
        input: &str,
        row: &NativeImport18EffectiveTextConstructionData,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        *output = Some(Self {
            started: true,
            failed: true,
            complete: false,
            mode: None,
            row: *row,
            texts: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            frames: Vec::new(),
            requested_text: 0,
            inserted_members: 0,
            maximum_intermediate_depth: 0,
            root: None,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.row.authenticate_data(input)?;
        owner.reserve_data()?;
        owner.mode = Some(actual_raw_mode_data()?);
        owner.texts.push(String::new());
        owner.requested_text = input.len();
        owner.texts[0]
            .try_reserve_exact(input.len())
            .map_err(|_| exhausted())?;
        owner.texts[0].push_str(input);
        owner.run_data()?;
        owner.retained_requested_storage_data(row.retained_requested_bytes_data())?;
        owner.complete = true;
        owner.failed = false;
        Ok(())
    }

    fn reserve_data(&mut self) -> Result<(), ProviderError> {
        self.texts
            .try_reserve_exact(self.row.text_slots)
            .map_err(|_| exhausted())?;
        self.nodes
            .try_reserve_exact(self.row.nodes)
            .map_err(|_| exhausted())?;
        self.edges
            .try_reserve_exact(self.row.nodes)
            .map_err(|_| exhausted())?;
        self.frames
            .try_reserve_exact(self.row.nodes)
            .map_err(|_| exhausted())?;
        Ok(())
    }

    fn run_data(&mut self) -> Result<(), ProviderError> {
        let mut next = Some(Job {
            text: 0,
            position: 0,
            local_depth: 0,
            expanded_depth: 0,
        });
        let mut returned = None;
        loop {
            if let Some(job) = next.take() {
                let (token, position) = self.lexical_data(job.text, job.position)?;
                let value = match token {
                    Lexical::Null => self.node_data(Kind::Null)?,
                    Lexical::Bool(value) => self.node_data(Kind::Bool(value))?,
                    Lexical::Number { start, end } => {
                        // Scalar-only locked parsing preserves long decimals and
                        // exact finite-number semantics without recursive owners.
                        let number =
                            serde_json::from_str::<Number>(&self.texts[job.text][start..end])
                                .map_err(|_| invalid())?;
                        self.node_data(Kind::Number(number))?
                    }
                    Lexical::String {
                        start,
                        end,
                        decoded,
                    } => {
                        let text = self.decode_text_data(job.text, start, end, decoded)?;
                        self.node_data(Kind::String(text))?
                    }
                    Lexical::Array | Lexical::Object => {
                        if job.local_depth >= TEXT_CONTAINER_LIMIT {
                            return Err(invalid());
                        }
                        let child = Job {
                            position,
                            local_depth: job.local_depth + 1,
                            expanded_depth: job
                                .expanded_depth
                                .checked_add(1)
                                .ok_or_else(exhausted)?,
                            ..job
                        };
                        if matches!(token, Lexical::Array) {
                            self.maximum_intermediate_depth =
                                self.maximum_intermediate_depth.max(child.expanded_depth);
                            let node = self.node_data(Kind::Array {
                                first: None,
                                last: None,
                            })?;
                            let (peek, after) = self.lexical_data(job.text, position)?;
                            if matches!(peek, Lexical::ArrayEnd) {
                                returned = Some(Returned {
                                    value: node,
                                    text: job.text,
                                    position: after,
                                });
                            } else {
                                self.frame_data(Frame::Array { node, job: child })?;
                                next = Some(child);
                            }
                        } else {
                            let (key, after_key) = self.lexical_data(job.text, position)?;
                            if matches!(key, Lexical::ObjectEnd) {
                                self.maximum_intermediate_depth =
                                    self.maximum_intermediate_depth.max(child.expanded_depth);
                                let node = self.node_data(Kind::Object(BTreeMap::new()))?;
                                returned = Some(Returned {
                                    value: node,
                                    text: job.text,
                                    position: after_key,
                                });
                            } else {
                                let key = self.key_data(job.text, key)?;
                                let after_colon = self.colon_data(job.text, after_key)?;
                                if matches!(self.mode, Some(RawMode::Reparse))
                                    && self.texts[key] == RAW_VALUE_KEY
                                {
                                    let (payload, after_payload) =
                                        self.lexical_data(job.text, after_colon)?;
                                    let Lexical::String {
                                        start,
                                        end,
                                        decoded,
                                    } = payload
                                    else {
                                        return Err(invalid());
                                    };
                                    let payload =
                                        self.decode_text_data(job.text, start, end, decoded)?;
                                    let node = self.node_data(Kind::Alias(None))?;
                                    self.frame_data(Frame::Raw {
                                        node,
                                        outer: Returned {
                                            value: node,
                                            text: job.text,
                                            position: after_payload,
                                        },
                                    })?;
                                    next = Some(Job {
                                        text: payload,
                                        position: 0,
                                        local_depth: 0,
                                        expanded_depth: job.expanded_depth,
                                    });
                                } else {
                                    self.maximum_intermediate_depth =
                                        self.maximum_intermediate_depth.max(child.expanded_depth);
                                    let node = self.node_data(Kind::Object(BTreeMap::new()))?;
                                    self.frame_data(Frame::Object {
                                        node,
                                        key,
                                        job: child,
                                    })?;
                                    next = Some(Job {
                                        position: after_colon,
                                        ..child
                                    });
                                }
                            }
                        }
                        continue;
                    }
                    _ => return Err(invalid()),
                };
                returned = Some(Returned {
                    value,
                    text: job.text,
                    position,
                });
            }

            let value = returned.take().ok_or_else(invalid)?;
            let Some(frame) = self.frames.pop() else {
                if !matches!(
                    self.lexical_data(value.text, value.position)?.0,
                    Lexical::End
                ) {
                    return Err(invalid());
                }
                self.root = Some(value.value);
                return Ok(());
            };
            match frame {
                Frame::Raw { node, outer } => {
                    if !matches!(
                        self.lexical_data(value.text, value.position)?.0,
                        Lexical::End
                    ) {
                        return Err(invalid());
                    }
                    self.nodes[node].kind = Kind::Alias(Some(value.value));
                    // The locked Value visitor completes the inner parser
                    // before end_map checks the outer tail. Keep the linked
                    // flat child even when that later tail refuses.
                    let (closing, position) = self.lexical_data(outer.text, outer.position)?;
                    if !matches!(closing, Lexical::ObjectEnd) {
                        return Err(invalid());
                    }
                    returned = Some(Returned { position, ..outer });
                }
                Frame::Array { node, job } => {
                    self.append_array_data(node, value.value)?;
                    let (separator, position) = self.lexical_data(value.text, value.position)?;
                    match separator {
                        Lexical::ArrayEnd => {
                            returned = Some(Returned {
                                value: node,
                                text: job.text,
                                position,
                            })
                        }
                        Lexical::Comma => {
                            self.frame_data(Frame::Array { node, job })?;
                            next = Some(Job { position, ..job });
                        }
                        _ => return Err(invalid()),
                    }
                }
                Frame::Object { node, key, job } => {
                    self.insert_object_data(node, key, value.value)?;
                    let (separator, position) = self.lexical_data(value.text, value.position)?;
                    match separator {
                        Lexical::ObjectEnd => {
                            returned = Some(Returned {
                                value: node,
                                text: job.text,
                                position,
                            })
                        }
                        Lexical::Comma => {
                            let (key, position) = self.lexical_data(job.text, position)?;
                            let key = self.key_data(job.text, key)?;
                            let position = self.colon_data(job.text, position)?;
                            self.frame_data(Frame::Object { node, key, job })?;
                            next = Some(Job { position, ..job });
                        }
                        _ => return Err(invalid()),
                    }
                }
            }
        }
    }

    fn lexical_data(
        &self,
        text: usize,
        position: usize,
    ) -> Result<(Lexical, usize), ProviderError> {
        let input = self.texts.get(text).ok_or_else(invalid)?;
        let mut cursor = Cursor::resume_data(input, position)?;
        let token = cursor.next_data()?;
        let end = cursor.position_data();
        let token = match token {
            None => Lexical::End,
            Some(Token::Null) => Lexical::Null,
            Some(Token::Bool(value)) => Lexical::Bool(value),
            Some(Token::Number(value)) => Lexical::Number {
                start: end - value.len(),
                end,
            },
            Some(Token::String(value)) => Lexical::String {
                start: end - value.quoted_data().len(),
                end,
                decoded: value.decoded_bytes_data(),
            },
            Some(Token::Array) => Lexical::Array,
            Some(Token::ArrayEnd) => Lexical::ArrayEnd,
            Some(Token::Object) => Lexical::Object,
            Some(Token::ObjectEnd) => Lexical::ObjectEnd,
            Some(Token::Colon) => Lexical::Colon,
            Some(Token::Comma) => Lexical::Comma,
        };
        Ok((token, end))
    }

    fn decode_text_data(
        &mut self,
        source: usize,
        start: usize,
        end: usize,
        decoded: usize,
    ) -> Result<usize, ProviderError> {
        if self.texts.len() >= self.row.text_slots {
            return Err(exhausted());
        }
        let output = self.texts.len();
        self.texts.push(String::new());
        self.requested_text = self
            .requested_text
            .checked_add(decoded)
            .ok_or_else(exhausted)?;
        if self.requested_text > self.row.text_bytes || source >= output {
            return Err(exhausted());
        }
        let (inputs, outputs) = self.texts.split_at_mut(output);
        let input = inputs
            .get(source)
            .and_then(|text| text.get(start..end))
            .ok_or_else(invalid)?;
        let mut cursor = Cursor::new_data(input);
        let Some(Token::String(span)) = cursor.next_data()? else {
            return Err(invalid());
        };
        span.decode_into_data(&mut outputs[0])?;
        Ok(output)
    }

    fn key_data(&mut self, text: usize, token: Lexical) -> Result<usize, ProviderError> {
        let Lexical::String {
            start,
            end,
            decoded,
        } = token
        else {
            return Err(invalid());
        };
        self.decode_text_data(text, start, end, decoded)
    }

    fn colon_data(&self, text: usize, position: usize) -> Result<usize, ProviderError> {
        let (token, position) = self.lexical_data(text, position)?;
        if !matches!(token, Lexical::Colon) {
            return Err(invalid());
        }
        Ok(position)
    }

    fn node_data(&mut self, kind: Kind) -> Result<usize, ProviderError> {
        if self.nodes.len() >= self.row.nodes {
            return Err(exhausted());
        }
        let index = self.nodes.len();
        self.nodes.push(Node { kind });
        Ok(index)
    }

    fn frame_data(&mut self, frame: Frame) -> Result<(), ProviderError> {
        if self.frames.len() >= self.row.nodes {
            return Err(exhausted());
        }
        self.frames.push(frame);
        Ok(())
    }

    fn append_array_data(&mut self, node: usize, value: usize) -> Result<(), ProviderError> {
        if self.edges.len() >= self.row.nodes {
            return Err(exhausted());
        }
        let next = self.edges.len();
        self.edges.push(Edge { value, next: None });
        let Kind::Array { first, last } = &mut self.nodes[node].kind else {
            return Err(invalid());
        };
        if let Some(last) = *last {
            self.edges[last].next = Some(next);
        } else {
            *first = Some(next);
        }
        *last = Some(next);
        Ok(())
    }

    fn insert_object_data(
        &mut self,
        node: usize,
        key: usize,
        value: usize,
    ) -> Result<(), ProviderError> {
        let Kind::Object(values) = &mut self.nodes[node].kind else {
            return Err(invalid());
        };
        if let Some(previous) = values.get_mut(self.texts[key].as_str()) {
            *previous = value;
        } else {
            self.inserted_members = self.inserted_members.checked_add(1).ok_or_else(exhausted)?;
            if self.inserted_members > self.row.nodes {
                return Err(exhausted());
            }
            // Move the retained decoded key into its final shallow map. A
            // duplicate key keeps the previous key owner and retains the new
            // text bank, while its previous flat value nodes remain initialized.
            values.insert(std::mem::take(&mut self.texts[key]), value);
        }
        Ok(())
    }

    /// Borrows the actual completed flat root without constructing a Value.
    ///
    /// # Errors
    /// Refuses a partial/failed attempt or missing actual root.
    pub(crate) fn completed_data(
        &self,
    ) -> Result<NativeImport18EffectiveValueViewData<'_>, ProviderError> {
        if !self.started || self.failed || !self.complete {
            return Err(invalid());
        }
        Ok(NativeImport18EffectiveValueViewData {
            owner: self,
            node: self.root.ok_or_else(invalid)?,
        })
    }

    /// Returns observed intermediate logical depth, including overwritten nodes.
    ///
    /// No recursive Value was materialized at this depth; the flat arena alone
    /// owns these nodes. A future typed adapter must prove its own safe boundary.
    pub(crate) const fn maximum_intermediate_depth_data(&self) -> usize {
        self.maximum_intermediate_depth
    }
}

/// Borrows one actual effective node without reconstructing a native/SDK owner.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18EffectiveValueViewData<'a> {
    owner: &'a NativeImport18EffectiveTextAttemptData,
    node: usize,
}

/// Lends only scalar text and shallow child-index iterators.
pub(crate) enum NativeImport18EffectiveValueKindData<'a> {
    /// Lends JSON null.
    Null,
    /// Lends the actual normalized Boolean.
    Bool(bool),
    /// Borrows the actual locked scalar-parser result.
    Number(&'a Number),
    /// Borrows one retained decoded UTF-8 string bank.
    String(&'a str),
    /// Iterates actual child indices in source array order.
    Array(EffectiveArray<'a>),
    /// Iterates actual final members in the selected BTreeMap order.
    Object(EffectiveObject<'a>),
}

/// Iterates shallow array edges without recursively owning their children.
pub(crate) struct EffectiveArray<'a> {
    owner: &'a NativeImport18EffectiveTextAttemptData,
    next: Option<usize>,
}

/// Iterates final decoded keys and flat value indices without copies.
pub(crate) struct EffectiveObject<'a> {
    owner: &'a NativeImport18EffectiveTextAttemptData,
    entries: std::collections::btree_map::Iter<'a, String, usize>,
}

impl<'a> NativeImport18EffectiveValueViewData<'a> {
    /// Resolves only private acyclic aliases and lends the actual stored kind.
    ///
    /// # Errors
    /// Refuses an incomplete alias or inconsistent private index.
    pub(crate) fn kind_data(
        self,
    ) -> Result<NativeImport18EffectiveValueKindData<'a>, ProviderError> {
        let mut node = self.node;
        for _ in 0..self.owner.nodes.len() {
            match &self.owner.nodes.get(node).ok_or_else(invalid)?.kind {
                Kind::Alias(Some(target)) => node = *target,
                Kind::Alias(None) => return Err(invalid()),
                Kind::Null => return Ok(NativeImport18EffectiveValueKindData::Null),
                Kind::Bool(value) => return Ok(NativeImport18EffectiveValueKindData::Bool(*value)),
                Kind::Number(value) => {
                    return Ok(NativeImport18EffectiveValueKindData::Number(value));
                }
                Kind::String(text) => {
                    return Ok(NativeImport18EffectiveValueKindData::String(
                        &self.owner.texts[*text],
                    ));
                }
                Kind::Array { first, .. } => {
                    return Ok(NativeImport18EffectiveValueKindData::Array(
                        EffectiveArray {
                            owner: self.owner,
                            next: *first,
                        },
                    ));
                }
                Kind::Object(values) => {
                    return Ok(NativeImport18EffectiveValueKindData::Object(
                        EffectiveObject {
                            owner: self.owner,
                            entries: values.iter(),
                        },
                    ));
                }
            }
        }
        Err(invalid())
    }
}

impl<'a> Iterator for EffectiveArray<'a> {
    type Item = NativeImport18EffectiveValueViewData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let edge = self.owner.edges.get(self.next?)?;
        self.next = edge.next;
        Some(NativeImport18EffectiveValueViewData {
            owner: self.owner,
            node: edge.value,
        })
    }
}

impl<'a> Iterator for EffectiveObject<'a> {
    type Item = (&'a str, NativeImport18EffectiveValueViewData<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.entries.next()?;
        Some((
            key.as_str(),
            NativeImport18EffectiveValueViewData {
                owner: self.owner,
                node: *value,
            },
        ))
    }
}

fn actual_raw_mode_data() -> Result<RawMode, ProviderError> {
    // Independently quoted fixed shallow probe: no user tree, key/registration
    // authority or caller-selectable flag participates in feature detection.
    let probe: Value = serde_json::from_str(RAW_PROBE).map_err(|_| invalid())?;
    match &probe {
        Value::Null => Ok(RawMode::Reparse),
        Value::Object(fields)
            if fields.len() == 1
                && fields.get(RAW_VALUE_KEY).and_then(Value::as_str) == Some("null") =>
        {
            Ok(RawMode::Ordinary)
        }
        _ => Err(invalid()),
    }
}

fn invalid() -> ProviderError {
    ProviderError::Frame("explicit18 effective text normalization")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("explicit18 effective text workspace")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only shallow fixtures use recursive serde Values for comparison. Deep
    // DATA controls inspect flat indices/depth and never reconstruct a Value.
    fn shallow_value(view: NativeImport18EffectiveValueViewData<'_>) -> Value {
        match view.kind_data().unwrap() {
            NativeImport18EffectiveValueKindData::Null => Value::Null,
            NativeImport18EffectiveValueKindData::Bool(value) => Value::Bool(value),
            NativeImport18EffectiveValueKindData::Number(value) => Value::Number(value.clone()),
            NativeImport18EffectiveValueKindData::String(value) => Value::String(value.into()),
            NativeImport18EffectiveValueKindData::Array(values) => {
                Value::Array(values.map(shallow_value).collect())
            }
            NativeImport18EffectiveValueKindData::Object(values) => Value::Object(
                values
                    .map(|(key, value)| (key.to_owned(), shallow_value(value)))
                    .collect(),
            ),
        }
    }

    fn assert_locked_text_semantics(input: &str) {
        let row =
            NativeImport18EffectiveTextConstructionData::quote_data(input, usize::MAX).unwrap();
        let mut attempt = None;
        let actual =
            NativeImport18EffectiveTextAttemptData::read_into_data(input, &row, &mut attempt);
        let expected = serde_json::from_str::<Value>(input);
        assert_eq!(actual.is_ok(), expected.is_ok(), "{input}");
        let attempt = attempt.as_ref().unwrap();
        assert!(
            attempt.retained_requested_storage_data(usize::MAX).unwrap()
                <= row.retained_requested_bytes_data()
        );
        if let Ok(expected) = expected {
            assert_eq!(
                shallow_value(attempt.completed_data().unwrap()),
                expected,
                "{input}"
            );
        } else {
            assert!(attempt.failed);
            assert!(!attempt.complete);
            assert!(attempt.completed_data().is_err());
        }
    }

    #[test]
    fn shallow_text_normalization_matches_locked_serde_without_order_assumptions() {
        for input in [
            "null",
            "true",
            "[false, -0.0, 1e-20]",
            r#"{"b":2,"a":1,"a":3}"#,
            r#"{"\u0061":1,"a":2}"#,
            r#""quotes \" \\ \ud83d\ude80""#,
            r#"{"$serde_json::private::RawValue":"[1,\"x\"]"}"#,
            r#"{"z":0,"$serde_json::private::RawValue":"null"}"#,
            r#"{"$serde_json::private::RawValue":"null","later":1}"#,
            r#"{"$serde_json::private::RawValue":[]}"#,
            r#"{"$serde_json::private::RawValue":""}"#,
            "[1,]",
            r#"{"x":}"#,
        ] {
            assert_locked_text_semantics(input);
        }
        let long_decimal = format!("0.{}1", "0".repeat(160));
        assert_locked_text_semantics(&long_decimal);
    }

    #[test]
    fn nested_raw_strings_and_duplicate_last_wins_match_locked_serde() {
        let mut input = r#"{"same":1,"same":2,"text":"\ud83d\ude80"}"#.to_owned();
        for _ in 0..3 {
            input = format!(
                r#"{{"$serde_json::private::RawValue":{}}}"#,
                serde_json::to_string(&input).unwrap()
            );
            assert_locked_text_semantics(&input);
        }
    }

    #[test]
    fn refused_partial_and_spare_workspace_remain_owned_and_nonretryable() {
        let input = r#"{"first":[1,2],"second":"unterminated}"#;
        let row =
            NativeImport18EffectiveTextConstructionData::quote_data(input, usize::MAX).unwrap();
        let mut output = None;

        assert!(
            NativeImport18EffectiveTextAttemptData::read_into_data(input, &row, &mut output)
                .is_err()
        );
        let owner = output.as_ref().unwrap();
        assert!(owner.started && owner.failed && !owner.complete);
        assert!(owner.texts.capacity() >= row.text_slots);
        assert!(owner.nodes.capacity() >= row.nodes);
        assert!(!owner.texts.is_empty());
        let retained = owner.retained_requested_storage_data(usize::MAX).unwrap();
        assert!(retained > size_of::<NativeImport18EffectiveTextAttemptData>());
        assert!(retained <= row.retained_requested_bytes_data());
        assert!(
            NativeImport18EffectiveTextAttemptData::read_into_data(input, &row, &mut output)
                .is_err()
        );
        assert_eq!(
            output
                .as_ref()
                .unwrap()
                .retained_requested_storage_data(usize::MAX)
                .unwrap(),
            retained
        );
    }

    #[test]
    fn independently_reset_parsers_keep_deep_intermediate_nodes_flat() {
        let mut input = "null".to_owned();
        for _ in 0..3 {
            let wrapped = format!(
                r#"{{"$serde_json::private::RawValue":{}}}"#,
                serde_json::to_string(&input).unwrap()
            );
            input = format!("{}{}{}", "[".repeat(70), wrapped, "]".repeat(70));
        }
        let row =
            NativeImport18EffectiveTextConstructionData::quote_data(&input, usize::MAX).unwrap();
        let mut output = None;
        NativeImport18EffectiveTextAttemptData::read_into_data(&input, &row, &mut output).unwrap();
        let owner = output.as_ref().unwrap();
        if matches!(owner.mode, Some(RawMode::Reparse)) {
            assert!(owner.maximum_intermediate_depth_data() > 128);
        }
        // Only flat arena members/String/BTreeMap<String,usize> are dropped.
        drop(output);
    }

    #[test]
    fn raw_tail_refusal_keeps_the_already_parsed_deep_child() {
        let child = format!("{}null{}", "[".repeat(80), "]".repeat(80));
        let payload = serde_json::to_string(&child).unwrap();
        for tail in [",\"later\":1}", "", ","] {
            let input = format!("{{\"$serde_json::private::RawValue\":{payload}{tail}");
            let row = NativeImport18EffectiveTextConstructionData::quote_data(&input, usize::MAX)
                .unwrap();
            let mut output = None;

            let result =
                NativeImport18EffectiveTextAttemptData::read_into_data(&input, &row, &mut output);
            let expected = serde_json::from_str::<Value>(&input);
            assert_eq!(result.is_ok(), expected.is_ok());
            let owner = output.as_ref().unwrap();
            if result.is_err() {
                assert!(owner.failed);
                assert!(owner.completed_data().is_err());
            } else {
                assert!(owner.completed_data().is_ok());
            }
            if matches!(owner.mode, Some(RawMode::Reparse)) {
                assert!(result.is_err());
                assert!(expected.is_err());
                let target = owner
                    .nodes
                    .iter()
                    .find_map(|node| match node.kind {
                        Kind::Alias(Some(target)) => Some(target),
                        _ => None,
                    })
                    .unwrap();
                assert!(matches!(owner.nodes[target].kind, Kind::Array { .. }));
                assert!(owner.nodes.len() > 80);
                assert!(owner.edges.len() >= 80);
                assert!(owner.maximum_intermediate_depth_data() >= 80);
                assert!(owner.texts.iter().any(|text| text == &child));
            }
            let before = owner.retained_requested_storage_data(usize::MAX).unwrap();
            assert!(before <= row.retained_requested_bytes_data());
            assert!(
                NativeImport18EffectiveTextAttemptData::read_into_data(&input, &row, &mut output)
                    .is_err()
            );
            assert_eq!(
                output
                    .as_ref()
                    .unwrap()
                    .retained_requested_storage_data(usize::MAX)
                    .unwrap(),
                before
            );
        }
    }
}

mod owned_value;
pub(crate) use owned_value::{
    NativeImport18OwnedValuePassAttemptData, NativeImport18OwnedValuePassConstructionData,
    NativeImport18OwnedValuePassKindData, NativeImport18OwnedValuePassViewData,
};

#[path = "effective18/materialize_value.rs"]
pub(crate) mod materialize_value;
