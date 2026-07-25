//! Cache stacks: the nestable try/mirror expression over cache endpoints.
//!
//! RFC-0004 ("Cache stores, stacks, and consistency validation") models a
//! registry's committed `[caches]` preference list as a small, nestable
//! expression. A [`StackNode`] is one of:
//!
//! - **endpoint** — a single cache base URL.
//! - **try** — an *ordered fall-through*: a client hits each member
//!   top-to-bottom and the first hit wins, so the stack's availability is the
//!   **union** of its members. This is the user-visible "stack"; it is what
//!   `apm`'s miss-fallthrough implements over the flattened list.
//! - **mirror** — a *replication contract*: every member is expected to hold
//!   the full closure set. A client may fetch from any member (first, or
//!   latency-based), but the validator's invariant is that the
//!   **intersection** of member coverage equals the union — i.e. each member
//!   individually covers everything. A shortfall is a replication failure, not
//!   a fall-through.
//!
//! Nodes nest, e.g. `try [ mirror [r2-eu, r2-us], upstream-cdn, s3-backup ]`:
//! internal fast replicas first, falling through to the upstream public cache,
//! then a cold backup.
//!
//! # Committed TOML encoding
//!
//! A stack is carried in a registry's committed `registry.toml` as the
//! `[caches]` table. Each node is a table that is *either* an endpoint
//! (`{ endpoint = "<url>" }`) *or* an inner node
//! (`{ kind = "try" | "mirror", members = [ <node>, … ] }`):
//!
//! ```toml
//! [caches]
//! kind = "try"
//! members = [
//!   { kind = "mirror", members = [
//!       { endpoint = "https://r2-eu.example.com" },
//!       { endpoint = "https://r2-us.example.com" },
//!   ] },
//!   { endpoint = "https://upstream-cdn.example.com" },
//!   { endpoint = "https://s3-backup.example.com" },
//! ]
//! ```
//!
//! The same node grammar appears at every depth, so the top-level
//! `[caches]` table may itself be a bare endpoint
//! (`[caches]` with `endpoint = "…"`). A registry that advertises a single
//! cache writes `[caches]\nendpoint = "…"`.
//!
//! For backward compatibility a legacy `[[caches]]` array of
//! `{ url, priority }` entries also parses (see
//! [`CachesConfig`](crate::manifest::CachesConfig)); the unified `[caches]`
//! stack is the form new tooling writes.
//!
//! # Flattening to a priority list
//!
//! [`StackNode::flatten`] walks the expression depth-first and yields the
//! endpoint URLs in priority order — exactly the list a stack-unaware client
//! gets. [`to_priority_caches`] turns that order into descending
//! `(url, priority)` pairs the indexer folds into the committed-cache list.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A node in a cache stack: an endpoint, a `try` group, or a `mirror` group.
///
/// See the [module documentation](self) for the union (`try`) versus
/// intersection (`mirror`) semantics and the committed TOML encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackNode {
    /// A single cache endpoint base URL.
    Endpoint(String),
    /// An ordered fall-through group: first hit wins; availability is the
    /// **union** of members.
    Try(Vec<StackNode>),
    /// A declared-replica group: every member is expected to hold the full
    /// set; validation enforces that each member individually covers it.
    Mirror(Vec<StackNode>),
}

/// The wire form of one [`StackNode`] in the committed `[caches]` TOML.
///
/// An untagged enum so serde accepts either an endpoint table
/// (`{ endpoint = "…" }`) or an inner-node table
/// (`{ kind = "try" | "mirror", members = [...] }`) without a discriminant on
/// the endpoint form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum StackNodeToml {
    /// `{ endpoint = "<url>" }`.
    Endpoint {
        /// The cache base URL.
        endpoint: String,
    },
    /// `{ kind = "try" | "mirror", members = [ <node>, … ] }`.
    Inner {
        /// `"try"` or `"mirror"`.
        kind: StackKind,
        /// The member nodes, in order. Defaulted so an empty or missing
        /// `members` is rejected by [`StackNodeToml::into_node`] with a clear
        /// message rather than a generic untagged-enum mismatch.
        #[serde(default)]
        members: Vec<StackNodeToml>,
    },
}

/// The `kind` discriminant of an inner [`StackNodeToml`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StackKind {
    /// Ordered fall-through (union semantics).
    Try,
    /// Declared replicas (intersection-must-equal-union semantics).
    Mirror,
}

/// The JSON storage form of a [`StackNode`], internally tagged by `kind`.
///
/// Distinct from [`StackNodeToml`]: the wire/TOML form is endpoint-or-inner
/// and untagged for ergonomic hand authoring, whereas this form is a single
/// adjacently-tagged shape that round-trips losslessly through `serde_json`
/// for database storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum JsonNode {
    /// A single cache endpoint.
    Endpoint {
        /// The cache base URL.
        url: String,
    },
    /// An ordered fall-through group.
    Try {
        /// Member nodes, in order.
        members: Vec<JsonNode>,
    },
    /// A declared-replica group.
    Mirror {
        /// Member nodes, in order.
        members: Vec<JsonNode>,
    },
}

impl From<&StackNode> for JsonNode {
    fn from(node: &StackNode) -> Self {
        match node {
            StackNode::Endpoint(url) => JsonNode::Endpoint { url: url.clone() },
            StackNode::Try(members) => JsonNode::Try {
                members: members.iter().map(JsonNode::from).collect(),
            },
            StackNode::Mirror(members) => JsonNode::Mirror {
                members: members.iter().map(JsonNode::from).collect(),
            },
        }
    }
}

impl From<JsonNode> for StackNode {
    fn from(node: JsonNode) -> Self {
        match node {
            JsonNode::Endpoint { url } => StackNode::Endpoint(url),
            JsonNode::Try { members } => {
                StackNode::Try(members.into_iter().map(StackNode::from).collect())
            }
            JsonNode::Mirror { members } => {
                StackNode::Mirror(members.into_iter().map(StackNode::from).collect())
            }
        }
    }
}

impl StackNodeToml {
    /// Convert one wire node into a [`StackNode`], rejecting empty groups.
    fn into_node(self) -> Result<StackNode> {
        match self {
            StackNodeToml::Endpoint { endpoint } => {
                if endpoint.trim().is_empty() {
                    anyhow::bail!("[caches] endpoint URL must not be empty");
                }
                Ok(StackNode::Endpoint(endpoint))
            }
            StackNodeToml::Inner { kind, members } => {
                if members.is_empty() {
                    anyhow::bail!("[caches] {kind:?} group must have at least one member");
                }
                let members = members
                    .into_iter()
                    .map(StackNodeToml::into_node)
                    .collect::<Result<Vec<_>>>()?;
                Ok(match kind {
                    StackKind::Try => StackNode::Try(members),
                    StackKind::Mirror => StackNode::Mirror(members),
                })
            }
        }
    }
}

impl StackNode {
    /// Serialize the stack to a compact JSON string for database storage.
    ///
    /// The hub persists a parsed stack alongside the rebuildable index so
    /// validation can recover its [`StackNode::mirror_groups`] without
    /// re-reading the surface; [`StackNode::from_json`] is the inverse.
    ///
    /// # Errors
    ///
    /// Returns an error only if JSON serialization fails, which for this
    /// closed value shape does not occur in practice.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&JsonNode::from(self)).context("serializing cache stack")
    }

    /// Reconstruct a stack from the JSON produced by [`StackNode::to_json`].
    ///
    /// # Errors
    ///
    /// Returns an error when `json` is not the expected shape.
    pub fn from_json(json: &str) -> Result<StackNode> {
        let node: JsonNode = serde_json::from_str(json).context("deserializing cache stack")?;
        Ok(StackNode::from(node))
    }

    /// The endpoint URLs in depth-first order — the priority list a
    /// stack-unaware client sees.
    ///
    /// A `try` or `mirror` group contributes its members left-to-right; an
    /// endpoint contributes itself. Duplicates are preserved (the caller
    /// dedups when building a cache list); use [`StackNode::endpoints`] for a
    /// distinct set.
    pub fn flatten(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.flatten_into(&mut out);
        out
    }

    fn flatten_into(&self, out: &mut Vec<String>) {
        match self {
            StackNode::Endpoint(url) => out.push(url.clone()),
            StackNode::Try(members) | StackNode::Mirror(members) => {
                for member in members {
                    member.flatten_into(out);
                }
            }
        }
    }

    /// All distinct endpoint URLs in the stack, in first-seen depth-first
    /// order.
    pub fn endpoints(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.flatten()
            .into_iter()
            .filter(|url| seen.insert(url.clone()))
            .collect()
    }

    /// The member endpoint set of every `mirror` node, nested groups included.
    ///
    /// Each returned inner vector is one mirror group's endpoints — the set
    /// the validator must check for per-member completeness (every member must
    /// individually cover the closure set). Nested mirrors yield one group
    /// each.
    pub fn mirror_groups(&self) -> Vec<Vec<String>> {
        let mut groups = Vec::new();
        self.mirror_groups_into(&mut groups);
        groups
    }

    fn mirror_groups_into(&self, groups: &mut Vec<Vec<String>>) {
        match self {
            StackNode::Endpoint(_) => {}
            StackNode::Try(members) => {
                for member in members {
                    member.mirror_groups_into(groups);
                }
            }
            StackNode::Mirror(members) => {
                groups.push(self.flatten());
                for member in members {
                    member.mirror_groups_into(groups);
                }
            }
        }
    }
}

/// Parse a committed `[caches]` section into a [`StackNode`].
///
/// Accepts the [TOML node grammar](self) as a [`toml::Value`] — the raw value
/// of the `[caches]` table the indexer pulls from the committed
/// `registry.toml`.
///
/// # Errors
///
/// Returns an error when the value does not match the node grammar (e.g. a
/// table that is neither an endpoint nor a `kind`/`members` inner node), when
/// a group has no members, or when an endpoint URL is empty.
pub fn parse_cache_stack(value: toml::Value) -> Result<StackNode> {
    let wire: StackNodeToml = value.try_into().context("parsing committed [caches]")?;
    wire.into_node()
}

/// Parse a committed `[caches]` section from its TOML source text.
///
/// A convenience wrapper over [`parse_cache_stack`] for callers holding the
/// raw `[caches]` table text (without the leading `[caches]` header) —
/// primarily tests.
///
/// # Errors
///
/// Returns an error when the text is not valid TOML or does not match the
/// node grammar (see [`parse_cache_stack`]).
pub fn parse_cache_stack_str(text: &str) -> Result<StackNode> {
    let value: toml::Value = toml::from_str(text).context("parsing [caches] TOML")?;
    parse_cache_stack(value)
}

/// Flatten a stack into `(url, priority)` pairs with descending priorities.
///
/// The depth-first endpoint order becomes a strictly descending priority
/// sequence starting at `base_priority`: the first (highest-preference)
/// endpoint gets `base_priority`, the next `base_priority - 1`, and so on
/// (saturating at `0` for very deep stacks). Duplicate endpoints keep only
/// their first (highest-priority) occurrence, so the result feeds straight
/// into the indexer's committed-cache list. The order matches what a
/// stack-aware `try` fall-through client would consult.
pub fn to_priority_caches(stack: &StackNode, base_priority: u32) -> Vec<(String, u32)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (offset, url) in stack.flatten().into_iter().enumerate() {
        if !seen.insert(url.clone()) {
            continue;
        }
        let priority = base_priority.saturating_sub(offset as u32);
        out.push((url, priority));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NESTED: &str = r#"
        kind = "try"
        members = [
          { kind = "mirror", members = [
              { endpoint = "https://a" },
              { endpoint = "https://b" },
          ] },
          { endpoint = "https://c" },
        ]
    "#;

    #[test]
    fn parses_nested_try_mirror() {
        let stack = parse_cache_stack_str(NESTED).unwrap();
        assert_eq!(
            stack,
            StackNode::Try(vec![
                StackNode::Mirror(vec![
                    StackNode::Endpoint("https://a".into()),
                    StackNode::Endpoint("https://b".into()),
                ]),
                StackNode::Endpoint("https://c".into()),
            ]),
        );
    }

    #[test]
    fn flatten_is_depth_first() {
        let stack = parse_cache_stack_str(NESTED).unwrap();
        assert_eq!(
            stack.flatten(),
            vec![
                "https://a".to_string(),
                "https://b".to_string(),
                "https://c".to_string(),
            ],
        );
    }

    #[test]
    fn mirror_groups_returns_the_replica_set() {
        let stack = parse_cache_stack_str(NESTED).unwrap();
        assert_eq!(
            stack.mirror_groups(),
            vec![vec!["https://a".to_string(), "https://b".to_string()]],
        );
    }

    #[test]
    fn endpoints_are_distinct_in_order() {
        let stack = StackNode::Try(vec![
            StackNode::Endpoint("https://a".into()),
            StackNode::Endpoint("https://b".into()),
            StackNode::Endpoint("https://a".into()),
        ]);
        assert_eq!(
            stack.endpoints(),
            vec!["https://a".to_string(), "https://b".to_string()],
        );
    }

    #[test]
    fn to_priority_caches_descends() {
        let stack = parse_cache_stack_str(NESTED).unwrap();
        assert_eq!(
            to_priority_caches(&stack, 100),
            vec![
                ("https://a".to_string(), 100),
                ("https://b".to_string(), 99),
                ("https://c".to_string(), 98),
            ],
        );
    }

    #[test]
    fn to_priority_caches_dedups_keeping_highest() {
        let stack = StackNode::Try(vec![
            StackNode::Endpoint("https://a".into()),
            StackNode::Endpoint("https://b".into()),
            StackNode::Endpoint("https://a".into()),
        ]);
        assert_eq!(
            to_priority_caches(&stack, 50),
            vec![("https://a".to_string(), 50), ("https://b".to_string(), 49)],
        );
    }

    #[test]
    fn bare_endpoint_stack_round_trips() {
        let stack = parse_cache_stack_str(r#"endpoint = "https://only""#).unwrap();
        assert_eq!(stack, StackNode::Endpoint("https://only".into()));
        assert_eq!(stack.mirror_groups(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn empty_group_is_rejected() {
        let err = parse_cache_stack_str(r#"kind = "try""#).unwrap_err();
        assert!(format!("{err:#}").contains("member"), "{err:#}");
    }

    #[test]
    fn empty_endpoint_is_rejected() {
        let err = parse_cache_stack_str(r#"endpoint = "  ""#).unwrap_err();
        assert!(format!("{err:#}").contains("empty"), "{err:#}");
    }

    #[test]
    fn malformed_node_is_rejected() {
        // A table that is neither an endpoint nor a kind/members inner node.
        let err = parse_cache_stack_str(r#"nonsense = true"#).unwrap_err();
        assert!(format!("{err:#}").contains("caches"), "{err:#}");
    }

    #[test]
    fn json_round_trips() {
        let stack = parse_cache_stack_str(NESTED).unwrap();
        let json = stack.to_json().unwrap();
        assert_eq!(StackNode::from_json(&json).unwrap(), stack);
    }

    #[test]
    fn nested_mirror_groups_each_reported() {
        let stack = StackNode::Try(vec![
            StackNode::Mirror(vec![
                StackNode::Endpoint("https://a".into()),
                StackNode::Mirror(vec![
                    StackNode::Endpoint("https://b".into()),
                    StackNode::Endpoint("https://c".into()),
                ]),
            ]),
            StackNode::Endpoint("https://d".into()),
        ]);
        let groups = stack.mirror_groups();
        assert_eq!(groups.len(), 2);
        // Outer mirror flattens all three of its endpoints; inner mirror two.
        assert_eq!(
            groups[0],
            vec![
                "https://a".to_string(),
                "https://b".to_string(),
                "https://c".to_string()
            ],
        );
        assert_eq!(
            groups[1],
            vec!["https://b".to_string(), "https://c".to_string()],
        );
    }
}
