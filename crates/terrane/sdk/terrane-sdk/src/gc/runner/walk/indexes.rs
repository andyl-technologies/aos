//! Loads complete bound I/P/G closures and records their actual contextual roles.

use super::{CollectionError, Expansion, INDEX, ROOT, VisitMode, history};
use crate::guard::Guard;
use crate::indexing::{self, ErrorKind};
use crate::store::{Clock, CorruptSubject, Store, StoreErrorKind, StoreFailure};
use std::collections::BTreeSet;
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::indexing::carrier::{self, Role, SemanticContext};
use terrane_format::indexing::evaluation::IndexData;
use terrane_format::tree_format::{self, NodeItems, TreeUse};

/// Verifies each local binding before retaining any contextual auxiliary claims.
///
/// # Errors
/// Preserves requested Node subjects and original loading/relationship errors;
/// refuses unsupported interpretations, missing closures and corrupt role data.
pub(super) async fn expand<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    occurrence: &history::Occurrence,
    mode: VisitMode,
    expansion: &mut Expansion,
) -> Result<(), CollectionError> {
    for (attribute, expected) in &occurrence.bindings {
        let loaded = indexing::load_for(
            guard.store(),
            *occurrence.context.root(),
            attribute,
            occurrence.revisions,
            guard.config().min_chunk_size,
            occurrence.usage,
        )
        .await
        .map_err(failure)?;
        if loaded.index_root() != *expected {
            return Err(history::invalid(
                terrane_format::indexing::evaluation::Error::Relationship,
            )
            .into());
        }
        {
            let sources = loaded.sources().map_err(failure)?;
            let prepared = loaded.prepare(&sources.trees).map_err(failure)?;
            drop(prepared);
        }
        let context = SemanticContext::new(
            occurrence.revisions.property,
            occurrence.revisions.attribute,
            occurrence.revisions.tree,
        )
        .map_err(history::invalid)?;
        record_closure(
            loaded.index_data(),
            context,
            guard.config().min_chunk_size,
            occurrence,
            mode,
            expansion,
        )?;
    }
    Ok(())
}

fn role_key(role: Role) -> u8 {
    match role {
        Role::Primary => 0,
        Role::Gap => 1,
        Role::PresentRoute => 2,
        Role::MissingRoute => 3,
    }
}

/// Visits already checked bytes with explicit edge roles rather than wire guesses.
///
/// # Errors
/// Rejects absent Nodes and physical or role validation failures.
pub(super) fn record_closure(
    data: &IndexData,
    context: SemanticContext,
    minimum: u64,
    occurrence: &history::Occurrence,
    mode: VisitMode,
    expansion: &mut Expansion,
) -> Result<(), StoreFailure> {
    let mut pending = vec![(data.root, Role::Primary, true)];
    let mut visited = BTreeSet::new();
    while let Some((hash, role, is_root)) = pending.pop() {
        if !visited.insert((hash, role_key(role), is_root)) {
            continue;
        }
        let bytes = data.nodes.get(&hash).ok_or_else(|| {
            StoreFailure::with_source(
                StoreErrorKind::Unavailable { retry_after: None },
                terrane_format::indexing::evaluation::Error::MissingNode,
            )
        })?;
        let node = tree_format::decode_node_for(bytes, is_root, minimum, TreeUse::Index)
            .map_err(history::invalid)?;
        let gap =
            carrier::validate_node(context, role, &node, is_root).map_err(history::invalid)?;
        expansion.object(
            2,
            hash,
            INDEX | mode.flags() | if is_root { ROOT } else { 0 },
            &occurrence.context,
        );
        if let Some(gap) = gap {
            pending.push((gap.node(), Role::Gap, true));
        }
        match &node.items {
            NodeItems::Internal(children) => {
                pending.extend(children.iter().map(|child| (child.child, role, false)));
            }
            NodeItems::Leaf(items) => {
                for item in items {
                    let row = carrier::validate_row(context, role, &item.key, &item.entry)
                        .map_err(history::invalid)?;
                    if mode == VisitMode::Full {
                        // prepare verified each row against this root's complete
                        // namespace. Its actual file ContentRef is visited with
                        // the descendant occurrences and supplies side targets.
                        // An Index digest alone cannot classify an object kind.
                        expansion.marks.insert(row.object());
                    }
                    if let Some(route) = row.route() {
                        let next_role = match role {
                            Role::Primary | Role::PresentRoute => Role::PresentRoute,
                            Role::Gap | Role::MissingRoute => Role::MissingRoute,
                        };
                        pending.push((route, next_role, true));
                    }
                }
            }
        }
    }
    Ok(())
}

fn failure(source: indexing::Error) -> StoreFailure {
    let kind = match source.kind() {
        ErrorKind::Incomplete => StoreErrorKind::Unavailable { retry_after: None },
        ErrorKind::Unsupported => StoreErrorKind::Unsupported,
        ErrorKind::Invalid => {
            let Some(subject) = source.subject() else {
                return history::invalid(source);
            };
            let identity = match TERRANE_V1.from_digest(IdentityKind::Node, &subject) {
                Ok(identity) => identity,
                Err(identity_error) => return history::invalid(identity_error),
            };
            StoreErrorKind::Corrupt(CorruptSubject::Identity(identity))
        }
        ErrorKind::Store => match &source {
            indexing::Error::Store { failure, .. } => failure.kind().clone(),
            _ => return history::invalid(source),
        },
    };
    StoreFailure::with_source(kind, source)
}
