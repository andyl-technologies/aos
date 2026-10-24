//! Joins a bounded group of already reached ordinary Node reads.
//!
//! Results carry bytes or the original failure, never validation or authority.
//! The owner consumes them in its unchanged depth-first validation order.

use super::*;
use crate::store::StoreFailure;
use std::future::poll_fn;
use std::task::Poll;
use terrane_format::identity::Identity;

/// Limits pending and completed read slots together to eight subjects.
/// Planning examines at most `WIDTH - 1` prospective DFS visits per fill;
/// the currently required subject occupies the first read slot.
pub(super) const WIDTH: usize = 8;

/// Retains opaque bytes or the original backend failure for DFS consumption.
pub(super) type Outcome = Result<Vec<u8>, StoreFailure>;

#[cfg(feature = "send")]
type ReadFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send + 'a>>;

#[cfg(not(feature = "send"))]
type ReadFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + 'a>>;

/// Owns at most one frontier's results until their DFS subjects are consumed.
#[derive(Default)]
pub(super) struct Frontier {
    outcomes: BTreeMap<Digest, Outcome>,
}

impl Frontier {
    /// Reports whether an unread outcome is retained for the subject.
    pub(super) fn contains(&self, node: &Digest) -> bool {
        self.outcomes.contains_key(node)
    }

    /// Returns free slots under the invariant that retained outcomes never exceed WIDTH.
    pub(super) fn remaining(&self) -> usize {
        WIDTH - self.outcomes.len()
    }

    /// Removes the outcome when its original DFS subject is consumed.
    pub(super) fn take(&mut self, node: &Digest) -> Option<Outcome> {
        self.outcomes.remove(node)
    }

    /// Polls only the supplied known subjects, retaining errors for DFS consumption.
    ///
    /// Identities outlive their borrowed Store futures. Pending and completed
    /// slots together stay within WIDTH, including earlier retained outcomes.
    /// Dropping this await drops every future; no operation is detached.
    ///
    /// # Errors
    /// Rejects an oversized internal frontier or an unrepresentable Node identity.
    /// Backend failures remain ordinary outcomes until their DFS subject is consumed.
    pub(super) async fn fill<S: ContentStore + ?Sized>(
        &mut self,
        store: &S,
        nodes: &[Digest],
    ) -> Result<(), Error> {
        if nodes.len() > self.remaining() {
            return Err(Error::Unsupported);
        }
        let identities = nodes
            .iter()
            .map(|node| {
                TERRANE_V1
                    .from_digest(IdentityKind::Node, node)
                    .map_err(|_| invalid(*node, evaluation::Error::Source))
            })
            .collect::<Result<Vec<Identity>, Error>>()?;
        let mut futures: Vec<Option<ReadFuture<'_>>> = identities
            .iter()
            .map(|identity| Some(store.get(identity, None)))
            .collect();
        poll_fn(|context| {
            let mut pending = false;
            for (node, future) in nodes.iter().zip(&mut futures) {
                let Some(read) = future else {
                    continue;
                };
                match read.as_mut().poll(context) {
                    Poll::Ready(outcome) => {
                        self.outcomes.insert(*node, outcome);
                        *future = None;
                    }
                    Poll::Pending => pending = true,
                }
            }
            if pending {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        Ok(())
    }
}

/// Screens prospective subjects before I/O without consuming their DFS checks.
pub(super) fn permitted(visit: &Visit) -> bool {
    visit.physical.len() <= usize::from(MAX_TREE_LEVEL)
        && !visit.physical.contains(&visit.node)
        && (!visit.is_root
            || (visit.roots.len() <= MAX_GRAFT_DEPTH && !visit.roots.contains(&visit.node)))
}

#[cfg(test)]
mod tests;
