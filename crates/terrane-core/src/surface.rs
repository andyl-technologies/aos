//! Pure view selectors, endpoints, exposure records, and tree schemas (SURF-1).
//!
//! Selectors contain no backend credentials and perform no I/O:
//!
//! ```text
//! refs/heads/main:/subtree@policy
//! commit:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//! ```

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use crate::{identity::Digest, refs::RefName, tree_format::validate_key};

/// Selects a mutable reference or an immutable commit (SURF-6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ViewTarget {
    /// Resolves a reference through the repository.
    Ref(RefName),
    /// Pins the exact commit identity.
    Commit(Digest),
}

/// Selects the repository content presented by an exposure (SURF-6 to SURF-8).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct View {
    /// The reference or immutable commit being exposed.
    pub target: ViewTarget,
    /// Root-relative subtree key; empty means the complete tree.
    pub subtree: Vec<u8>,
    /// Registered policy name, resolved by the repository before serving.
    pub policy: Option<String>,
}

impl View {
    /// Parses the view selector grammar without resolving content or policies.
    ///
    /// # Errors
    /// Rejects malformed reference names, digest lengths, subtree keys, and
    /// empty or ambiguous policy names (SURF-31).
    pub fn parse(selector: &str) -> Result<Self, ViewError> {
        let (selector, policy) = match selector.rsplit_once('@') {
            Some((selector, policy)) => {
                if policy.is_empty() || policy.contains(['/', ':', '@']) {
                    return Err(ViewError::Policy);
                }
                (selector, Some(policy.to_string()))
            }
            None => (selector, None),
        };

        let (target, subtree) = if let Some(commit) = selector.strip_prefix("commit:") {
            let (digest, subtree) = split_subtree(commit)?;
            if digest.len() != 64 {
                return Err(ViewError::Target);
            }
            let mut identity = [0; 32];
            for (destination, pair) in identity
                .iter_mut()
                .zip(digest.as_bytes().as_chunks::<2>().0)
            {
                let text = core::str::from_utf8(pair).map_err(|_| ViewError::Target)?;
                *destination = u8::from_str_radix(text, 16).map_err(|_| ViewError::Target)?;
            }
            (ViewTarget::Commit(identity), subtree)
        } else {
            let (reference, subtree) = split_subtree(selector)?;
            let reference = RefName::parse(reference).map_err(|_| ViewError::Target)?;
            (ViewTarget::Ref(reference), subtree)
        };

        let subtree = if subtree.is_empty() || subtree == "/" {
            Vec::new()
        } else {
            let path = subtree.strip_prefix('/').ok_or(ViewError::Subtree)?;
            // The selector grammar permits one trailing directory separator.
            let key = path.strip_suffix('/').unwrap_or(path).as_bytes();
            validate_key(key).map_err(|_| ViewError::Subtree)?;
            key.to_vec()
        };

        Ok(Self {
            target,
            subtree,
            policy,
        })
    }
}

// Omitting ':' selects the complete tree; an explicit separator requires a subtree.
fn split_subtree(selector: &str) -> Result<(&str, &str), ViewError> {
    match selector.split_once(':') {
        Some((_, "")) => Err(ViewError::Subtree),
        Some(pair) => Ok(pair),
        None => Ok((selector, "")),
    }
}

/// Describes a malformed view selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewError {
    /// The target is neither a valid ref nor an exact commit digest.
    Target,
    /// The subtree is not a valid absolute selector path.
    Subtree,
    /// The policy name is empty or ambiguous.
    Policy,
}

impl fmt::Display for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Target => "invalid view target",
            Self::Subtree => "invalid view subtree",
            Self::Policy => "invalid view policy",
        })
    }
}

impl core::error::Error for ViewError {}

/// Names the kind of address accepted by a surface (SURF-10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointKind {
    /// A directory used for SDK checkout or a kernel mount.
    Directory,
    /// A Unix-domain socket.
    UnixSocket,
    /// An HTTP URL prefix.
    HttpPrefix,
    /// A device node.
    DeviceNode,
}

/// Describes where a surface presents its view without opening that address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    /// The address's registered kind.
    pub kind: EndpointKind,
    /// The address in its surface-specific encoding.
    pub address: String,
}

/// Selects how an exposure observes reference advances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderMode {
    /// Serves the commit resolved when the exposure started.
    Pinned,
    /// Resolves reference advances within the configured consistency bound.
    Follow,
}

/// Selects when a writable surface commits its working tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterMode {
    /// Commits only upon an explicit request.
    Manual,
    /// Commits at the configured interval.
    Periodic,
    /// Acknowledges mutation only after durable commit.
    Sync,
}

/// Holds the pure configuration of one registered exposure (SURF-29).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Exposure {
    /// Stable identifier unique within an instance.
    pub id: String,
    /// Content selector.
    pub view: View,
    /// Registered surface name.
    pub surface: String,
    /// Exclusive presentation address.
    pub endpoint: Endpoint,
    /// Credential locator, never an inline capability token.
    pub token: String,
    /// Reference observation mode.
    pub reader: ReaderMode,
    /// Mutation acknowledgment mode, absent for read-only surfaces.
    pub writer: Option<WriterMode>,
}

/// Names the metadata kind required at a schema path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaEntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A grafted tree.
    Tree,
}

/// Declares metadata requirements without reading object content (SURF-14).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TreeSchema {
    /// Required paths and their entry kinds.
    pub required_entries: Vec<(Vec<u8>, SchemaEntryKind)>,
    /// Required paths, attribute names, and canonical CBOR major types.
    pub required_attributes: Vec<(Vec<u8>, String, u8)>,
    /// Required property names and permitted canonical CBOR values.
    pub required_properties: Vec<(String, Vec<Vec<u8>>)>,
    /// Forbidden root-relative paths.
    pub forbidden_entries: Vec<Vec<u8>>,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "invalid selector fixtures must fail the test"
)]
mod tests {
    use super::*;

    #[test]
    fn selector_accepts_commit_and_ref_subtrees() {
        let view = View::parse("refs/heads/main:/nested/tree@strict").unwrap();
        assert_eq!(view.subtree, b"nested/tree");
        assert_eq!(view.policy.as_deref(), Some("strict"));
        assert!(matches!(
            View::parse(&alloc::format!("commit:{}", "ab".repeat(32)))
                .unwrap()
                .target,
            ViewTarget::Commit(_)
        ));
    }

    #[test]
    fn selector_rejects_escape_and_malformed_digest() {
        for selector in [
            "commit:aa",
            "refs/heads/main:relative",
            "refs/heads/main:/../escape",
            "refs/heads/main:/a//b",
            "refs/heads/main@",
        ] {
            assert!(View::parse(selector).is_err(), "{selector}");
        }
    }

    #[test]
    fn selector_requires_subtree_after_explicit_separator() {
        for selector in [
            "refs/heads/main:",
            "commit:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:",
        ] {
            assert_eq!(View::parse(selector), Err(ViewError::Subtree));
        }
    }

    #[test]
    fn selector_normalizes_one_trailing_directory_separator() {
        for target in [
            "refs/heads/main",
            "commit:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(
                View::parse(&alloc::format!("{target}:/nested/tree/@strict")).unwrap(),
                View::parse(&alloc::format!("{target}:/nested/tree@strict")).unwrap()
            );
            assert_eq!(
                View::parse(&alloc::format!("{target}:/nested/tree//")),
                Err(ViewError::Subtree)
            );
        }
    }
}
