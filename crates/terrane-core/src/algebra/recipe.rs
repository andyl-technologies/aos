//! Encodes ordered composition operands and explicit merge policy recipes.
//!
//! ```text
//! {1: "merge", 2: [base, ours, theirs], 3: {"policy": ["keep-conflict"]}}
//! ```

use alloc::vec::Vec;

use crate::cbor;
use crate::identity::Digest;
use crate::identity::{IdentityError, IdentityKind, TERRANE_V1};

/// An ordered conflict-resolution step in a three-way merge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergePolicy {
    /// Selects the current parent branch's candidate, including deletion.
    PreferOurs,
    /// Selects the incoming branch's candidate, including deletion.
    PreferTheirs,
    /// Selects the sole candidate accepted by the supplied trust selector.
    PreferTrusted,
    /// Selects the candidate with the later verified introducing-commit timestamp.
    PreferNewer,
    /// Preserves the unresolved alternatives for later resolution.
    KeepConflict,
    /// Returns an error when an unresolved conflict reaches this step.
    Error,
}

impl MergePolicy {
    /// Returns the registered wire name of the policy.
    pub const fn name(self) -> &'static str {
        match self {
            Self::PreferOurs => "prefer-ours",
            Self::PreferTheirs => "prefer-theirs",
            Self::PreferTrusted => "prefer-trusted",
            Self::PreferNewer => "prefer-newer",
            Self::KeepConflict => "keep-conflict",
            Self::Error => "error",
        }
    }
}

/// A canonical recipe preserving the operation's operand order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recipe<'a> {
    /// Consults layers from highest precedence to lowest precedence.
    Overlay(&'a [Digest]),
    /// Consults ordered layers with recorded effective input ownership.
    OverlayWithDomains {
        /// Roots ordered from highest to lowest precedence.
        roots: &'a [Digest],
        /// Trusted effective domain bindings needed for materialization.
        domains: &'a super::OperationDomains,
    },
    /// Replaces a parent path with an independently governed root entry.
    Graft {
        /// Parent root before replacement.
        parent: Digest,
        /// Independently governed target root.
        target: Digest,
        /// Parent-relative graft path.
        at: &'a [u8],
        /// Canonical tree-entry bytes, including overrides and attributes.
        entry: &'a [u8],
        /// Whether inline descendants are removed in the same operation.
        replace: bool,
        /// Effective domain evidence for inherited or implicit ownership.
        domains: Option<&'a super::OperationDomains>,
    },
    /// Merges base, ours, and theirs under an ordered policy list.
    Merge {
        /// Common ancestor tree root.
        base: Digest,
        /// Current destination tree root.
        ours: Digest,
        /// Incoming tree root.
        theirs: Digest,
        /// Conflict resolution steps, applied in this order.
        policies: &'a [MergePolicy],
        /// Trust policy evidence and any authenticated input bindings.
        trust: &'a super::TrustContext,
        /// Effective domain evidence for changed destination roots.
        domains: Option<&'a super::OperationDomains>,
    },
}

/// A malformed or unsupported canonical algebra recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipeError {
    /// CBOR is malformed or noncanonical.
    Encoding(cbor::Error),
    /// The operation, argument names, or policy is unsupported.
    Schema,
    /// A trust context is malformed.
    Trust(super::TrustError),
}

impl core::fmt::Display for RecipeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(error) => error.fmt(formatter),
            Self::Schema => formatter.write_str("invalid algebra recipe schema"),
            Self::Trust(error) => error.fmt(formatter),
        }
    }
}

impl core::error::Error for RecipeError {}

/// An owned, validated recipe decoded from canonical CBOR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedRecipe {
    roots: Vec<Digest>,
    merge: Option<([Digest; 3], Vec<MergePolicy>, super::TrustContext)>,
    graft: Option<OwnedGraft>,
    domains: Option<super::OperationDomains>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedGraft {
    at: Vec<u8>,
    entry: Vec<u8>,
    replace: bool,
}

impl OwnedRecipe {
    /// Binds recorded domain evidence to independently resolved operation inputs.
    ///
    /// # Errors
    /// Rejects missing evidence, unverified bindings, or different root/domain
    /// pairs. Decoding a recipe alone never authorizes ownership-sensitive edits.
    pub fn bind_domains(mut self, domains: &super::OperationDomains) -> Result<Self, RecipeError> {
        self.domains = Some(
            self.domains
                .as_ref()
                .ok_or(RecipeError::Schema)?
                .bind(domains)?,
        );
        Ok(self)
    }

    /// Rebinds a decoded fold's signed input after replaying recorded exclusions.
    ///
    /// # Errors
    /// Rejects nonmerge recipes, input root mismatches, unordered exclusions, or
    /// a preprocessing replay/configuration that differs from the recipe.
    pub fn bind_fold_verified<'a>(
        mut self,
        evaluators: Vec<crate::provenance::TrustContext>,
        base: &crate::tree_builder::Tree<'a>,
        original: &crate::tree_builder::Tree<'a>,
        filtered: &crate::tree_builder::Tree<'a>,
        excluded: &[Vec<u8>],
    ) -> Result<Self, RecipeError> {
        let Some((roots, policies, trust)) = self.merge.take() else {
            return Err(RecipeError::Schema);
        };
        if roots[0] != base.root_identity() || roots[2] != filtered.root_identity() {
            return Err(RecipeError::Schema);
        }
        let trust = trust
            .bind_fold_verified(evaluators, base, original, filtered, excluded)
            .map_err(RecipeError::Trust)?;
        trust.bind_inputs(roots).map_err(RecipeError::Trust)?;
        self.merge = Some((roots, policies, trust));
        Ok(self)
    }

    /// Rebinds fold recipe evidence with trusted source-domain resolution.
    ///
    /// # Errors
    /// Rejects nonmerge recipes, mismatched operands or ownership, unordered
    /// exclusions, and any difference from deterministic recorded preprocessing.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_fold_verified_with_domains<'a>(
        mut self,
        evaluators: Vec<crate::provenance::TrustContext>,
        base: &crate::tree_builder::Tree<'a>,
        original: &crate::tree_builder::Tree<'a>,
        filtered: &crate::tree_builder::Tree<'a>,
        excluded: &[Vec<u8>],
        domains: &'a super::OperationDomains,
    ) -> Result<Self, RecipeError> {
        let Some((roots, policies, trust)) = self.merge.take() else {
            return Err(RecipeError::Schema);
        };
        if roots[0] != base.root_identity() || roots[2] != filtered.root_identity() {
            return Err(RecipeError::Schema);
        }
        let trust = trust
            .bind_fold_verified_with_domains(
                evaluators, base, original, filtered, excluded, domains,
            )
            .map_err(RecipeError::Trust)?;
        trust.bind_inputs(roots).map_err(RecipeError::Trust)?;
        self.merge = Some((roots, policies, trust));
        Ok(self)
    }

    /// Binds a decoded merge's trust evidence to matching verified signed views.
    ///
    /// Decoding alone grants no authority to execute trust-sensitive policies.
    ///
    /// # Errors
    /// Rejects nonmerge recipes, signed views whose roots differ from the
    /// recorded operands, or a different canonical evaluator configuration.
    pub fn bind_verified(
        mut self,
        evaluators: Vec<crate::provenance::TrustContext>,
    ) -> Result<Self, RecipeError> {
        let Some((roots, policies, trust)) = self.merge.take() else {
            return Err(RecipeError::Schema);
        };
        let trust = trust
            .bind_verified(evaluators)
            .map_err(RecipeError::Trust)?;
        trust.bind_inputs(roots).map_err(RecipeError::Trust)?;
        self.merge = Some((roots, policies, trust));
        Ok(self)
    }

    /// Borrows the validated operation and its semantic inputs.
    pub fn as_recipe(&self) -> Recipe<'_> {
        if let Some(graft) = &self.graft {
            return Recipe::Graft {
                parent: self.roots[0],
                target: self.roots[1],
                at: &graft.at,
                entry: &graft.entry,
                replace: graft.replace,
                domains: self.domains.as_ref(),
            };
        }
        match &self.merge {
            Some(([base, ours, theirs], policies, trust)) => Recipe::Merge {
                base: *base,
                ours: *ours,
                theirs: *theirs,
                policies,
                trust,
                domains: self.domains.as_ref(),
            },
            None => match &self.domains {
                Some(domains) => Recipe::OverlayWithDomains {
                    roots: &self.roots,
                    domains,
                },
                None => Recipe::Overlay(&self.roots),
            },
        }
    }
}

impl Recipe<'_> {
    /// Decodes a canonical overlay, graft, or merge recipe into owned semantic inputs.
    ///
    /// Trust receipts remain authority-provided inputs; decoding does not verify
    /// their signatures or confer provenance-verification authority.
    ///
    /// # Errors
    /// Rejects noncanonical CBOR, unsupported operations or arguments, malformed
    /// identities, and trust arguments inconsistent with the policy list.
    /// Trust configuration remains unauthenticated until [`OwnedRecipe::bind_verified`].
    pub fn decode(bytes: &[u8]) -> Result<OwnedRecipe, RecipeError> {
        let mut decoder = cbor::Decoder::new(bytes);
        let fields = decoder.map(3).map_err(RecipeError::Encoding)?;
        if decoder.uint().map_err(RecipeError::Encoding)? != 1 {
            return Err(RecipeError::Schema);
        }
        let operation = decoder.text(bytes.len()).map_err(RecipeError::Encoding)?;
        if decoder.uint().map_err(RecipeError::Encoding)? != 2 {
            return Err(RecipeError::Schema);
        }
        let count = decoder.array(bytes.len()).map_err(RecipeError::Encoding)?;
        let mut roots = Vec::new();
        for _ in 0..count {
            roots.push(
                decoder
                    .bytes(32)
                    .map_err(RecipeError::Encoding)?
                    .try_into()
                    .map_err(|_| RecipeError::Schema)?,
            );
        }
        let mut graft = None;
        let mut domains = None;
        let merge = match operation {
            "overlay" if fields == 2 => None,
            "overlay" if fields == 3 => {
                if decoder.uint().map_err(RecipeError::Encoding)? != 3
                    || decoder.map(1).map_err(RecipeError::Encoding)? != 1
                    || decoder.text(bytes.len()).map_err(RecipeError::Encoding)? != "domains"
                {
                    return Err(RecipeError::Schema);
                }
                domains = Some(super::OperationDomains::decode(&mut decoder, bytes.len())?);
                None
            }
            "graft" if fields == 3 && roots.len() == 2 => {
                if decoder.uint().map_err(RecipeError::Encoding)? != 3 {
                    return Err(RecipeError::Schema);
                }
                let arguments = decoder.map(4).map_err(RecipeError::Encoding)?;
                if !matches!(arguments, 3 | 4)
                    || decoder.text(bytes.len()).map_err(RecipeError::Encoding)? != "at"
                {
                    return Err(RecipeError::Schema);
                }
                let at = decoder.bytes(4096).map_err(RecipeError::Encoding)?.to_vec();
                crate::tree_format::validate_key(&at).map_err(|_| RecipeError::Schema)?;
                if decoder.text(bytes.len()).map_err(RecipeError::Encoding)? != "entry" {
                    return Err(RecipeError::Schema);
                }
                let entry = decoder
                    .bytes(bytes.len())
                    .map_err(RecipeError::Encoding)?
                    .to_vec();
                let valid_target = {
                    let value = crate::tree_format::decode_entry_bytes(&entry, 0)
                        .map_err(|_| RecipeError::Schema)?;
                    matches!(value.kind, crate::tree_format::EntryKind::Tree { root, .. } if root == roots[1])
                };
                if arguments == 4 {
                    if decoder.text(bytes.len()).map_err(RecipeError::Encoding)? != "domains" {
                        return Err(RecipeError::Schema);
                    }
                    domains = Some(super::OperationDomains::decode(&mut decoder, bytes.len())?);
                }
                if !valid_target
                    || decoder.text(bytes.len()).map_err(RecipeError::Encoding)? != "replace"
                {
                    return Err(RecipeError::Schema);
                }
                let replace = match decoder.simple().map_err(RecipeError::Encoding)? {
                    0xf4 => false,
                    0xf5 => true,
                    _ => return Err(RecipeError::Schema),
                };
                graft = Some(OwnedGraft { at, entry, replace });
                None
            }
            "merge" if fields == 3 && roots.len() == 3 => {
                if decoder.uint().map_err(RecipeError::Encoding)? != 3 {
                    return Err(RecipeError::Schema);
                }
                let arguments = decoder.map(3).map_err(RecipeError::Encoding)?;
                let first = decoder.text(bytes.len()).map_err(RecipeError::Encoding)?;
                let trust = if first == "trust" {
                    Some(
                        super::TrustContext::decode_from(&mut decoder, bytes)
                            .map_err(RecipeError::Trust)?,
                    )
                } else if first == "policy" {
                    None
                } else {
                    return Err(RecipeError::Schema);
                };
                if trust.is_some()
                    && decoder.text(bytes.len()).map_err(RecipeError::Encoding)? != "policy"
                {
                    return Err(RecipeError::Schema);
                }
                let count = decoder.array(bytes.len()).map_err(RecipeError::Encoding)?;
                let mut policies = Vec::new();
                for _ in 0..count {
                    policies.push(
                        match decoder.text(bytes.len()).map_err(RecipeError::Encoding)? {
                            "prefer-ours" => MergePolicy::PreferOurs,
                            "prefer-theirs" => MergePolicy::PreferTheirs,
                            "prefer-trusted" => MergePolicy::PreferTrusted,
                            "prefer-newer" => MergePolicy::PreferNewer,
                            "keep-conflict" => MergePolicy::KeepConflict,
                            "error" => MergePolicy::Error,
                            _ => return Err(RecipeError::Schema),
                        },
                    );
                }
                if policies.iter().any(|policy| {
                    matches!(
                        policy,
                        MergePolicy::PreferTrusted | MergePolicy::PreferNewer
                    )
                }) != trust.is_some()
                {
                    return Err(RecipeError::Schema);
                }
                let ordinary_arguments = 1 + usize::from(trust.is_some());
                if arguments == ordinary_arguments + 1 {
                    if decoder.text(bytes.len()).map_err(RecipeError::Encoding)? != "domains" {
                        return Err(RecipeError::Schema);
                    }
                    domains = Some(super::OperationDomains::decode(&mut decoder, bytes.len())?);
                } else if arguments != ordinary_arguments {
                    return Err(RecipeError::Schema);
                }
                Some((
                    roots
                        .as_slice()
                        .try_into()
                        .map_err(|_| RecipeError::Schema)?,
                    policies,
                    trust.unwrap_or_else(super::TrustContext::any),
                ))
            }
            _ => return Err(RecipeError::Schema),
        };
        decoder.finish().map_err(RecipeError::Encoding)?;
        Ok(OwnedRecipe {
            roots,
            merge,
            graft,
            domains,
        })
    }

    /// Produces deterministic CBOR matching the normative recipe schema.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        match self {
            Self::Graft {
                parent,
                target,
                at,
                entry,
                replace,
                domains,
            } => {
                cbor::write_map(&mut bytes, 3);
                cbor::write_uint(&mut bytes, 1);
                cbor::write_text(&mut bytes, "graft");
                cbor::write_uint(&mut bytes, 2);
                cbor::write_array(&mut bytes, 2);
                for root in [parent, target] {
                    cbor::write_bytes(&mut bytes, root);
                }
                cbor::write_uint(&mut bytes, 3);
                cbor::write_map(&mut bytes, 3 + usize::from(domains.is_some()));
                cbor::write_text(&mut bytes, "at");
                cbor::write_bytes(&mut bytes, at);
                cbor::write_text(&mut bytes, "entry");
                cbor::write_bytes(&mut bytes, entry);
                if let Some(domains) = domains {
                    cbor::write_text(&mut bytes, "domains");
                    domains.encode(&mut bytes);
                }
                cbor::write_text(&mut bytes, "replace");
                bytes.push(if *replace { 0xf5 } else { 0xf4 });
            }
            Self::Overlay(roots) => {
                cbor::write_map(&mut bytes, 2);
                cbor::write_uint(&mut bytes, 1);
                cbor::write_text(&mut bytes, "overlay");
                cbor::write_uint(&mut bytes, 2);
                cbor::write_array(&mut bytes, roots.len());
                for root in *roots {
                    cbor::write_bytes(&mut bytes, root);
                }
            }
            Self::OverlayWithDomains { roots, domains } => {
                cbor::write_map(&mut bytes, 3);
                cbor::write_uint(&mut bytes, 1);
                cbor::write_text(&mut bytes, "overlay");
                cbor::write_uint(&mut bytes, 2);
                cbor::write_array(&mut bytes, roots.len());
                for root in *roots {
                    cbor::write_bytes(&mut bytes, root);
                }
                cbor::write_uint(&mut bytes, 3);
                cbor::write_map(&mut bytes, 1);
                cbor::write_text(&mut bytes, "domains");
                domains.encode(&mut bytes);
            }
            Self::Merge {
                base,
                ours,
                theirs,
                policies,
                trust,
                domains,
            } => {
                cbor::write_map(&mut bytes, 3);
                cbor::write_uint(&mut bytes, 1);
                cbor::write_text(&mut bytes, "merge");
                cbor::write_uint(&mut bytes, 2);
                cbor::write_array(&mut bytes, 3);
                for root in [base, ours, theirs] {
                    cbor::write_bytes(&mut bytes, root);
                }
                cbor::write_uint(&mut bytes, 3);
                let uses_trust = policies.iter().any(|policy| {
                    matches!(
                        policy,
                        MergePolicy::PreferTrusted | MergePolicy::PreferNewer
                    )
                });
                cbor::write_map(
                    &mut bytes,
                    1 + usize::from(uses_trust) + usize::from(domains.is_some()),
                );
                if uses_trust {
                    cbor::write_text(&mut bytes, "trust");
                    trust.encode(&mut bytes);
                }
                cbor::write_text(&mut bytes, "policy");
                cbor::write_array(&mut bytes, policies.len());
                for policy in *policies {
                    cbor::write_text(&mut bytes, policy.name());
                }
                if let Some(domains) = domains {
                    cbor::write_text(&mut bytes, "domains");
                    domains.encode(&mut bytes);
                }
            }
        }

        bytes
    }

    /// Computes the recipe identity in the registered memo domain.
    ///
    /// # Errors
    /// Returns an identity error if the profile cannot identify memo objects.
    pub fn identity(&self) -> Result<Digest, IdentityError> {
        TERRANE_V1
            .calculate(IdentityKind::Memo, &self.encode())?
            .terrane_v1_digest()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn recipe_decode_roundtrips_and_rejects_noncanonical_inputs() {
        let trust = super::super::TrustContext::any();
        let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
        let recipes = [
            Recipe::Overlay(&[[1; 32], [2; 32]]),
            Recipe::Merge {
                base: [1; 32],
                ours: [2; 32],
                theirs: [3; 32],
                policies: &policies,
                trust: &trust,
                domains: None,
            },
        ];
        for recipe in recipes {
            let encoded = recipe.encode();
            let decoded = Recipe::decode(&encoded).unwrap();
            assert_eq!(decoded.as_recipe().encode(), encoded);
            assert_eq!(decoded.as_recipe().identity(), recipe.identity());
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(Recipe::decode(&trailing).is_err());
            for length in 0..encoded.len() {
                assert!(Recipe::decode(&encoded[..length]).is_err());
            }
        }
        assert!(Recipe::decode(b"\xa2\x18\x01\x67overlay\x02\x80").is_err());
        assert!(Recipe::decode(b"\xa2\x01\x67unknown\x02\x80").is_err());
    }

    #[test]
    fn overlay_recipe_preserves_precedence() {
        let roots = [[1; 32], [2; 32]];
        let reversed = [roots[1], roots[0]];

        assert_ne!(
            Recipe::Overlay(&roots).identity().unwrap(),
            Recipe::Overlay(&reversed).identity().unwrap()
        );
        assert_eq!(
            &Recipe::Overlay(&[]).encode(),
            b"\xa2\x01\x67overlay\x02\x80"
        );
    }

    #[test]
    fn merge_recipe_preserves_policy_order() {
        let first = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
        let second = [MergePolicy::KeepConflict, MergePolicy::PreferTrusted];
        let trust = super::super::TrustContext::any();
        let recipe = |policies| Recipe::Merge {
            base: [1; 32],
            ours: [2; 32],
            theirs: [3; 32],
            policies,
            trust: &trust,
            domains: None,
        };

        assert_ne!(
            recipe(&first).identity().unwrap(),
            recipe(&second).identity().unwrap()
        );
    }
}
