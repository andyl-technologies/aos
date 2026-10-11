//! Owns explicit property interpretation inputs and role-preserving policy layers.
//!
//! Configuration is supplied by an independently trusted caller. Copying these
//! ordinary values does not authenticate registration or recover an association.

use super::{Rejected, encoding};
use crate::{
    cbor,
    properties::{Defaults, EffectiveProperties, RootLayer, semantics::RecordedContext},
    provenance::history::PolicyLayer,
    tree_format::Property,
};
use alloc::{string::String, vec::Vec};

/// Retains a caller's fixed revision and canonical copies of its name fences.
#[derive(Clone, Debug)]
pub(super) struct OwnedRecorded {
    context: RecordedContext,
}

impl OwnedRecorded {
    /// Copies validated inputs without changing the caller's preservation set.
    pub(super) fn new(context: &RecordedContext) -> Self {
        Self {
            context: context.clone(),
        }
    }

    /// Encodes the selected caller interpretation in the registered v3 tuple.
    ///
    /// # Errors
    /// Rejects inconsistent ordinary context fields or invalid canonical fences.
    pub(super) fn encode(
        &self,
        fields: encoding::ContextFields<'_>,
        root: &crate::identity::Digest,
    ) -> Result<Vec<u8>, Rejected> {
        let later: Vec<_> = self
            .context
            .later_registered()
            .iter()
            .map(String::as_str)
            .collect();
        encoding::encode_recorded(encoding::RecordedContextFields {
            context: fields,
            root,
            revision: self.context.revision(),
            behavioral: &self.context.behavioral_names().collect::<Vec<_>>(),
            later: &later,
        })
    }

    fn resolve<'a>(
        &self,
        layers: &[RootLayer<'a>],
        defaults: Defaults<'a>,
    ) -> Result<EffectiveProperties<'a>, Rejected> {
        self.context.resolve(layers, defaults).map_err(|_| Rejected)
    }
}

/// Retains legacy projections or explicitly recorded physical placement roles.
pub(super) enum PolicyInputs<'a> {
    /// Existing merged bindings used by the unchanged v1/v2 mode.
    Legacy(Vec<Vec<Property<'a>>>),
    /// Original bindings and graft replacements retained separately for v3.
    Recorded(Vec<PolicyLayer<'a>>),
}

impl PolicyInputs<'_> {
    /// Returns the ancestor-first policy layer count.
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Legacy(layers) => layers.len(),
            Self::Recorded(layers) => layers.len(),
        }
    }

    /// Resolves one complete ancestor prefix under this mode's interpretation.
    ///
    /// # Errors
    /// Rejects invalid prefixes, property types/placement or unregistered names.
    pub(super) fn resolve_prefix(
        &self,
        end: usize,
        recorded: Option<&OwnedRecorded>,
        selection: &crate::properties::selected::Selection,
    ) -> Result<EffectiveProperties<'_>, Rejected> {
        let layers: Vec<_> = match self {
            Self::Legacy(layers) => layers
                .iter()
                .map(|properties| RootLayer {
                    properties,
                    overrides: &[],
                })
                .collect(),
            Self::Recorded(layers) => layers
                .iter()
                .map(|layer| RootLayer {
                    properties: &layer.properties,
                    overrides: layer.overrides.as_deref().unwrap_or(&[]),
                })
                .collect(),
        };
        let prefix = layers.get(..end).ok_or(Rejected)?;
        let defaults = Defaults {
            store: "provenance",
            private_domain: "private:provenance",
            home: "provenance",
        };
        match (self, recorded) {
            (Self::Recorded(_), Some(context)) => {
                if *selection
                    != crate::properties::selected::Selection::Recorded(context.context.clone())
                {
                    return Err(Rejected);
                }
                context.resolve(prefix, defaults)
            }
            (_, None)
                if !matches!(
                    selection,
                    crate::properties::selected::Selection::Recorded(_)
                ) =>
            {
                selection.resolve(prefix, defaults).map_err(|_| Rejected)
            }
            _ => Err(Rejected),
        }
    }

    /// Adds exact raw binding evidence to the existing content-context memo key.
    ///
    /// Location/path metadata is not a cache key: identical verified contexts may
    /// share evaluation. Recorded mode additionally retains replacement roles.
    ///
    /// # Errors
    /// Rejects an absent layer instead of indexing beyond the retained prefix.
    pub(super) fn write_layer(&self, index: usize, key: &mut Vec<u8>) -> Result<(), Rejected> {
        match self {
            Self::Legacy(layers) => write_properties(key, layers.get(index).ok_or(Rejected)?),
            Self::Recorded(layers) => {
                let layer = layers.get(index).ok_or(Rejected)?;
                cbor::write_array(key, 2);
                write_properties(key, &layer.properties);
                if let Some(overrides) = &layer.overrides {
                    write_properties(key, overrides);
                } else {
                    key.push(0xf6);
                }
            }
        }
        Ok(())
    }
}

fn write_properties(key: &mut Vec<u8>, properties: &[Property<'_>]) {
    cbor::write_array(key, properties.len());
    for property in properties {
        cbor::write_array(key, 2);
        cbor::write_text(key, property.name);
        cbor::write_bytes(key, property.value);
    }
}
