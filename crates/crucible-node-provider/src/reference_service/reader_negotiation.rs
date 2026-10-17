//! Owns the selected source's exact typed Hello registrar and original roster.
//!
//! The local roster is regenerated from privately installed, measured source
//! roles before the socket opens. It negotiates transport only; host namespace,
//! dynamic input, native custody and graph qualification remain independent.

use std::rc::Rc;

use crucible_node_contract::{ContractError, ExtensionSelection, IdSet, Validate};
use serde_json::Value;

use crate::ProviderError;
use crate::envelope::Envelope;
use crate::handshake::{
    ConnectionAuthority, EXTENSION_NEGOTIATION_V1, ExtensionHandshake, ExtensionOfferV1, Handshake,
    InstalledExtensionNegotiationVerifier, MAXIMUM_NEGOTIATED_EXTENSIONS, TrustedHandshakeVerifier,
    select_installed_extensions,
};
use crate::reference_lineage::InputLineageDefinition;

pub(super) enum SourceHandshake {
    Legacy(Handshake),
    Negotiated {
        handshake: ExtensionHandshake,
        installed: Rc<ReaderPeerPolicy>,
    },
}

impl SourceHandshake {
    pub(super) fn new(
        handshake: Handshake,
        definition: Option<&InputLineageDefinition>,
    ) -> Result<Self, ProviderError> {
        let Some(definition) = definition.filter(|definition| {
            definition
                .declaration()
                .required_features
                .iter()
                .any(|feature| feature.as_str() == EXTENSION_NEGOTIATION_V1)
        }) else {
            return Ok(Self::Legacy(handshake));
        };
        let installed = Rc::new(ReaderPeerPolicy {
            definition: definition.clone(),
            roster: vec![definition.selection().clone()],
        });
        let handshake = ExtensionHandshake::new(handshake, installed.clone())?;
        Ok(Self::Negotiated {
            handshake,
            installed,
        })
    }

    pub(super) fn select_response(
        &self,
        request: &Envelope,
        response: &mut Envelope,
        features: &IdSet,
    ) -> Result<(), ProviderError> {
        let Self::Negotiated { installed, .. } = self else {
            return Ok(());
        };
        let value =
            request
                .extensions
                .get(EXTENSION_NEGOTIATION_V1)
                .ok_or(ProviderError::Correlation(
                    "typed reader Hello offer absent",
                ))?;
        // The original bounded Envelope already retains encoded bytes. Charge
        // the entire borrowed roster before serde copies any declaration tuple.
        let mut encoded_credit =
            EncodedCredit(crate::handshake::MAXIMUM_EXTENSION_NEGOTIATION_BYTES);
        serde_json::to_writer(&mut encoded_credit, value).map_err(ContractError::from)?;
        let count =
            ["required", "optional"]
                .into_iter()
                .try_fold(0usize, |total, key| {
                    let entries = value.get(key).and_then(Value::as_array).ok_or(
                        ProviderError::Correlation("typed reader Hello roster absent"),
                    )?;
                    total
                        .checked_add(entries.len())
                        .filter(|count| *count <= MAXIMUM_NEGOTIATED_EXTENSIONS)
                        .ok_or(ProviderError::ResourceExhausted(
                            "typed reader Hello roster",
                        ))
                })?;
        if count > MAXIMUM_NEGOTIATED_EXTENSIONS {
            return Err(ProviderError::ResourceExhausted(
                "typed reader Hello roster",
            ));
        }
        let offer: ExtensionOfferV1 =
            serde_json::from_value(value.clone()).map_err(ContractError::from)?;
        let selected = select_installed_extensions(&offer, installed.as_ref(), features)?;
        response.extensions.insert(
            EXTENSION_NEGOTIATION_V1.into(),
            serde_json::to_value(selected).map_err(ContractError::from)?,
        );
        Ok(())
    }

    pub(super) fn admit(
        &mut self,
        request: &Envelope,
        response: &Envelope,
        connection: crucible_node_contract::Id,
        verifier: &mut impl TrustedHandshakeVerifier,
    ) -> Result<ConnectionAuthority, ProviderError> {
        match self {
            Self::Legacy(handshake) => {
                handshake.admit_envelopes(request, response, connection, verifier)
            }
            Self::Negotiated { handshake, .. } => {
                handshake.admit_envelopes(request, response, connection, verifier)
            }
        }
    }
}

pub(super) struct ReaderPeerPolicy {
    definition: InputLineageDefinition,
    roster: Vec<ExtensionSelection>,
}

impl InstalledExtensionNegotiationVerifier for ReaderPeerPolicy {
    fn supported(&self) -> &[ExtensionSelection] {
        &self.roster
    }

    fn required(&self) -> &[ExtensionSelection] {
        &self.roster
    }

    fn verify_selection(
        &self,
        selected: &[ExtensionSelection],
        features: &IdSet,
    ) -> Result<(), ProviderError> {
        self.definition.declaration().validate()?;
        if selected != self.roster
            || self
                .definition
                .declaration()
                .required_features
                .iter()
                .any(|required| !features.contains(required))
        {
            return Err(ProviderError::Correlation(
                "typed reader selected source contract differs",
            ));
        }
        for (reference, bytes) in self.definition.objects() {
            reference.verify(bytes)?;
        }
        Ok(())
    }
}

struct EncodedCredit(usize);

impl std::io::Write for EncodedCredit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("typed reader Hello encoded credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
