//! Closed version1 peer offers and exact selections without behavioral authority.
//!
//! The opt-in Hello envelope extension has an explicit edition and complete
//! declaration identities. Legacy Hello bodies remain unchanged.
//!
//! ```json
//! { "format": "1", "required": [], "optional": [] }
//! ```

use crucible_node_contract::{ExtensionSelection, IdSet, U64, Validate};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ProviderError;

/// Names the opt-in wire contract and required transport feature.
pub const EXTENSION_NEGOTIATION_V1: &str = "cnp.extension-negotiation/1";

/// Bounds the complete encoded offer or selected roster before decoding copies.
pub const MAXIMUM_EXTENSION_NEGOTIATION_BYTES: usize = 1_048_576;

/// Bounds each peer's complete exact definition roster.
pub const MAXIMUM_NEGOTIATED_EXTENSIONS: usize = 256;

/// Offers exact required and optional extension definitions to one peer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionOfferV1 {
    /// Selects this closed negotiation contract's edition1.
    pub format: U64,
    /// Requires every exact definition; an incompatible tuple refuses Hello.
    pub required: Vec<ExtensionSelection>,
    /// Offers optional exact definitions without authorizing their semantics.
    pub optional: Vec<ExtensionSelection>,
}

/// Returns every exact mutually selected definition explicitly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionSelectionV1 {
    /// Selects this closed negotiation contract's edition1.
    pub format: U64,
    /// Retains identifier, exact SemVer, schema digest and declaration reference.
    pub selected: Vec<ExtensionSelection>,
}

impl Validate for ExtensionOfferV1 {
    fn validate(&self) -> Result<(), crucible_node_contract::ContractError> {
        edition(self.format)?;
        validate_roster(&self.required)?;
        validate_roster(&self.optional)?;
        if self.required.len() + self.optional.len() > MAXIMUM_NEGOTIATED_EXTENSIONS
            || self.required.iter().any(|required| {
                self.optional
                    .iter()
                    .any(|optional| optional.identifier == required.identifier)
            })
        {
            return Err(invalid(
                "offer repeats an identifier or exceeds its aggregate bound",
            ));
        }
        Ok(())
    }
}

impl Validate for ExtensionSelectionV1 {
    fn validate(&self) -> Result<(), crucible_node_contract::ContractError> {
        edition(self.format)?;
        validate_roster(&self.selected)
    }
}

/// Authenticates exact peer contracts against independently installed local source.
///
/// Implementations are trusted host registry code, not vendor wire claims.
/// Successful verification grants no graph qualification, native execution,
/// dynamic Input handling, preservation, or global activation authority.
pub trait InstalledExtensionNegotiationVerifier {
    /// Borrows the complete bounded source-installed definition roster.
    fn supported(&self) -> &[ExtensionSelection];

    /// Borrows the exact local mandatory definitions within that roster.
    fn required(&self) -> &[ExtensionSelection];

    /// Rechecks source-installed contracts, dependencies and required features.
    ///
    /// # Errors
    /// Refuses unknown declarations, version/schema substitution, omitted exact
    /// dependencies, unavailable required features, or changed local installation.
    fn verify_selection(
        &self,
        selected: &[ExtensionSelection],
        features: &IdSet,
    ) -> Result<(), ProviderError>;
}

/// Computes an exact deterministic intersection against installed peer contracts.
///
/// Optional tuples with unsupported versions or schemas remain unselected.
/// Each required tuple must match completely; no version inference or fallback
/// is permitted. The installed verifier still checks semantic prerequisites.
///
/// # Errors
/// Refuses malformed rosters, conflicting requirements, unsupported exact tuples,
/// missing dependencies/features, or a roster allocation exceeding finite bounds.
pub fn select_installed_extensions(
    offer: &ExtensionOfferV1,
    installed: &dyn InstalledExtensionNegotiationVerifier,
    features: &IdSet,
) -> Result<ExtensionSelectionV1, ProviderError> {
    let result = exact_intersection(offer, installed)?;
    features.validate()?;
    installed.verify_selection(&result.selected, features)?;
    Ok(result)
}

pub(super) fn exact_intersection(
    offer: &ExtensionOfferV1,
    installed: &dyn InstalledExtensionNegotiationVerifier,
) -> Result<ExtensionSelectionV1, ProviderError> {
    offer.validate()?;
    preflight_encoded(offer)?;
    #[derive(Serialize)]
    struct InstalledProjection<'a> {
        supported: &'a [ExtensionSelection],
        required: &'a [ExtensionSelection],
    }
    preflight_encoded(&InstalledProjection {
        supported: installed.supported(),
        required: installed.required(),
    })?;
    validate_roster(installed.supported())?;
    validate_roster(installed.required())?;
    if installed.required().iter().any(|required| {
        !installed.supported().contains(required)
            || !offer
                .required
                .iter()
                .chain(&offer.optional)
                .any(|offered| offered == required)
    }) || offer
        .required
        .iter()
        .any(|required| !installed.supported().contains(required))
    {
        return Err(ProviderError::Correlation(
            "unsupported required exact extension contract",
        ));
    }

    let count = offer
        .required
        .iter()
        .chain(&offer.optional)
        .filter(|offered| installed.supported().contains(offered))
        .count();
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(count)
        .map_err(|_| ProviderError::ResourceExhausted("extension selection roster"))?;
    for supported in installed.supported() {
        if offer
            .required
            .iter()
            .chain(&offer.optional)
            .any(|offered| offered == supported)
        {
            selected.push(supported.clone());
        }
    }
    Ok(ExtensionSelectionV1 {
        format: U64::new(1),
        selected,
    })
}

pub(super) fn decode_bounded<'a, T: Deserialize<'a>>(value: &'a Value) -> Result<T, ProviderError> {
    preflight_encoded(value)?;
    preflight_roster_entries(value)?;
    T::deserialize(value).map_err(|error| crucible_node_contract::ContractError::from(error).into())
}

fn preflight_roster_entries(value: &Value) -> Result<(), ProviderError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("require a negotiation object"))?;
    let mut entries = 0usize;
    // Inspect the already parsed borrowed arrays before serde reconstructs any
    // full declaration references. Required and optional share one offer credit.
    for field in ["required", "optional", "selected"] {
        if let Some(roster) = object.get(field).and_then(Value::as_array) {
            entries = entries
                .checked_add(roster.len())
                .filter(|count| *count <= MAXIMUM_NEGOTIATED_EXTENSIONS)
                .ok_or(ProviderError::ResourceExhausted(
                    "extension negotiation entries",
                ))?;
        }
    }
    // Missing, foreign and non-array fields remain errors in the closed typed
    // grammar; this preflight grants no shape or contract validity.
    Ok(())
}

pub(super) fn preflight_encoded(value: &impl Serialize) -> Result<(), ProviderError> {
    struct Counter(usize);

    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|total| *total <= MAXIMUM_EXTENSION_NEGOTIATION_BYTES)
                .ok_or_else(|| std::io::Error::other("extension negotiation byte ceiling"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // Count the borrowed encoded Value before deserialization retains strings
    // or full references; the outer frame/parser ceiling remains independent.
    serde_json::to_writer(Counter(0), value)
        .map_err(|_| ProviderError::ResourceExhausted("extension negotiation bytes"))?;
    Ok(())
}

fn edition(format: U64) -> Result<(), crucible_node_contract::ContractError> {
    if format.get() == 1 {
        Ok(())
    } else {
        Err(invalid("unsupported negotiation edition"))
    }
}

pub(super) fn validate_roster(
    roster: &[ExtensionSelection],
) -> Result<(), crucible_node_contract::ContractError> {
    if roster.len() > MAXIMUM_NEGOTIATED_EXTENSIONS
        || roster
            .windows(2)
            .any(|pair| pair[0].identifier >= pair[1].identifier)
    {
        return Err(invalid(
            "require a bounded roster with unique sorted identifiers",
        ));
    }
    for selection in roster {
        selection.validate()?;
    }
    Ok(())
}

fn invalid(reason: &'static str) -> crucible_node_contract::ContractError {
    crucible_node_contract::ContractError::Invalid {
        field: "extension_negotiation",
        reason: reason.into(),
    }
}
