//! Retains reached negotiation tables under the shared closed predicates.
//!
//! Ordinary adapters dispose tables in the original reverse construction
//! order. Selected parsing keeps the reached prefix and current namespace on
//! every refusal; these are nonauthorizing comparison data.

use super::*;
use aos_sandbox_model::{RegistryError, selector::InvalidFeatureNamespace};

#[derive(Clone, Copy)]
enum Disposition {
    Ordinary,
    Retained,
}

#[derive(Default)]
struct Features {
    values: Vec<FeatureRef>,
    current_namespace: Option<String>,
    constructor: Option<Result<(), InvalidFeatureNamespace>>,
    registry: Option<Result<(), RegistryError>>,
}

impl Features {
    fn capture(&mut self, features: &[Feature], disposition: Disposition)
        -> Result<(), BrokerSessionNegotiationError>
    {
        if matches!(disposition, Disposition::Ordinary) {
            self.values = feature_refs(features)?;
            return Ok(());
        }

        for feature in features {
            self.current_namespace = Some(feature.namespace.clone());
            let result = FeatureRef::new_retaining_v1(
                &mut self.current_namespace, feature.major, feature.minor,
            );
            match result {
                Ok(value) => {
                    self.constructor = Some(Ok(()));
                    self.values.push(value);
                }
                Err(error) => {
                    self.constructor = Some(Err(error));
                    return Err(BrokerSessionNegotiationError::Features);
                }
            }
        }

        self.registry = Some(validate_required_features(&self.values));
        if !matches!(self.registry, Some(Ok(()))) {
            return Err(BrokerSessionNegotiationError::Features);
        }
        require_feature_order(&self.values)?;
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.constructor.as_ref().and_then(|r| r.as_ref().err())
            .map(|e| e as &(dyn std::error::Error + Send + Sync))
            .or_else(|| self.registry.as_ref().and_then(|r| r.as_ref().err())
                .map(|e| e as &(dyn std::error::Error + Send + Sync)))
    }
}

#[derive(Default)]
struct Methods {
    values: Vec<BrokerMethod>,
}

impl Methods {
    fn capture(
        &mut self, source: &[buffa::EnumValue<BrokerMethod>],
        protocol: BrokerSessionProtocolV1, audience: Audience, disposition: Disposition,
    ) -> Result<(), BrokerSessionNegotiationError> {
        if matches!(disposition, Disposition::Ordinary) {
            self.values = methods(source, protocol, audience)?;
            return Ok(());
        }
        for method in source {
            self.values.push(known_method(method, protocol)?);
        }
        require_method_order_and_role(&self.values, audience)
    }
}

pub(crate) struct NegotiationCapture {
    required_features: Features,
    advertised_features: Features,
    required_methods: Methods,
    advertised_methods: Methods,
    result: Option<Result<Option<ValidatedBrokerSessionNegotiationV1>, BrokerSessionNegotiationError>>,
    disposition: Disposition,
}

impl NegotiationCapture {
    pub(crate) fn new() -> Self {
        Self {
            required_features: Features::default(),
            advertised_features: Features::default(),
            required_methods: Methods::default(),
            advertised_methods: Methods::default(),
            result: None,
            disposition: Disposition::Retained,
        }
    }

    // E is the total actual encoded Hello extent. Each reached feature has
    // at least a tag and length; each packed method consumes at least one byte.
    // Three reached carriers cover old+new Vec backing during growth; eight
    // covers both initial capacity floors. Namespace clones partition E, and
    // the registry can additionally clone one validated <=255-byte namespace.
    pub(crate) fn receiving_heap_bytes_v1(encoded_hello_bytes: usize) -> Option<usize> {
        let features = (encoded_hello_bytes / 2).checked_mul(3)?.checked_add(8)?;
        let methods = encoded_hello_bytes.checked_mul(3)?.checked_add(8)?;
        features.checked_mul(std::mem::size_of::<FeatureRef>())?
            .checked_add(methods.checked_mul(std::mem::size_of::<BrokerMethod>())?)?
            .checked_add(encoded_hello_bytes)?.checked_add(255)
    }

    pub(crate) const fn receiving_metadata_cells_v1() -> Option<usize> {
        // Four Vec headers, two current strings, two constructor Results,
        // two registry Results, one negotiated output Result and disposition.
        Some(12)
    }

    pub(crate) fn receiving_table_metadata_cells_v1(encoded_hello_bytes: usize) -> Option<usize> {
        // Feature records and their String allocations coexist with method
        // records; include old/new Vec backing plus the current registry clone.
        (encoded_hello_bytes / 2).checked_mul(2)?
            .checked_add(encoded_hello_bytes)?.checked_add(9)
    }

    pub(super) fn ordinary() -> Self {
        Self { disposition: Disposition::Ordinary, ..Self::new() }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.required_features.failure()
            .or_else(|| self.advertised_features.failure())
            .or_else(|| self.result.as_ref().and_then(|r| r.as_ref().err())
                .map(|e| e as &(dyn std::error::Error + Send + Sync)))
    }

    pub(crate) fn capture(
        &mut self, client: &BrokerClientHello, broker: &BrokerServerHello,
        protocol: BrokerSessionProtocolV1, major: u16, minor: u16, audience: Audience,
    ) {
        if self.result.is_none() {
            self.result = Some(self.validate_inner(client, broker, protocol, major, minor, audience).map(Some));
        }
    }

    pub(crate) fn take(&mut self)
        -> Result<ValidatedBrokerSessionNegotiationV1, BrokerSessionNegotiationError>
    {
        if let Some(Err(error)) = &self.result {
            return Err(error.clone());
        }
        self.result.as_mut().and_then(|r| r.as_mut().ok()).and_then(Option::take)
            .ok_or(BrokerSessionNegotiationError::Features)
    }

    pub(super) fn into_ordinary_result(mut self)
        -> Result<ValidatedBrokerSessionNegotiationV1, BrokerSessionNegotiationError>
    {
        let error = self.result.as_ref().and_then(|r| r.as_ref().err()).cloned();
        if let Some(error) = error {
            // These four locals had reverse construction-order disposal.
            drop(std::mem::take(&mut self.advertised_methods));
            drop(std::mem::take(&mut self.required_methods));
            drop(std::mem::take(&mut self.advertised_features));
            drop(std::mem::take(&mut self.required_features));
            return Err(error);
        }
        self.take()
    }

    fn validate_inner(
        &mut self,
        client: &BrokerClientHello,
        broker: &BrokerServerHello,
        protocol: BrokerSessionProtocolV1,
        context_major: u16,
        context_minor: u16,
        context_audience: Audience,
    ) -> Result<ValidatedBrokerSessionNegotiationV1, BrokerSessionNegotiationError> {
        if broker.error.as_option().is_some() {
            return Err(BrokerSessionNegotiationError::Features);
        }
        let expected = supported_broker_session_version_v1(protocol);
        if (context_major, context_minor) != expected
            || client.protocol_major != u32::from(expected.0)
            || client.protocol_minor != u32::from(expected.1)
            || broker.protocol_major != u32::from(expected.0)
            || broker.protocol_minor != u32::from(expected.1)
            || client.audience.as_known() != Some(context_audience)
        {
            return Err(BrokerSessionNegotiationError::Version);
        }
        validate_role(context_audience, protocol)?;

        self.required_features.capture(&client.required_features, self.disposition)?;
        let required_features = &self.required_features.values;
        self.advertised_features.capture(&broker.features, self.disposition)?;
        let advertised_features = &self.advertised_features.values;
        require_exact_authentication_feature(&required_features)?;
        require_exact_authentication_feature(&advertised_features)?;
        if required_features
            .iter()
            .any(|required| advertised_features.binary_search(required).is_err())
        {
            return Err(BrokerSessionNegotiationError::Features);
        }

        self.required_methods.capture(&client.required_methods, protocol, context_audience, self.disposition)?;
        let required_methods = &self.required_methods.values;
        self.advertised_methods.capture(&broker.methods, protocol, context_audience, self.disposition)?;
        let advertised_methods = &self.advertised_methods.values;
        if required_methods.iter().any(|required| {
            advertised_methods
                .binary_search_by_key(&method_number(*required), |method| method_number(*method))
                .is_err()
        }) {
            return Err(BrokerSessionNegotiationError::Methods);
        }
        validate_feature_conditions(
            protocol,
            &required_features,
            &advertised_features,
            &required_methods,
            &advertised_methods,
        )?;

        let response_maximum = u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
            .map_err(|_| BrokerSessionNegotiationError::Ceiling)?;
        if !(AUTHENTICATED_RESPONSE_MINIMUM_BYTES..=response_maximum)
            .contains(&client.maximum_response_bytes)
            || !(AUTHENTICATED_RESPONSE_MINIMUM_BYTES..=client.maximum_response_bytes)
                .contains(&broker.maximum_response_bytes)
        {
            return Err(BrokerSessionNegotiationError::Ceiling);
        }
        let protocol_request_maximum = maximum_broker_session_request_bytes_v1(protocol);
        let maximum_request_bytes = usize::try_from(broker.maximum_request_bytes)
            .map_err(|_| BrokerSessionNegotiationError::Ceiling)?;
        if maximum_request_bytes == 0 || maximum_request_bytes > protocol_request_maximum {
            return Err(BrokerSessionNegotiationError::Ceiling);
        }

        Ok(ValidatedBrokerSessionNegotiationV1 {
            protocol,
            major: expected.0,
            minor: expected.1,
            audience: context_audience,
            required_features: std::mem::take(&mut self.required_features.values),
            advertised_features: std::mem::take(&mut self.advertised_features.values),
            required_methods: std::mem::take(&mut self.required_methods.values),
            advertised_methods: std::mem::take(&mut self.advertised_methods.values),
            maximum_request_bytes,
            maximum_response_bytes: broker.maximum_response_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_current_namespace_and_completed_prefix_stay_owned() {
        let source = [
            Feature { namespace: "a.valid".to_owned(), major: 1, ..Default::default() },
            Feature { namespace: "Invalid!".to_owned(), major: 1, ..Default::default() },
        ];
        let mut capture = Features::default();

        assert!(capture.capture(&source, Disposition::Retained).is_err());
        assert_eq!(capture.values.len(), 1);
        assert_eq!(capture.current_namespace.as_deref(), Some("Invalid!"));
        assert!(capture.constructor.as_ref().unwrap().is_err());
        assert!(capture.registry.is_none());
    }

    #[test]
    fn unknown_registry_namespace_retains_whole_owned_error_and_table() {
        let source = [Feature { namespace: "a.unknown".to_owned(), major: 1, ..Default::default() }];
        let mut capture = Features::default();

        assert!(capture.capture(&source, Disposition::Retained).is_err());
        assert_eq!(capture.values.len(), 1);
        let error = capture.registry.as_ref().unwrap().as_ref().unwrap_err();
        assert!(matches!(error, RegistryError::UnknownRequiredFeature { namespace, .. } if namespace == "a.unknown"));
        assert!(std::ptr::eq(capture.failure().unwrap().downcast_ref::<RegistryError>().unwrap(), error));
    }
}
