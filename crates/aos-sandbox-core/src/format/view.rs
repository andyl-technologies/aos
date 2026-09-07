//! Canonical codecs for portable filesystem views and environments.

use crate::model::{
    CacheDomain, CacheDomainKind, Environment, EnvironmentEntry, PresentationAction, View,
    ViewConsistency, ViewMutation, ViewSource,
};
use crate::registry::DescriptorRole;
use crate::{CacheDomainId, ExportId, ObjectDescriptor, Revision, SandboxId};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{
    decode_descriptor_for_role, decode_feature, decode_path, decode_vec, encode_descriptor,
    encode_feature, encode_path, encode_slice, exact_bytes, semantics,
};

/// Encodes one filesystem view in its exact portable v1 CBOR form.
#[must_use]
pub fn encode_view(view: &View) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(8);
    encoder.unsigned(1);
    encode_view_source(&mut encoder, view.source());
    encode_slice(
        &mut encoder,
        view.presentation(),
        encode_presentation_action,
    );
    encoder.unsigned(view_consistency_code(view.consistency()));
    encoder.unsigned(view_mutation_code(view.mutation()));
    encode_feature(&mut encoder, view.identity_presentation());
    encode_cache_domain(&mut encoder, view.disclosure());
    encode_slice(&mut encoder, view.required_features(), encode_feature);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 filesystem view.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for deterministic-CBOR, schema, closed
/// registry, presentation, feature-ordering, or consistency violations.
pub fn decode_view(bytes: &[u8], limits: DecodeLimits) -> Result<View, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(8)?;
    decoder.exact("view version", 1)?;
    let source = decode_view_source(&mut decoder)?;
    let presentation = decode_vec(&mut decoder, decode_presentation_action)?;
    let consistency = decode_view_consistency(&mut decoder)?;
    let mutation = decode_view_mutation(&mut decoder)?;
    let identity_presentation = decode_feature(&mut decoder)?;
    let disclosure = decode_cache_domain(&mut decoder)?;
    let required_features = decode_vec(&mut decoder, decode_feature)?;
    decoder.finish()?;
    View::new(
        source,
        presentation,
        consistency,
        mutation,
        identity_presentation,
        disclosure,
        required_features,
    )
    .map_err(|error| semantics("view", error))
}

/// Encodes one immutable project environment in portable v1 CBOR form.
#[must_use]
pub fn encode_environment(environment: &Environment) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(5);
    encoder.unsigned(1);
    encode_slice(&mut encoder, environment.closure(), encode_descriptor);
    encode_slice(
        &mut encoder,
        environment.variables(),
        encode_environment_entry,
    );
    encode_slice(&mut encoder, environment.command_search_path(), encode_path);
    encode_slice(
        &mut encoder,
        environment.required_features(),
        encode_feature,
    );
    encoder.finish()
}

/// Decodes and validates one exact portable v1 project environment.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for deterministic-CBOR, schema, bound,
/// canonical collection, path, or environment-entry violations.
pub fn decode_environment(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<Environment, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(5)?;
    decoder.exact("environment version", 1)?;
    let closure = decode_vec(&mut decoder, decode_environment_member)?;
    let variables = decode_vec(&mut decoder, decode_environment_entry)?;
    let command_search_path = decode_vec(&mut decoder, decode_path)?;
    let required_features = decode_vec(&mut decoder, decode_feature)?;
    decoder.finish()?;
    Environment::new(closure, variables, command_search_path, required_features)
        .map_err(|error| semantics("environment", error))
}

fn encode_view_source(encoder: &mut Encoder, source: &ViewSource) {
    match source {
        ViewSource::ImmutableTree { tree } => {
            encoder.array(2);
            encoder.unsigned(0);
            encode_descriptor(encoder, tree);
        }
        ViewSource::LiveExport {
            owner_sandbox,
            export,
            source_generation,
        } => {
            encoder.array(4);
            encoder.unsigned(1);
            encoder.bytes(owner_sandbox.as_bytes());
            encoder.bytes(export.as_bytes());
            encoder.unsigned(source_generation.get());
        }
    }
}

fn decode_view_source(decoder: &mut Decoder<'_>) -> Result<ViewSource, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("view source kind", 1)?;
    match (kind, length) {
        (0, 2) => Ok(ViewSource::ImmutableTree {
            tree: decode_descriptor_for_role(decoder, DescriptorRole::ImmutableViewSource)?,
        }),
        (1, 4) => Ok(ViewSource::LiveExport {
            owner_sandbox: SandboxId::from_bytes(exact_bytes(decoder, 16)?),
            export: ExportId::from_bytes(exact_bytes(decoder, 16)?),
            source_generation: Revision::new(decoder.unsigned()?),
        }),
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if kind == 0 { 2 } else { 4 },
            actual: length,
            offset,
        }),
    }
}

fn decode_environment_member(
    decoder: &mut Decoder<'_>,
) -> Result<ObjectDescriptor, CanonicalCborError> {
    decode_descriptor_for_role(decoder, DescriptorRole::EnvironmentClosure)
}

fn encode_presentation_action(encoder: &mut Encoder, action: &PresentationAction) {
    match action {
        PresentationAction::Include {
            source_prefix,
            destination,
        } => {
            encoder.array(3);
            encoder.unsigned(0);
            encode_path(encoder, source_prefix);
            encode_path(encoder, destination);
        }
        PresentationAction::Exclude { destination } => {
            encoder.array(2);
            encoder.unsigned(1);
            encode_path(encoder, destination);
        }
        PresentationAction::Present {
            destination,
            presentation_profile,
        } => {
            encoder.array(3);
            encoder.unsigned(2);
            encode_path(encoder, destination);
            encode_feature(encoder, presentation_profile);
        }
    }
}

fn decode_presentation_action(
    decoder: &mut Decoder<'_>,
) -> Result<PresentationAction, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("view presentation action", 2)?;
    match (kind, length) {
        (0, 3) => Ok(PresentationAction::Include {
            source_prefix: decode_path(decoder)?,
            destination: decode_path(decoder)?,
        }),
        (1, 2) => Ok(PresentationAction::Exclude {
            destination: decode_path(decoder)?,
        }),
        (2, 3) => Ok(PresentationAction::Present {
            destination: decode_path(decoder)?,
            presentation_profile: decode_feature(decoder)?,
        }),
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if kind == 1 { 2 } else { 3 },
            actual: length,
            offset,
        }),
    }
}

pub(super) fn encode_cache_domain(encoder: &mut Encoder, domain: CacheDomain) {
    encoder.array(2);
    encoder.unsigned(match domain.kind() {
        CacheDomainKind::Private => 0,
        CacheDomainKind::Project => 1,
        CacheDomainKind::TrustDomain => 2,
        CacheDomainKind::Public => 3,
    });
    encoder.bytes(domain.domain_id().as_bytes());
}

pub(super) fn decode_cache_domain(
    decoder: &mut Decoder<'_>,
) -> Result<CacheDomain, CanonicalCborError> {
    decoder.array(2)?;
    let kind = match decoder.closed("cache domain kind", 3)? {
        0 => CacheDomainKind::Private,
        1 => CacheDomainKind::Project,
        2 => CacheDomainKind::TrustDomain,
        3 => CacheDomainKind::Public,
        _ => unreachable!("closed cache domain kind"),
    };
    let domain_id = CacheDomainId::from_bytes(exact_bytes(decoder, 16)?);
    Ok(CacheDomain::new(kind, domain_id))
}

pub(super) const fn view_mutation_code(mutation: ViewMutation) -> u64 {
    match mutation {
        ViewMutation::ReadOnly => 0,
        ViewMutation::ReadWrite => 1,
        ViewMutation::PrivateCow => 2,
        ViewMutation::AppendOnly => 3,
        ViewMutation::Service => 4,
    }
}

pub(super) fn decode_view_mutation(
    decoder: &mut Decoder<'_>,
) -> Result<ViewMutation, CanonicalCborError> {
    Ok(match decoder.closed("view mutation", 4)? {
        0 => ViewMutation::ReadOnly,
        1 => ViewMutation::ReadWrite,
        2 => ViewMutation::PrivateCow,
        3 => ViewMutation::AppendOnly,
        4 => ViewMutation::Service,
        _ => unreachable!("closed view mutation"),
    })
}

fn view_consistency_code(consistency: ViewConsistency) -> u64 {
    match consistency {
        ViewConsistency::Immutable => 0,
        ViewConsistency::LocalLive => 1,
        ViewConsistency::ExternalVersioned => 2,
    }
}

fn decode_view_consistency(
    decoder: &mut Decoder<'_>,
) -> Result<ViewConsistency, CanonicalCborError> {
    Ok(match decoder.closed("view consistency", 2)? {
        0 => ViewConsistency::Immutable,
        1 => ViewConsistency::LocalLive,
        2 => ViewConsistency::ExternalVersioned,
        _ => unreachable!("closed view consistency"),
    })
}

fn encode_environment_entry(encoder: &mut Encoder, entry: &EnvironmentEntry) {
    encoder.array(2);
    encoder.text(entry.name());
    encoder.text(entry.value());
}

fn decode_environment_entry(
    decoder: &mut Decoder<'_>,
) -> Result<EnvironmentEntry, CanonicalCborError> {
    decoder.array(2)?;
    let name = decoder.text(4_096)?.to_owned();
    let value = decoder.text(1_048_576)?.to_owned();
    EnvironmentEntry::new(name, value).map_err(|error| semantics("environment entry", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InvalidViewModel;
    use crate::{FeatureRef, MediaType, ObjectDescriptor, ObjectDigest};

    fn feature() -> FeatureRef {
        FeatureRef::new("aos.sandbox.identity.posix32", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"))
    }

    fn descriptor() -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([7; 32]),
            12,
        )
    }

    #[test]
    fn view_round_trip_preserves_live_generation() {
        let view = View::new(
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([1; 16]),
                export: ExportId::from_bytes([2; 16]),
                source_generation: Revision::new(42),
            },
            Vec::new(),
            ViewConsistency::LocalLive,
            ViewMutation::ReadOnly,
            feature(),
            CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test view failed: {error}"));
        let encoded = encode_view(&view);

        assert_eq!(decode_view(&encoded, DecodeLimits::default()), Ok(view));
    }

    #[test]
    fn environment_round_trip_preserves_ordered_search_path() {
        let environment = Environment::new(
            vec![descriptor()],
            vec![
                EnvironmentEntry::new("PATH".to_owned(), "bin".to_owned())
                    .unwrap_or_else(|error| panic!("test entry failed: {error}")),
            ],
            vec![crate::RelativePath::default()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test environment failed: {error}"));
        let encoded = encode_environment(&environment);

        assert_eq!(
            decode_environment(&encoded, DecodeLimits::default()),
            Ok(environment)
        );
    }

    #[test]
    fn view_decoder_rejects_unknown_mutation() {
        let view = View::new(
            ViewSource::ImmutableTree { tree: descriptor() },
            Vec::new(),
            ViewConsistency::Immutable,
            ViewMutation::ReadOnly,
            feature(),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test view failed: {error}"));
        let mut encoded = encode_view(&view);
        let mutation_offset = {
            let mut decoder = Decoder::new(&encoded, DecodeLimits::default())
                .unwrap_or_else(|error| panic!("test decoder failed: {error}"));
            decoder
                .array(8)
                .unwrap_or_else(|error| panic!("test array failed: {error}"));
            decoder
                .exact("view version", 1)
                .unwrap_or_else(|error| panic!("test version failed: {error}"));
            decode_view_source(&mut decoder)
                .unwrap_or_else(|error| panic!("test source failed: {error}"));
            assert_eq!(
                decoder
                    .array_len()
                    .unwrap_or_else(|error| panic!("test actions failed: {error}")),
                0
            );
            decode_view_consistency(&mut decoder)
                .unwrap_or_else(|error| panic!("test consistency failed: {error}"));
            decoder.position()
        };
        encoded[mutation_offset] = 5;

        assert!(decode_view(&encoded, DecodeLimits::default()).is_err());
    }

    #[test]
    fn overlapping_actions_remain_semantically_invalid() {
        let action = PresentationAction::Exclude {
            destination: crate::RelativePath::default(),
        };
        let result = View::new(
            ViewSource::ImmutableTree { tree: descriptor() },
            vec![action.clone(), action],
            ViewConsistency::Immutable,
            ViewMutation::ReadOnly,
            feature(),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        );
        assert_eq!(result, Err(InvalidViewModel::OverlappingDestination));
    }
}
