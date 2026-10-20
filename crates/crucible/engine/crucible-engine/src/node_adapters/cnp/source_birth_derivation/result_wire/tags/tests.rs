//! Checks the actual classifier against owned serde, Provider and world errors.

use super::*;
use crate::node_adapters::cnp::source_birth_derivation::result_wire::{Identity, ResultHeader};

#[test]
fn actual_serde_categories_and_coordinates_survive_nested_owners_without_rebasing() {
    for bytes in [b"[\n  ".as_slice(), b"[\n  !]".as_slice()] {
        let error = serde_json::from_slice::<serde_json::Value>(bytes).unwrap_err();
        let expected_line = u64::try_from(error.line()).unwrap();
        let expected_column = u64::try_from(error.column()).unwrap();
        let expected_category = match error.classify() {
            serde_json::error::Category::Eof => SerdeCategory::Eof,
            serde_json::error::Category::Syntax => SerdeCategory::Syntax,
            _ => panic!("wrong actual serde fixture"),
        };
        let owned = DerivationCause::Provider(ProviderError::Contract(ContractError::Json(error)));
        let (cause, metadata) = classify_cause(&owned).unwrap();
        assert_eq!(cause, Cause::ProviderContractJson);
        assert_eq!(
            metadata,
            Some(SerdeMetadata {
                category: expected_category,
                line: expected_line,
                column: expected_column
            })
        );
        let info = FailureInfo {
            status: Status::DerivationFailure,
            stage: Stage::CoordinatorDecode,
            cause,
            metadata,
        };
        let header = ResultHeader::failure(
            Identity {
                task_digest: [1; 32],
                input_digest: [2; 32],
            },
            info,
            "complete original error",
            256,
        )
        .unwrap();
        let encoded = header.encode();
        assert_eq!(encoded[11], 1);
        assert_eq!(
            ResultHeader::decode(&encoded).unwrap().serde_metadata(),
            metadata
        );
        let mut unknown = encoded;
        unknown[12] = 255;
        assert_eq!(
            ResultHeader::decode(&unknown),
            Err(WireError::UnknownTag(TagField::SerdeCategory, 255))
        );
        let mut absent = encoded;
        absent[11] = 0;
        assert_eq!(ResultHeader::decode(&absent), Err(WireError::InvalidShape));
    }
}

#[test]
fn actual_zero_coordinate_io_and_nonserde_refusals_are_distinct() {
    let error = serde_json::Error::io(std::io::ErrorKind::BrokenPipe.into());
    let line = u64::try_from(error.line()).unwrap();
    let column = u64::try_from(error.column()).unwrap();
    let (cause, metadata) = classify_cause(&DerivationCause::Json(error)).unwrap();
    assert_eq!(cause, Cause::Json);
    assert_eq!(
        metadata,
        Some(SerdeMetadata {
            category: SerdeCategory::Io,
            line,
            column
        })
    );
    let (cause, metadata) = classify_cause(&DerivationCause::Provider(ProviderError::Io(
        std::io::ErrorKind::BrokenPipe.into(),
    )))
    .unwrap();
    assert_eq!(cause, Cause::ProviderIo);
    assert_eq!(metadata, None);
    let (cause, metadata) = classify_cause(&DerivationCause::World(
        WorldRefusal::ReactiveCoordinatorChanged,
    ))
    .unwrap();
    assert_eq!(cause, Cause::WorldReactiveChanged);
    assert_eq!(metadata, None);
    assert!(!valid_failure(
        Status::DerivationFailure,
        Stage::LaunchValidation,
        Cause::WorldReactiveChanged
    ));
    assert!(!valid_failure(
        Status::DerivationFailure,
        Stage::WorldComparison,
        Cause::OutputLimit
    ));
    assert!(!valid_failure(
        Status::OperationalFailure,
        Stage::WorldComparison,
        Cause::DiagnosticLimit
    ));
}
