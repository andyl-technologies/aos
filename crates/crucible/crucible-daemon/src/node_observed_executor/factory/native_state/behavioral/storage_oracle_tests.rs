//! Exercises the independent finite model without constructing a live owner.

use super::*;
use crucible_device::block::BlockCodecError;
use crucible_engine::node_adapters::ScriptedRequest;
use crucible_engine::node_contract::OperationFailure;
use crucible_node_format::ContractError;

#[derive(Debug)]
enum TestError {
    Script(OperationFailure),
    Block(BlockCodecError),
    Contract(ContractError),
    Qualification(QualificationError),
    Io(io::Error),
}

impl std::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Script(error) => write!(formatter, "script source refused: {error:?}"),
            Self::Block(error) => write!(formatter, "block codec refused: {error}"),
            Self::Contract(error) => write!(formatter, "contract refused: {error}"),
            Self::Qualification(error) => write!(formatter, "oracle refused: {error}"),
            Self::Io(error) => write!(formatter, "byte writer refused: {error}"),
        }
    }
}

impl From<OperationFailure> for TestError {
    fn from(error: OperationFailure) -> Self {
        Self::Script(error)
    }
}

impl From<BlockCodecError> for TestError {
    fn from(error: BlockCodecError) -> Self {
        Self::Block(error)
    }
}

impl From<ContractError> for TestError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<QualificationError> for TestError {
    fn from(error: QualificationError) -> Self {
        Self::Qualification(error)
    }
}

impl From<io::Error> for TestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn source_script(write: BlockRequest, read: BlockRequest) -> Result<Vec<u8>, TestError> {
    ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: write.encode()?,
            },
            ScriptedRequest {
                time_ps: 1_000_000_000,
                payload: read.encode()?,
            },
        ],
    )?
    .script_bytes()
    .map_err(TestError::Script)
}

#[test]
fn original_write_and_read_are_computed_from_the_base_array() -> Result<(), TestError> {
    let script = source_script(
        BlockRequest::write(9, 0, vec![0x33; 512]),
        BlockRequest::read(10, 0, 512),
    )?;
    let base = vec![0x11; 4096];

    let (_, responses, disk) = independent_model(&script, &base)?;

    assert_eq!(&disk[..512], &[0x33; 512]);
    assert_eq!(&disk[512..], &[0x11; 3584]);
    assert_eq!(base, vec![0x11; 4096]);
    assert_eq!(responses[0].len(), 20);
    assert_eq!(responses[0][12..16], 9u32.to_le_bytes());
    assert_eq!(responses[0][16..20], 0u32.to_le_bytes());
    assert_eq!(responses[1][12..16], 10u32.to_le_bytes());
    assert_eq!(responses[1][16..20], 512u32.to_le_bytes());
    assert_eq!(&responses[1][20..], &[0x33; 512]);

    Ok(())
}

#[test]
fn a_different_source_request_cannot_select_the_fixed_oracle() -> Result<(), TestError> {
    let script = source_script(
        BlockRequest::write(9, 512, vec![0x33; 512]),
        BlockRequest::read(10, 0, 512),
    )?;

    assert!(independent_model(&script, &[0x11; 4096]).is_err());

    Ok(())
}

#[test]
fn base_identity_changes_do_not_become_observed_expected_bytes() -> Result<(), TestError> {
    let script = source_script(
        BlockRequest::write(9, 0, vec![0x33; 512]),
        BlockRequest::read(10, 0, 512),
    )?;
    let mut changed = [0x11; 4096];
    changed[4095] = 0x33;

    assert!(independent_model(&script, &changed).is_err());
    assert!(independent_model(&script, &[0x11; 512]).is_err());

    Ok(())
}

#[test]
fn a_trailing_request_octet_is_not_silently_normalized() -> Result<(), TestError> {
    let script = source_script(
        BlockRequest::write(9, 0, vec![0x33; 512]),
        BlockRequest::read(10, 0, 512),
    )?;
    let mut changed = script;
    changed.push(0);

    assert!(independent_model(&changed, &[0x11; 4096]).is_err());

    Ok(())
}

#[test]
fn a_changed_fifo_request_identity_is_not_equivalent_to_readback() -> Result<(), TestError> {
    let script = source_script(
        BlockRequest::write(10, 0, vec![0x33; 512]),
        BlockRequest::read(9, 0, 512),
    )?;

    assert!(independent_model(&script, &[0x11; 4096]).is_err());

    Ok(())
}

#[test]
fn repeated_typed_bodies_retain_one_exact_original() -> Result<(), TestError> {
    let reference = canonical::content_ref(b"original", "application/octet-stream")?;
    let mut objects = Vec::new();

    retain_object(&mut objects, (reference.clone(), b"original".to_vec()))?;
    retain_object(&mut objects, (reference, b"original".to_vec()))?;

    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].1, b"original");

    Ok(())
}

#[test]
fn aggregate_byte_writer_refuses_before_copying_an_extra_octet() -> Result<(), TestError> {
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        maximum: 8,
    };

    writer.write_all(b"original")?;

    assert!(writer.write_all(b"x").is_err());
    assert_eq!(writer.bytes, b"original");

    Ok(())
}
