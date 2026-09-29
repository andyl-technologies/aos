//! Adapts the shared, input-proportional property-value validator.

use super::Error;
use crate::{cbor::Decoder, tree_format};

pub(super) fn skip_value(decoder: &mut Decoder<'_>, max_bytes: usize) -> Result<(), Error> {
    let start = decoder.position();
    tree_format::property_value(decoder).map_err(|error| match error {
        tree_format::Error::Cbor(error) => Error::Cbor(error),
        tree_format::Error::Limit => Error::Limit,
        _ => Error::InvalidValue,
    })?;
    if decoder.position() - start > max_bytes {
        return Err(Error::Limit);
    }
    Ok(())
}
