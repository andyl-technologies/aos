//! Checks a borrowed object's canonical extent without retaining output bytes.
//!
//! The defining writer still performs JCS ordering, escaping and finite-number
//! formatting. Their temporary allocations and diagnostics remain separate
//! work; only the whole canonical output bank and owning root wrapper disappear.

use super::{ContractError, Map, Value, canonical_json_object_to_writer_at_depth};
use std::io::{self, Write};

/// Measures a borrowed root object's JCS encoding under a byte restriction.
///
/// Returns its exact encoded length when it fits, or `None` when writing would
/// exceed `maximum_bytes`. The walk stops at the first exhausted restriction;
/// an oversized prefix need not inspect later fields. No output bank or owning
/// JSON tree is constructed. Sorting and string-formatting allocations remain
/// independently funded work under the unchanged canonical grammar.
///
/// # Errors
/// Rejects unsupported nesting, excessive arrays, invalid numbers or canonical
/// encoding failure encountered before the byte restriction is exhausted.
pub fn canonical_json_object_length_with_limit(
    values: &Map<String, Value>,
    maximum_bytes: usize,
) -> Result<Option<usize>, ContractError> {
    let mut output = Extent {
        used: 0,
        maximum: maximum_bytes,
        exceeded: false,
    };
    let result = canonical_json_object_to_writer_at_depth(values, &mut output, 0);
    if output.exceeded {
        return Ok(None);
    }
    result?;
    Ok(Some(output.used))
}

struct Extent {
    used: usize,
    maximum: usize,
    exceeded: bool,
}

impl Write for Extent {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Every successful write preserves used <= maximum, so subtraction and
        // the subsequent addition cannot wrap even at usize::MAX.
        if bytes.len() > self.maximum - self.used {
            self.exceeded = true;
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.used += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Names this sink's controls within the defining general canonical counter.
///
/// Input owners, ordering/formatter backing and compiler frames remain separate.
pub(in crate::canonical) fn counter_scratch_data() -> usize {
    use std::mem::size_of;

    size_of::<Extent>()
        + size_of::<&Map<String, Value>>()
        // Each enclosing object can retain loans in write_canonical, the
        // borrowed object adapter and write_object_fields. The entry and sink
        // also retain their own loans alongside those recursive activations.
        + 65 * 3 * size_of::<&mut Extent>()
        + 2 * size_of::<&mut Extent>()
        + size_of::<&[u8]>()
        + size_of::<usize>() * 2
        + size_of::<bool>()
        + size_of::<Option<usize>>()
        + size_of::<io::Error>()
        + size_of::<Result<usize, io::Error>>()
        + size_of::<Result<(), ContractError>>()
        + size_of::<Result<Option<usize>, ContractError>>()
}

#[cfg(test)]
#[path = "extent/tests.rs"]
mod tests;
