//! Bounds and hashes the existing borrowed scheduler checkpoint representation.
//!
//! The first CBOR pass counts bytes before hashing their length-prefixed
//! hexadecimal representation. Both passes refuse an overlong write before it
//! reaches the destination; the stored checkpoint format remains unchanged.

use std::io::{self, Write};

use serde::Serialize;

use super::{
    MAGIC, MAX_SINGLE_SCHEDULER_CHECKPOINT_PAYLOAD_BYTES, SingleSchedulerCheckpointError,
    SingleSchedulerWire,
};
use crate::ContentHash;
use crate::model::HexMaterialWriter;

const DOMAIN: &str = "crucible.production-vm-exact-ram-frontier.v1";

pub(super) fn identity(
    wire: &SingleSchedulerWire,
) -> Result<ContentHash, SingleSchedulerCheckpointError> {
    identity_with_limit(wire, MAX_SINGLE_SCHEDULER_CHECKPOINT_PAYLOAD_BYTES)
}

fn identity_with_limit<T: Serialize>(
    wire: &T,
    maximum_payload: usize,
) -> Result<ContentHash, SingleSchedulerCheckpointError> {
    let mut count = PayloadCount {
        written: 0,
        maximum: maximum_payload,
        exceeded: false,
    };
    if ciborium::ser::into_writer(wire, &mut count).is_err() {
        return Err(if count.exceeded {
            SingleSchedulerCheckpointError::Limit
        } else {
            SingleSchedulerCheckpointError::Malformed
        });
    }
    let bytes = MAGIC
        .len()
        .checked_add(count.written)
        .ok_or(SingleSchedulerCheckpointError::Limit)?;
    let mut output =
        HexMaterialWriter::new(DOMAIN, bytes).ok_or(SingleSchedulerCheckpointError::Limit)?;
    output
        .write_all(MAGIC)
        .map_err(|_| SingleSchedulerCheckpointError::Malformed)?;
    ciborium::ser::into_writer(wire, &mut output)
        .map_err(|_| SingleSchedulerCheckpointError::Malformed)?;
    output
        .finish()
        .ok_or(SingleSchedulerCheckpointError::Malformed)
}

struct PayloadCount {
    written: usize,
    maximum: usize,
    exceeded: bool,
}

impl Write for PayloadCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(written) = self
            .written
            .checked_add(bytes.len())
            .filter(|written| *written <= self.maximum)
        else {
            self.exceeded = true;
            return Err(io::ErrorKind::FileTooLarge.into());
        };
        self.written = written;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn payload_limit_is_enforced_during_serialization() {
        let value = vec![0_u8, 23, 24, 255];
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&value, &mut payload).unwrap();
        let mut original = MAGIC.to_vec();
        original.extend_from_slice(&payload);
        let expected = ContentHash::from_canonical_hex_bytes(DOMAIN, &original);
        assert_eq!(
            identity_with_limit(&value, payload.len() - 1),
            Err(SingleSchedulerCheckpointError::Limit)
        );
        assert_eq!(identity_with_limit(&value, payload.len()), Ok(expected));
        assert_eq!(identity_with_limit(&value, payload.len() + 1), Ok(expected));

        let mut count = PayloadCount {
            written: 0,
            maximum: 3,
            exceeded: false,
        };
        count.write_all(&[0, 1]).unwrap();
        assert!(count.write_all(&[2, 3]).is_err());
        assert_eq!(count.written, 2);
        assert!(count.exceeded);
    }

    struct Changing(Cell<bool>);

    impl Serialize for Changing {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            if self.0.replace(true) {
                serializer.serialize_u64(256)
            } else {
                serializer.serialize_u64(0)
            }
        }
    }

    #[test]
    fn changing_serializer_cannot_publish_a_digest() {
        assert_eq!(
            identity_with_limit(&Changing(Cell::new(false)), 8),
            Err(SingleSchedulerCheckpointError::Malformed)
        );
    }
}
