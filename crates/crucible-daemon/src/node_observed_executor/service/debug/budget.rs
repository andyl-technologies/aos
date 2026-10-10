//! Charges direct authored JSON before allocating its canonical representation.

use super::{NodeObservationServiceError, refused};
use serde::Serialize;
use std::io::{self, Write};

pub(super) fn bounded_json<T: Serialize>(
    value: &T,
    maximum_bytes: usize,
) -> Result<(), NodeObservationServiceError> {
    // This writer retains no bytes. Derived typed profiles serialize into its
    // finite credit before canonical encoding can allocate a Value or Vec.
    let mut writer = AdmissionCredit {
        remaining: maximum_bytes,
    };
    serde_json::to_writer(&mut writer, value).map_err(refused)
}

struct AdmissionCredit {
    remaining: usize,
}

impl Write for AdmissionCredit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            return Err(io::Error::other(
                "Debug original JSON byte credit exhausted",
            ));
        };
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
