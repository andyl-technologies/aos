//! Computes raw reference digests without using any Terrane record codec.
//!
//! The independent CBOR vector generator supplies bytes on standard input and
//! consumes one lowercase BLAKE3 digest on standard output. This tool provides
//! only the already vendored hash primitive; it grants no content or authority
//! interpretation to its input. The bound limits the reference tool's input,
//! rather than changing any format decoder's limits.

use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    const MAX_REFERENCE_BYTES: u64 = 16 * 1024 * 1024;
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REFERENCE_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_REFERENCE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reference input exceeds 16 MiB",
        ));
    }

    writeln!(io::stdout().lock(), "{}", blake3::hash(&input).to_hex())
}
