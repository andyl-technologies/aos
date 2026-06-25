//! Prints the generated Crucible shared-memory C ABI header.

use std::io::{self, Write};

fn main() -> io::Result<()> {
    let header = crucible_shmem::generated_c_header();
    io::stdout().lock().write_all(header.as_bytes())
}
