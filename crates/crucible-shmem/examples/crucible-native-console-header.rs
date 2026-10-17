//! Prints the generated portable native-console process-protocol header.

use std::io::{self, Write};

fn main() -> io::Result<()> {
    let header = crucible_shmem::native_console::generated_native_console_c_header();
    io::stdout().lock().write_all(header.as_bytes())
}
