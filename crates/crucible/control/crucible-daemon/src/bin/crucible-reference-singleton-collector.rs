//! Runs one source-selected native singleton collection and prints its original result.
//!
//! The argument names a fresh private custody directory. The result records
//! unresolved qualification obligations and never issues an Accepted token.

use std::{io::Write, path::PathBuf};

use crucible_daemon::node_observed_executor::InstalledSingletonCollector;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let directory = arguments
        .next()
        .ok_or("fresh private custody directory required")?;
    if arguments.next().is_some() {
        return Err("only one private custody directory is accepted".into());
    }
    let run = InstalledSingletonCollector::built_in()?.start(PathBuf::from(directory))?;
    let original = match run.wait() {
        Ok(original) => original,
        Err(error) => {
            // The actor keeps uncertain journals and native owners. Preserve this
            // same process too; a notified failure cannot become clean exit.
            eprintln!("CRUCIBLE_SINGLETON_ORIGINAL_HELD: {error}");
            loop {
                std::thread::park_timeout(std::time::Duration::from_secs(1));
            }
        }
    };
    let mut output = std::io::stdout().lock();
    output.write_all(original.bytes())?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
