//! Provides explicit host administration and the read-only quota query helper.

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() == 7
        && arguments[0] == "initialize"
        && arguments[1] == "--config"
        && arguments[3] == "--ledger"
        && arguments[5] == "--roles"
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        return runtime.block_on(
            aos_terrane_integration::host::initial_enrollment::initialize(
                &PathBuf::from(&arguments[2]),
                &PathBuf::from(&arguments[4]),
                &PathBuf::from(&arguments[6]),
            ),
        );
    }
    if arguments.len() == 7
        && arguments[0] == "query"
        && arguments[1] == "--config"
        && arguments[3] == "--owner"
        && arguments[5] == "--domain"
    {
        let owner = arguments[4]
            .to_str()
            .ok_or_else(|| io::Error::other("invalid owner identifier"))?;
        let domain = arguments[6]
            .to_str()
            .ok_or_else(|| io::Error::other("invalid disclosure domain"))?;
        let evidence =
            aos_terrane_integration::host::query(&PathBuf::from(&arguments[2]), owner, domain)?;
        let observation = evidence.observation();
        println!(
            "project={} hard_limit_bytes={} charged_reserved_bytes={} roots={}",
            observation.project_id,
            observation.hard_limit_bytes,
            observation.charged_reserved_bytes,
            observation.roots.len()
        );
        return Ok(());
    }
    if arguments.len() != 5 || arguments[1] != "--config" || arguments[3] != "--ledger" {
        return Err(io::Error::other(
            "usage: aos-terrane-host <provision|serve> --config PATH --ledger PATH; \
             aos-terrane-host initialize --config PATH --ledger PATH --roles PATH",
        ));
    }
    let config = PathBuf::from(&arguments[2]);
    let ledger = PathBuf::from(&arguments[4]);
    match arguments[0].to_str() {
        Some("provision") => aos_terrane_integration::host::provision(&config, &ledger),
        Some("serve") => aos_terrane_integration::host::serve(&config, &ledger),
        _ => Err(io::Error::other("unknown host administrative operation")),
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-terrane-host: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("aos-terrane-host requires Linux");
    std::process::ExitCode::FAILURE
}
