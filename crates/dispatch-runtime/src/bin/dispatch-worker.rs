//! Runs bounded native optimization behind an independent Rust verifier.

use std::path::PathBuf;

use dispatch_runtime::{
    RuntimeError,
    worker::{RunnerConfig, run},
};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = execute().await {
        eprintln!("dispatch-worker: {error}");
        std::process::exit(1);
    }
}

async fn execute() -> Result<(), RuntimeError> {
    let mut arguments = std::env::args_os().skip(1);
    let mut backend = None;
    let mut backend_arguments = Vec::new();
    let mut maximum = 16 * 1024 * 1024;
    let mut connect = None;
    let mut owner_group_cleanup = false;
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--owner-group-cleanup") => owner_group_cleanup = true,
            Some("--backend") => backend = arguments.next().map(PathBuf::from),
            Some("--backend-arg") => backend_arguments.push(
                arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or_else(|| {
                        RuntimeError::Unsupported("--backend-arg requires UTF-8 text".into())
                    })?,
            ),
            Some("--max-frame-bytes") => {
                maximum = arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|value| *value >= 65_536)
                    .ok_or_else(|| RuntimeError::Unsupported("invalid --max-frame-bytes".into()))?
            }
            Some("--connect") => connect = arguments.next().map(PathBuf::from),
            _ => return Err(RuntimeError::Unsupported("unknown worker argument".into())),
        }
    }
    let config = RunnerConfig {
        backend: backend
            .ok_or_else(|| RuntimeError::Unsupported("--backend is required".into()))?,
        arguments: backend_arguments,
        max_frame_bytes: maximum,
        owner_group_cleanup,
    };
    #[cfg(unix)]
    if let Some(path) = connect {
        let stream = tokio::net::UnixStream::connect(path).await?;
        let (reader, writer) = stream.into_split();
        return run(config, reader, writer).await;
    }
    #[cfg(not(unix))]
    if connect.is_some() {
        return Err(RuntimeError::Unsupported(
            "local socket execution requires Unix".into(),
        ));
    }
    run(config, tokio::io::stdin(), tokio::io::stdout()).await
}
