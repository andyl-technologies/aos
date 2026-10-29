//! Read-only, bounded physical provider observations for an operator.
//!
//! A selection is finite and explicit. Responses do not establish installed
//! authority, complete inventory, provider settlement, or writer exclusion.

mod config;
mod journal;
mod transport;

#[cfg(test)]
mod tests;

use std::{fs::File, io::Read, path::Path};

use anyhow::{ensure, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use config::{Credentials, Selection};
use journal::Journal;
use transport::Cutoff;

fn executable() -> Result<Value> {
    use std::os::unix::fs::MetadataExt;
    let mut file = File::open("/proc/self/exe")?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= 512 * 1024 * 1024,
        "producer executable bound differs"
    );
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .ok_or_else(|| anyhow::anyhow!("executable size overflow"))?;
        ensure!(
            size <= 512 * 1024 * 1024,
            "producer executable grew beyond bound"
        );
        hash.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    ensure!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        ) && size == before.len(),
        "producer executable changed"
    );
    let process = std::fs::read_to_string("/proc/self/stat")?;
    let fields = process
        .rsplit_once(") ")
        .ok_or_else(|| anyhow::anyhow!("process identity absent"))?
        .1;
    let start_ticks = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow::anyhow!("start ticks absent"))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    Ok(
        json!({"file":std::fs::read_link("/proc/self/exe")?,"sha256":hex::encode(hash.finalize()),"byteSize":size.to_string(),
        "pid":std::process::id(),"uid":rustix::process::geteuid().as_raw(),"startTicks":start_ticks,"bootId":boot.trim(),
        "networkNamespace":std::fs::read_link("/proc/self/ns/net")?,"mountNamespace":std::fs::read_link("/proc/self/ns/mnt")?}),
    )
}

pub(super) async fn run(selection_fd: u32, credentials_fd: u32, output: &Path) -> Result<()> {
    // The package recipe must supply the actual source commitment. A runtime
    // argument cannot turn an unbound development executable into that package.
    let source = option_env!("AOS_PROVIDER_READBACK_SOURCE_SHA256")
        .ok_or_else(|| anyhow::anyhow!("producer has no compiled source commitment"))?;
    ensure!(
        source.len() == 64 && source.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "producer source commitment malformed"
    );
    ensure!(
        selection_fd >= 3 && credentials_fd >= 3 && selection_fd != credentials_fd,
        "inherited descriptors differ"
    );
    let selected_bytes = config::inherited(selection_fd, 16 * 1024)?;
    let selection: Selection = serde_json::from_slice(&selected_bytes)
        .map_err(|_| anyhow::anyhow!("readback selection schema differs"))?;
    let cutoff = Cutoff::new(&selection)?;
    let journal = Journal::create(output)?;
    let selection_ref = journal.write("selection.json", &selected_bytes)?;
    let identity = executable()?;
    journal.write(
        "producer.json",
        &serde_json::to_vec(&json!({"version":1,"sourceSha256":source,"executable":identity}))?,
    )?;
    cutoff.remaining()?;

    // Credential bytes and their hashes never enter a receipt or public error.
    let credential_bytes = config::inherited(credentials_fd, 8 * 1024)?;
    let credentials: Credentials = serde_json::from_slice(&credential_bytes)
        .map_err(|_| anyhow::anyhow!("credential descriptor schema differs"))?;
    credentials.validate()?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| anyhow::anyhow!("verified HTTPS client unavailable"))?;
    let requests = transport::requests(
        &selection,
        &credentials,
        transport::unix_now()?,
        cutoff.remaining()?.as_secs().max(1),
    )?;
    let mut observations = Vec::new();
    let mut stopped = false;
    for (ordinal, request) in requests.iter().enumerate() {
        match transport::observe(
            &client,
            request,
            &credentials,
            &selection,
            &cutoff,
            &journal,
            ordinal,
        )
        .await
        {
            Ok(row) => {
                let terminal = row.get("outcome").and_then(Value::as_str) != Some("complete");
                journal.write(
                    &format!("{ordinal:02}-observation.json"),
                    &serde_json::to_vec(&row)?,
                )?;
                observations.push(row);
                if terminal {
                    stopped = true;
                    break;
                }
            }
            Err(_) => {
                stopped = true;
                break;
            }
        }
    }
    let response_coverage = !stopped && observations.len() == requests.len();
    journal.write("report.json", &serde_json::to_vec(&json!({"version":1,"scope":"selected_readonly_provider_metadata",
        "selection":selection_ref,"producerSourceSha256":source,"plannedRequests":requests.len(),"observations":observations,
        "responseCoverageComplete":response_coverage,"stopped":stopped,"unobservedOrdinals":(observations.len()..requests.len()).collect::<Vec<_>>(),"qualificationComplete":false,
        "effectivePermissions":null,"globalWriterClosure":null,"fullInventory":null,"providerBilledBytes":null,
        "scopeLimits":"One bounded list page, selected object HEAD metadata, ordinary verified HTTPS; no object content GET, mutation, retry or remote-drain claim."}))?)?;
    Ok(())
}
