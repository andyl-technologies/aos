//! Reserves exclusive host transport/port slots before their service starts.
//!
//! The ownership record is a claim, rather than a socket: services own their listening
//! sockets. First acquisition checks the kernel, while replay checks the shared
//! claim ledger so the claimant's running service does not collide with itself.

use std::fs;
use std::net::{Ipv6Addr, SocketAddrV6, TcpListener, UdpSocket};

use anyhow::{Result, ensure};
use aos_activation::activation::{Action, Invocation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{STATE_ROOT, atomic_write, read_regular, state_path};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    transport: String,
    port: u16,
}

impl Input {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.transport.as_str(), "tcp" | "udp") && self.port != 0,
            "listener requires tcp/udp and a nonzero port"
        );
        Ok(())
    }

    fn resource(&self) -> String {
        format!("listener:{}:{}", self.transport, self.port)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnedState {
    owner: String,
    revision: String,
    input: Input,
}

fn available(input: &Input) -> Result<()> {
    // An IPv6 wildcard also covers IPv4 on the selected Linux host backend.
    // Check IPv4 separately so a v6-only kernel setting cannot hide a conflict.
    let address = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, input.port, 0, 0);
    if input.transport == "tcp" {
        let socket = TcpListener::bind(address)?;
        drop(socket);
        let socket = TcpListener::bind(("0.0.0.0", input.port))?;
        drop(socket);
    } else {
        let socket = UdpSocket::bind(address)?;
        drop(socket);
        let socket = UdpSocket::bind(("0.0.0.0", input.port))?;
        drop(socket);
    }
    Ok(())
}

/// Reserves or observes one exclusive native host listener slot.
///
/// # Errors
/// Returns an error for invalid endpoints, conflicting claims, occupied initial ports, or failed ownership record writes.
pub(super) fn execute(invocation: &Invocation, action: &str) -> Result<Value> {
    let input: Input = serde_json::from_value(invocation.input.clone())?;
    input.validate()?;
    let path = state_path(invocation, "listener");
    let prior: Option<OwnedState> = read_regular(&path, 65_536)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    if let Some(owned_state) = &prior {
        ensure!(
            owned_state.owner == invocation.id,
            "listener ownership record owner differs"
        );
        if owned_state.revision != invocation.revision {
            ensure!(
                action != "remove"
                    && invocation
                        .previous
                        .as_ref()
                        .is_some_and(|previous| previous.revision == owned_state.revision
                            && serde_json::from_value::<Input>(previous.input.clone())
                                .is_ok_and(|input| input == owned_state.input)),
                "listener update lacks its exact retained previous authority"
            );
        }
    }
    if action == "remove" {
        if prior.is_some() {
            fs::remove_file(path)?;
        }
        return Ok(json!({}));
    }
    for entry in fs::read_dir(STATE_ROOT)? {
        let entry = entry?;
        if entry.path() == path
            || !entry
                .file_name()
                .to_string_lossy()
                .ends_with("-listener.json")
        {
            continue;
        }
        let bytes = read_regular(&entry.path(), 65_536)?
            .ok_or_else(|| anyhow::anyhow!("listener ownership record disappeared"))?;
        let owned_state: OwnedState = serde_json::from_slice(&bytes)?;
        ensure!(
            owned_state.input != input,
            "listener already claimed by another effect"
        );
    }
    if action == "observe" {
        if prior.is_none() && invocation.action == Action::Remove {
            return Ok(json!({"status":"absent"}));
        }
        return Ok(match prior {
            Some(owned_state)
                if owned_state.input == input && owned_state.revision == invocation.revision =>
            {
                json!({"status":"current", "outputs":{"resource":input.resource()}})
            }
            _ => json!({"status":"retry-safe"}),
        });
    }
    if prior
        .as_ref()
        .is_none_or(|owned_state| owned_state.input != input)
    {
        available(&input)?;
    }
    let owned_state = OwnedState {
        owner: invocation.id.clone(),
        revision: invocation.revision.clone(),
        input: input.clone(),
    };
    atomic_write(&path, &serde_json::to_vec(&owned_state)?, 0o600)?;
    Ok(json!({"resource":input.resource()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_slots_validate_transport_and_port() {
        assert!(
            Input {
                transport: "tcp".into(),
                port: 53
            }
            .validate()
            .is_ok()
        );
        assert!(
            Input {
                transport: "udp".into(),
                port: 0
            }
            .validate()
            .is_err()
        );
        assert!(
            Input {
                transport: "sctp".into(),
                port: 53
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn kernel_collision_is_rejected() {
        let socket = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        assert!(
            available(&Input {
                transport: "tcp".into(),
                port
            })
            .is_err()
        );
    }
}
