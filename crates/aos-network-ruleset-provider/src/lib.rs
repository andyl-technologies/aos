//! Native reconciliation of the host firewall through one owned nftables table.
//!
//! Apply replaces the table atomically and retains its observed JSON digest.
//! Observe checks that receipt against the kernel. Interrupted mutations without
//! a completed receipt are indeterminate; another installation scope or unmanaged
//! table is never silently adopted or removed.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const STATE_ROOT: &str = "/var/lib/aos/network-ruleset";
const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "aos_filter";
const MAX_MARKER_BYTES: u64 = 1024 * 1024;
const MAX_OBSERVATION_BYTES: usize = 8 * 1024 * 1024;
const NFT_EXECUTABLE: &str = match option_env!("AOS_NFT_EXECUTABLE") {
    Some(path) => path,
    None => "/nonexistent/aos-nft",
};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    transport: Transport,
    port: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Policy {
    Accept,
    Drop,
}

impl Policy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Drop => "drop",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IngressPolicy {
    endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ForwardingPolicy {
    policy: Policy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RulesetRequest {
    #[serde(rename = "defaultPolicy")]
    input_policy: Policy,
    forward_policy: Policy,
    trusted_interfaces: Vec<String>,
    #[serde(rename = "allowedTCP")]
    allowed_tcp: Vec<u16>,
    #[serde(rename = "allowedUDP")]
    allowed_udp: Vec<u16>,
    #[serde(default)]
    ingress: BTreeMap<String, IngressPolicy>,
    #[serde(default)]
    forwarding: BTreeMap<String, ForwardingPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateMarker {
    id: String,
    revision: String,
    observed_digest: Option<Sha256Digest>,
}

/// Reconciles one host firewall using the retained, source-built nft executable.
pub struct NetworkRulesetProvider {
    nft: PathBuf,
    state_root: PathBuf,
}

impl NetworkRulesetProvider {
    /// Constructs the production handler with the build-authenticated nft path.
    #[must_use]
    pub fn production() -> Self {
        Self {
            nft: NFT_EXECUTABLE.into(),
            state_root: STATE_ROOT.into(),
        }
    }

    /// Handles an apply, remove, or observe native process invocation.
    ///
    /// # Errors
    /// Returns an error for invalid input, conflicting ownership, drift, malformed
    /// retained state, a concurrent invocation, or a failed nftables transaction.
    pub fn handle(&self, purpose: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        let invocation: Invocation = serde_json::from_slice(bytes)?;
        ensure!(
            matches!(purpose, "apply" | "remove" | "observe"),
            "unsupported handler action"
        );
        ensure!(
            purpose == "observe"
                || matches!(
                    (purpose, invocation.action),
                    ("apply", Action::Apply) | ("remove", Action::Remove)
                ),
            "action differs from invocation"
        );
        let identity = &invocation.effect.identity;
        ensure!(
            identity.len() >= 3
                && identity[identity.len() - 3] == "networkPolicy"
                && identity[identity.len() - 2] == "ruleset",
            "unsupported native operation"
        );
        let request: RulesetRequest = serde_json::from_value(invocation.input.clone())?;
        validate_request(&request)?;

        fs::create_dir_all(&self.state_root)?;
        ensure!(
            !fs::symlink_metadata(&self.state_root)?
                .file_type()
                .is_symlink(),
            "state root is a symlink"
        );
        fs::set_permissions(&self.state_root, fs::Permissions::from_mode(0o700))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(self.state_root.join("lock"))?;
        lock.try_lock().context("locking the host ruleset")?;

        let marker = self.read_marker()?;
        let observed = self.observed_digest()?;
        let status = classify_receipt(
            invocation.action,
            &invocation.id,
            &invocation.revision,
            invocation
                .previous
                .as_ref()
                .map(|previous| previous.revision.as_str()),
            marker.as_ref(),
            observed,
        );

        let result = match purpose {
            "observe" => {
                if status == "current" {
                    json!({"status": status, "outputs": outputs()})
                } else {
                    json!({"status": status})
                }
            }
            "apply" => {
                ensure!(
                    matches!(status, "current" | "retry-safe"),
                    "ruleset is unclaimed, conflicted, or drifted"
                );
                self.write_marker(&StateMarker {
                    id: invocation.id.clone(),
                    revision: invocation.revision.clone(),
                    observed_digest: None,
                })?;
                self.apply(&request)?;
                let digest = self
                    .observed_digest()?
                    .context("applied ruleset is absent")?;
                self.write_marker(&StateMarker {
                    id: invocation.id,
                    revision: invocation.revision,
                    observed_digest: Some(digest),
                })?;
                outputs()
            }
            "remove" => {
                if status != "absent" {
                    ensure!(
                        status == "retry-safe",
                        "refusing to remove a conflicted or drifted table"
                    );
                    self.remove_table_if_present()?;
                    fs::remove_file(self.state_root.join("claim.json"))?;
                    fs::File::open(&self.state_root)?.sync_all()?;
                }
                json!({})
            }
            _ => bail!("unsupported handler action"),
        };
        serde_json::to_vec(&result).context("encoding native ruleset result")
    }

    fn apply(&self, desired: &RulesetRequest) -> Result<()> {
        let replacement = render_replacement(desired, self.table_exists()?);
        let mut child = Command::new(&self.nft)
            .args(["--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting nftables ruleset transaction")?;
        child
            .stdin
            .take()
            .context("nftables omitted stdin")?
            .write_all(replacement.as_bytes())?;
        let output = child.wait_with_output()?;
        ensure!(
            output.status.success(),
            "nftables rejected the ruleset: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    fn observed_digest(&self) -> Result<Option<Sha256Digest>> {
        if !self.table_exists()? {
            return Ok(None);
        }
        let output = Command::new(&self.nft)
            .args(["-j", "list", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .context("observing nftables ruleset")?;
        ensure!(
            output.status.success(),
            "nftables could not observe its owned table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            output.stdout.len() <= MAX_OBSERVATION_BYTES,
            "nftables observation exceeds its bound"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("decoding nftables JSON observation")?;
        Ok(Some(Sha256Digest::of_canonical(
            "aos.network.ruleset-observation/v1",
            &value,
        )?))
    }

    fn table_exists(&self) -> Result<bool> {
        let output = Command::new(&self.nft)
            .args(["-j", "list", "tables"])
            .output()
            .context("listing nftables tables")?;
        ensure!(
            output.status.success(),
            "nftables could not list tables: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            output.stdout.len() <= MAX_OBSERVATION_BYTES,
            "nftables table inventory exceeds its bound"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("decoding nftables table inventory")?;
        let entries = value
            .get("nftables")
            .and_then(serde_json::Value::as_array)
            .context("nftables table inventory omits its entry array")?;
        Ok(entries.iter().any(|entry| {
            entry.get("table").is_some_and(|table| {
                table.get("family").and_then(serde_json::Value::as_str) == Some(TABLE_FAMILY)
                    && table.get("name").and_then(serde_json::Value::as_str) == Some(TABLE_NAME)
            })
        }))
    }

    fn remove_table_if_present(&self) -> Result<()> {
        if !self.table_exists()? {
            return Ok(());
        }
        let output = Command::new(&self.nft)
            .args(["delete", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .context("removing nftables ruleset")?;
        ensure!(
            output.status.success(),
            "nftables could not remove its owned table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    fn read_marker(&self) -> Result<Option<StateMarker>> {
        let file = match fs::File::open(self.state_root.join("claim.json")) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading ruleset receipt"),
        };
        let mut bytes = Vec::new();
        file.take(MAX_MARKER_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            u64::try_from(bytes.len())? <= MAX_MARKER_BYTES,
            "receipt exceeds bound"
        );
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    fn write_marker(&self, marker: &StateMarker) -> Result<()> {
        let temporary = self.state_root.join("claim.tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(marker)?)?;
        file.sync_all()?;
        fs::rename(temporary, self.state_root.join("claim.json"))?;
        fs::File::open(&self.state_root)?.sync_all()?;
        Ok(())
    }
}

// Receipts bind mutations to the current or explicitly retained previous
// revision. A matching logical identity alone cannot authorize a stale caller.
fn classify_receipt(
    action: Action,
    id: &str,
    revision: &str,
    previous_revision: Option<&str>,
    marker: Option<&StateMarker>,
    observed: Option<Sha256Digest>,
) -> &'static str {
    let Some(marker) = marker else {
        return if observed.is_none() {
            if action == Action::Remove {
                "absent"
            } else {
                "retry-safe"
            }
        } else {
            "indeterminate"
        };
    };
    let compatible_revision = marker.revision == revision
        || (action == Action::Apply && previous_revision == Some(marker.revision.as_str()));
    if marker.id != id || !compatible_revision {
        return "indeterminate";
    }
    if observed.is_none() {
        return "retry-safe";
    }
    if marker.observed_digest.is_none() || marker.observed_digest != observed {
        return "indeterminate";
    }
    if action == Action::Apply && marker.revision == revision {
        "current"
    } else {
        "retry-safe"
    }
}

fn outputs() -> Value {
    json!({"resource": "inet/aos_filter"})
}

fn render_ruleset(request: &RulesetRequest) -> String {
    let mut tcp = request.allowed_tcp.iter().copied().collect::<BTreeSet<_>>();
    let mut udp = request.allowed_udp.iter().copied().collect::<BTreeSet<_>>();
    for policy in request.ingress.values() {
        for endpoint in &policy.endpoints {
            match endpoint.transport {
                Transport::Tcp => tcp.insert(endpoint.port),
                Transport::Udp => udp.insert(endpoint.port),
            };
        }
    }
    let forwarding = if request.forward_policy == Policy::Drop
        || request
            .forwarding
            .values()
            .any(|policy| policy.policy == Policy::Drop)
    {
        Policy::Drop
    } else {
        Policy::Accept
    };
    let mut rules = format!(
        "table {TABLE_FAMILY} {TABLE_NAME} {{\n  chain input {{\n    type filter hook input priority 0; policy {};\n    ct state established,related accept\n    ct state invalid drop\n",
        request.input_policy.as_str()
    );
    for interface in &request.trusted_interfaces {
        rules.push_str(&format!(
            "    iifname \"{}\" accept\n",
            escape_nft_string(interface)
        ));
    }
    rules.push_str("    ip protocol icmp accept\n    ip6 nexthdr ipv6-icmp accept\n");
    if !tcp.is_empty() {
        rules.push_str(&format!(
            "    tcp dport {{ {} }} accept\n",
            join_ports(&tcp)
        ));
    }
    if !udp.is_empty() {
        rules.push_str(&format!(
            "    udp dport {{ {} }} accept\n",
            join_ports(&udp)
        ));
    }
    rules.push_str(&format!(
        "  }}\n  chain forward {{\n    type filter hook forward priority 0; policy {};\n    ct state established,related accept\n    ct state invalid drop\n  }}\n  chain output {{\n    type filter hook output priority 0; policy accept;\n  }}\n}}\n",
        forwarding.as_str()
    ));
    rules
}

fn render_replacement(request: &RulesetRequest, table_exists: bool) -> String {
    let ruleset = render_ruleset(request);
    if table_exists {
        format!("delete table {TABLE_FAMILY} {TABLE_NAME}\n{ruleset}")
    } else {
        ruleset
    }
}

fn join_ports(ports: &BTreeSet<u16>) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn escape_nft_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn validate_request(request: &RulesetRequest) -> Result<()> {
    ensure!(
        request.ingress.len() <= 4096 && request.forwarding.len() <= 4096,
        "contribution bound exceeded"
    );
    ensure!(
        request.trusted_interfaces.len() <= 256,
        "trusted interface bound exceeded"
    );
    for interface in &request.trusted_interfaces {
        ensure!(
            !interface.is_empty()
                && interface.len() <= 128
                && !interface.contains(['\0', '\n', '\r']),
            "invalid interface name"
        );
    }
    ensure!(
        request.allowed_tcp.len() <= 4096 && request.allowed_udp.len() <= 4096,
        "port bound exceeded"
    );
    ensure!(
        request
            .allowed_tcp
            .iter()
            .chain(&request.allowed_udp)
            .all(|port| *port > 0),
        "port zero is invalid"
    );
    for contribution in request.ingress.values() {
        ensure!(
            contribution.endpoints.len() <= 65536,
            "endpoint bound exceeded"
        );
        ensure!(
            contribution
                .endpoints
                .iter()
                .all(|endpoint| endpoint.port > 0),
            "port zero is invalid"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RulesetRequest {
        RulesetRequest {
            input_policy: Policy::Drop,
            forward_policy: Policy::Accept,
            trusted_interfaces: vec!["lo".into()],
            allowed_tcp: vec![443, 443],
            allowed_udp: vec![53],
            ingress: BTreeMap::new(),
            forwarding: BTreeMap::new(),
        }
    }

    #[test]
    fn native_module_fields_round_trip_and_render() {
        let value = json!({
            "defaultPolicy": "drop", "forwardPolicy": "accept",
            "trustedInterfaces": ["lo"], "allowedTCP": [443], "allowedUDP": [53]
        });
        let request: RulesetRequest = serde_json::from_value(value).unwrap();
        validate_request(&request).unwrap();
        assert!(render_ruleset(&request).contains("tcp dport { 443 } accept"));
        let encoded = serde_json::to_value(request).unwrap();
        assert_eq!(encoded["allowedTCP"], json!([443]));
        assert!(encoded.get("allowedTcp").is_none());
    }

    #[test]
    fn rendering_preserves_allowances_and_atomic_replacement() {
        let mut request = request();
        request.ingress.insert(
            "web".into(),
            IngressPolicy {
                endpoints: vec![Endpoint {
                    transport: Transport::Tcp,
                    port: 80,
                }],
            },
        );
        request.forwarding.insert(
            "restriction".into(),
            ForwardingPolicy {
                policy: Policy::Drop,
            },
        );
        let rules = render_replacement(&request, true);
        assert!(rules.starts_with("delete table inet aos_filter\n"));
        assert!(rules.contains("tcp dport { 80, 443 } accept"));
        assert!(rules.contains("udp dport { 53 } accept"));
        assert!(rules.contains("hook forward priority 0; policy drop;"));
    }

    #[test]
    fn rejects_zero_ports_and_configuration_delimiters() {
        let mut request = request();
        request.allowed_tcp.push(0);
        assert!(validate_request(&request).is_err());
        request.allowed_tcp.pop();
        request.trusted_interfaces.push("lo\nadd table".into());
        assert!(validate_request(&request).is_err());
    }
    #[test]
    fn receipts_distinguish_current_drift_and_interrupted_mutations() {
        let digest = Sha256Digest::of_canonical("test", &json!({"table": "rules"})).unwrap();
        let mut marker = StateMarker {
            id: "owned".into(),
            revision: "old".into(),
            observed_digest: Some(digest),
        };
        assert_eq!(
            classify_receipt(
                Action::Apply,
                "owned",
                "old",
                None,
                Some(&marker),
                Some(digest)
            ),
            "current"
        );
        assert_eq!(
            classify_receipt(
                Action::Apply,
                "owned",
                "new",
                Some("old"),
                Some(&marker),
                Some(digest)
            ),
            "retry-safe"
        );
        assert_eq!(
            classify_receipt(
                Action::Apply,
                "owned",
                "new",
                None,
                Some(&marker),
                Some(digest)
            ),
            "indeterminate"
        );
        assert_eq!(
            classify_receipt(
                Action::Remove,
                "other",
                "old",
                None,
                Some(&marker),
                Some(digest)
            ),
            "indeterminate"
        );
        assert_eq!(
            classify_receipt(Action::Apply, "owned", "old", None, None, Some(digest)),
            "indeterminate"
        );
        marker.observed_digest = None;
        assert_eq!(
            classify_receipt(
                Action::Apply,
                "owned",
                "old",
                None,
                Some(&marker),
                Some(digest)
            ),
            "indeterminate"
        );
        assert_eq!(
            classify_receipt(Action::Remove, "owned", "old", None, Some(&marker), None),
            "retry-safe"
        );
        assert_eq!(
            classify_receipt(Action::Remove, "owned", "old", None, None, None),
            "absent"
        );
    }
}
