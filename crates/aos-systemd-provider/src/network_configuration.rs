//! Systemd realization of the provider-neutral host network configuration.
//!
//! The pure renderer owns networkd and resolved file syntax. The live terminal
//! owns only the exact metadata seed and networkd reload operation selected by
//! the checked controller resource.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_ability_model::{
    AbilityValue, AccessMode, LocalKey, MethodReference, MethodSemantics, ResourceReference,
};
use aos_contract::Sha256Digest;
use aos_net::{BootstrapLinkSelector, BootstrapNetwork};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA, SupportedPurposes,
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tempfile::NamedTempFile;
use tokio::process::Command;

use crate::{decode_value, target_context, value};

pub(crate) const EFFECTS_INTERFACE_NAME: &str = "aos.network.configuration-effects";
pub(crate) const REALIZATION_SCHEMA: &str = "aos.systemd.network-configuration-realization/v1";
pub(crate) const STATIC_INPUT_SCHEMA: &str = "aos.systemd.network-configuration-static-input/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.network-configuration-observation/v1";
const CONTEXT_SCHEMA: &str = "aos.systemd.network-configuration-context/v1";
const SEED_RELATIVE_PATH: &str = "systemd/network/10-aos-seed.network";

#[derive(Clone, Debug, Eq, PartialEq)]
enum NetworkAuthority {
    Image,
    Operator,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LinkSelector {
    Name(String),
    Mac(String),
    Ethernet,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Addressing {
    dhcp: bool,
    addresses: Vec<String>,
    gateway: Option<String>,
    dns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NetworkLink {
    Ethernet {
        name: LocalKey,
        selector: LinkSelector,
        addressing: Addressing,
    },
    Vlan {
        name: LocalKey,
        parent: LinkSelector,
        id: u16,
        addressing: Addressing,
    },
    Bond {
        name: LocalKey,
        members: Vec<LinkSelector>,
        mode: String,
        addressing: Addressing,
    },
}

impl NetworkLink {
    fn name(&self) -> &LocalKey {
        match self {
            Self::Ethernet { name, .. } | Self::Vlan { name, .. } | Self::Bond { name, .. } => name,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolverConfiguration {
    enabled: bool,
    nameservers: Vec<String>,
    search: Vec<String>,
    dnssec: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NetworkConfiguration {
    authority: NetworkAuthority,
    links: Vec<NetworkLink>,
    resolver: ResolverConfiguration,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TaggedArtifactReference {
    #[serde(rename = "_type")]
    value_type: String,
    content: Sha256Digest,
    store_path: String,
    nar_hash: Sha256Digest,
    closure: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkConfigurationRealization {
    schema: String,
    systemd: TaggedArtifactReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NetworkObservation {
    schema: String,
    expected: NetworkConfiguration,
    applied_bootstrap: Option<BootstrapNetwork>,
    state: NetworkState,
    discrepancies: Vec<LocalKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NetworkState {
    Absent,
    Ready,
    Drifted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NetworkContext {
    schema: String,
    configuration_matches: bool,
    seed_matches: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RenderedConfiguration {
    files: BTreeMap<PathBuf, Vec<u8>>,
}

pub(crate) fn supports(method: &MethodReference) -> bool {
    method.interface.name.as_str() == EFFECTS_INTERFACE_NAME
}

pub(crate) fn render_static(value: Value, output: &Path) -> Result<()> {
    let document = object(&value, "static network-configuration input")?;
    if text_field(document, "schema")? != STATIC_INPUT_SCHEMA {
        bail!("unsupported static network-configuration input schema");
    }
    let desired = ability_value_field(document, "desired")?;
    let desired = network_configuration_from_validated(&desired)?;
    let realization = serde_json::from_value(
        document
            .get("realization")
            .context("static network-configuration input has no realization")?
            .clone(),
    )
    .context("decoding systemd network-configuration realization")?;
    require_realization(&realization)?;
    let rendered = render(&desired)?;

    for (relative, bytes) in rendered.files {
        let destination = output.join("etc").join(relative);
        let parent = destination
            .parent()
            .ok_or_else(|| anyhow::anyhow!("rendered network path has no parent"))?;
        fs::create_dir_all(parent).context("creating rendered network directory")?;
        fs::write(destination, bytes).context("writing rendered network configuration")?;
    }
    Ok(())
}

fn network_configuration_from_validated(value: &AbilityValue) -> Result<NetworkConfiguration> {
    let document = object(value.as_json(), "validated network configuration")?;
    let authority = match text_field(document, "authority")? {
        "image" => NetworkAuthority::Image,
        "operator" => NetworkAuthority::Operator,
        _ => bail!("validated network configuration has an unknown authority"),
    };
    let links = array_field(document, "links")?
        .iter()
        .map(network_link_from_validated)
        .collect::<Result<Vec<_>>>()?;
    let resolver = resolver_from_validated(field(document, "resolver")?)?;
    let prerequisites = serde_json::from_value(field(document, "prerequisites")?.clone())
        .context("projecting validated network prerequisites")?;

    Ok(NetworkConfiguration {
        authority,
        links,
        resolver,
        prerequisites,
    })
}

fn network_link_from_validated(value: &Value) -> Result<NetworkLink> {
    let document = object(value, "validated network link")?;
    let name = LocalKey::new(text_field(document, "name")?)?;
    let addressing = addressing_from_validated(field(document, "addressing")?)?;
    match text_field(document, "kind")? {
        "ethernet" => Ok(NetworkLink::Ethernet {
            name,
            selector: selector_from_validated(field(document, "selector")?)?,
            addressing,
        }),
        "vlan" => {
            let id = field(document, "id")?
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .context("validated VLAN id is not an unsigned 16-bit integer")?;
            Ok(NetworkLink::Vlan {
                name,
                parent: selector_from_validated(field(document, "parent")?)?,
                id,
                addressing,
            })
        }
        "bond" => Ok(NetworkLink::Bond {
            name,
            members: array_field(document, "members")?
                .iter()
                .map(selector_from_validated)
                .collect::<Result<Vec<_>>>()?,
            mode: text_field(document, "mode")?.to_string(),
            addressing,
        }),
        _ => bail!("validated network link has an unknown kind"),
    }
}

fn selector_from_validated(value: &Value) -> Result<LinkSelector> {
    let document = object(value, "validated network selector")?;
    match text_field(document, "kind")? {
        "name" => Ok(LinkSelector::Name(
            text_field(document, "value")?.to_string(),
        )),
        "mac" => Ok(LinkSelector::Mac(
            text_field(document, "value")?.to_string(),
        )),
        "ethernet" => Ok(LinkSelector::Ethernet),
        _ => bail!("validated network selector has an unknown kind"),
    }
}

fn addressing_from_validated(value: &Value) -> Result<Addressing> {
    let document = object(value, "validated network addressing")?;
    Ok(Addressing {
        dhcp: field(document, "dhcp")?
            .as_bool()
            .context("validated network DHCP field is not Boolean")?,
        addresses: string_list_field(document, "addresses")?,
        gateway: optional_text_field(document, "gateway")?,
        dns: string_list_field(document, "dns")?,
    })
}

fn resolver_from_validated(value: &Value) -> Result<ResolverConfiguration> {
    let document = object(value, "validated network resolver")?;
    Ok(ResolverConfiguration {
        enabled: field(document, "enabled")?
            .as_bool()
            .context("validated network resolver enabled field is not Boolean")?,
        nameservers: string_list_field(document, "nameservers")?,
        search: string_list_field(document, "search")?,
        dnssec: text_field(document, "dnssec")?.to_string(),
    })
}

fn bootstrap_from_apply_input(value: &AbilityValue) -> Result<Option<BootstrapNetwork>> {
    let document = object(value.as_json(), "validated network apply input")?;
    let Some(bootstrap) = document.get("bootstrap").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let bootstrap = AbilityValue::new(bootstrap.clone())
        .context("projecting validated network bootstrap input")?;
    BootstrapNetwork::from_validated(&bootstrap).map(Some)
}

fn ability_value_field(document: &Map<String, Value>, name: &str) -> Result<AbilityValue> {
    AbilityValue::new(field(document, name)?.clone())
        .with_context(|| format!("projecting validated network {name}"))
}

fn object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .with_context(|| format!("{context} is not an object"))
}

fn field<'a>(document: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    document
        .get(name)
        .with_context(|| format!("validated network value has no {name} field"))
}

fn text_field<'a>(document: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    field(document, name)?
        .as_str()
        .with_context(|| format!("validated network {name} field is not text"))
}

fn optional_text_field(document: &Map<String, Value>, name: &str) -> Result<Option<String>> {
    document
        .get(name)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("validated network {name} field is not text"))
        })
        .transpose()
}

fn array_field<'a>(document: &'a Map<String, Value>, name: &str) -> Result<&'a Vec<Value>> {
    field(document, name)?
        .as_array()
        .with_context(|| format!("validated network {name} field is not a list"))
}

fn string_list_field(document: &Map<String, Value>, name: &str) -> Result<Vec<String>> {
    array_field(document, name)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("validated network {name} item is not text"))
        })
        .collect()
}

pub(crate) async fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported admission request schema");
    }
    validate_admission_resource(&request)?;
    require_method(&request.method, &request.semantics)?;
    validate_resource_contexts(&request.resources)?;

    let expected = network_configuration_from_validated(&request.resource_spec.value)?;
    require_resource_contexts(&expected.prerequisites, &request.resources)?;
    let realization: NetworkConfigurationRealization =
        decode_value(&request.resource_spec.realization)?;
    require_realization(&realization)?;
    let rendered = render(&expected)?;
    let configuration_matches = rendered_matches(Path::new("/etc"), &rendered)?;
    let observation = observation(&expected, None, configuration_matches, true, false)?;
    let supported_purposes = SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .ok_or_else(|| anyhow::anyhow!("provider purpose set is not canonical"))?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: if configuration_matches {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: Some(request.assignment.incarnation),
        observation: effect_observation(&observation)?,
        native_context: value(&NetworkContext {
            schema: CONTEXT_SCHEMA.to_string(),
            configuration_matches,
            seed_matches: true,
        })?,
        supported_purposes,
    })
}

pub(crate) async fn invoke(invocation: Invocation) -> Result<InvocationResult> {
    if invocation.schema != INVOCATION_SCHEMA || invocation.request.schema != REQUEST_SCHEMA {
        bail!("unsupported invocation schema");
    }
    if !invocation.method_is_bound() {
        bail!("invocation method is not bound to its durable recovery contract");
    }
    require_method(&invocation.method, &invocation.semantics)?;
    require_method(&invocation.request.method, &invocation.request.semantics)?;
    if resource_set_digest(&invocation.request.resources)?
        != invocation.request.native_context_digest
    {
        bail!("invocation resource-set digest does not match");
    }
    validate_resource_contexts(&invocation.request.resources)?;

    let target = target_context(&invocation)?;
    let bound = validate_resource_context(target)?;
    let expected = network_configuration_from_validated(&bound.resource_spec.value)?;
    let bootstrap = bootstrap_from_apply_input(&invocation.request.inputs)?;
    validate_apply_input(&expected, bootstrap.as_ref())?;
    require_resource_contexts(&expected.prerequisites, &invocation.request.resources)?;
    let realization: NetworkConfigurationRealization =
        decode_value(&bound.resource_spec.realization)?;
    require_realization(&realization)?;
    let context: NetworkContext = decode_value(&bound.provider_context)?;
    if context.schema != CONTEXT_SCHEMA {
        bail!("unsupported network provider context schema");
    }

    let method = invocation.method.method.as_str();
    let removing = method == "remove";
    let mutate = invocation.purpose == InvocationPurpose::Effect
        || (invocation.purpose == InvocationPurpose::Reconcile
            && matches!(method, "apply" | "remove"));
    if mutate {
        converge_seed(
            Path::new("/var/etc"),
            &expected.authority,
            bootstrap.as_ref(),
        )?;
        reload_networkd(&realization).await?;
    }

    let rendered = render(&expected)?;
    let configuration_matches = if removing {
        true
    } else {
        rendered_matches(Path::new("/etc"), &rendered)?
    };
    let seed_matches = seed_matches(
        Path::new("/var/etc"),
        &expected.authority,
        bootstrap.as_ref(),
    )?;
    let raw = observation(
        &expected,
        bootstrap.as_ref(),
        configuration_matches,
        seed_matches,
        removing,
    )?;
    let evidence = effect_observation(&raw)?;
    let mut outputs = BTreeMap::new();
    outputs.insert(LocalKey::new("observation")?, evidence.clone());

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition: InvocationDisposition::Completed,
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn require_method(method: &MethodReference, semantics: &MethodSemantics) -> Result<()> {
    if !supports(method) {
        bail!("handler invocation selects an unsupported network-effects interface");
    }
    let expected = match method.method.as_str() {
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "remove" => MethodSemantics::provider_stop(),
        "apply" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        _ => bail!("handler invocation selects an unsupported network method"),
    };
    if *semantics != expected {
        bail!("network method carries mismatched semantics");
    }
    Ok(())
}

fn require_realization(realization: &NetworkConfigurationRealization) -> Result<()> {
    if realization.schema != REALIZATION_SCHEMA {
        bail!("unsupported network-configuration realization schema");
    }
    if realization.systemd.value_type != "aos-artifact-reference" {
        bail!("systemd artifact carries an unsupported value type");
    }
    let path = Path::new(&realization.systemd.store_path);
    if !path.is_absolute()
        || !realization.systemd.store_path.starts_with("/nix/store/")
        || !path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("systemd artifact does not carry a normalized store path");
    }
    Ok(())
}

fn require_resource_contexts(
    prerequisites: &[ResourceReference],
    contexts: &[aos_provider_protocol::ResourceContext],
) -> Result<()> {
    for prerequisite in prerequisites {
        if contexts
            .iter()
            .filter(|context| context.reference == *prerequisite)
            .count()
            != 1
        {
            bail!("network input lacks one exact prerequisite context");
        }
    }
    Ok(())
}

fn render(configuration: &NetworkConfiguration) -> Result<RenderedConfiguration> {
    validate_configuration(configuration)?;
    let mut files = BTreeMap::new();
    for link in &configuration.links {
        render_link(link, &mut files)?;
    }
    if configuration.resolver.enabled {
        files.insert(
            PathBuf::from("systemd/resolved.conf"),
            render_resolver(&configuration.resolver).into_bytes(),
        );
        files.insert(
            PathBuf::from("tmpfiles.d/aos-resolved.conf"),
            b"# Keep libc and static tools on systemd-resolved's runtime stub.\nL /etc/resolv.conf - - - - /run/systemd/resolve/stub-resolv.conf\n".to_vec(),
        );
    }
    Ok(RenderedConfiguration { files })
}

fn validate_configuration(configuration: &NetworkConfiguration) -> Result<()> {
    let mut previous: Option<&LocalKey> = None;
    for link in &configuration.links {
        if previous.is_some_and(|name| name >= link.name()) {
            bail!("network links are not uniquely and canonically ordered");
        }
        validate_addressing(match link {
            NetworkLink::Ethernet { addressing, .. }
            | NetworkLink::Vlan { addressing, .. }
            | NetworkLink::Bond { addressing, .. } => addressing,
        })?;
        previous = Some(link.name());
    }
    if configuration.resolver.dnssec != "yes"
        && configuration.resolver.dnssec != "no"
        && configuration.resolver.dnssec != "allow-downgrade"
    {
        bail!("network resolver selects an unsupported DNSSEC mode");
    }
    Ok(())
}

fn validate_apply_input(
    configuration: &NetworkConfiguration,
    bootstrap: Option<&BootstrapNetwork>,
) -> Result<()> {
    if let Some(bootstrap) = bootstrap {
        if configuration.authority != NetworkAuthority::Image {
            bail!("only image-owned network policy may carry an early bootstrap result");
        }
        if bootstrap.addresses.is_empty() {
            bail!("bootstrap network requires at least one address");
        }
    }
    Ok(())
}

fn validate_addressing(addressing: &Addressing) -> Result<()> {
    if addressing.dhcp && !addressing.addresses.is_empty() {
        bail!("network link cannot combine DHCP and static addresses");
    }
    if !addressing.dhcp && addressing.addresses.is_empty() {
        bail!("network link requires DHCP or at least one static address");
    }
    Ok(())
}

fn render_link(link: &NetworkLink, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
    match link {
        NetworkLink::Ethernet {
            name,
            selector,
            addressing,
        } => {
            let priority = if matches!(selector, LinkSelector::Ethernet) {
                "80"
            } else {
                "10"
            };
            insert_file(
                files,
                format!("systemd/network/{priority}-{name}.network"),
                render_network(selector, addressing, &[], &[]),
            )?;
        }
        NetworkLink::Vlan {
            name,
            parent,
            id,
            addressing,
        } => {
            insert_file(
                files,
                format!("systemd/network/05-{name}.netdev"),
                format!("[NetDev]\nName={name}\nKind=vlan\n\n[VLAN]\nId={id}\n"),
            )?;
            insert_file(
                files,
                format!("systemd/network/10-{name}.network"),
                render_network(&LinkSelector::Name(name.to_string()), addressing, &[], &[]),
            )?;
            insert_file(
                files,
                format!("systemd/network/09-{name}-parent.network"),
                render_network(parent, &empty_addressing(), &[name.as_str()], &[]),
            )?;
        }
        NetworkLink::Bond {
            name,
            members,
            mode,
            addressing,
        } => {
            insert_file(
                files,
                format!("systemd/network/05-{name}.netdev"),
                format!(
                    "[NetDev]\nName={name}\nKind=bond\n\n[Bond]\nMode={mode}\nMIIMonitorSec=100ms\n"
                ),
            )?;
            insert_file(
                files,
                format!("systemd/network/10-{name}.network"),
                render_network(&LinkSelector::Name(name.to_string()), addressing, &[], &[]),
            )?;
            for (index, member) in members.iter().enumerate() {
                insert_file(
                    files,
                    format!("systemd/network/09-{name}-member-{index}.network"),
                    render_network(member, &empty_addressing(), &[], &[name.as_str()]),
                )?;
            }
        }
    }
    Ok(())
}

fn empty_addressing() -> Addressing {
    Addressing {
        dhcp: false,
        addresses: Vec::new(),
        gateway: None,
        dns: Vec::new(),
    }
}

fn render_network(
    selector: &LinkSelector,
    addressing: &Addressing,
    vlans: &[&str],
    bonds: &[&str],
) -> String {
    let mut output = String::from("[Match]\n");
    render_selector(&mut output, selector);
    output.push_str("\n[Network]\n");
    if addressing.dhcp {
        output.push_str("DHCP=yes\n");
    }
    for address in &addressing.addresses {
        output.push_str(&format!("Address={address}\n"));
    }
    if let Some(gateway) = &addressing.gateway {
        output.push_str(&format!("Gateway={gateway}\n"));
    }
    for dns in &addressing.dns {
        output.push_str(&format!("DNS={dns}\n"));
    }
    for vlan in vlans {
        output.push_str(&format!("VLAN={vlan}\n"));
    }
    for bond in bonds {
        output.push_str(&format!("Bond={bond}\n"));
    }
    if matches!(selector, LinkSelector::Ethernet) && addressing.dhcp {
        output.push_str("\n[DHCPv4]\nUseDNS=yes\nUseNTP=yes\nUseDomains=yes\n");
    }
    output
}

fn render_selector(output: &mut String, selector: &LinkSelector) {
    match selector {
        LinkSelector::Name(value) => output.push_str(&format!("Name={value}\n")),
        LinkSelector::Mac(value) => output.push_str(&format!("MACAddress={value}\n")),
        LinkSelector::Ethernet => output.push_str("Name=en*\nType=ether\n"),
    }
}

fn render_resolver(resolver: &ResolverConfiguration) -> String {
    let mut output = String::from("[Resolve]\n");
    if !resolver.nameservers.is_empty() {
        output.push_str(&format!("DNS={}\n", resolver.nameservers.join(" ")));
    }
    if !resolver.search.is_empty() {
        output.push_str(&format!("Domains={}\n", resolver.search.join(" ")));
    }
    output.push_str(&format!(
        "DNSSEC={}\nDNSOverTLS=opportunistic\nMulticastDNS=no\nLLMNR=no\n",
        resolver.dnssec
    ));
    output
}

fn render_bootstrap(bootstrap: &BootstrapNetwork) -> String {
    let selector = match &bootstrap.selector {
        BootstrapLinkSelector::Name(value) => LinkSelector::Name(value.clone()),
        BootstrapLinkSelector::Mac(value) => LinkSelector::Mac(value.clone()),
    };
    render_network(
        &selector,
        &Addressing {
            dhcp: false,
            addresses: bootstrap.addresses.clone(),
            gateway: bootstrap.gateway.clone(),
            dns: bootstrap.dns.clone(),
        },
        &[],
        &[],
    )
}

fn insert_file(
    files: &mut BTreeMap<PathBuf, Vec<u8>>,
    path: String,
    contents: String,
) -> Result<()> {
    if files
        .insert(PathBuf::from(&path), contents.into_bytes())
        .is_some()
    {
        bail!("network configuration renders duplicate path {path}");
    }
    Ok(())
}

fn rendered_matches(root: &Path, rendered: &RenderedConfiguration) -> Result<bool> {
    for (relative, expected) in &rendered.files {
        match fs::read(root.join(relative)) {
            Ok(actual) if actual == *expected => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).context("reading rendered network configuration"),
        }
    }
    Ok(true)
}

fn seed_matches(
    root: &Path,
    authority: &NetworkAuthority,
    bootstrap: Option<&BootstrapNetwork>,
) -> Result<bool> {
    let desired = match (authority, bootstrap) {
        (NetworkAuthority::Image, Some(bootstrap)) => {
            Some(render_bootstrap(bootstrap).into_bytes())
        }
        (NetworkAuthority::Image, None) | (NetworkAuthority::Operator, None) => None,
        (NetworkAuthority::Operator, Some(_)) => {
            bail!("operator-owned network policy cannot retain an image bootstrap seed")
        }
    };
    match (desired, fs::read(root.join(SEED_RELATIVE_PATH))) {
        (Some(expected), Ok(actual)) => Ok(actual == expected),
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        (Some(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        (None, Ok(_)) => Ok(false),
        (_, Err(error)) => Err(error).context("reading metadata network seed"),
    }
}

fn converge_seed(
    root: &Path,
    authority: &NetworkAuthority,
    bootstrap: Option<&BootstrapNetwork>,
) -> Result<()> {
    let destination = root.join(SEED_RELATIVE_PATH);
    match (authority, bootstrap) {
        (NetworkAuthority::Image, Some(bootstrap)) => {
            let parent = destination
                .parent()
                .ok_or_else(|| anyhow::anyhow!("metadata seed path has no parent"))?;
            ensure_seed_directory(root, parent)?;
            let mut temporary = NamedTempFile::new_in(parent)
                .context("creating temporary metadata network seed")?;
            temporary
                .as_file()
                .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
            temporary.write_all(render_bootstrap(bootstrap).as_bytes())?;
            temporary.as_file().sync_all()?;
            temporary
                .persist(&destination)
                .map_err(|error| error.error)
                .context("publishing metadata network seed")?;
            fs::File::open(parent)?.sync_all()?;
        }
        (NetworkAuthority::Image, None) | (NetworkAuthority::Operator, None) => {
            match fs::remove_file(&destination) {
                Ok(()) => {
                    if let Some(parent) = destination.parent() {
                        fs::File::open(parent)?.sync_all()?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("removing metadata network seed"),
            }
        }
        (NetworkAuthority::Operator, Some(_)) => {
            bail!("operator-owned network policy cannot retain an image bootstrap seed")
        }
    }
    Ok(())
}

fn ensure_seed_directory(root: &Path, destination: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    for component in ["systemd", "network"] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => bail!("metadata seed path traverses a non-directory or symbolic link"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).context("creating metadata seed directory")?;
            }
            Err(error) => return Err(error).context("inspecting metadata seed directory"),
        }
    }
    if current != destination {
        bail!("metadata seed directory differs from its fixed destination");
    }
    Ok(())
}

async fn reload_networkd(realization: &NetworkConfigurationRealization) -> Result<()> {
    let networkctl = Path::new(&realization.systemd.store_path).join("bin/networkctl");
    for arguments in [["reload"].as_slice(), ["reconfigure", "--all"].as_slice()] {
        let status = Command::new(&networkctl)
            .args(arguments)
            .status()
            .await
            .with_context(|| format!("executing {}", networkctl.display()))?;
        if !status.success() {
            bail!("networkctl {} failed with {status}", arguments.join(" "));
        }
    }
    Ok(())
}

fn observation(
    expected: &NetworkConfiguration,
    applied_bootstrap: Option<&BootstrapNetwork>,
    configuration_matches: bool,
    seed_matches: bool,
    removing: bool,
) -> Result<NetworkObservation> {
    let mut discrepancies = Vec::new();
    if !configuration_matches {
        discrepancies.push(LocalKey::new("configuration-files")?);
    }
    if !seed_matches {
        discrepancies.push(LocalKey::new("metadata-seed")?);
    }
    let state = if removing {
        NetworkState::Absent
    } else if discrepancies.is_empty() {
        NetworkState::Ready
    } else {
        NetworkState::Drifted
    };
    Ok(NetworkObservation {
        schema: OBSERVATION_SCHEMA.to_string(),
        expected: expected.clone(),
        applied_bootstrap: applied_bootstrap.cloned(),
        state,
        discrepancies,
    })
}

fn effect_observation(observation: &NetworkObservation) -> Result<AbilityValue> {
    let mut document = Map::new();
    document.insert(
        "schema".to_string(),
        Value::String(observation.schema.clone()),
    );
    document.insert(
        "expected".to_string(),
        network_configuration_to_json(&observation.expected)?,
    );
    if let Some(bootstrap) = &observation.applied_bootstrap {
        document.insert(
            "applied_bootstrap".to_string(),
            bootstrap.clone().into_json(),
        );
    }
    document.insert(
        "state".to_string(),
        Value::String(
            match observation.state {
                NetworkState::Absent => "absent",
                NetworkState::Ready => "ready",
                NetworkState::Drifted => "drifted",
            }
            .to_string(),
        ),
    );
    document.insert(
        "discrepancies".to_string(),
        Value::Array(
            observation
                .discrepancies
                .iter()
                .map(|value| Value::String(value.to_string()))
                .collect(),
        ),
    );
    AbilityValue::new(Value::Object(document)).context("encoding network observation")
}

fn network_configuration_to_json(configuration: &NetworkConfiguration) -> Result<Value> {
    let mut document = Map::new();
    document.insert(
        "authority".to_string(),
        Value::String(
            match configuration.authority {
                NetworkAuthority::Image => "image",
                NetworkAuthority::Operator => "operator",
            }
            .to_string(),
        ),
    );
    document.insert(
        "links".to_string(),
        Value::Array(
            configuration
                .links
                .iter()
                .map(network_link_to_json)
                .collect::<Result<Vec<_>>>()?,
        ),
    );
    document.insert(
        "resolver".to_string(),
        resolver_to_json(&configuration.resolver),
    );
    document.insert(
        "prerequisites".to_string(),
        serde_json::to_value(&configuration.prerequisites)
            .context("encoding network prerequisites")?,
    );
    Ok(Value::Object(document))
}

fn network_link_to_json(link: &NetworkLink) -> Result<Value> {
    let (kind, name, selector_name, selector, addressing, extra) = match link {
        NetworkLink::Ethernet {
            name,
            selector,
            addressing,
        } => ("ethernet", name, "selector", selector, addressing, None),
        NetworkLink::Vlan {
            name,
            parent,
            id,
            addressing,
        } => (
            "vlan",
            name,
            "parent",
            parent,
            addressing,
            Some(("id", Value::from(*id))),
        ),
        NetworkLink::Bond {
            name,
            members,
            mode,
            addressing,
        } => {
            let mut document = common_link_json("bond", name, addressing);
            document.insert(
                "members".to_string(),
                Value::Array(members.iter().map(selector_to_json).collect()),
            );
            document.insert("mode".to_string(), Value::String(mode.clone()));
            return Ok(Value::Object(document));
        }
    };
    let mut document = common_link_json(kind, name, addressing);
    document.insert(selector_name.to_string(), selector_to_json(selector));
    if let Some((name, value)) = extra {
        document.insert(name.to_string(), value);
    }
    Ok(Value::Object(document))
}

fn common_link_json(kind: &str, name: &LocalKey, addressing: &Addressing) -> Map<String, Value> {
    let mut document = Map::new();
    document.insert("kind".to_string(), Value::String(kind.to_string()));
    document.insert("name".to_string(), Value::String(name.to_string()));
    document.insert("addressing".to_string(), addressing_to_json(addressing));
    document
}

fn selector_to_json(selector: &LinkSelector) -> Value {
    let mut document = Map::new();
    match selector {
        LinkSelector::Name(value) => {
            document.insert("kind".to_string(), Value::String("name".to_string()));
            document.insert("value".to_string(), Value::String(value.clone()));
        }
        LinkSelector::Mac(value) => {
            document.insert("kind".to_string(), Value::String("mac".to_string()));
            document.insert("value".to_string(), Value::String(value.clone()));
        }
        LinkSelector::Ethernet => {
            document.insert("kind".to_string(), Value::String("ethernet".to_string()));
        }
    }
    Value::Object(document)
}

fn addressing_to_json(addressing: &Addressing) -> Value {
    let mut document = Map::new();
    document.insert("dhcp".to_string(), Value::Bool(addressing.dhcp));
    document.insert(
        "addresses".to_string(),
        Value::Array(
            addressing
                .addresses
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    if let Some(gateway) = &addressing.gateway {
        document.insert("gateway".to_string(), Value::String(gateway.clone()));
    }
    document.insert(
        "dns".to_string(),
        Value::Array(addressing.dns.iter().cloned().map(Value::String).collect()),
    );
    Value::Object(document)
}

fn resolver_to_json(resolver: &ResolverConfiguration) -> Value {
    let mut document = Map::new();
    document.insert("enabled".to_string(), Value::Bool(resolver.enabled));
    document.insert(
        "nameservers".to_string(),
        Value::Array(
            resolver
                .nameservers
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    document.insert(
        "search".to_string(),
        Value::Array(resolver.search.iter().cloned().map(Value::String).collect()),
    );
    document.insert("dnssec".to_string(), Value::String(resolver.dnssec.clone()));
    Value::Object(document)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use aos_net::{BootstrapLinkSelector, BootstrapNetwork};

    use super::{
        Addressing, LinkSelector, NetworkAuthority, NetworkConfiguration,
        NetworkConfigurationRealization, NetworkLink, ResolverConfiguration, Sha256Digest,
        converge_seed, network_configuration_to_json, render, render_static,
    };

    fn configuration(authority: NetworkAuthority) -> NetworkConfiguration {
        NetworkConfiguration {
            authority,
            links: vec![NetworkLink::Ethernet {
                name: aos_ability_model::LocalKey::new("host").expect("valid key"),
                selector: LinkSelector::Mac("02:00:00:00:00:01".to_string()),
                addressing: Addressing {
                    dhcp: false,
                    addresses: vec!["192.0.2.10/24".to_string()],
                    gateway: Some("192.0.2.1".to_string()),
                    dns: vec!["192.0.2.53".to_string()],
                },
            }],
            resolver: ResolverConfiguration {
                enabled: true,
                nameservers: vec!["192.0.2.53".to_string()],
                search: vec!["example.test".to_string()],
                dnssec: "yes".to_string(),
            },
            prerequisites: Vec::new(),
        }
    }

    fn bootstrap() -> BootstrapNetwork {
        BootstrapNetwork {
            selector: BootstrapLinkSelector::Mac("02:00:00:00:00:01".to_string()),
            addresses: vec!["198.51.100.10/24".to_string()],
            gateway: Some("198.51.100.1".to_string()),
            dns: vec!["198.51.100.53".to_string()],
        }
    }

    #[test]
    fn semantic_configuration_renders_networkd_and_resolved_files() {
        let rendered = render(&configuration(NetworkAuthority::Operator)).expect("render succeeds");
        let network = rendered
            .files
            .get(std::path::Path::new("systemd/network/10-host.network"))
            .expect("network file");
        assert_eq!(
            String::from_utf8_lossy(network),
            "[Match]\nMACAddress=02:00:00:00:00:01\n\n[Network]\nAddress=192.0.2.10/24\nGateway=192.0.2.1\nDNS=192.0.2.53\n"
        );
        assert!(
            rendered
                .files
                .contains_key(std::path::Path::new("systemd/resolved.conf"))
        );
    }

    #[test]
    fn static_configuration_materializes_an_etc_tree() {
        let output = TempDir::new().expect("temporary output");
        let desired = network_configuration_to_json(&configuration(NetworkAuthority::Operator))
            .expect("semantic network value");
        let realization = NetworkConfigurationRealization {
            schema: super::REALIZATION_SCHEMA.to_string(),
            systemd: super::TaggedArtifactReference {
                value_type: "aos-artifact-reference".to_string(),
                content: Sha256Digest::from_bytes([1; 32]),
                store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-systemd".to_string(),
                nar_hash: Sha256Digest::from_bytes([2; 32]),
                closure: Sha256Digest::from_bytes([3; 32]),
            },
        };
        let input = serde_json::json!({
            "schema": super::STATIC_INPUT_SCHEMA,
            "desired": desired,
            "realization": realization,
        });

        render_static(input, output.path()).expect("static render succeeds");

        assert!(
            output
                .path()
                .join("etc/systemd/network/10-host.network")
                .is_file()
        );
        assert!(output.path().join("etc/systemd/resolved.conf").is_file());
        assert!(
            output
                .path()
                .join("etc/tmpfiles.d/aos-resolved.conf")
                .is_file()
        );
        assert!(!output.path().join("systemd/network").exists());
    }

    #[test]
    fn operator_configuration_retires_and_image_rollback_restores_seed() {
        let root = TempDir::new().expect("temporary root");
        let bootstrap = bootstrap();
        converge_seed(root.path(), &NetworkAuthority::Image, Some(&bootstrap))
            .expect("seed is created");
        let seed = root.path().join(super::SEED_RELATIVE_PATH);
        assert!(
            fs::read_to_string(&seed)
                .expect("read seed")
                .contains("198.51.100.10/24")
        );

        converge_seed(root.path(), &NetworkAuthority::Operator, None).expect("seed is retired");
        assert!(!seed.exists());

        converge_seed(root.path(), &NetworkAuthority::Image, Some(&bootstrap))
            .expect("seed is restored");
        assert!(
            fs::read_to_string(seed)
                .expect("read seed")
                .contains("198.51.100.10/24")
        );
    }
}
