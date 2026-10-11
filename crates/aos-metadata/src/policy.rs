//! Package-owned metadata authorization handler.
//!
//! Exact host bytes and semantic early-network facts cross operations only
//! through protected typed outputs. The complete initrd configuration
//! evaluator consumes the authorization result directly.

use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use crate::AcquiredMetadata;
use crate::native_handler::{read_invocation, write_response};
use crate::trust::{CONFIG_SIGNATURE_NAMESPACE, authenticate_config_payload_files};
use anyhow::{Context as _, Result, ensure};
use aos_storage_provisioning::{
    AuthorizedProvisioningInput, BaseLibraryIdentity, CanonicalProvisioningSource,
    ProvisioningAuthorization, ProvisioningTrustMode, observed_instance_facts,
    validate_authorized_provisioning_input,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationParameters {
    configuration: AuthorizationConfiguration,
    acquired_metadata: AcquiredMetadata,
    evaluation_context: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationConfiguration {
    schema: String,
    trust_mode: ProvisioningTrustMode,
    trusted_config_keys: Vec<TrustedKeyFile>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum TrustedKeyFile {
    ImmutableFile {
        path: String,
        content_sha256: String,
    },
}

/// Executes one native whole-input metadata authorization operation.
///
/// # Errors
/// Returns an error for invalid input, mutable trust anchors, mismatched base
/// library identity, or failed signature authentication.
pub async fn run_policy_provider_from_process() -> Result<()> {
    let (purpose, invocation) = read_invocation()?;
    let operation = invocation
        .effect
        .identity
        .iter()
        .rev()
        .nth(1)
        .context("metadata operation identity is missing")?;
    ensure!(
        operation == "authorize",
        "unknown metadata authorization operation"
    );
    let output = match purpose.as_str() {
        "remove" => serde_json::json!({}),
        "observe" if invocation.action == aos_ability_runtime::activation::Action::Remove => {
            serde_json::json!({"status":"absent"})
        }
        "observe" => serde_json::json!({"status":"retry-safe"}),
        _ => {
            let parameters: AuthorizationParameters = serde_json::from_value(invocation.input)?;
            let authorized = authorize(
                &parameters.configuration,
                &parameters.acquired_metadata,
                &parameters.evaluation_context,
                invocation.effect.timeout_ms,
            )?;
            let bytes = aos_contract::canonical::to_vec(&authorized)?;
            let canonical_input =
                String::from_utf8(bytes).context("authorized input is not UTF-8")?;
            serde_json::json!({"authorized_input": authorized,"canonical_input":canonical_input})
        }
    };
    write_response(&output)
}

fn authorize(
    configuration: &AuthorizationConfiguration,
    acquired: &AcquiredMetadata,
    evaluation_context: &str,
    timeout_ms: u64,
) -> Result<AuthorizedProvisioningInput> {
    validate_authorization_configuration(configuration)?;
    validate_acquired_metadata(acquired)?;
    let base_library = read_evaluation_library(evaluation_context)?;
    verify_base_library(&base_library, timeout_ms)?;
    authorize_validated_input(configuration, acquired, &base_library)
}

fn authorize_validated_input(
    configuration: &AuthorizationConfiguration,
    acquired: &AcquiredMetadata,
    base_library: &BaseLibraryIdentity,
) -> Result<AuthorizedProvisioningInput> {
    let facts = observed_instance_facts(serde_json::to_value(&acquired.facts)?)?;
    let input = match &acquired.host_module {
        Some(module) => {
            let signer = match configuration.trust_mode {
                ProvisioningTrustMode::Platform => None,
                ProvisioningTrustMode::Signed => {
                    let trusted_keys = trusted_key_files(&configuration.trusted_config_keys)?;
                    Some(
                        authenticate_config_payload_files(
                            module.as_bytes(),
                            acquired.host_module_signature.as_deref(),
                            &trusted_keys,
                            CONFIG_SIGNATURE_NAMESPACE,
                        )
                        .map_err(anyhow::Error::new)
                        .context("authorizing signed host module")?
                        .operator_key,
                    )
                }
            };

            AuthorizedProvisioningInput {
                schema: "aos.metadata.authorized-provisioning-input/v1".into(),
                source: CanonicalProvisioningSource::Operator,
                host_module: Some(module.clone()),
                host_module_sha256: Some(digest(module.as_bytes())),
                authorization: ProvisioningAuthorization {
                    trust_mode: configuration.trust_mode,
                    platform_id: acquired.platform_id.clone(),
                    signer,
                },
                facts,
                base_library: base_library.clone(),
            }
        }
        None => AuthorizedProvisioningInput {
            schema: "aos.metadata.authorized-provisioning-input/v1".into(),
            source: CanonicalProvisioningSource::Fallback,
            host_module: None,
            host_module_sha256: None,
            authorization: ProvisioningAuthorization {
                trust_mode: configuration.trust_mode,
                platform_id: acquired.platform_id.clone(),
                signer: None,
            },
            facts,
            base_library: base_library.clone(),
        },
    };
    validate_authorized_provisioning_input(&input)?;
    Ok(input)
}

fn validate_acquired_metadata(acquired: &AcquiredMetadata) -> Result<()> {
    ensure!(
        acquired.schema == "aos.metadata.acquired-provisioning-input/v1",
        "unsupported acquired metadata result"
    );
    crate::detect::PlatformId::parse(&acquired.platform_id)?;
    ensure!(
        acquired.host_module.is_some() || acquired.host_module_signature.is_none(),
        "metadata signature has no corresponding host module"
    );
    ensure!(
        crate::canonicalize_host_facts(&acquired.facts)? == acquired.facts,
        "acquired metadata facts are not canonical"
    );
    Ok(())
}

fn validate_authorization_configuration(configuration: &AuthorizationConfiguration) -> Result<()> {
    ensure!(
        configuration.schema == "aos.metadata.provisioning-authorization-configuration/v1",
        "unsupported provisioning authorization configuration"
    );
    ensure!(
        configuration.trusted_config_keys.len() <= 64,
        "trusted configuration keys exceed the interface bound"
    );
    if configuration.trust_mode == ProvisioningTrustMode::Signed {
        ensure!(
            !configuration.trusted_config_keys.is_empty(),
            "signed provisioning requires a trusted configuration key"
        );
    }
    trusted_key_files(&configuration.trusted_config_keys)?;
    Ok(())
}

fn trusted_key_files(files: &[TrustedKeyFile]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for file in files {
        let path = match file {
            TrustedKeyFile::ImmutableFile {
                path,
                content_sha256,
            } => {
                ensure!(
                    path.starts_with("/nix/store/"),
                    "trusted configuration key is not immutable"
                );
                let selected = immutable_path(path)?;
                ensure!(
                    fs::metadata(&selected)?.len() <= 64 * 1024,
                    "configuration key exceeds its bound"
                );
                let bytes = fs::read(&selected)?;
                ensure!(
                    digest(&bytes) == *content_sha256,
                    "trusted configuration key differs from its content digest"
                );
                selected
            }
        };
        ensure!(
            path.is_file(),
            "trusted configuration key is not a regular file"
        );
        if paths.iter().any(|existing| existing == &path) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("trusted configuration key has no UTF-8 file name")?;
        ensure!(
            name.ends_with(".pub") && name.len() > 4,
            "trusted configuration key must use an operator .pub file name"
        );
        ensure!(
            names.insert(name.to_string()),
            "trusted configuration key names collide"
        );
        paths.push(path);
    }
    Ok(paths)
}

fn immutable_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    let relative = path
        .strip_prefix("/nix/store")
        .context("metadata trust input is outside immutable store")?;
    ensure!(
        relative.components().count() > 0
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "metadata trust input is not normalized"
    );
    let selected = fs::canonicalize(path)?;
    ensure!(
        selected.starts_with("/nix/store"),
        "metadata trust input escapes immutable store"
    );
    Ok(selected)
}

// Only authority-relevant members are projected here. APM owns the full
// native package descriptor, whose immutable locator is admitted before dispatch.
#[derive(Deserialize)]
struct EvaluationLibrary {
    schema: String,
    library: PathBuf,
    #[serde(rename = "libraryNarHash")]
    library_nar_hash: aos_contract::Sha256Digest,
}

fn read_evaluation_library(descriptor: &str) -> Result<BaseLibraryIdentity> {
    let descriptor = immutable_path(descriptor)?;
    let mut bytes = Vec::new();
    fs::File::open(descriptor)?
        .take((aos_ability_plan::module_graph::GRAPH_LIMITS.max_bytes as u64) + 1)
        .read_to_end(&mut bytes)?;
    let context: EvaluationLibrary = aos_ability_plan::module_graph::GRAPH_LIMITS
        .decode(&bytes, "native evaluation descriptor")?;
    ensure!(
        context.schema == "aos.package.evaluation-input",
        "unsupported native evaluation descriptor"
    );
    let library = immutable_path(
        context
            .library
            .to_str()
            .context("library locator is not UTF-8")?,
    )?;
    let relative = library.strip_prefix("/nix/store")?;
    let root = relative
        .components()
        .next()
        .context("native library has no store root")?;
    Ok(BaseLibraryIdentity {
        store_path: Path::new("/nix/store")
            .join(root.as_os_str())
            .to_str()
            .context("native library root is not UTF-8")?
            .to_owned(),
        nar_hash: context.library_nar_hash.to_string(),
    })
}

fn verify_base_library(identity: &BaseLibraryIdentity, timeout_ms: u64) -> Result<()> {
    let library = immutable_path(&identity.store_path)?;
    ensure!(
        library.parent() == Some(Path::new("/nix/store")),
        "native library identity must name an exact store root"
    );
    let current = std::env::current_exe()?;
    let tool = current
        .parent()
        .context("metadata handler has no package directory")?
        .join("../libexec/nix-store");
    let tool = fs::canonicalize(tool)?;
    let tool = crate::executable::resolve_executable(
        tool.to_str().context("store executable is not UTF-8")?,
    )?;
    let command = aos_core::nix::identity::store_nar_command(
        &tool,
        library.to_str().context("library path is not UTF-8")?,
    )?;
    let (actual, _) = aos_core::nix::identity::hash_nar_command(
        command,
        std::time::Duration::from_millis(timeout_ms),
    )?;
    ensure!(
        actual.to_string() == identity.nar_hash,
        "native module library NAR differs from its admitted identity"
    );
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_authorization_preserves_typed_input_without_file_round_trip() {
        let host_module = "{ aos.provisioning.storage.partitions = {}; }";
        let configuration = AuthorizationConfiguration {
            schema: "aos.metadata.provisioning-authorization-configuration/v1".into(),
            trust_mode: ProvisioningTrustMode::Platform,
            trusted_config_keys: Vec::new(),
        };
        let acquired = AcquiredMetadata {
            schema: "aos.metadata.acquired-provisioning-input/v1".into(),
            platform_id: "qemu".into(),
            host_module: Some(host_module.into()),
            host_module_signature: None,
            facts: crate::Facts {
                hostname: Some("provisioning-test".into()),
                ..Default::default()
            },
        };

        let authorized = authorize_validated_input(
            &configuration,
            &acquired,
            &BaseLibraryIdentity {
                store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base-lib".into(),
                nar_hash: format!("sha256:{}", "00".repeat(32)),
            },
        )
        .expect("typed authorization");

        assert_eq!(authorized.source, CanonicalProvisioningSource::Operator);
        assert_eq!(authorized.host_module.as_deref(), Some(host_module));
        assert_eq!(
            authorized.host_module_sha256,
            Some(digest(host_module.as_bytes()))
        );
        assert_eq!(authorized.authorization.signer, None);
        let encoded = serde_json::to_value(&authorized).expect("serialized authorization");
        assert!(
            encoded["authorization"]
                .as_object()
                .unwrap()
                .contains_key("signer")
        );
        assert!(encoded["authorization"]["signer"].is_null());
        assert_eq!(
            authorized.facts.value["hostname"],
            serde_json::Value::String("provisioning-test".into())
        );
    }

    #[test]
    #[ignore = "requires a source-built native metadata transaction"]
    fn serialized_metadata_results_match_exported_native_contracts() {
        let transaction_path = std::env::var("AOS_TEST_METADATA_TRANSACTION")
            .expect("source-built native transaction fixture is required");
        let transaction: serde_json::Value = serde_json::from_slice(
            &std::fs::read(transaction_path).expect("read source-built transaction"),
        )
        .expect("decode source-built transaction");
        let graph = aos_ability_plan::module_graph::CheckedModuleGraph::decode(
            &aos_contract::canonical::to_vec(&transaction["graph"]).unwrap(),
        )
        .expect("admit the exported native graph");
        let effect = |operation: &str| {
            graph
                .graph()
                .nodes
                .values()
                .find(|effect| {
                    effect.identity.iter().rev().nth(2).map(String::as_str) == Some("metadata")
                        && effect.identity.iter().rev().nth(1).map(String::as_str)
                            == Some(operation)
                })
                .expect("metadata operation in exported graph")
        };
        let configuration = AuthorizationConfiguration {
            schema: "aos.metadata.provisioning-authorization-configuration/v1".into(),
            trust_mode: ProvisioningTrustMode::Platform,
            trusted_config_keys: Vec::new(),
        };
        let library = BaseLibraryIdentity {
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base-lib".into(),
            nar_hash: format!("sha256:{}", "00".repeat(32)),
        };
        let bootstrap = aos_net::BootstrapNetwork {
            selector: aos_net::BootstrapLinkSelector::Name("eth0".into()),
            addresses: vec!["192.0.2.10/24".into()],
            gateway: None,
            dns: Vec::new(),
        }
        .into_ability_value()
        .expect("typed static network without a gateway");

        for module in [None, Some("{}".to_string())] {
            let acquired = AcquiredMetadata {
                schema: "aos.metadata.acquired-provisioning-input/v1".into(),
                platform_id: "qemu".into(),
                host_module: module,
                host_module_signature: None,
                facts: crate::Facts::default(),
            };
            effect("acquire")
                .check_results(&serde_json::json!({
                    "acquired_metadata": acquired,
                    "network_bootstrap": bootstrap,
                }))
                .expect("acquisition satisfies the actual Nix result contract");

            let authorized = authorize_validated_input(&configuration, &acquired, &library)
                .expect("authorize platform operator or fallback input");
            let canonical_input =
                String::from_utf8(aos_contract::canonical::to_vec(&authorized).unwrap()).unwrap();
            let output = serde_json::json!({
                "authorized_input": authorized,
                "canonical_input": canonical_input,
            });
            effect("authorize")
                .check_results(&output)
                .expect("authorization satisfies the actual Nix result contract");

            let mut omitted = output;
            omitted["authorized_input"]["authorization"]
                .as_object_mut()
                .unwrap()
                .remove("signer");
            assert!(effect("authorize").check_results(&omitted).is_err());
        }
    }
}
