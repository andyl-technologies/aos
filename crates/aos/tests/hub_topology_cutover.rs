//! End-to-end tests for the authenticated Hub topology-cutover bundle.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const ROOT_SIGNER_ID: &str = "key/root/example";
const DOCUMENT_SIGNER_ID: &str = "key/release/example";
const VERIFICATION_SIGNER_ID: &str = "key/verification/example";

#[test]
fn topology_api_has_no_legacy_endpoint_update_surface() -> Result<()> {
    let root = workspace_root();
    let sources = [
        root.join("crates/aos-proto/src/proto/aos/hub/v1/hub.proto"),
        root.join("crates/aos-hub-core/src/connect.rs"),
        root.join("crates/aos-remote/src/hub.rs"),
        root.join("crates/aos/src/commands/hub.rs"),
        root.join("docs/rfcs/0012-hub-surface-topology/hub-api-manifest-v1.json"),
    ];
    for path in sources {
        let source = fs::read_to_string(&path)?;
        assert!(
            !source.contains("PlanUpdateDeliveryEndpoint")
                && !source.contains("UpdateDeliveryEndpoint"),
            "legacy endpoint update survives in {}",
            path.display()
        );
    }
    let proto = fs::read_to_string(root.join("crates/aos-proto/src/proto/aos/hub/v1/hub.proto"))?;
    for method in [
        "ListDeliveryEndpointGenerations",
        "GetDeliveryEndpointGeneration",
        "PlanStageDeliveryEndpointGeneration",
        "StageDeliveryEndpointGeneration",
        "PlanActivateDeliveryEndpointGeneration",
        "ActivateDeliveryEndpointGeneration",
    ] {
        assert!(
            proto.contains(method),
            "missing endpoint lifecycle method {method}"
        );
    }
    Ok(())
}

#[test]
fn registry_mutations_are_plan_apply_only() -> Result<()> {
    let root = workspace_root();
    let files = [
        root.join("crates/aos-proto/src/proto/aos/hub/v1/hub.proto"),
        root.join("crates/aos-hub-core/src/connect.rs"),
        root.join("crates/aos-remote/src/hub.rs"),
        root.join("docs/rfcs/0012-hub-surface-topology/hub-api-manifest-v1.json"),
    ];
    for path in files {
        let source = fs::read_to_string(&path)?;
        assert!(
            !source.contains("SetCrawlPolicy"),
            "legacy crawl mutation in {}",
            path.display()
        );
        for method in [
            "PlanUpdateRegistry",
            "UpdateRegistry",
            "PlanDeleteRegistry",
            "DeleteRegistry",
        ] {
            assert!(
                source.contains(method),
                "missing {method} in {}",
                path.display()
            );
        }
    }
    let direct_mutation_files = [
        root.join("crates/aos-hub-core/src/db/mod.rs"),
        root.join("crates/aos-hub-core/src/config/mod.rs"),
        root.join("crates/aos-hub-core/src/web/console/handlers.rs"),
        root.join("crates/aos-hub-core/src/web/console/router.rs"),
        root.join("crates/aos-hub-core/src/web/console/manifest.rs"),
    ];
    for path in direct_mutation_files {
        let source = fs::read_to_string(&path)?;
        for forbidden in [
            "set_registry_visibility",
            "set_registry_crawl_policy",
            "set_registry_llms_txt",
            "change_registry_visibility",
            "change_registry_crawl_policy",
            "org_create_registry",
            "settings/access/visibility",
            "settings/access/crawl-policy",
            "settings/danger/delete",
        ] {
            assert!(
                !source.contains(forbidden),
                "direct registry mutation {forbidden} remains in {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn project_mutations_are_plan_apply_only() -> Result<()> {
    let root = workspace_root();
    let proto = fs::read_to_string(root.join("crates/aos-proto/src/proto/aos/hub/v1/hub.proto"))?;
    for method in [
        "ListProjects",
        "GetProject",
        "PlanCreateProject",
        "CreateProject",
        "PlanDeleteProject",
        "DeleteProject",
    ] {
        assert!(
            proto.contains(method),
            "missing ProjectService method {method}"
        );
    }
    assert!(!proto.contains("message CreateProjectRequest {"));
    assert!(!proto.contains("message CreateProjectResponse {"));

    for relative in [
        "crates/aos-hub-core/src/web/console/router.rs",
        "crates/aos-hub-core/src/web/console/handlers.rs",
        "crates/aos-hub-core/src/web/console/manifest.rs",
    ] {
        let path = root.join(relative);
        let source = fs::read_to_string(&path)?;
        assert!(!source.contains("org_create_project"), "{relative}");
        assert!(!source.contains("org_delete_project"), "{relative}");
        assert!(!source.contains("projects/{project}/delete"), "{relative}");
    }
    Ok(())
}

#[test]
fn webhook_mutations_are_plan_apply_and_plaintext_secret_free() -> Result<()> {
    let root = workspace_root();
    let proto = fs::read_to_string(root.join("crates/aos-proto/src/proto/aos/hub/v1/hub.proto"))?;
    for method in [
        "PlanCreateWebhook",
        "CreateWebhook",
        "PlanDeleteWebhook",
        "DeleteWebhook",
    ] {
        assert!(
            proto.contains(method),
            "missing WebhookService method {method}"
        );
    }
    let create_request = proto
        .split("message PlanCreateWebhookRequest {")
        .nth(1)
        .and_then(|tail| tail.split("\n}").next())
        .context("PlanCreateWebhookRequest")?;
    assert!(create_request.contains("secret_version_ref"));
    assert!(create_request.contains("credential_fingerprint"));
    assert!(
        !create_request
            .lines()
            .any(|line| line.trim_start().starts_with("string secret ="))
    );
    let create_response = proto
        .split("message CreateWebhookResponse {")
        .nth(1)
        .and_then(|tail| tail.split("\n}").next())
        .context("CreateWebhookResponse")?;
    assert!(create_response.contains("reserved \"secret\""));
    assert!(
        !create_response
            .lines()
            .any(|line| line.trim_start().starts_with("string secret ="))
    );

    let schema = fs::read_to_string(root.join("crates/aos-hub-core/src/db/schema.sql"))?;
    let webhooks = schema
        .split("CREATE TABLE webhooks(")
        .nth(1)
        .and_then(|tail| tail.split("CREATE INDEX webhooks_org_idx").next())
        .context("webhooks schema")?;
    assert!(webhooks.contains("secret_version_ref"));
    assert!(webhooks.contains("credential_fingerprint"));
    assert!(!webhooks.contains(" secret "));
    let deliveries = schema
        .split("CREATE TABLE webhook_deliveries(")
        .nth(1)
        .and_then(|tail| tail.split("CREATE INDEX webhook_deliveries_due_idx").next())
        .context("webhook deliveries schema")?;
    for required in [
        "delivery_id KEYTEXT64 NOT NULL UNIQUE",
        "outbox_event_id KEYTEXT64 NOT NULL",
        "claim_token KEYTEXT64",
        "claim_expires_at INTEGER",
        "CHECK(length(payload) <= 1048576)",
    ] {
        assert!(
            deliveries.contains(required),
            "missing durable delivery invariant {required}"
        );
    }
    let outbox = schema
        .split("CREATE TABLE topology_event_outbox(")
        .nth(1)
        .and_then(|tail| {
            tail.split("CREATE INDEX topology_event_outbox_pending_idx")
                .next()
        })
        .context("topology event outbox schema")?;
    assert!(
        outbox.contains("'webhook'"),
        "webhook create/delete events must satisfy the final outbox vocabulary"
    );

    let service = fs::read_to_string(root.join("crates/aos-hub-core/src/service.rs"))?;
    let webhook_family = service
        .split("pub async fn plan_create_webhook")
        .nth(1)
        .and_then(|tail| tail.split("pub async fn apply_delete_webhook").next())
        .context("webhook service family")?;
    for forbidden in ["generate_token", "secret:"] {
        assert!(
            !webhook_family.contains(forbidden),
            "webhook plaintext path: {forbidden}"
        );
    }
    assert!(
        !webhook_family
            .match_indices("record.secret")
            .any(|(offset, matched)| webhook_family[offset + matched.len()..]
                .chars()
                .next()
                .is_none_or(|next| next != '_' && !next.is_ascii_alphanumeric())),
        "webhook plaintext record field remains"
    );
    assert!(
        webhook_family.contains("secret_versions")
            && webhook_family.contains("verify_secret_fingerprint"),
        "webhook planning must resolve the exact version and verify its fingerprint"
    );

    for relative in [
        "crates/aos-hub-core/src/storage_credential.rs",
        "crates/aos-hub/src/coreports.rs",
        "crates/aos-hub/src/webhook.rs",
        "crates/aos-hub-worker/src/consoleports.rs",
        "crates/aos-hub-worker/src/surface.rs",
    ] {
        let source = fs::read_to_string(root.join(relative))?;
        assert!(
            !source.contains("unseal(&credential.secret_version_ref")
                && !source.contains("unseal(&delivery.secret_version_ref"),
            "SecretSealer still resolves provider refs in {relative}"
        );
    }

    let jobs = fs::read_to_string(root.join("crates/aos-hub-core/src/jobs.rs"))?;
    let delivery_job = jobs
        .split("DeliverWebhook {")
        .nth(1)
        .and_then(|tail| tail.split("},").next())
        .context("DeliverWebhook job")?;
    assert!(delivery_job.contains("delivery_id"));
    assert!(!delivery_job.contains("webhook_id") && !delivery_job.contains("event"));

    let egress = fs::read_to_string(root.join("crates/aos-hub-core/src/egress_protocol.rs"))?;
    assert!(egress.contains("aos-hardened-egress-v3"));
    for field in ["webhook_event", "webhook_signature", "webhook_delivery_id"] {
        assert!(egress.contains(field), "egress evidence omits {field}");
    }
    let webhook = fs::read_to_string(root.join("crates/aos-hub-core/src/webhook.rs"))?;
    assert!(webhook.contains("enqueue_operational_webhook_event"));
    assert!(!webhook.contains("enqueue_delivery"));
    for event in [
        "webhook.created",
        "topology.storage_gateway.created",
        "topology.delivery_route.revised",
        "topology.delivery_endpoint.generation_activated",
    ] {
        assert!(webhook.contains(event), "webhook taxonomy omits {event}");
    }
    Ok(())
}

#[test]
fn pin_resolution_controller_is_fail_closed_and_typed() -> Result<()> {
    let root = workspace_root();
    let proto = fs::read_to_string(root.join("crates/aos-proto/src/proto/aos/hub/v1/hub.proto"))?;
    assert!(proto.contains("repeated TopologyPinImpact live_pin_impacts = 13;"));
    assert!(!proto.contains("repeated string live_pin_impacts"));
    assert!(proto.contains("enum PinResolutionAction"));

    let service = fs::read_to_string(root.join("crates/aos-hub-core/src/service.rs"))?;
    for guard in [
        "pinResolutions must contain exactly one action for every live grant pin and no extras",
        "source target for pin",
        "replacement route target is stale or disabled",
        "replacement endpoint target is stale",
        "placement release requires an offline, drain-complete, unreferenced placement",
        "endpoint release requires the exact selected generation with no routes, gateways, or defaults",
    ] {
        assert!(
            service.contains(guard),
            "missing pin-resolution guard: {guard}"
        );
    }
    for family in [
        "NetworkBoundaryGrant",
        "DeliveryEndpointGrant",
        "StorageGatewayGrant",
        "StorageBindingGrant",
    ] {
        assert!(service.contains(family), "missing grant family {family}");
    }

    let controller = fs::read_to_string(root.join("crates/aos-hub-core/src/topology_probe.rs"))?;
    for invariant in [
        "consumer_scope_grant_revocation",
        "source route changed before grant revocation",
        "replacement route changed before grant revocation",
        "replacement endpoint changed or changes stable identity",
        "placement is not delete-eligible",
        "grant changed before coordinated revocation",
        "boundary coordination left unacknowledged child jobs",
    ] {
        assert!(
            controller.contains(invariant),
            "missing controller invariant: {invariant}"
        );
    }
    Ok(())
}

#[test]
fn assembles_signs_and_verifies_closed_bundle() -> Result<()> {
    let fixture = CutoverFixture::assemble()?;
    let materialized = fixture.materialize_verifier()?;
    assert_success_json(&materialized, "materialized")?;

    let generated = fixture.generate()?;
    assert_success_json(&generated, "generated")?;

    let verified = fixture.verify(&fixture.bundled_verifier)?;
    let value = assert_success_json(&verified, "verified")?;
    assert_eq!(value["materialized_fixture_count"], 77);
    assert_eq!(value["signatures_verified"], 5);

    let altered_verifier = fixture.root.path().join("altered-aos");
    fs::copy(&fixture.bundled_verifier, &altered_verifier)?;
    OpenOptions::new()
        .append(true)
        .open(&altered_verifier)?
        .write_all(b"byte-identity-negative-fixture")?;
    let rejected = fixture.verify(&altered_verifier)?;
    if rejected.status.success() {
        bail!("byte-different verifier unexpectedly authenticated");
    }
    let failure: Value =
        serde_json::from_slice(&rejected.stdout).context("parsing byte-identity failure JSON")?;
    assert_eq!(failure["result"], "failed");
    assert_eq!(
        failure["code"], "running_verifier_identity_mismatch",
        "unexpected verifier rejection: {failure:#}"
    );

    let existing_manifest = fixture.generate()?;
    assert_failure_code(&existing_manifest, "output_already_exists")?;
    fs::remove_file(&fixture.manifest)?;
    let replay = fixture.generate()?;
    assert_failure_code(&replay, "output_already_exists")?;

    Ok(())
}

#[test]
fn generation_preflight_rejects_any_preseeded_generated_leaf() -> Result<()> {
    let fixture = CutoverFixture::assemble()?;
    fixture.materialize_verifier()?;
    fs::write(
        fixture.bundle.join("trust/signer-key-map.json"),
        b"preseeded untrusted output",
    )?;
    let rejected = fixture.generate()?;
    assert_failure_code(&rejected, "output_already_exists")?;
    assert!(!fixture.bundle.join("signatures/key-map.sig").exists());
    assert!(!fixture.manifest.exists());

    let duplicate_layout = CutoverFixture::assemble()?;
    duplicate_layout.materialize_verifier()?;
    let mut recipe: Value = serde_json::from_slice(&fs::read(&duplicate_layout.recipe)?)?;
    let first_path = recipe["layout"][0]["path"].clone();
    recipe["layout"][1]["path"] = first_path;
    fs::write(&duplicate_layout.recipe, serde_json::to_vec(&recipe)?)?;
    let rejected = duplicate_layout.generate()?;
    assert_failure_code(&rejected, "input_invalid")?;
    assert!(
        !duplicate_layout
            .bundle
            .join("trust/signer-key-map.json")
            .exists()
    );
    assert!(!duplicate_layout.manifest.exists());
    Ok(())
}

#[test]
fn rejects_root_key_reused_as_document_authority() -> Result<()> {
    let fixture = CutoverFixture::assemble()?;
    fixture.materialize_verifier()?;
    fs::write(
        fixture.bundle.join("keys/release.pub"),
        fs::read(&fixture.public_key)?,
    )?;
    let duplicate_root_key = fixture.root.path().join("duplicate-root-as-document.pk8");
    fs::copy(&fixture.root_signing_key, &duplicate_root_key)?;
    let rejected = fixture.generate_with_document_key(&duplicate_root_key)?;
    assert_failure_code(&rejected, "signer_separation_invalid")
}

#[test]
fn command_boundaries_emit_closed_external_failure_codes() -> Result<()> {
    let malformed_recipe = CutoverFixture::assemble()?;
    fs::write(&malformed_recipe.recipe, b"{")?;
    let rejected = malformed_recipe.materialize_verifier()?;
    assert_failure_code(&rejected, "input_invalid")?;

    let malformed_manifest = CutoverFixture::assemble()?;
    malformed_manifest.materialize_verifier()?;
    assert_success_json(&malformed_manifest.generate()?, "generated")?;
    fs::write(&malformed_manifest.manifest, b"{")?;
    let rejected = malformed_manifest.verify(&malformed_manifest.bundled_verifier)?;
    assert_failure_code(&rejected, "input_invalid")?;

    let wrong_fingerprint = CutoverFixture::assemble()?;
    wrong_fingerprint.materialize_verifier()?;
    assert_success_json(&wrong_fingerprint.generate()?, "generated")?;
    let rejected = wrong_fingerprint
        .verify_with_fingerprint(&wrong_fingerprint.bundled_verifier, &"00".repeat(32))?;
    assert_failure_code(&rejected, "trust_root_invalid")?;

    let stale_provenance = CutoverFixture::assemble()?;
    stale_provenance.materialize_verifier()?;
    let verification_path = stale_provenance.source.join("documents/verification.json");
    let mut verification: Value = serde_json::from_slice(&fs::read(&verification_path)?)?;
    verification["authored_at"] = Value::from("2026-08-05T02:59:59Z");
    fs::write(&verification_path, serde_json::to_vec(&verification)?)?;
    assert_success_json(&stale_provenance.generate()?, "generated")?;
    let rejected = stale_provenance.verify(&stale_provenance.bundled_verifier)?;
    assert_failure_code(&rejected, "signature_invalid")
}

#[cfg(unix)]
#[test]
fn rejects_hardlinked_and_symlinked_inputs() -> Result<()> {
    use std::os::unix::fs::symlink;

    let hardlinked = CutoverFixture::assemble()?;
    let key_alias = hardlinked.root.path().join("document-key-alias.pk8");
    fs::hard_link(&hardlinked.document_signing_key, &key_alias)?;
    let rejected = hardlinked.generate_with_document_key(&key_alias)?;
    assert_failure_code(&rejected, "input_identity_aliased")?;

    let symlinked = CutoverFixture::assemble()?;
    let alias_parent = symlinked.root.path().join("alias-parent");
    symlink(symlinked.root.path(), &alias_parent)?;
    let bundle_alias = alias_parent.join("bundle");
    let rejected = symlinked.materialize_verifier_at(&bundle_alias)?;
    assert_failure_code(&rejected, "filesystem_boundary_invalid")
}

struct CutoverFixture {
    root: TempDir,
    bundle: PathBuf,
    source: PathBuf,
    recipe: PathBuf,
    manifest: PathBuf,
    root_signing_key: PathBuf,
    document_signing_key: PathBuf,
    verification_signing_key: PathBuf,
    public_key: PathBuf,
    trusted_root_sha256: String,
    bundled_verifier: PathBuf,
}

impl CutoverFixture {
    fn assemble() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let bundle = root.path().join("bundle");
        let source = root.path().join("source");
        fs::create_dir(&bundle)?;
        fs::create_dir(&source)?;

        let docs = workspace_root().join("docs/rfcs/0012-hub-surface-topology");
        let recipe = root.path().join("bundle-generation.json");
        fs::copy(
            docs.join("hub-topology-cutover-bundle-generation-v1.fixture.json"),
            &recipe,
        )?;
        let recipe_value: Value = serde_json::from_slice(&fs::read(&recipe)?)?;
        for entry in recipe_value["layout"]
            .as_array()
            .context("generation recipe layout is not an array")?
        {
            let relative = entry["path"]
                .as_str()
                .context("generation layout path is not a string")?;
            create_parent(&bundle.join(relative))?;
            create_parent(&source.join(relative))?;
        }

        for (relative, fixture) in source_files() {
            copy_fixture(&docs, fixture, &source.join(relative))?;
        }
        for (relative, fixture) in static_bundle_files() {
            copy_fixture(&docs, fixture, &bundle.join(relative))?;
        }

        let bundled_verifier = bundle.join("bin/aos");
        fs::write(
            bundle.join("tools/topology-transformer"),
            b"fixture transformer v1\n",
        )?;

        let root_key = SigningKey::from_bytes(&[0x42; 32]);
        let root_der = root_key.to_pkcs8_der()?;
        let root_signing_key = root.path().join("release-root.pk8");
        fs::write(&root_signing_key, root_der.as_bytes())?;
        let public_bytes = root_key.verifying_key().to_bytes();
        let public_key = root.path().join("release-root.pub");
        fs::write(&public_key, public_bytes)?;

        let document_key = SigningKey::from_bytes(&[0x24; 32]);
        let document_der = document_key.to_pkcs8_der()?;
        let document_signing_key = root.path().join("document-signer.pk8");
        fs::write(&document_signing_key, document_der.as_bytes())?;
        fs::write(
            bundle.join("keys/release.pub"),
            document_key.verifying_key().to_bytes(),
        )?;
        let verification_key = SigningKey::from_bytes(&[0x66; 32]);
        let verification_der = verification_key.to_pkcs8_der()?;
        let verification_signing_key = root.path().join("verification-signer.pk8");
        fs::write(&verification_signing_key, verification_der.as_bytes())?;
        fs::write(
            bundle.join("keys/verification.pub"),
            verification_key.verifying_key().to_bytes(),
        )?;

        let trusted_root_sha256 = hex(&Sha256::digest(public_bytes));
        let manifest = root.path().join("bundle.manifest.json");
        Ok(Self {
            root,
            bundle,
            source,
            recipe,
            manifest,
            root_signing_key,
            document_signing_key,
            verification_signing_key,
            public_key,
            trusted_root_sha256,
            bundled_verifier,
        })
    }

    fn materialize_verifier(&self) -> Result<Output> {
        self.materialize_verifier_at(&self.bundle)
    }

    fn materialize_verifier_at(&self, bundle: &Path) -> Result<Output> {
        Command::new(env!("CARGO_BIN_EXE_aos"))
            .args([
                "hub",
                "topology",
                "cutover",
                "materialize-verifier",
                "--bundle",
            ])
            .arg(bundle)
            .arg("--bundle-recipe")
            .arg(&self.recipe)
            .output()
            .context("materializing the cutover verifier")
    }

    fn generate(&self) -> Result<Output> {
        self.generate_with_document_key(&self.document_signing_key)
    }

    fn generate_with_document_key(&self, document_signing_key: &Path) -> Result<Output> {
        Command::new(env!("CARGO_BIN_EXE_aos"))
            .args(["hub", "topology", "cutover", "generate", "--bundle"])
            .arg(&self.bundle)
            .arg("--bundle-source")
            .arg(&self.source)
            .arg("--bundle-recipe")
            .arg(&self.recipe)
            .arg("--bundle-manifest-output")
            .arg(&self.manifest)
            .arg("--root-signing-key")
            .arg(&self.root_signing_key)
            .arg("--document-signing-key")
            .arg(document_signing_key)
            .arg("--verification-signing-key")
            .arg(&self.verification_signing_key)
            .arg("--trusted-root-public-key")
            .arg(&self.public_key)
            .arg("--root-signer-key-id")
            .arg(ROOT_SIGNER_ID)
            .arg("--document-signer-key-id")
            .arg(DOCUMENT_SIGNER_ID)
            .arg("--verification-signer-key-id")
            .arg(VERIFICATION_SIGNER_ID)
            .output()
            .context("running atomic cutover generation")
    }

    fn verify(&self, executable: &Path) -> Result<Output> {
        self.verify_with_fingerprint(executable, &self.trusted_root_sha256)
    }

    fn verify_with_fingerprint(&self, executable: &Path, fingerprint: &str) -> Result<Output> {
        Command::new(executable)
            .args(["hub", "topology", "cutover", "verify", "--bundle"])
            .arg(&self.bundle)
            .arg("--bundle-manifest")
            .arg(&self.manifest)
            .arg("--trusted-root-public-key")
            .arg(&self.public_key)
            .arg("--trusted-root-sha256")
            .arg(fingerprint)
            .output()
            .context("running cutover verifier")
    }
}

fn assert_success_json(output: &Output, expected_result: &str) -> Result<Value> {
    if !output.status.success() {
        bail!(
            "cutover command failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if !output.stderr.is_empty() {
        bail!(
            "successful cutover command wrote to stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    if value["result"] != expected_result {
        bail!("unexpected cutover command result: {value}");
    }
    Ok(value)
}

fn assert_failure_code(output: &Output, expected_code: &str) -> Result<()> {
    if output.status.success() {
        bail!("cutover command unexpectedly succeeded");
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    if value["result"] != "failed" || value["code"] != expected_code {
        bail!("unexpected cutover failure: {value}");
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
        .to_path_buf()
}

fn create_parent(path: &Path) -> Result<()> {
    fs::create_dir_all(path.parent().context("fixture output has no parent")?)?;
    Ok(())
}

fn copy_fixture(docs: &Path, fixture: &str, output: &Path) -> Result<()> {
    fs::copy(docs.join(fixture), output)
        .with_context(|| format!("copying {fixture} to {}", output.display()))?;
    Ok(())
}

fn source_files() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "documents/plan.json",
            "hub-topology-cutover-plan-v1.fixture-source.json",
        ),
        (
            "documents/report.json",
            "hub-topology-cutover-report-v1.fixture-source.json",
        ),
        (
            "documents/verification.json",
            "hub-topology-cutover-digest-verification-v1.fixture-source.json",
        ),
        (
            "trust/signer-key-map.json",
            "hub-topology-cutover-signer-key-map-v1.fixture-source.json",
        ),
        (
            "schemas/bundle-generation.json",
            "hub-topology-cutover-bundle-generation-v1.schema.json",
        ),
        (
            "schemas/plan.json",
            "hub-topology-cutover-plan-v1.schema.json",
        ),
        (
            "schemas/report.json",
            "hub-topology-cutover-report-v1.schema.json",
        ),
        (
            "schemas/verification.json",
            "hub-topology-cutover-digest-verification-v1.schema.json",
        ),
        (
            "schemas/signer-key-map.json",
            "hub-topology-cutover-signer-key-map-v1.schema.json",
        ),
    ]
}

fn static_bundle_files() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "evidence/backup-d1.sql",
            "hub-topology-cutover-backup-d1-v1.fixture.json",
        ),
        (
            "evidence/backup-do-topology.json",
            "hub-topology-cutover-backup-do-v1.fixture.json",
        ),
        (
            "evidence/source-deployment.json",
            "hub-topology-cutover-source-deployment-v1.fixture.json",
        ),
        (
            "evidence/source-export.json",
            "hub-topology-cutover-source-export-v1.fixture.json",
        ),
        (
            "evidence/cutover.json",
            "hub-topology-cutover-evidence-v1.fixture.json",
        ),
        ("manifests/api.json", "hub-api-manifest-v1.json"),
        ("manifests/cli.json", "hub-cli-json-schema-v1.json"),
        (
            "fixtures/cases.json",
            "hub-topology-cutover-fixtures-v1.json",
        ),
        ("manifests/routes.md", "11-web-route-cutover-ledger.md"),
        (
            "rules/database-restore.json",
            "hub-topology-cutover-database-restore-rules-v1.fixture.json",
        ),
        (
            "schemas/bundle.json",
            "hub-topology-cutover-bundle-v1.schema.json",
        ),
        (
            "schemas/bundle-generation.json",
            "hub-topology-cutover-bundle-generation-v1.schema.json",
        ),
        (
            "schemas/dialect.json",
            "aos-cutover-schema-v1.metaschema.json",
        ),
        (
            "schemas/fixtures.json",
            "hub-topology-cutover-fixtures-v1.schema.json",
        ),
        (
            "schemas/plan.json",
            "hub-topology-cutover-plan-v1.schema.json",
        ),
        (
            "schemas/report.json",
            "hub-topology-cutover-report-v1.schema.json",
        ),
        (
            "schemas/signature-envelope.json",
            "hub-topology-cutover-signature-envelope-v1.schema.json",
        ),
        (
            "schemas/signer-key-map.json",
            "hub-topology-cutover-signer-key-map-v1.schema.json",
        ),
        (
            "schemas/verification.json",
            "hub-topology-cutover-digest-verification-v1.schema.json",
        ),
    ]
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(*byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(*byte & 0x0f)]));
    }
    output
}
