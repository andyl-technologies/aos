//! Arguments for `aos hub` — the registry-hub control-plane client.
//!
//! These subcommands interact with a running `aos-hub` purely through
//! its public ConnectRPC API (RFC-0004), never by touching the hub's database
//! directly. `login` uses browser-approved device authorization by default.
//! Public topology reads run anonymously; private inventory and all desired-state
//! writes use an explicit bearer or the active stored Hub profile. Mutations use typed resource
//! references, optimistic concurrency, and the shared immutable plan/apply
//! contract.
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::hub`, which drives `aos_remote::HubClient`.

use clap::{Args, Subcommand};
use std::path::PathBuf;

use super::{
    HubAccessTokenCmd, HubIdentityProviderCmd, HubInstanceSettingsSectionCmd, HubInvitationCmd,
    HubOrgMemberCmd, HubOrganizationDomainCmd, HubServiceAccountCmd, HubSigningKeyCmd,
};

#[derive(Args, Debug, Clone)]
pub struct HubAccessArgs {
    /// Hub base URL; defaults to the active profile
    #[arg(long, env = "AOS_HUB")]
    pub hub: Option<String>,
    /// Hub access JWT; defaults to AOS_TOKEN or the matching active profile
    #[arg(long, env = "AOS_TOKEN")]
    pub token: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct HubOptionalAccessArgs {
    /// Hub base URL (required when starting a drain)
    #[arg(long, env = "AOS_HUB")]
    pub hub: Option<String>,
    /// Hub access JWT for authenticated access
    #[arg(long, env = "AOS_TOKEN")]
    pub token: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct HubMutationArgs {
    /// Stable key used to retry this exact plan or apply request
    #[arg(long, value_name = "KEY")]
    pub idempotency_key: Option<String>,
    /// Print the semantic plan without applying it
    #[arg(long, conflicts_with_all = ["plan_id", "yes"])]
    pub plan: bool,
    /// Apply a previously reviewed plan
    #[arg(
        long,
        value_name = "ID",
        requires = "confirm_hash",
        conflicts_with = "plan"
    )]
    pub plan_id: Option<String>,
    /// Confirm the exact reviewed effect manifest
    #[arg(
        long,
        value_name = "HASH",
        requires = "plan_id",
        conflicts_with = "plan"
    )]
    pub confirm_hash: Option<String>,
    /// Require this resource version
    #[arg(long, value_name = "VALUE")]
    pub if_version: Option<String>,
    /// Read a versioned exact-pin resolution document
    #[arg(long = "pin-resolution-file", value_name = "FILE")]
    pub pin_resolution_file: Option<PathBuf>,
    /// Confirm non-interactive application of a supplied reviewed plan
    #[arg(long, requires = "plan_id", conflicts_with = "plan")]
    pub yes: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct HubPaginationArgs {
    /// Limit the number of resources returned
    #[arg(long)]
    pub page_size: Option<u32>,
    /// Continue from an opaque page token
    #[arg(long)]
    pub page_token: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct HubOperationArgs {
    /// Watch the returned operation until it reaches a terminal state
    #[arg(long)]
    pub wait: bool,
    /// Stop waiting after this duration
    #[arg(long, requires = "wait")]
    pub timeout: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct HubAccessPolicyArgs {
    /// Select public, hub-auth, external-provider, or private-network access
    #[arg(long, value_parser = ["public", "hub-auth", "external-provider", "private-network"])]
    pub access: Option<String>,
    /// Permit this Hub principal (repeatable)
    #[arg(long = "hub-principal")]
    pub hub_principals: Vec<String>,
    /// Permit this Hub client class (repeatable)
    #[arg(long = "hub-client-class")]
    pub hub_client_classes: Vec<String>,
    /// Select the external authorization provider kind
    #[arg(long)]
    pub external_provider_kind: Option<String>,
    /// Select the external authorization provider resource
    #[arg(long)]
    pub external_provider_resource_id: Option<String>,
    /// Pin the external authorization provider revision
    #[arg(long)]
    pub external_provider_revision: Option<String>,
    /// Add mechanism=verification-secret-ref (repeatable)
    #[arg(long = "external-client-mechanism")]
    pub external_client_mechanisms: Vec<String>,
    /// Permit this external client class (repeatable)
    #[arg(long = "external-client-class")]
    pub external_client_classes: Vec<String>,
    /// Pin the private network policy revision
    #[arg(long)]
    pub access_boundary: Option<String>,
}

#[derive(Subcommand)]
pub enum HubCmd {
    /// Sign in through browser-approved device authorization
    Login {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Bootstrap with an administrator-issued provisioning secret
        #[arg(long)]
        provisioning_token: Option<String>,
        /// Request authority at this canonical stable scope
        #[arg(long)]
        scope: Option<String>,
    },
    /// Revoke and remove a stored Hub profile
    Logout {
        /// Hub base URL; defaults to the active profile
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
    },
    /// Show the authenticated principal, live grants, and token authority
    Whoami {
        #[command(flatten)]
        access: HubAccessArgs,
    },
    /// Manage scoped access-token generations
    AccessToken {
        #[command(subcommand)]
        command: HubAccessTokenCmd,
    },
    /// Generate or verify topology cutover artifacts offline
    Topology {
        #[command(subcommand)]
        command: HubTopologyCmd,
    },
    /// View and edit deployment-wide instance settings (needs instance admin)
    Instance {
        #[command(subcommand)]
        command: HubInstanceCmd,
    },
    /// Manage organizations (the tenant boundary)
    Org {
        #[command(subcommand)]
        command: HubOrgCmd,
    },
    /// Manage signer identity, custody, generations, and usages
    SigningKey {
        #[command(subcommand)]
        command: HubSigningKeyCmd,
    },
    /// Inspect and manage registries
    Registry {
        #[command(subcommand)]
        command: HubRegistryCmd,
    },
    /// Browse canonical package documentation through the Hub API
    Docs {
        #[command(subcommand)]
        command: HubDocumentationCmd,
    },
    /// Manage binary-cache definitions, retention, population, and garbage collection
    Cache {
        #[command(subcommand)]
        command: HubCacheCmd,
    },
    /// Manage bindings
    Binding {
        #[command(subcommand)]
        command: HubBindingCmd,
    },
    /// Inspect a registry or binary-cache surface
    Surface {
        #[command(subcommand)]
        command: HubSurfaceCmd,
    },
    /// Inspect and manage registry and binary-cache placements
    Placement {
        #[command(subcommand)]
        command: HubPlacementCmd,
    },
    /// Manage immutable placement-policy revisions
    PlacementPolicy {
        #[command(subcommand)]
        command: HubPlacementPolicyCmd,
    },
    /// Manage verified equivalence between physical placements
    PlacementEquivalence {
        #[command(subcommand)]
        command: HubPlacementEquivalenceCmd,
    },
    /// Manage DNS domains
    Domain {
        #[command(subcommand)]
        command: HubDomainCmd,
    },
    /// Manage network-boundary identities and revisions
    NetworkPolicy {
        #[command(subcommand)]
        command: HubNetworkPolicyCmd,
    },
    /// Manage endpoints
    Endpoint {
        #[command(subcommand)]
        command: HubEndpointCmd,
    },
    /// Manage gateways
    Gateway {
        #[command(subcommand)]
        command: HubGatewayCmd,
    },
    /// Manage surface routes
    Route {
        #[command(subcommand)]
        command: HubRouteCmd,
    },
    /// Inspect and control long-running Hub operations
    Operation {
        #[command(subcommand)]
        command: HubOperationCmd,
    },
}

#[derive(Subcommand)]
pub enum HubDocumentationCmd {
    /// Search package documentation
    Search {
        #[command(flatten)]
        access: HubAccessArgs,
        query: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        kind: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Fetch one exact package documentation object
    Package {
        #[command(flatten)]
        access: HubAccessArgs,
        package: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        platform: Option<String>,
    },
    /// List or select an exact typed option
    Option {
        #[command(flatten)]
        access: HubAccessArgs,
        package: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        owner: Option<String>,
        #[arg(long = "type")]
        option_type: Option<String>,
        #[arg(long)]
        contributable: Option<bool>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Compare two package documentation versions
    Compare {
        #[command(flatten)]
        access: HubAccessArgs,
        package: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        platform: String,
    },
    /// Verify and write one exact canonical documentation object
    Fetch {
        #[command(flatten)]
        access: HubAccessArgs,
        package: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Print the canonical browser URL for one package
    Open {
        #[command(flatten)]
        access: HubAccessArgs,
        package: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        platform: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum HubTopologyCmd {
    /// Operate on one-shot topology cutover artifacts
    Cutover {
        #[command(subcommand)]
        command: HubTopologyCutoverCmd,
    },
}

#[derive(Subcommand)]
pub enum HubTopologyCutoverCmd {
    /// Install the exact running verifier bytes into a fresh bundle path
    MaterializeVerifier(HubTopologyCutoverMaterializeVerifierArgs),
    /// Canonicalize, digest, and sign a cutover bundle
    Generate(HubTopologyCutoverGenerateArgs),
    /// Verify schemas, canonical digests, signatures, fixtures, and semantics
    Verify(HubTopologyCutoverVerifyArgs),
}

#[derive(Args, Debug, Clone)]
pub struct HubTopologyCutoverMaterializeVerifierArgs {
    /// Fresh cutover bundle directory
    #[arg(long)]
    pub bundle: PathBuf,
    /// Immutable generation recipe declaring the verifier node and path
    #[arg(long)]
    pub bundle_recipe: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct HubTopologyCutoverVerifyArgs {
    /// Closed cutover bundle directory
    #[arg(long)]
    pub bundle: PathBuf,
    /// Bundle manifest JSON, outside the bundle directory
    #[arg(long)]
    pub bundle_manifest: PathBuf,
    /// Out-of-band Ed25519 root public key
    #[arg(long)]
    pub trusted_root_public_key: PathBuf,
    /// Out-of-band SHA-256 fingerprint of the exact root-key file bytes
    #[arg(long, value_name = "HEX")]
    pub trusted_root_sha256: String,
}

#[derive(Args, Debug, Clone)]
pub struct HubTopologyCutoverGenerateArgs {
    /// Closed cutover bundle directory
    #[arg(long)]
    pub bundle: PathBuf,
    /// Immutable source tree for generated bundle documents and schemas
    #[arg(long)]
    pub bundle_source: PathBuf,
    /// Immutable generation recipe JSON, outside the bundle directory
    #[arg(long)]
    pub bundle_recipe: PathBuf,
    /// Fresh final manifest output, outside the bundle directory
    #[arg(long)]
    pub bundle_manifest_output: PathBuf,
    /// Ed25519 PKCS#8 root signing key, outside the bundle directory
    #[arg(long)]
    pub root_signing_key: PathBuf,
    /// Ed25519 PKCS#8 plan/report signing key, outside the bundle directory
    #[arg(long)]
    pub document_signing_key: PathBuf,
    /// Ed25519 PKCS#8 verification signing key, outside the bundle directory
    #[arg(long)]
    pub verification_signing_key: PathBuf,
    /// Out-of-band Ed25519 root public key, outside the bundle directory
    #[arg(long)]
    pub trusted_root_public_key: PathBuf,
    /// Root signer identity used for the key map and final bundle
    #[arg(long)]
    pub root_signer_key_id: String,
    /// Plan/report signer identity present in the authenticated key map
    #[arg(long)]
    pub document_signer_key_id: String,
    /// Verification signer identity present in the authenticated key map
    #[arg(long)]
    pub verification_signer_key_id: String,
}

#[derive(Subcommand)]
pub enum HubProjectCmd {
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one project by materialized path
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[arg(long, default_value = "")]
        path: String,
    },
    /// Plan creation or apply a reviewed project plan
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[arg(long, default_value = "")]
        path: String,
        #[arg(long)]
        name: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Delete an empty project after a reviewed plan
    Delete {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[arg(long, default_value = "")]
        path: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubAuditCmd {
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long, default_value = "instance")]
        scope: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubWebhookCmd {
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[arg(long)]
        url: String,
        /// Subscribe to one supported event; repeat, or omit to receive all.
        #[arg(long = "event")]
        events: Vec<String>,
        /// Use this immutable operator-managed secret-provider version.
        #[arg(long)]
        secret_version_ref: String,
        /// Require the resolved signing secret to have this SHA-256 digest.
        #[arg(long)]
        credential_fingerprint: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    Delete {
        #[command(flatten)]
        access: HubAccessArgs,
        id: i64,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubPackageCmd {
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        name: String,
    },
}

#[derive(Subcommand)]
pub enum HubChannelCmd {
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        name: String,
    },
}

#[derive(Subcommand)]
pub enum HubPublishCmd {
    /// List publication sessions newest first
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        /// Filter by an exact publication lifecycle state
        #[arg(long, value_parser = ["preparing", "writing_pointers", "ready", "failed", "retired"])]
        state: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Atomically publish a complete APR surface to every required placement
    Upload {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        /// Read a reviewed publication manifest instead of deriving one from --root.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Read every declared object below this surface root.
        #[arg(long)]
        root: PathBuf,
    },
    Begin {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        /// Read the exact publication manifest from this JSON file.
        #[arg(long)]
        manifest: PathBuf,
    },
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        publication_id: String,
    },
    Commit {
        #[command(flatten)]
        access: HubAccessArgs,
        publication_id: String,
    },
    Abort {
        #[command(flatten)]
        access: HubAccessArgs,
        publication_id: String,
    },
}

#[derive(Subcommand)]
pub enum HubConfigCmd {
    Changesets {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long, default_value = "")]
        scope: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        change_id: String,
    },
    Log {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    Diff {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
    ChangeRequests {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubOperationCmd {
    /// Show one operation
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        operation_id: String,
    },
    /// List operations for one target or authorization scope
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Qualified target, for example registry:andyl/main or cache:andyl/shared
        #[arg(
            long,
            value_name = "KIND:ID",
            conflicts_with = "scope",
            required_unless_present = "scope"
        )]
        target: Option<String>,
        /// Immutable scope, including all descendant-owned operations
        #[arg(
            long,
            value_name = "SCOPE",
            conflicts_with = "target",
            required_unless_present = "target"
        )]
        scope: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Watch an operation until terminal or timeout
    Watch {
        #[command(flatten)]
        access: HubAccessArgs,
        operation_id: String,
        #[arg(long)]
        timeout: Option<String>,
    },
    /// Request best-effort cancellation
    Cancel {
        #[command(flatten)]
        access: HubAccessArgs,
        operation_id: String,
        #[arg(long)]
        if_version: Option<String>,
    },
    /// Retry a retryable terminal operation
    Retry {
        #[command(flatten)]
        access: HubAccessArgs,
        operation_id: String,
        #[arg(long)]
        if_version: Option<String>,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubInstanceCmd {
    /// Manage identity, signup, and session settings
    Identity {
        #[command(subcommand)]
        command: HubInstanceSettingsSectionCmd,
    },
    /// Manage defaults inherited by newly created resources
    ResourceDefaults {
        #[command(subcommand)]
        command: HubInstanceSettingsSectionCmd,
    },
    /// Manage site branding, announcements, and footer links
    Branding {
        #[command(subcommand)]
        command: HubInstanceSettingsSectionCmd,
    },
    /// Manage instance topology defaults
    TopologyDefaults {
        #[command(subcommand)]
        command: HubInstanceTopologyDefaultsCmd,
    },
}

#[derive(Subcommand)]
pub enum HubInstanceTopologyDefaultsCmd {
    /// Show exact default delivery generations
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
    },
    /// Set one or more topology defaults
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Clear one or more topology defaults
    Clear {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        domain: bool,
        #[arg(long)]
        endpoint: bool,
        #[arg(long)]
        gateway: bool,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubOrgCmd {
    /// List visible organizations
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one organization
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
    },
    /// Plan creation or apply a reviewed organization plan
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        slug: Option<String>,
        #[arg(long)]
        display_name: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Update organization profile metadata
    Update {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Organization slug
        org: Option<String>,
        /// Replace the display name
        #[arg(long)]
        display_name: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Plan deletion or apply a reviewed organization plan
    Delete {
        #[command(flatten)]
        access: HubAccessArgs,
        org: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Manage organization topology defaults
    TopologyDefaults {
        #[command(subcommand)]
        command: HubOrgTopologyDefaultsCmd,
    },
    /// Manage projects owned by an organization
    Project {
        #[command(subcommand)]
        command: HubProjectCmd,
    },
    /// Inspect the organization's audit log
    Audit {
        #[command(subcommand)]
        command: HubAuditCmd,
    },
    /// Manage organization webhooks
    Webhook {
        #[command(subcommand)]
        command: HubWebhookCmd,
    },
    /// Manage organization memberships
    Member {
        #[command(subcommand)]
        command: HubOrgMemberCmd,
    },
    /// Manage organization-owned service accounts
    ServiceAccount {
        #[command(subcommand)]
        command: HubServiceAccountCmd,
    },
    /// Manage organization invitations
    Invitation {
        #[command(subcommand)]
        command: HubInvitationCmd,
    },
    /// Manage the organization OIDC identity provider
    IdentityProvider {
        #[command(subcommand)]
        command: HubIdentityProviderCmd,
    },
    /// Manage organization email-domain claims
    Domain {
        #[command(subcommand)]
        command: HubOrganizationDomainCmd,
    },
}

#[derive(Subcommand)]
pub enum HubOrgTopologyDefaultsCmd {
    /// Show exact organization topology defaults
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
    },
    /// Set one or more topology defaults
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[arg(long)]
        binding: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Clear one or more topology defaults
    Clear {
        #[command(flatten)]
        access: HubAccessArgs,
        org: String,
        #[arg(long)]
        binding: bool,
        #[arg(long)]
        domain: bool,
        #[arg(long)]
        endpoint: bool,
        #[arg(long)]
        gateway: bool,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubBindingCmd {
    /// List the bindings under an org
    List {
        /// Hub base URL; defaults to the active profile
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Hub access JWT; defaults to AOS_TOKEN or the matching active profile
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
        /// Organization slug; omit for instance-owned bindings
        #[arg(long)]
        org: Option<String>,
        /// Include bindings explicitly granted to the selected scope
        #[arg(long)]
        include_granted: bool,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Create an instance or organization binding
    Create {
        /// Hub base URL; defaults to the active profile
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Hub access JWT; defaults to AOS_TOKEN or the matching active profile
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
        /// Org slug; omit for an instance binding
        #[arg(long)]
        org: Option<String>,
        /// Binding name
        #[arg(long)]
        name: String,
        /// Stable resource identity (generated when omitted)
        #[arg(long)]
        stable_id: Option<String>,
        /// Backend kind: local-fs, s3, r2, or deployment-r2
        #[arg(long, value_parser = ["local-fs", "s3", "r2", "deployment-r2"])]
        kind: Option<String>,
        /// Absolute local-filesystem root
        #[arg(long)]
        root: Option<String>,
        /// Object-storage bucket
        #[arg(long)]
        bucket: Option<String>,
        /// Optional object prefix within the bucket
        #[arg(long)]
        prefix: Option<String>,
        /// Endpoint origin URL for s3/r2 (e.g. https://<acct>.r2.cloudflarestorage.com)
        #[arg(long)]
        endpoint: Option<String>,
        /// Signing region for s3/r2
        #[arg(long)]
        region: Option<String>,
        /// Access mode for s3/r2: private (default) or public
        #[arg(long, value_parser = ["public", "private"])]
        access: Option<String>,
        /// Cloudflare Worker R2 attachment (REGISTRY_BUCKET) for deployment-r2
        #[arg(long)]
        bucket_binding: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Show one binding
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Stable storage-binding reference
        binding_ref: String,
    },
    /// Manage purpose-scoped binding credentials
    Credential {
        #[command(subcommand)]
        command: HubBindingCredentialCmd,
    },
    /// Inspect immutable binding write revisions
    WriteRevision {
        #[command(subcommand)]
        command: HubBindingWriteRevisionCmd,
    },
    /// Grant a consumer scope access to a binding
    Grant {
        #[command(flatten)]
        access: HubAccessArgs,
        binding_ref: String,
        #[arg(long)]
        consumer_scope: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Revoke a consumer-scope grant
    Revoke {
        #[command(flatten)]
        access: HubAccessArgs,
        binding_ref: String,
        #[arg(long)]
        consumer_scope: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Delete an unused organization binding
    Delete {
        #[command(flatten)]
        access: HubAccessArgs,
        binding_ref: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubBindingCredentialCmd {
    /// Set the current credential reference for one purpose
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        binding_ref: String,
        #[arg(long, value_parser = ["read", "write", "delete", "list", "presign"])]
        purpose: String,
        /// Use this immutable operator-managed secret-provider version.
        #[arg(long)]
        secret_version_ref: String,
        /// Require the resolved credential to have this SHA-256 digest.
        #[arg(long)]
        credential_fingerprint: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Rotate one credential from an exact generation
    Rotate {
        #[command(flatten)]
        access: HubAccessArgs,
        binding_ref: String,
        #[arg(long, value_parser = ["read", "write", "delete", "list", "presign"])]
        purpose: String,
        #[arg(long)]
        from_generation: u64,
        /// Use this immutable operator-managed secret-provider version.
        #[arg(long)]
        secret_version_ref: String,
        /// Require the resolved credential to have this SHA-256 digest.
        #[arg(long)]
        credential_fingerprint: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Validate one or all purpose-scoped credentials
    Validate {
        #[command(flatten)]
        access: HubAccessArgs,
        binding_ref: String,
        #[arg(long, value_parser = ["read", "write", "delete", "list", "presign"])]
        purpose: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubBindingWriteRevisionCmd {
    /// List immutable write revisions
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        binding_ref: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one immutable write revision
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        binding_ref: String,
        revision: u64,
    },
}

#[derive(Subcommand)]
pub enum HubSurfaceCmd {
    /// Show one surface and its resource version
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Typed registry:<slug> or cache:<slug> reference
        surface_ref: String,
    },
    /// Show placements, policies, routes, endpoints, and health as a tree
    Topology {
        #[command(flatten)]
        access: HubAccessArgs,
        surface_ref: String,
    },
    /// Explain how a URL and optional machine path resolve
    Explain {
        #[command(flatten)]
        access: HubAccessArgs,
        surface_ref: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        path: Option<String>,
        /// Select the route capability to explain
        #[arg(long, value_parser = ["web", "git", "nix_cache"], default_value = "web")]
        access_class: String,
    },
}

#[derive(Subcommand)]
pub enum HubDomainCmd {
    /// List domains visible at an optional organization scope
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Limit results to one organization
        #[arg(long)]
        org: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show desired and observed domain state
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        hostname: String,
    },
    /// Add an immutable DNS hostname
    Add {
        #[command(flatten)]
        access: HubAccessArgs,
        hostname: String,
        #[arg(long)]
        org: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Configure domain DNS ownership and records
    Dns {
        #[command(subcommand)]
        command: HubDomainDnsCmd,
    },
    /// Configure domain certificate issuance
    Certificate {
        #[command(subcommand)]
        command: HubDomainCertificateCmd,
    },
    /// Verify DNS-name ownership
    Verify {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Select the domain by DNS hostname or stable identity
        #[arg(value_name = "HOSTNAME_OR_ID")]
        hostname: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Show DNS and certificate observations
    Status {
        #[command(flatten)]
        access: HubAccessArgs,
        hostname: String,
    },
    /// Remove an unused domain
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        hostname: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubDomainDnsCmd {
    /// Configure Hub-managed or external DNS
    Configure {
        #[command(flatten)]
        access: HubAccessArgs,
        hostname: String,
        #[arg(long, value_parser = ["hub-managed", "external"])]
        mode: String,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        zone_id: Option<String>,
        #[arg(long)]
        record_ttl: Option<u32>,
        #[arg(long)]
        expected_target: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubDomainCertificateCmd {
    /// Configure Hub-managed or external certificate issuance
    Configure {
        #[command(flatten)]
        access: HubAccessArgs,
        hostname: String,
        #[arg(long, value_parser = ["hub-managed", "external"])]
        mode: String,
        #[arg(long)]
        certificate_ref: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubNetworkPolicyCmd {
    /// List stable boundary identities
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        org: Option<String>,
        /// Include network policies explicitly granted to the selected scope
        #[arg(long)]
        include_granted: bool,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show a boundary and its default revision
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary: String,
    },
    /// Add a typed immutable boundary identity
    Add {
        #[command(flatten)]
        access: HubAccessArgs,
        name: String,
        /// Use this stable identity instead of generating one
        #[arg(long)]
        stable_id: Option<String>,
        #[arg(long, value_parser = ["vpn", "vpc", "tunnel", "source-allowlist", "trusted-ingress"])]
        kind: Option<String>,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        provider_account: Option<String>,
        #[arg(long)]
        resource_id: Option<String>,
        #[arg(long)]
        allowlist_id: Option<String>,
        #[arg(long)]
        listener_id: Option<String>,
        /// Require or waive protected transport for the initial revision
        #[arg(long, value_parser = ["required", "not-required"])]
        protected_transport: Option<String>,
        /// Probe-location configuration for the initial revision
        #[arg(long)]
        probe_location: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Create a staged immutable boundary revision
    Revise {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary: String,
        #[arg(long, value_parser = ["required", "not-required"])]
        protected_transport: Option<String>,
        #[arg(long, value_parser = ["none", "mtls", "signed-assertion"])]
        trusted_ingress: Option<String>,
        #[arg(long)]
        ca_secret_ref: Option<String>,
        #[arg(long = "client-san", conflicts_with = "clear_client_sans")]
        client_sans: Vec<String>,
        /// Replace the mTLS client-SAN set with an empty set
        #[arg(long, conflicts_with = "client_sans")]
        clear_client_sans: bool,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        audience: Option<String>,
        #[arg(long)]
        verification_key_secret_ref: Option<String>,
        #[arg(long = "cidr", conflicts_with = "clear_cidrs")]
        cidrs: Vec<String>,
        #[arg(long, conflicts_with = "cidrs")]
        clear_cidrs: bool,
        #[arg(long, conflicts_with = "clear_probe_location")]
        probe_location: Option<String>,
        #[arg(long, conflicts_with = "probe_location")]
        clear_probe_location: bool,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Grant the boundary identity to a consumer scope
    Grant {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary: String,
        #[arg(long)]
        consumer_scope: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Revoke a boundary grant after its live pins reach zero
    Revoke {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary: String,
        #[arg(long)]
        consumer_scope: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Manage immutable boundary revisions
    Revision {
        #[command(subcommand)]
        command: HubNetworkPolicyRevisionCmd,
    },
    /// Show all revision lifecycle and observation state
    Status {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary: String,
    },
    /// Remove an unused non-public boundary
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubNetworkPolicyRevisionCmd {
    /// List immutable revisions and lifecycle state
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one exact boundary revision
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary_revision: String,
    },
    /// Activate a staged revision
    Activate {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary_revision: String,
        #[arg(long, value_parser = ["overlap", "coordinated"])]
        mode: String,
        #[arg(long, value_parser = ["yes", "no"])]
        default_for_new_plans: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Retire an active or retiring revision
    Retire {
        #[command(flatten)]
        access: HubAccessArgs,
        boundary_revision: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubEndpointCmd {
    /// List endpoints
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        org: Option<String>,
        /// Include endpoints explicitly granted to the selected scope
        #[arg(long)]
        include_granted: bool,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show typed origin and desired/observed state
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
    },
    /// List every immutable generation of an endpoint
    Generations {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one immutable endpoint generation
    Generation {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
        generation: i64,
    },
    /// Add an endpoint with an exact network policy
    Add {
        #[command(flatten)]
        access: HubAccessArgs,
        origin: String,
        /// Use this stable identity instead of generating one
        #[arg(long)]
        stable_id: Option<String>,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        acknowledge_cleartext: bool,
        #[arg(long)]
        network_policy: String,
        #[arg(long, value_parser = ["hub", "external", "layer7"])]
        ingress: String,
        #[arg(long, value_parser = ["hub-native", "hub-worker", "external", "layer7"])]
        listener_provider: String,
        #[arg(long)]
        listener_resource_id: String,
        /// Record the HTTPS termination provider
        #[arg(long, value_parser = ["hub-managed", "external"])]
        tls_provider: Option<String>,
        /// Pin the certificate identity used by the termination provider
        #[arg(long)]
        certificate_ref: Option<String>,
        #[arg(long, value_parser = ["native-file", "worker-secret", "external"])]
        probe_provider: String,
        #[arg(long)]
        probe_signer_secret_ref: String,
        /// Pin the base64url-no-padding Ed25519 probe public key
        #[arg(long)]
        probe_public_key: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Stage a new immutable endpoint generation without selecting it
    Stage {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
        #[arg(long, value_parser = ["hub", "external", "layer7"])]
        ingress: Option<String>,
        #[arg(long)]
        boundary_revision: Option<u64>,
        #[arg(long, value_parser = ["hub-native", "hub-worker", "external", "layer7"])]
        listener_provider: Option<String>,
        #[arg(long)]
        listener_resource_id: Option<String>,
        #[arg(long, value_parser = ["hub-managed", "external"])]
        tls_provider: Option<String>,
        #[arg(long)]
        certificate_ref: Option<String>,
        #[arg(long, value_parser = ["native-file", "worker-secret", "external"])]
        probe_provider: Option<String>,
        #[arg(long)]
        probe_signer_secret_ref: Option<String>,
        /// Pin the base64url-no-padding Ed25519 probe public key
        #[arg(long)]
        probe_public_key: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Select one previously staged endpoint generation
    Activate {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
        generation: i64,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Grant the desired endpoint generation to a consumer scope
    Grant {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
        #[arg(long)]
        consumer_scope: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Revoke an exact endpoint-generation grant
    Revoke {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
        #[arg(long)]
        consumer_scope: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Show endpoint health and observations
    Status {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
    },
    /// Remove an unused endpoint identity
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        endpoint: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubGatewayCmd {
    /// List visible gateways, optionally filtered by binding
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Restrict results to an instance or organization binding reference
        #[arg(long)]
        binding: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one gateway and its desired generation
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        gateway: String,
    },
    /// Add a gateway
    Add {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Use this stable identity instead of generating one
        #[arg(long)]
        stable_id: Option<String>,
        #[arg(long)]
        binding: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value = "/")]
        client_base_path: String,
        #[arg(long, default_value = "/")]
        origin_prefix: String,
        #[command(flatten)]
        policy: HubAccessPolicyArgs,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Create a new immutable gateway generation
    Update {
        #[command(flatten)]
        access: HubAccessArgs,
        gateway: String,
        #[arg(long)]
        endpoint_generation: Option<u64>,
        #[arg(long)]
        client_base_path: Option<String>,
        #[arg(long)]
        origin_prefix: Option<String>,
        #[command(flatten)]
        policy: HubAccessPolicyArgs,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Grant an exact gateway generation to a consumer scope
    Grant {
        #[command(flatten)]
        access: HubAccessArgs,
        gateway_generation: String,
        #[arg(long)]
        consumer_scope: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Revoke an exact gateway-generation grant
    Revoke {
        #[command(flatten)]
        access: HubAccessArgs,
        gateway_generation: String,
        #[arg(long)]
        consumer_scope: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Preview explicit direct-route plans without creating routes
    Preview {
        #[command(flatten)]
        access: HubAccessArgs,
        gateway: String,
    },
    /// Enable a gateway generation for route use
    Enable {
        #[command(flatten)]
        access: HubAccessArgs,
        gateway: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Disable a gateway after its live route pins reach zero
    Disable {
        #[command(flatten)]
        access: HubAccessArgs,
        gateway: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Remove an unused gateway
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        gateway: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Args, Debug, Clone)]
pub struct HubRouteSpecArgs {
    /// Select a stable endpoint identity
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Pin an endpoint generation for update workflows
    #[arg(long)]
    pub endpoint_generation: Option<u64>,
    /// Set the Hub-route path; direct paths are derived
    #[arg(long)]
    pub base_path: Option<String>,
    /// Select hub-proxy, hub-redirect, or direct delivery
    #[arg(long, value_parser = ["hub-proxy", "hub-redirect", "direct"])]
    pub mode: Option<String>,
    /// Pin a complete placement
    #[arg(long, conflicts_with = "placement_policy")]
    pub placement: Option<String>,
    /// Pin a placement-policy name@revision
    #[arg(long, conflicts_with_all = ["placement", "gateway"])]
    pub placement_policy: Option<String>,
    /// Pin an exact gateway generation for direct delivery
    #[arg(long)]
    pub gateway: Option<String>,
    /// Replace the complete route capability set
    #[arg(long = "serves", value_parser = ["git", "cache", "web"])]
    pub serves: Vec<String>,
    #[command(flatten)]
    pub policy: HubAccessPolicyArgs,
}

#[derive(Subcommand)]
pub enum HubRouteCmd {
    /// List routes for one typed surface
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        surface_ref: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Add a disabled, non-route advertisement
    Add {
        #[command(flatten)]
        access: HubAccessArgs,
        surface_ref: String,
        /// Use this stable identity instead of generating one
        #[arg(long)]
        stable_id: Option<String>,
        #[command(flatten)]
        spec: HubRouteSpecArgs,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Update a route without changing its rendered URL identity
    Update {
        #[command(flatten)]
        access: HubAccessArgs,
        route: String,
        #[command(flatten)]
        spec: HubRouteSpecArgs,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Create a replacement route with a distinct URL reservation
    Replace {
        #[command(flatten)]
        access: HubAccessArgs,
        route: String,
        #[command(flatten)]
        spec: HubRouteSpecArgs,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Explain routing, access, publication, and placement selection
    Explain {
        #[command(flatten)]
        access: HubAccessArgs,
        route: String,
        #[arg(long)]
        path: Option<String>,
        /// Select the route capability to explain
        #[arg(long, value_parser = ["web", "git", "nix_cache"], default_value = "web")]
        access_class: String,
    },
    /// Enable a route and queue its current configuration probe
    Enable {
        #[command(flatten)]
        access: HubAccessArgs,
        route: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Disable a route after signed-stack references are removed
    Disable {
        #[command(flatten)]
        access: HubAccessArgs,
        route: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Delete an unreferenced disabled route
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        route: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Set the route as canonical for one audience
    Canonical {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Typed surface ref (`registry:<slug>` or `cache:<slug>`)
        surface_ref: String,
        route: String,
        #[arg(long, value_parser = ["git", "nix_cache", "web"])]
        audience: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubCacheCmd {
    /// List binary-cache definitions
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        org: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one qualified binary-cache definition
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Qualified cache ref (`<org>/<cache>`) or stable id
        cache: String,
    },
    /// Create one qualified binary-cache definition
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        /// New qualified cache ref (`<org>/<cache>`)
        cache: String,
        /// Human-readable cache name
        #[arg(long)]
        name: Option<String>,
        /// Initial access posture
        #[arg(long, value_parser = ["public", "internal", "private"])]
        visibility: Option<String>,
        /// Nix substituter priority (lower is preferred)
        #[arg(long, default_value_t = 40)]
        nix_priority: u32,
        /// NAR compression advertised by this cache
        #[arg(long, value_parser = ["zstd", "xz", "none"], default_value = "zstd")]
        compression: String,
        /// Enable or disable Nix mass-query support
        #[arg(long, value_parser = ["enabled", "disabled"], default_value = "disabled")]
        mass_query: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Update cache identity or access posture
    Update {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Qualified cache ref or stable id
        cache: String,
        /// Replace the human-readable name
        #[arg(long)]
        name: Option<String>,
        /// Replace the access posture
        #[arg(long, value_parser = ["public", "internal", "private"])]
        visibility: Option<String>,
        /// Replace the Nix substituter priority
        #[arg(long)]
        nix_priority: Option<u32>,
        /// Replace the advertised NAR compression
        #[arg(long, value_parser = ["zstd", "xz", "none"])]
        compression: Option<String>,
        /// Enable or disable Nix mass-query support
        #[arg(long, value_parser = ["enabled", "disabled"])]
        mass_query: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Delete a cache definition after a reviewed plan
    Delete {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Qualified cache ref or stable id
        cache: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Manage registry-derived retention subscriptions
    Retention {
        #[command(subcommand)]
        command: HubCacheRetentionCmd,
    },
    /// Manage manual roots
    Root {
        #[command(subcommand)]
        command: HubCacheRootCmd,
    },
    /// Manage manual-root leases
    Lease {
        #[command(subcommand)]
        command: HubCacheLeaseCmd,
    },
    /// Manage population targets and runs
    Population {
        #[command(subcommand)]
        command: HubCachePopulationCmd,
    },
    /// Inspect and repair population coverage
    Coverage {
        #[command(subcommand)]
        command: HubCacheCoverageCmd,
    },
    /// Plan and run logical garbage collection
    Gc {
        #[command(subcommand)]
        command: HubCacheGcCmd,
    },
    /// Inspect one cache's registry integrations
    Integration {
        #[command(subcommand)]
        command: HubCacheIntegrationCmd,
    },
    /// Preview independent publication, retention, and population plans
    Integrate {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Qualified cache ref or stable id
        cache: String,
        /// Qualified registry ref
        #[arg(long)]
        registry: String,
        /// Preview adding this cache to the signed consumer stack
        #[arg(long)]
        use_for_clients: bool,
        /// Retain the registry's current catalog closure
        #[arg(long)]
        retain_current_catalog: bool,
        /// Retain the current target of this channel (repeatable)
        #[arg(long = "retain-channel")]
        retain_channels: Vec<String>,
        /// Retain this many newest releases
        #[arg(long)]
        retain_recent_releases: Option<u32>,
        /// Include prereleases in the recent-release selector
        #[arg(long, requires = "retain_recent_releases")]
        recent_include_prereleases: bool,
        /// Retain one exact release tag (repeatable)
        #[arg(long = "retain-release")]
        retain_releases: Vec<String>,
        /// Retain releases matching this semver requirement
        #[arg(long)]
        retain_semver: Option<String>,
        /// Include prereleases in the semver selector
        #[arg(long, requires = "retain_semver")]
        semver_include_prereleases: bool,
        /// Retain every indexed release
        #[arg(long)]
        retain_all_releases: bool,
        /// Preview a required or best-effort population target
        #[arg(long, value_parser = ["required", "best-effort"])]
        populate: Option<String>,
        /// Select when population runs
        #[arg(long, value_parser = ["release", "manual", "continuous"])]
        population_trigger: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum HubCacheRetentionCmd {
    /// List retention subscriptions
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Replace one registry retention subscription
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: Option<String>,
        #[arg(long)]
        current_catalog: bool,
        #[arg(long = "channel", conflicts_with = "all_channel_targets")]
        channels: Vec<String>,
        #[arg(long, conflicts_with = "channels")]
        all_channel_targets: bool,
        #[arg(long)]
        recent_releases: Option<u32>,
        #[arg(long, requires = "recent_releases")]
        recent_include_prereleases: bool,
        #[arg(long = "release")]
        releases: Vec<String>,
        #[arg(long)]
        semver: Option<String>,
        #[arg(long, requires = "semver")]
        semver_include_prereleases: bool,
        #[arg(long)]
        all_releases: bool,
        #[arg(long)]
        removal_grace: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Remove one registry retention subscription
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Refresh one or all registry subscriptions
    Refresh {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Explain all active retention reasons for an object
    Explain {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        store_hash: String,
    },
    /// List active root reasons
    Roots {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubCacheRootCmd {
    /// List manual retention roots
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one manual retention root
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        root_id: String,
    },
    /// Create an indefinite or leased manual root
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        store_hash: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        lease_until: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Delete a manual root
    Delete {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        root_id: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubCacheLeaseCmd {
    /// Renew a root lease by creating a successor record
    Renew {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        root_id: String,
        #[arg(long)]
        expires: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Revoke an active lease
    Revoke {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        lease_id: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubCachePopulationCmd {
    /// List population targets
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Replace one population target
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: String,
        #[arg(long, value_parser = ["release", "manual", "continuous"])]
        trigger: String,
        #[arg(
            long,
            conflicts_with = "best_effort",
            required_unless_present = "best_effort"
        )]
        required: bool,
        #[arg(
            long,
            conflicts_with = "required",
            required_unless_present = "required"
        )]
        best_effort: bool,
        #[arg(long)]
        placement_policy: Option<String>,
        #[arg(long, value_parser = ["presence", "integrity", "none"])]
        validation_gate: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Trigger a population operation
    Run {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        release: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Remove one population target
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubCacheCoverageCmd {
    /// Show current coverage state
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Run coverage validation
    Validate {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Trigger coverage repair
    Repair {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubCacheGcCmd {
    /// Manage cache-global collection policy
    Policy {
        #[command(subcommand)]
        command: HubCacheGcPolicyCmd,
    },
    /// Create and inspect immutable GC plans
    Plan {
        #[command(subcommand)]
        command: HubCacheGcPlanCmd,
    },
    /// Acknowledge the first destructive sweep gate
    FirstSweep {
        #[command(subcommand)]
        command: HubCacheGcFirstSweepCmd,
    },
    /// Run a reviewed immutable GC plan
    Run {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        plan_id: String,
        #[arg(long)]
        confirm_hash: String,
        /// Reuse this key for every retry of the reviewed apply
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Inspect GC operations
    Runs {
        #[command(subcommand)]
        command: HubCacheGcRunsCmd,
    },
    /// Inspect and manage physical deletion jobs
    Jobs {
        #[command(subcommand)]
        command: HubCacheGcJobsCmd,
    },
}

#[derive(Subcommand)]
pub enum HubCacheGcPolicyCmd {
    /// Show cache-global collection policy
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
    },
    /// Replace cache-global collection policy
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        unreferenced_grace: String,
        #[arg(long, conflicts_with = "clear_soft_max_bytes")]
        soft_max_bytes: Option<u64>,
        #[arg(long, conflicts_with = "soft_max_bytes")]
        clear_soft_max_bytes: bool,
        #[arg(long, conflicts_with = "clear_soft_max_objects")]
        soft_max_objects: Option<u64>,
        #[arg(long, conflicts_with = "soft_max_objects")]
        clear_soft_max_objects: bool,
        #[arg(long)]
        schedule: String,
        #[arg(long)]
        deletion_concurrency: u32,
        #[arg(long)]
        retry_initial: String,
        #[arg(long)]
        retry_max: String,
        #[arg(long)]
        retry_max_attempts: u32,
        #[arg(long)]
        tombstone_retention: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubCacheGcPlanCmd {
    /// Create an immutable GC plan
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
    },
    /// Show one immutable GC plan
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        plan_id: String,
    },
}

#[derive(Subcommand)]
pub enum HubCacheGcFirstSweepCmd {
    /// Plan acknowledgement of the first destructive sweep
    PlanAcknowledgement {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        gc_plan_id: String,
        /// Bind retries of this planning request to one stable key
        #[arg(long)]
        idempotency_key: String,
    },
    /// Apply a reviewed first-sweep acknowledgement
    Acknowledge {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        ack_plan_id: String,
        #[arg(long)]
        confirm_hash: String,
        /// Reuse this key for every retry of the reviewed apply
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum HubCacheGcRunsCmd {
    /// List GC runs
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one GC run
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        operation_id: String,
    },
    /// Watch one GC run until terminal
    Watch {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        operation_id: String,
        #[arg(long)]
        timeout: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum HubCacheGcJobsCmd {
    /// List deletion jobs for a GC run
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        operation_id: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one deletion job
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        job_id: String,
    },
    /// Retry a failed deletion job idempotently
    Retry {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        job_id: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Abandon a terminally blocked deletion job
    Abandon {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        job_id: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubCacheIntegrationCmd {
    /// List registry integrations and independent effects
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one registry integration
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        cache: String,
        #[arg(long)]
        registry: String,
    },
}

#[derive(Subcommand)]
pub enum HubPlacementCmd {
    /// List a surface's physical placements
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Typed surface: registry:<slug> or cache:<slug>
        surface: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one placement by its stable name
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Typed surface: registry:<slug> or cache:<org>/<cache>
        surface: String,
        /// Stable placement name within the surface
        name: String,
    },
    /// List placement presence observations for one object
    Presence {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        object: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Add a provisioning/unknown placement
    Add {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Typed surface: registry:<slug> or cache:<slug>
        surface: Option<String>,
        /// Stable placement name within the surface
        name: Option<String>,
        /// Stable storage-binding name
        #[arg(long = "binding")]
        binding: Option<String>,
        /// Binding-relative object prefix
        #[arg(long)]
        prefix: Option<String>,
        /// Placement kind: complete, shard, or archive
        #[arg(long, value_parser = ["complete", "shard", "archive"], default_value = "complete")]
        kind: Option<String>,
        /// Initial desired lifecycle: active or offline
        #[arg(long, value_parser = ["active", "offline"], default_value = "active")]
        desired_state: String,
        /// Enable or disable desired reads (defaults off for archive, on otherwise)
        #[arg(long, value_parser = ["enabled", "disabled"])]
        read: Option<String>,
        /// Read-selection priority (lower is preferred)
        #[arg(long, default_value_t = 0)]
        read_order: i64,
        /// Half-open 16-bit shard range in <start>-<end> form
        #[arg(long)]
        hash_range: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Replace desired selection fields under an optimistic-concurrency check
    Update {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Typed surface: registry:<slug> or cache:<slug>
        surface: String,
        /// Stable placement name within the surface
        name: String,
        /// Desired lifecycle: active or offline
        #[arg(long, value_parser = ["active", "offline"])]
        desired_state: Option<String>,
        /// Desired read selection
        #[arg(long, value_parser = ["enabled", "disabled"])]
        read: Option<String>,
        /// Read-selection priority (lower is preferred)
        #[arg(long)]
        read_order: Option<i64>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Scan one placement and refresh its observations
    Scan {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        name: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Replicate objects between two placements
    Replicate {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        #[arg(long = "from")]
        source: String,
        #[arg(long = "to")]
        destination: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Repair one placement from another healthy placement
    Repair {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        name: String,
        #[arg(long = "from")]
        source: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
    /// Plan or apply a write-authority promotion
    Promote {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        name: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Manage an in-flight placement promotion
    Promotion {
        #[command(subcommand)]
        command: HubPlacementPromotionCmd,
    },
    /// Plan a safe drain or apply a previously reviewed plan
    #[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
    Drain {
        #[command(flatten)]
        access: HubOptionalAccessArgs,
        /// Typed surface to drain
        surface: Option<String>,
        /// Placement name within the surface
        name: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
        #[command(subcommand)]
        command: Option<HubPlacementDrainCmd>,
    },
    /// Plan metadata deletion or apply a previously reviewed plan
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        /// Typed surface: registry:<slug> or cache:<slug>
        surface: String,
        /// Stable placement name within the surface
        name: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Plan or run physical eviction from one placement
    Eviction {
        #[command(subcommand)]
        command: HubPlacementEvictionCmd,
    },
}

#[derive(Subcommand)]
pub enum HubPlacementDrainCmd {
    /// Cancel a planned or active placement drain
    Cancel {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        name: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubPlacementPromotionCmd {
    /// Cancel a pending placement promotion
    Cancel {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubPlacementPolicyCmd {
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        policy: String,
        #[arg(long)]
        revision: Option<i64>,
    },
    Revisions {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        policy: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        policy: String,
        #[arg(long, value_parser = ["ordered-failover", "local-then-remote", "hash-partition"])]
        kind: Option<String>,
        #[arg(long = "member")]
        members: Vec<String>,
        #[arg(long)]
        local_boundary: Option<String>,
        #[arg(long = "local")]
        local: Vec<String>,
        #[arg(long = "remote")]
        remote: Vec<String>,
        #[arg(long = "range")]
        ranges: Vec<String>,
        #[arg(long = "complete-fallback")]
        complete_fallback: Vec<String>,
        #[arg(long)]
        allow_remote_fallback: bool,
        #[arg(
            long = "retry-on",
            value_parser = [
                "connect-failure",
                "timeout-before-headers",
                "origin-429",
                "origin-502",
                "origin-503",
                "origin-504",
                "presence-mismatch",
                "verified-corruption"
            ]
        )]
        retry_on: Vec<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    Revise {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        policy: String,
        #[arg(long, value_parser = ["ordered-failover", "local-then-remote", "hash-partition"])]
        kind: Option<String>,
        #[arg(long = "member")]
        members: Vec<String>,
        #[arg(long)]
        local_boundary: Option<String>,
        #[arg(long = "local")]
        local: Vec<String>,
        #[arg(long = "remote")]
        remote: Vec<String>,
        #[arg(long = "range")]
        ranges: Vec<String>,
        #[arg(long = "complete-fallback")]
        complete_fallback: Vec<String>,
        #[arg(long)]
        allow_remote_fallback: bool,
        #[arg(
            long = "retry-on",
            value_parser = [
                "connect-failure",
                "timeout-before-headers",
                "origin-429",
                "origin-502",
                "origin-503",
                "origin-504",
                "presence-mismatch",
                "verified-corruption"
            ]
        )]
        retry_on: Vec<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    Test {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        policy: String,
        #[arg(long)]
        revision: i64,
        #[arg(long)]
        object: String,
        #[arg(long, value_parser = ["local", "remote"])]
        access_class: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum HubPlacementEquivalenceCmd {
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    Confirm {
        #[command(flatten)]
        access: HubAccessArgs,
        surface: String,
        placement_a: String,
        placement_b: String,
        #[arg(long)]
        if_a_version: Option<String>,
        #[arg(long)]
        if_b_version: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        equivalence: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubPlacementEvictionCmd {
    /// Create an immutable placement-eviction plan
    Plan {
        #[command(flatten)]
        access: HubAccessArgs,
        surface_ref: String,
        placement: String,
        /// Require this placement resource version
        #[arg(long)]
        if_version: String,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Run a reviewed placement-eviction plan
    Run {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        plan_id: String,
        /// Confirm the reviewed eviction manifest
        #[arg(long)]
        confirm_hash: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        idempotency_key: String,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubRegistryCmd {
    /// List visible registries
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one registry
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
    },
    /// List releases in one registry
    Releases {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Plan creation or apply a reviewed registry plan
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        org: Option<String>,
        #[arg(long, default_value = "")]
        project: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_parser = ["public", "internal", "private"])]
        visibility: Option<String>,
        #[arg(long = "trust-key")]
        trust_keys: Vec<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Plan a registry configuration update or apply a reviewed plan
    Update {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[arg(long, value_parser = ["public", "internal", "private"])]
        visibility: Option<String>,
        #[arg(long, value_parser = ["allow_all", "allow_no_ai", "deny_all"])]
        crawl_policy: Option<String>,
        #[arg(long, conflicts_with = "clear_llms_txt")]
        llms_txt_body: Option<String>,
        #[arg(long, conflicts_with = "llms_txt_body")]
        clear_llms_txt: bool,
        #[arg(long = "trust-key", conflicts_with = "clear_trust_keys")]
        trust_keys: Vec<String>,
        #[arg(long, conflicts_with = "trust_keys")]
        clear_trust_keys: bool,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Plan registry deletion or apply a reviewed plan
    Delete {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Manage the signed consumer cache stack
    CacheStack {
        #[command(subcommand)]
        command: HubRegistryCacheStackCmd,
    },
    /// Configure an upstream registry mirror
    Mirror {
        #[command(subcommand)]
        command: HubRegistryMirrorCmd,
    },
    /// Inspect packages in a registry
    Package {
        #[command(subcommand)]
        command: HubPackageCmd,
    },
    /// Inspect channels in a registry
    Channel {
        #[command(subcommand)]
        command: HubChannelCmd,
    },
    /// Manage registry publication credentials
    Publish {
        #[command(subcommand)]
        command: HubPublishCmd,
    },
    /// Inspect and review registry configuration changes
    Configuration {
        #[command(subcommand)]
        command: HubConfigCmd,
    },
}

#[derive(Subcommand)]
pub enum HubRegistryMirrorCmd {
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
    },
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        refspec: Option<String>,
        #[arg(long)]
        auth_secret_ref: Option<String>,
        #[arg(long)]
        interval: Option<String>,
        #[arg(long, value_parser = ["required", "optional", "disabled"])]
        signature_policy: Option<String>,
        #[arg(long, value_parser = ["full", "pull-through"], default_value = "full")]
        mode: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    Sync {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
        #[command(flatten)]
        operation: HubOperationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubRegistryCacheStackCmd {
    /// Show signed and pending consumer cache entries
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
    },
    /// Add a managed or external consumer cache entry
    Add {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[arg(long, conflicts_with = "url", required_unless_present = "url")]
        cache: Option<String>,
        #[arg(long, conflicts_with = "cache", required_unless_present = "cache")]
        url: Option<String>,
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        mirror_with: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Move one cache entry before another
    Move {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        entry: String,
        #[arg(long)]
        before: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Remove one consumer cache entry
    Remove {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        entry: String,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Validate the current signed stack and route pins
    Validate {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
    },
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use clap::Parser as _;

    use crate::cli::{
        Cli, Commands, HubAccessTokenCmd, HubAccessTokenIssueCmd, HubBindingCmd, HubCacheCmd,
        HubCacheRetentionCmd, HubCmd, HubIdentityProviderCmd, HubIdentityProviderSetCmd,
        HubInvitationCmd, HubInvitationCreateCmd, HubNetworkPolicyCmd, HubOperationCmd, HubOrgCmd,
        HubOrganizationDomainCmd, HubOrganizationDomainVerifyCmd, HubPlacementCmd,
        HubPlacementDrainCmd, HubRegistryCacheStackCmd, HubRegistryCmd, HubRouteCmd,
        HubServiceAccountCmd, HubServiceAccountUpdateCmd, HubSurfaceCmd,
    };

    fn parse_cli<I, T>(args: I) -> Result<Cli, clap::Error>
    where
        I: IntoIterator<Item = T> + Send + 'static,
        I::IntoIter: Send,
        T: Into<OsString> + Clone + Send + 'static,
    {
        std::thread::Builder::new()
            .name("hub-cli-parser".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Cli::try_parse_from(args))
            .expect("CLI parser test thread must start")
            .join()
            .expect("CLI parser test thread must complete")
    }

    #[test]
    fn placement_list_parses_typed_surface() {
        let cli = parse_cli([
            "aos",
            "hub",
            "placement",
            "list",
            "--hub",
            "https://aos.example",
            "registry:andyl/main",
        ])
        .unwrap();
        match cli.command {
            Commands::Hub {
                command:
                    HubCmd::Placement {
                        command:
                            HubPlacementCmd::List {
                                access, surface, ..
                            },
                    },
            } => {
                assert_eq!(access.hub.as_deref(), Some("https://aos.example"));
                assert!(access.token.is_none());
                assert_eq!(surface, "registry:andyl/main");
            }
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn placement_show_accepts_global_json_flag() {
        let cli = parse_cli([
            "aos",
            "--json",
            "hub",
            "placement",
            "show",
            "--hub",
            "https://aos.example",
            "cache:andyl/nix",
            "primary",
        ])
        .unwrap();
        assert!(cli.json);
        match cli.command {
            Commands::Hub {
                command:
                    HubCmd::Placement {
                        command: HubPlacementCmd::Show { surface, name, .. },
                    },
            } => {
                assert_eq!(surface, "cache:andyl/nix");
                assert_eq!(name, "primary");
            }
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn placement_add_accepts_normalized_desired_spec() {
        let cli = parse_cli([
            "aos",
            "hub",
            "placement",
            "add",
            "--hub",
            "https://aos.example",
            "registry:andyl/main",
            "replica-west",
            "--binding",
            "west",
            "--prefix",
            "registries/main",
            "--kind",
            "complete",
            "--read",
            "enabled",
            "--read-order",
            "20",
        ])
        .unwrap();
        match cli.command {
            Commands::Hub {
                command:
                    HubCmd::Placement {
                        command:
                            HubPlacementCmd::Add {
                                surface,
                                name,
                                kind,
                                read,
                                ..
                            },
                    },
            } => {
                assert_eq!(surface.as_deref(), Some("registry:andyl/main"));
                assert_eq!(name.as_deref(), Some("replica-west"));
                assert_eq!(kind.as_deref(), Some("complete"));
                assert_eq!(read.as_deref(), Some("enabled"));
            }
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn placement_remove_is_plan_only_without_plan_id() {
        let cli = parse_cli([
            "aos",
            "hub",
            "placement",
            "remove",
            "--hub",
            "https://aos.example",
            "cache:andyl/nix",
            "cold",
            "--if-version",
            "7",
        ])
        .unwrap();
        match cli.command {
            Commands::Hub {
                command:
                    HubCmd::Placement {
                        command: HubPlacementCmd::Remove { mutation, .. },
                    },
            } => assert!(mutation.plan_id.is_none()),
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn surface_explain_requires_a_supported_access_class() {
        let cli = parse_cli([
            "aos",
            "hub",
            "surface",
            "explain",
            "cache:andyl/nix",
            "--url",
            "https://cache.example/nar/object.nar.zst",
            "--access-class",
            "nix_cache",
        ])
        .unwrap();
        match cli.command {
            Commands::Hub {
                command:
                    HubCmd::Surface {
                        command: HubSurfaceCmd::Explain { access_class, .. },
                    },
            } => assert_eq!(access_class, "nix_cache"),
            _ => panic!("unexpected command shape"),
        }

        assert!(parse_cli([
            "aos",
            "hub",
            "surface",
            "explain",
            "cache:andyl/nix",
            "--url",
            "https://cache.example",
            "--access-class",
            "smtp",
        ])
        .is_err());
    }

    #[test]
    fn non_interactive_confirmation_requires_a_reviewed_plan() {
        let error = parse_cli([
            "aos",
            "hub",
            "placement",
            "remove",
            "--hub",
            "https://aos.example",
            "cache:andyl/nix",
            "cold",
            "--yes",
        ])
        .err()
        .expect("--yes without --plan-id must be rejected");
        assert!(error.to_string().contains("--plan-id"));
    }

    #[test]
    fn retention_apply_does_not_require_selector_inputs() {
        parse_cli([
            "aos",
            "hub",
            "cache",
            "retention",
            "set",
            "--hub",
            "https://aos.example",
            "andyl/nix",
            "--plan-id",
            "plan-1",
            "--confirm-hash",
            "sha256:abc",
            "--yes",
        ])
        .unwrap();
    }

    #[test]
    fn specialized_apply_does_not_require_desired_fields() {
        for arguments in [
            vec!["org", "update", "andyl"],
            vec!["registry", "mirror", "set", "andyl/main"],
        ] {
            let mut command = vec!["aos", "hub"];
            command.extend(arguments);
            command.extend([
                "--hub",
                "https://aos.example",
                "--plan-id",
                "plan-1",
                "--confirm-hash",
                "sha256:abc",
                "--yes",
            ]);
            parse_cli(command).unwrap();
        }
    }

    #[test]
    fn placement_drain_cancel_uses_the_nested_ledger_spelling() {
        let cli = parse_cli([
            "aos",
            "hub",
            "placement",
            "drain",
            "cancel",
            "--hub",
            "https://aos.example",
            "cache:andyl/nix",
            "cold",
            "--if-version",
            "7",
        ])
        .unwrap();
        match cli.command {
            Commands::Hub {
                command:
                    HubCmd::Placement {
                        command:
                            HubPlacementCmd::Drain {
                                command: Some(HubPlacementDrainCmd::Cancel { surface, name, .. }),
                                ..
                            },
                    },
            } => {
                assert_eq!(surface, "cache:andyl/nix");
                assert_eq!(name, "cold");
            }
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn binding_replaces_the_legacy_storage_binding_command() {
        let cli = parse_cli([
            "aos",
            "hub",
            "binding",
            "list",
            "--hub",
            "https://aos.example",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Hub {
                command: HubCmd::Binding {
                    command: HubBindingCmd::List { .. }
                }
            }
        ));
        assert!(parse_cli([
            "aos",
            "hub",
            "storage-binding",
            "list",
            "--hub",
            "https://aos.example",
            "--org",
            "andyl",
        ])
        .is_err());
    }

    #[test]
    fn binding_accepts_worker_native_r2_bindings() {
        let cli = parse_cli([
            "aos",
            "hub",
            "binding",
            "create",
            "--hub",
            "https://aos.example",
            "--name",
            "worker-objects",
            "--stable-id",
            "storage-binding:worker-objects",
            "--kind",
            "deployment-r2",
            "--bucket-binding",
            "REGISTRY_BUCKET",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Hub {
                command: HubCmd::Binding {
                    command: HubBindingCmd::Create {
                        stable_id: Some(ref stable_id),
                        bucket_binding: Some(ref binding),
                        org: None,
                        ..
                    }
                }
            } if stable_id == "storage-binding:worker-objects" && binding == "REGISTRY_BUCKET"
        ));
    }

    #[test]
    fn binding_list_accepts_instance_scope_without_an_organization() {
        let list = parse_cli([
            "aos",
            "hub",
            "binding",
            "list",
            "--hub",
            "https://aos.example",
        ])
        .unwrap();
        assert!(matches!(
            list.command,
            Commands::Hub {
                command: HubCmd::Binding {
                    command: HubBindingCmd::List { org: None, .. }
                }
            }
        ));

        let create = parse_cli([
            "aos",
            "hub",
            "binding",
            "create",
            "--hub",
            "https://aos.example",
            "--name",
            "native-storage",
            "--kind",
            "local-fs",
            "--root",
            "/var/lib/aos-hub/storage",
        ])
        .unwrap();
        assert!(matches!(
            create.command,
            Commands::Hub {
                command: HubCmd::Binding {
                    command: HubBindingCmd::Create { org: None, .. }
                }
            }
        ));
    }

    #[test]
    fn direct_route_accepts_exact_gateway_generation() {
        let cli = parse_cli([
            "aos",
            "hub",
            "route",
            "add",
            "--hub",
            "https://aos.example",
            "cache:andyl/main",
            "--endpoint",
            "cache.example@3",
            "--mode",
            "direct",
            "--placement",
            "primary",
            "--gateway",
            "r2-public@7",
            "--serves",
            "cache",
            "--plan",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Hub {
                command: HubCmd::Route {
                    command: HubRouteCmd::Add { .. }
                }
            }
        ));
    }

    #[test]
    fn route_advertisement_requires_a_typed_surface() {
        let cli = parse_cli([
            "aos",
            "hub",
            "route",
            "canonical",
            "registry:andyl/main",
            "route:public",
            "--audience",
            "nix_cache",
            "--plan",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Hub {
                command: HubCmd::Route {
                    command: HubRouteCmd::Canonical {
                        ref surface_ref,
                        ref route,
                        ref audience,
                        ..
                    }
                }
            } if surface_ref == "registry:andyl/main"
                && route == "route:public"
                && audience == "nix_cache"
        ));
    }

    #[test]
    fn boundary_activation_requires_an_explicit_default_choice() {
        assert!(parse_cli([
            "aos",
            "hub",
            "network-policy",
            "revision",
            "activate",
            "--hub",
            "https://aos.example",
            "corp@2",
            "--mode",
            "overlap",
        ])
        .is_err());
        let parsed = parse_cli([
            "aos",
            "hub",
            "network-policy",
            "revision",
            "activate",
            "--hub",
            "https://aos.example",
            "corp@2",
            "--mode",
            "overlap",
            "--default-for-new-plans",
            "yes",
            "--plan",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Hub {
                command: HubCmd::NetworkPolicy {
                    command: HubNetworkPolicyCmd::Revision { .. }
                }
            }
        ));
    }

    #[test]
    fn cache_retention_is_independent_from_consumer_publication() {
        let parsed = parse_cli([
            "aos",
            "hub",
            "cache",
            "retention",
            "set",
            "nix",
            "--hub",
            "https://aos.example",
            "--registry",
            "andyl/main",
            "--recent-releases",
            "5",
            "--plan",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Hub {
                command: HubCmd::Cache {
                    command: HubCacheCmd::Retention {
                        command: HubCacheRetentionCmd::Set { .. }
                    }
                }
            }
        ));
    }

    #[test]
    fn binary_cache_definition_has_plan_apply_crud() {
        let parsed = parse_cli([
            "aos",
            "hub",
            "cache",
            "create",
            "andyl/nix",
            "--hub",
            "https://aos.example",
            "--name",
            "Nix cache",
            "--visibility",
            "private",
            "--plan",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Hub {
                command: HubCmd::Cache {
                    command: HubCacheCmd::Create { .. }
                }
            }
        ));
    }

    #[test]
    fn registry_cache_stack_accepts_one_typed_source() {
        let parsed = parse_cli([
            "aos",
            "hub",
            "registry",
            "cache-stack",
            "add",
            "andyl/main",
            "--hub",
            "https://aos.example",
            "--cache",
            "nix",
            "--before",
            "cache-entry-2",
            "--plan",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Hub {
                command: HubCmd::Registry {
                    command: HubRegistryCmd::CacheStack {
                        command: HubRegistryCacheStackCmd::Add { .. }
                    }
                }
            }
        ));
        assert!(parse_cli([
            "aos",
            "hub",
            "registry",
            "cache-stack",
            "add",
            "andyl/main",
            "--hub",
            "https://aos.example",
            "--cache",
            "nix",
            "--url",
            "https://cache.example",
        ])
        .is_err());
    }

    #[test]
    fn legacy_cache_commands_are_removed_at_the_parser_boundary() {
        for removed in [
            "link",
            "unlink",
            "change-storage",
            "gc-policy",
            "pin",
            "unpin",
        ] {
            assert!(
                parse_cli([
                    "aos",
                    "hub",
                    "cache",
                    removed,
                    "nix",
                    "--hub",
                    "https://aos.example",
                ])
                .is_err(),
                "legacy cache command unexpectedly parsed: {removed}"
            );
        }
    }

    #[test]
    fn access_tokens_are_scope_owned_and_registry_token_nesting_is_removed() {
        let parsed = parse_cli([
            "aos",
            "hub",
            "access-token",
            "issue",
            "plan",
            "registry:0123456789abcdef0123456789abcdef",
            "--hub",
            "https://aos.example",
            "--owner",
            "service_account:andyl/publisher",
            "--permission",
            "publish",
            "--comment",
            "release publisher",
            "--idempotency-key",
            "plan-release-publisher",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Hub {
                command: HubCmd::AccessToken {
                    command: HubAccessTokenCmd::Issue {
                        command: HubAccessTokenIssueCmd::Plan { .. }
                    }
                }
            }
        ));
        assert!(parse_cli(["aos", "hub", "registry", "token"]).is_err());
    }

    #[test]
    fn service_accounts_expose_inventory_and_reviewed_lifecycle_commands() {
        let parsed = parse_cli([
            "aos",
            "hub",
            "org",
            "service-account",
            "update",
            "plan",
            "andyl",
            "publisher",
            "--new-name",
            "release-publisher",
            "--if-version",
            "sha256:0123456789abcdef",
            "--hub",
            "https://aos.example",
            "--idempotency-key",
            "rename-release-publisher",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Hub {
                command: HubCmd::Org {
                    command: HubOrgCmd::ServiceAccount {
                        command: HubServiceAccountCmd::Update {
                            command: HubServiceAccountUpdateCmd::Plan { .. }
                        }
                    },
                    ..
                }
            }
        ));

        for command in ["list", "show", "create", "update", "delete"] {
            assert!(
                parse_cli(["aos", "hub", "service-account", command]).is_err(),
                "top-level service-account command unexpectedly parsed: {command}"
            );
        }
    }

    #[test]
    fn invitations_are_organization_scoped_and_reviewed() {
        let parsed = parse_cli([
            "aos",
            "hub",
            "org",
            "invitation",
            "create",
            "plan",
            "andyl",
            "new.member@example.test",
            "--scope",
            "org:0123456789abcdef0123456789abcdef",
            "--role",
            "developer",
            "--hub",
            "https://aos.example",
            "--idempotency-key",
            "invite-new-member",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Hub {
                command: HubCmd::Org {
                    command: HubOrgCmd::Invitation {
                        command: HubInvitationCmd::Create {
                            command: HubInvitationCreateCmd::Plan { .. }
                        }
                    },
                    ..
                }
            }
        ));
        assert!(parse_cli(["aos", "hub", "invitation", "list"]).is_err());
    }

    #[test]
    fn organization_sso_has_separate_provider_and_domain_resources() {
        let provider = parse_cli([
            "aos",
            "hub",
            "org",
            "identity-provider",
            "set",
            "plan",
            "andyl",
            "--issuer",
            "https://idp.example.test",
            "--authorization-endpoint",
            "https://idp.example.test/authorize",
            "--token-endpoint",
            "https://idp.example.test/token",
            "--jwks-uri",
            "https://idp.example.test/jwks",
            "--client-id",
            "hub",
            "--if-version",
            "absent",
            "--idempotency-key",
            "plan-idp",
        ])
        .unwrap();
        assert!(matches!(
            provider.command,
            Commands::Hub {
                command: HubCmd::Org {
                    command: HubOrgCmd::IdentityProvider {
                        command: HubIdentityProviderCmd::Set {
                            command: HubIdentityProviderSetCmd::Plan { .. }
                        }
                    },
                    ..
                }
            }
        ));

        let domain = parse_cli([
            "aos",
            "hub",
            "org",
            "domain",
            "verify",
            "plan",
            "andyl",
            "login.example.test",
            "--if-version",
            "1",
            "--idempotency-key",
            "plan-domain-verify",
        ])
        .unwrap();
        assert!(matches!(
            domain.command,
            Commands::Hub {
                command: HubCmd::Org {
                    command: HubOrgCmd::Domain {
                        command: HubOrganizationDomainCmd::Verify {
                            command: HubOrganizationDomainVerifyCmd::Plan { .. }
                        }
                    },
                    ..
                }
            }
        ));
        assert!(parse_cli(["aos", "hub", "org", "sso"]).is_err());
    }

    #[test]
    fn operation_inventory_requires_one_explicit_selector() {
        let target = parse_cli([
            "aos",
            "hub",
            "operation",
            "list",
            "--target",
            "registry:andyl/main",
        ])
        .unwrap();
        assert!(matches!(
            target.command,
            Commands::Hub {
                command: HubCmd::Operation {
                    command: HubOperationCmd::List {
                        target: Some(_),
                        scope: None,
                        ..
                    }
                }
            }
        ));

        let scope = parse_cli([
            "aos",
            "hub",
            "operation",
            "list",
            "--scope",
            "org:0123456789abcdef0123456789abcdef",
        ])
        .unwrap();
        assert!(matches!(
            scope.command,
            Commands::Hub {
                command: HubCmd::Operation {
                    command: HubOperationCmd::List {
                        target: None,
                        scope: Some(_),
                        ..
                    }
                }
            }
        ));

        assert!(parse_cli(["aos", "hub", "operation", "list", "registry:andyl/main"]).is_err());
        assert!(parse_cli([
            "aos",
            "hub",
            "operation",
            "list",
            "--target",
            "registry:andyl/main",
            "--scope",
            "instance",
        ])
        .is_err());
    }

    #[test]
    fn owner_scoped_families_have_no_top_level_aliases() {
        for removed in [
            "project", "audit", "webhook", "identity", "package", "channel", "publish", "config",
        ] {
            let error = parse_cli(["aos", "hub", removed])
                .err()
                .expect("removed top-level family must be rejected");
            assert!(
                error.to_string().contains("unrecognized subcommand"),
                "removed top-level family unexpectedly parsed: {removed}"
            );
        }

        parse_cli([
            "aos",
            "hub",
            "org",
            "project",
            "list",
            "--hub",
            "https://aos.example",
            "andyl",
        ])
        .unwrap();
        parse_cli([
            "aos",
            "hub",
            "registry",
            "package",
            "list",
            "--hub",
            "https://aos.example",
            "andyl/main",
        ])
        .unwrap();
    }
}
