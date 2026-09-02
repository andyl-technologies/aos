//! Clap surface for `aos container`.
//!
//! The command family deliberately remains distinct from `aos image`, whose
//! established contract is signed AOS disk/system images. Definition commands
//! use Nix; path and registry operations are daemon-free.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ContainerFormat {
    /// Produce a directory in OCI image-layout format.
    #[default]
    OciLayout,
    /// Produce an uncompressed OCI image-layout tar archive.
    OciArchive,
    /// Produce a Docker-load-compatible tar archive.
    DockerArchive,
}

impl From<ContainerFormat> for aos_oci::ArtifactFormat {
    fn from(value: ContainerFormat) -> Self {
        match value {
            ContainerFormat::OciLayout => Self::OciLayout,
            ContainerFormat::OciArchive => Self::OciArchive,
            ContainerFormat::DockerArchive => Self::DockerArchive,
        }
    }
}

#[derive(Subcommand)]
pub enum ContainerCommand {
    /// List Nix-defined container images
    List,
    /// Show one evaluated container definition
    Show {
        /// Container definition name
        name: String,
    },
    /// Build one Nix-defined container image
    Build {
        /// Container definition name
        name: String,
        /// Select OS/architecture, such as linux/amd64
        #[arg(long)]
        platform: Option<String>,
        /// Select the local artifact representation
        #[arg(long, value_enum, default_value_t)]
        format: ContainerFormat,
        /// Write the result at this path
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        /// Remote AOS build server URL
        #[arg(long, env = "AOS_REMOTE")]
        remote: Option<String>,
        /// Remote build view
        #[arg(long, env = "AOS_VIEW", default_value = "default")]
        view: String,
        /// Remote build provisioning token
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
    },
    /// Verify and inspect a definition, local artifact, or registry reference
    Inspect {
        /// Definition name, local path, or AUTHORITY/REPOSITORY reference
        target: String,
        /// Select OS/architecture, such as linux/amd64
        #[arg(long)]
        platform: Option<String>,
        /// Emit the selected layout's exact index JSON
        #[arg(long)]
        raw: bool,
        /// Override the registry HTTP(S) origin
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Use this Hub access token
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
    },
    /// Pull a registry reference without a container daemon
    Pull {
        /// AUTHORITY/REPOSITORY[:TAG|@DIGEST]
        reference: String,
        /// Select OS/architecture, such as linux/amd64
        #[arg(long)]
        platform: Option<String>,
        /// Select the local artifact representation
        #[arg(long, value_enum, default_value_t)]
        format: ContainerFormat,
        /// Write the result at this path
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        /// Replace an existing destination
        #[arg(long)]
        force: bool,
        /// Override the registry HTTP(S) origin
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Use this Hub access token
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
    },
    /// Push a verified definition or local OCI artifact
    Push {
        /// Container definition name or local OCI path
        source: String,
        /// AUTHORITY/REPOSITORY[:TAG|@DIGEST]
        reference: String,
        /// Select OS/architecture, such as linux/amd64
        #[arg(long)]
        platform: Option<String>,
        /// Try mounting blobs from this same-registry repository
        #[arg(long = "mount-from")]
        mount_from: Vec<String>,
        /// Override the registry HTTP(S) origin
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Use this Hub access token
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
    },
    /// Emit the exact DSSE PAE bytes for an external signer
    PrepareSignature {
        /// Nix-generated publicationInputs directory
        inputs: PathBuf,
        /// Create the exact binary PAE payload at this path
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
    /// Verify an external SSHSIG and assemble the signed publication bundle
    FinalizeSignature {
        /// Original Nix-generated publicationInputs directory
        inputs: PathBuf,
        /// Exact AOS trust identity: name:Ed25519:base64-key-blob
        #[arg(long)]
        signer: String,
        /// Armored SSHSIG over the exact prepared PAE bytes
        #[arg(long)]
        signature: PathBuf,
        /// Atomically create the final bundle directory at this path
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
    /// Finalize a complete graph from an indexed signed AOS release
    Publish {
        /// Container definition name
        name: String,
        /// AUTHORITY/REPOSITORY[:TAG|@DIGEST]
        reference: String,
        /// Canonical sidecar already committed in the signed AOS release
        #[arg(long)]
        release: PathBuf,
        /// Final OCI layout or archive containing every sidecar-declared object
        #[arg(long)]
        release_layout: PathBuf,
        /// Nix-generated unsigned signature-input.json
        #[arg(long)]
        signature_input: PathBuf,
        /// Hub registry slug that owns the destination repository
        #[arg(long)]
        registry: String,
        /// Try mounting blobs from this same-registry repository
        #[arg(long = "mount-from")]
        mount_from: Vec<String>,
        /// Expected mutable-tag resource version for compare-and-swap
        #[arg(long)]
        expected_tag_resource_version: Option<String>,
        /// Expected current mutable-tag digest for compare-and-swap
        #[arg(long)]
        expected_tag_digest: Option<String>,
        /// Stable retry identity shared by begin, commit, and recovery
        #[arg(long)]
        idempotency_key: String,
        /// Upload and verify the immutable graph without calling Hub control
        #[arg(long)]
        stage_only: bool,
        /// Override the OCI Distribution origin
        #[arg(long, env = "AOS_REGISTRY_ORIGIN")]
        registry_origin: Option<String>,
        /// Seed credential sent only to the OCI Distribution origin
        #[arg(long, env = "AOS_REGISTRY_TOKEN")]
        registry_token: Option<String>,
        /// Hub Connect control-plane origin
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Hub control-plane access token
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Commands};

    #[test]
    fn parses_build_platform_format_and_remote_options() {
        let cli = Cli::try_parse_from([
            "aos",
            "container",
            "build",
            "aos",
            "--platform",
            "linux/amd64",
            "--format",
            "docker-archive",
            "--remote",
            "https://build.example",
        ])
        .expect("container build command");
        let Commands::Container {
            command:
                ContainerCommand::Build {
                    name,
                    platform,
                    format,
                    remote,
                    ..
                },
        } = cli.command
        else {
            panic!("expected container build command");
        };
        assert_eq!(name, "aos");
        assert_eq!(platform.as_deref(), Some("linux/amd64"));
        assert_eq!(format, ContainerFormat::DockerArchive);
        assert_eq!(remote.as_deref(), Some("https://build.example"));
    }

    #[test]
    fn parses_daemonless_transfer_auth_and_output_options() {
        let cli = Cli::try_parse_from([
            "aos",
            "container",
            "pull",
            "registry.example/aos:latest",
            "--hub",
            "https://registry.example",
            "--token",
            "redacted",
            "--format",
            "oci-archive",
            "-o",
            "aos.tar",
        ])
        .expect("container pull command");
        let Commands::Container {
            command:
                ContainerCommand::Pull {
                    reference,
                    hub,
                    token,
                    format,
                    output,
                    ..
                },
        } = cli.command
        else {
            panic!("expected container pull command");
        };
        assert_eq!(reference, "registry.example/aos:latest");
        assert_eq!(hub.as_deref(), Some("https://registry.example"));
        assert_eq!(token.as_deref(), Some("redacted"));
        assert_eq!(format, ContainerFormat::OciArchive);
        assert_eq!(output.as_deref(), Some(std::path::Path::new("aos.tar")));
    }

    #[test]
    fn parses_same_registry_mount_sources_for_push() {
        let cli = Cli::try_parse_from([
            "aos",
            "container",
            "push",
            "image.oci.tar",
            "registry.example/team/aos:edge",
            "--mount-from",
            "team/base",
            "--mount-from",
            "team/runtime",
        ])
        .expect("container push command");
        let Commands::Container {
            command: ContainerCommand::Push { mount_from, .. },
        } = cli.command
        else {
            panic!("expected container push command");
        };
        assert_eq!(mount_from, ["team/base", "team/runtime"]);
    }

    #[test]
    fn verified_publish_requires_signed_and_concurrency_inputs() {
        let cli = Cli::try_parse_from([
            "aos",
            "container",
            "publish",
            "aos",
            "registry.example/aos:stable",
            "--release",
            "containers-v1-index.json",
            "--release-layout",
            "aos.signed.oci.tar",
            "--signature-input",
            "signature-input.json",
            "--registry",
            "core",
            "--idempotency-key",
            "release-42",
            "--stage-only",
            "--expected-tag-resource-version",
            "7",
            "--expected-tag-digest",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--registry-origin",
            "https://oci.example",
            "--registry-token",
            "registry-secret",
            "--hub",
            "https://hub.example",
            "--token",
            "hub-secret",
        ])
        .expect("verified publish command");
        let Commands::Container {
            command:
                ContainerCommand::Publish {
                    release,
                    release_layout,
                    signature_input,
                    registry,
                    idempotency_key,
                    stage_only,
                    expected_tag_resource_version,
                    expected_tag_digest,
                    registry_origin,
                    registry_token,
                    hub,
                    token,
                    ..
                },
        } = cli.command
        else {
            panic!("expected container publish command");
        };
        assert_eq!(release, PathBuf::from("containers-v1-index.json"));
        assert_eq!(release_layout, PathBuf::from("aos.signed.oci.tar"));
        assert_eq!(signature_input, PathBuf::from("signature-input.json"));
        assert_eq!(registry, "core");
        assert_eq!(idempotency_key, "release-42");
        assert!(stage_only);
        assert_eq!(expected_tag_resource_version.as_deref(), Some("7"));
        assert!(expected_tag_digest.is_some());
        assert_eq!(registry_origin.as_deref(), Some("https://oci.example"));
        assert_eq!(registry_token.as_deref(), Some("registry-secret"));
        assert_eq!(hub.as_deref(), Some("https://hub.example"));
        assert_eq!(token.as_deref(), Some("hub-secret"));
    }

    #[test]
    fn parses_private_key_free_external_signing_leaves() {
        let prepare = Cli::try_parse_from([
            "aos",
            "container",
            "prepare-signature",
            "/nix/store/publication-inputs",
            "--output",
            "/var/tmp/container.pae",
        ])
        .expect("container prepare-signature command");
        assert!(matches!(
            prepare.command,
            Commands::Container {
                command: ContainerCommand::PrepareSignature { .. }
            }
        ));

        let finalize = Cli::try_parse_from([
            "aos",
            "container",
            "finalize-signature",
            "/nix/store/publication-inputs",
            "--signer",
            "release:Ed25519:AAAA",
            "--signature",
            "/var/tmp/container.pae.sig",
            "--output",
            "/var/tmp/final-container",
        ])
        .expect("container finalize-signature command");
        let Commands::Container {
            command:
                ContainerCommand::FinalizeSignature {
                    inputs,
                    signer,
                    signature,
                    output,
                },
        } = finalize.command
        else {
            panic!("expected container finalize-signature command");
        };
        assert_eq!(inputs, PathBuf::from("/nix/store/publication-inputs"));
        assert_eq!(signer, "release:Ed25519:AAAA");
        assert_eq!(signature, PathBuf::from("/var/tmp/container.pae.sig"));
        assert_eq!(output, PathBuf::from("/var/tmp/final-container"));
    }

    #[test]
    fn system_image_semantics_remain_separate() {
        let cli = Cli::try_parse_from(["aos", "image", "list", "--registry", "core"])
            .expect("system image command");
        assert!(matches!(cli.command, Commands::Image { .. }));
    }
}
