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
        /// Override the registry HTTP(S) origin
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Use this Hub access token
        #[arg(long, env = "AOS_TOKEN")]
        token: Option<String>,
    },
    /// Build a definition and push it with immutable-before-tag ordering
    Publish {
        /// Container definition name
        name: String,
        /// AUTHORITY/REPOSITORY[:TAG|@DIGEST]
        reference: String,
        /// Select OS/architecture, such as linux/amd64
        #[arg(long)]
        platform: Option<String>,
        /// Override the registry HTTP(S) origin
        #[arg(long, env = "AOS_HUB")]
        hub: Option<String>,
        /// Use this Hub access token
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
    fn system_image_semantics_remain_separate() {
        let cli = Cli::try_parse_from(["aos", "image", "list", "--registry", "core"])
            .expect("system image command");
        assert!(matches!(cli.command, Commands::Image { .. }));
    }
}
