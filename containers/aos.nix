##! containers/aos.nix — Initial AOS base-container definition
##!
##! The baked roots are inherited from the production server golden image.
##! This is analogous to a distribution base image: it contains the standard
##! userland and AOS CLI closure. Phase 2 enables daemonless APM mutation only
##! after the embedded Nix database and baked GC roots are qualified.
{
  lib,
  pkgs,
  goldenRoots,
  aosSystem,
}: let
  architecture =
    if aosSystem == "x86_64-linux"
    then "amd64"
    else if aosSystem == "aarch64-linux"
    then "arm64"
    else throw "containers.aos: unsupported AOS target '${aosSystem}'";

  coreRoots = [pkgs.glibc pkgs.gcc-libs pkgs.ca-certificates];
  shellRoots = [pkgs.bash pkgs.coreutils pkgs.findutils pkgs.grep pkgs.sed pkgs.gawk];
  cliRoots = [pkgs.aos];
in {
  config = {
    name = "aos";
    packageRoots = goldenRoots;
    layers = [
      {
        name = "runtime-core";
        roots = coreRoots;
      }
      {
        name = "shell-core";
        roots = shellRoots;
        subtractRoots = coreRoots;
      }
      {
        name = "aos-cli";
        roots = cliRoots;
        subtractRoots = coreRoots ++ shellRoots;
      }
      {
        name = "golden-userland";
        roots = goldenRoots;
        subtractRoots = coreRoots ++ shellRoots ++ cliRoots;
      }
    ];

    filesystem = {
      directories = [
        {path = "/root";}
        {
          path = "/tmp";
          mode = "1777";
        }
        {path = "/var/lib/apm";}
        {path = "/var/cache/apm";}
        {path = "/root/.config/apm";}
        {path = "/root/.cache/apm";}
        {path = "/root/.local/state/apm";}
      ];
      facade = [
        {
          name = "aos";
          target = "${pkgs.aos}/bin/aos";
        }
        {
          name = "apm";
          target = "${pkgs.aos}/bin/apm";
        }
        {
          name = "apr";
          target = "${pkgs.aos}/bin/apr";
        }
      ];
      shell = true;
    };

    runtime = {
      entrypoint = ["/usr/bin/aos-container-init"];
      command = ["/usr/bin/aos" "--help"];
      environment = {
        AOS_RUNTIME = "container";
        HOME = "/root";
        USER = "root";
        XDG_CACHE_HOME = "/root/.cache";
        XDG_CONFIG_HOME = "/root/.config";
        XDG_STATE_HOME = "/root/.local/state";
        NIX_REMOTE = "";
        SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
        NIX_SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
        PATH = "/root/.nix-profile/bin:/usr/bin:/usr/sbin:/bin";
      };
      user = "0:0";
      workingDirectory = "/root";
      stopSignal = "SIGTERM";
    };

    platform = {
      os = "linux";
      inherit architecture aosSystem;
    };

    packageManagement.enable = false;
    budgets = {
      maxClosureMiB = 768;
      maxDevelopmentPayloadMiB = 48;
      maxLayers = 8;
    };
    annotations = {
      "org.opencontainers.image.title" = "AOS";
      "org.opencontainers.image.description" = "AOS base userland built entirely from AOS packages";
      "org.opencontainers.image.vendor" = "Andyl, Inc.";
      "org.opencontainers.image.source" = "https://github.com/andyl-technologies/aos";
      "dev.andyl.aos.container.definition" = "aos";
      "dev.andyl.aos.system" = aosSystem;
    };
    publication = {
      repository = "aos";
      releaseIdentity = "containers/aos";
    };
  };
}
