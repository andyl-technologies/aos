##! containers/aos.nix — Initial AOS base-container definition
##!
##! The baked roots are inherited from the production server golden image.
##! This is analogous to a distribution base image: it contains the standard
##! userland and full AOS CLI wrapper closure. The container runtime initializes
##! a daemonless local Nix database and retains every baked golden root.
{
  lib,
  pkgs,
  goldenRoots,
  evidenceOverrides ? [],
  aosSystem,
}: let
  hostSystem = pkgs.stdenv.hostPlatform.system;
  validatedSystem =
    if aosSystem == hostSystem
    then hostSystem
    else throw "containers.aos: requested target '${aosSystem}' does not match package-set target '${hostSystem}'";
  architecture =
    if validatedSystem == "x86_64-linux"
    then "amd64"
    else if validatedSystem == "aarch64-linux"
    then "arm64"
    else throw "containers.aos: unsupported AOS package-set target '${validatedSystem}'";

  coreRoots = [pkgs.glibc pkgs.gcc-libs pkgs.ca-certificates];
  shellRoots = [pkgs.bash pkgs.coreutils pkgs.findutils pkgs.grep pkgs.sed pkgs.gawk];
  # The CLI is intentionally split into independently portable outputs.  Keep
  # all three commands in the image closure and expose their canonical names
  # explicitly; the server golden profile is not the authority for the base
  # image's documented command surface.
  cliRoots = [pkgs.aos pkgs.aos.apm pkgs.aos.apr];
  packageRoots = lib.unique (goldenRoots ++ cliRoots);
in {
  config = {
    name = "aos";
    # Every facade target must also be a baked GC root.  The split apm/apr
    # outputs are not necessarily members of the server golden profile, and a
    # daemonless container must retain them across an explicit APM/Nix GC.
    inherit packageRoots;
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
      facade = [
        {
          name = "aos";
          target = "${pkgs.aos}/bin/aos";
        }
        {
          name = "apm";
          target = "${pkgs.aos.apm}/bin/apm";
        }
        {
          name = "apr";
          target = "${pkgs.aos.apr}/bin/apr";
        }
      ];
      directories = [
        {
          path = "/root";
          mode = "0700";
        }
        {
          path = "/root/.cache";
          mode = "0700";
        }
        {
          path = "/root/.cache/apm";
          mode = "0700";
        }
        {
          path = "/root/.config";
          mode = "0700";
        }
        {
          path = "/root/.config/apm";
          mode = "0700";
        }
        {
          path = "/root/.local";
          mode = "0700";
        }
        {
          path = "/root/.local/share";
          mode = "0700";
        }
        {
          path = "/root/.local/share/apm";
          mode = "0700";
        }
        {
          path = "/root/.local/share/apm/registries";
          mode = "0700";
        }
        {
          path = "/root/.local/share/apm/remote";
          mode = "0700";
        }
        {
          path = "/root/.local/state";
          mode = "0700";
        }
        {
          path = "/root/.local/state/apm";
          mode = "0700";
        }
        {
          path = "/tmp";
          mode = "1777";
        }
        {path = "/work";}
        {
          path = "/var/cache/apm";
          mode = "0700";
        }
        {
          path = "/var/lib/apm";
          mode = "0700";
        }
      ];
      # The server package order has one reviewed collision: coreutils `kill`
      # wins over util-linux, matching the production system PATH.
      allowedFacadeCollisions = ["kill"];
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
        XDG_DATA_HOME = "/root/.local/share";
        XDG_STATE_HOME = "/root/.local/state";
        NIX_REMOTE = "local";
        SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
        NIX_SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
        PATH = "/var/lib/profiles/per-user/root/current/bin:/var/lib/profiles/per-user/root/current/sbin:/usr/bin:/usr/sbin:/bin";
      };
      user = "0:0";
      workingDirectory = "/work";
      stopSignal = "SIGTERM";
    };

    platform = {
      os = "linux";
      inherit architecture;
      aosSystem = validatedSystem;
    };

    packageManagement = {
      enable = true;
      bakedGcRoots = true;
    };
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
      "dev.andyl.aos.system" = validatedSystem;
    };
    publication = {
      repository = "aos";
      # The strict Hub sidecar binds the exact signed APR package release.
      # Repository/image identity is carried separately as `aos`.
      releaseIdentity = pkgs.aos.version;
      inherit evidenceOverrides;
    };
  };
}
