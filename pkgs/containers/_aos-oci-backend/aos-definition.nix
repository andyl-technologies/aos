##! AOS base-container definition owned by the OCI backend package.
##!
##! The baked roots are a typed slice of the evaluated system package set plus
##! the runtime core and AOS CLI outputs. The container runtime initializes a
##! daemonless local Nix database and retains every baked root.
{
  lib,
  pkgs,
  systemPackageSlice,
  evidenceOverrides ? [],
  platform,
}: let
  coreRoots = [pkgs.glibc pkgs.gcc-libs pkgs.ca-certificates];
  shellRoots = [pkgs.bash pkgs.coreutils pkgs.findutils pkgs.grep];
  # APM and its startup runtime are independently installable outputs of the
  # CLI source build. Retain only the commands needed by a fresh container.
  cliRoots = [pkgs.apm pkgs.aos-package-runtime];
  packageRoots = lib.uniqueBy builtins.toString (coreRoots ++ shellRoots ++ systemPackageSlice ++ cliRoots);
in {
  config = {
    name = "aos";
    # Every facade target must also be a baked GC root. The CLI subpackages
    # are not necessarily members of the selected system slice, and a
    # daemonless container must retain them across an explicit APM/Nix GC.
    inherit packageRoots;
    # Available handlers retain their implementations only when selected by
    # the checked graph, rather than installing the host provider set.
    packageModules = lib.uniqueBy builtins.toString (packageRoots ++ [pkgs.aos-filesystem-provider pkgs.aos-configuration-provider pkgs.aos-init-provider]);
    layers = [
      {
        name = "runtime-core";
        roots = coreRoots;
      }
      {
        name = "system-userland";
        roots = lib.uniqueBy builtins.toString (shellRoots ++ systemPackageSlice);
        subtractRoots = coreRoots;
      }
      {
        name = "aos-cli";
        roots = cliRoots;
        subtractRoots = lib.uniqueBy builtins.toString (coreRoots ++ shellRoots ++ systemPackageSlice);
      }
    ];

    filesystem = {
      facade = [
        {
          name = "apm";
          target = "${pkgs.apm}/bin/apm";
        }
      ];
      files = [
        {
          path = "/etc/profile";
          mode = "0644";
          text = import ../../system/_aos-host-policy/profile-text.nix {
            inherit lib;
            path = "/var/lib/profiles/per-user/root/current/bin:/var/lib/profiles/per-user/root/current/sbin:/usr/bin:/usr/sbin:/bin";
            pager = "cat";
          };
        }
        {
          path = "/etc/bashrc";
          mode = "0644";
          text = import ../../system/_aos-host-policy/bashrc-text.nix {
            inherit lib;
            completionFiles = ["${pkgs.apm}/share/bash-completion/completions/apm"];
          };
        }
        {
          path = "/etc/inputrc";
          mode = "0644";
          text = import ../../system/_aos-host-policy/inputrc-text.nix;
        }
        {
          path = "/root/.bashrc";
          mode = "0644";
          text = ". /etc/bashrc\n";
        }
        {
          path = "/root/.bash_profile";
          mode = "0644";
          text = ". /etc/profile\n. /root/.bashrc\n";
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
        {
          path = "/var/tmp";
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
      # The current package set has one `kill` provider (util-linux), so the
      # reviewed production facade contains no executable collisions.
      allowedFacadeCollisions = [];
      shell = true;
    };

    runtime = {
      entrypoint = ["/usr/bin/aos-container-init"];
      # The stable entrypoint selects the installed init. An explicit runtime
      # command replaces it; an empty command falls back to the local shell.
      command = [];
      environment = {
        AOS_RUNTIME = "container";
        HOME = "/root";
        USER = "root";
        XDG_CACHE_HOME = "/root/.cache";
        XDG_CONFIG_HOME = "/root/.config";
        XDG_DATA_HOME = "/root/.local/share";
        XDG_STATE_HOME = "/root/.local/state";
        NIX_REMOTE = "local";
        LANG = "C.UTF-8";
        SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
        NIX_SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
        PATH = "/var/lib/profiles/per-user/root/current/bin:/var/lib/profiles/per-user/root/current/sbin:/usr/bin:/usr/sbin:/bin";
      };
      user = "0:0";
      workingDirectory = "/work";
      stopSignal = "SIGTERM";
    };

    platform = platform // {aosSystem = pkgs.stdenv.hostPlatform.system;};

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
      "dev.andyl.aos.system" = pkgs.stdenv.hostPlatform.system;
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
