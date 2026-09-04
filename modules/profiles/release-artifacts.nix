##! modules/profiles/release-artifacts.nix — Shared release artifact identity
##!
##! Projects one release profile into both bootable images and their associated
##! OCI container. Disk-only behavior remains under `aos.image`; container-only
##! behavior remains under `aos.containers`; the registry, channel, support tier,
##! trust anchor, and warning are shared inputs evaluated exactly once.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.release;
  registryRenderer = import ../base/_apm-registry-renderer.nix {inherit lib;};
  registry = {
    url = cfg.url;
    channel = cfg.channel;
    trustKeys = cfg.trustKeys;
    required = true;
    priority = 100;
    caches = [];
    sbDbCerts = [];
  };
  registryToml = registryRenderer.registryToml cfg.clientName registry;
  trustedKeys = registryRenderer.trustedKeys registry;
  testingRegistryPattern = "andyl/testing(-v([2-9]|[1-9][0-9]+))?";
  expectedClientName =
    if cfg.registry == "andyl/main"
    then "andyl"
    else builtins.replaceStrings ["/"] ["-"] cfg.registry;
  expectedUrl = "https://aos.andyl.org/${cfg.registry}/";
in {
  options.aos.release = {
    enabled = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether this system is a published release artifact profile.";
    };

    tier = lib.mkOption {
      type = lib.types.enum ["production" "testing"];
      default = "production";
      description = "Support and lifecycle tier shared by disk and OCI artifacts.";
    };

    registry = lib.mkOption {
      type = lib.types.str;
      default = "andyl/main";
      description = "Exact signed Hub registry identity.";
    };

    rootEpoch = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value > 0);
      default = 1;
      description = "Out-of-band trust-root epoch encoded by the registry identity.";
    };

    clientName = lib.mkOption {
      type = lib.types.str;
      default = "andyl";
      description = "Slash-free local APM alias and trust-line prefix.";
    };

    url = lib.mkOption {
      type = lib.types.str;
      default = "https://aos.andyl.org/andyl/main/";
      description = "Canonical same-origin Hub URL baked into both artifact forms.";
    };

    channel = lib.mkOption {
      type = lib.types.enum ["edge" "candidate" "stable"];
      default = "stable";
      description = "Signed channel selected by default in both artifact forms.";
    };

    trustKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Out-of-band APM trust lines baked into both artifact forms.";
    };

    warning = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = "User-visible release-tier notice baked into both artifact forms.";
    };
  };

  config = lib.mkIf cfg.enabled {
    assertions = [
      {
        assertion = cfg.trustKeys != [];
        message = "published release artifacts require at least one baked registry trust key";
      }
      {
        assertion = builtins.all (key: builtins.match (registryRenderer.trustKeyPattern cfg.clientName) key != null) cfg.trustKeys;
        message = "release registry trust lines must be valid Ed25519 lines for the configured slash-free client name";
      }
      {
        assertion =
          if cfg.tier == "production"
          then cfg.registry == "andyl/main" && cfg.rootEpoch == 1
          else builtins.match testingRegistryPattern cfg.registry != null;
        message = "production artifacts use andyl/main; testing artifacts use an epoch-scoped andyl/testing identity";
      }
      {
        assertion = cfg.tier != "testing" || cfg.channel == "edge";
        message = "testing artifacts must follow only the edge channel";
      }
      {
        assertion = cfg.clientName == expectedClientName;
        message = "release artifact client alias must match its signed registry identity";
      }
      {
        assertion = cfg.url == expectedUrl;
        message = "public release artifacts must use the canonical production Hub registry URL";
      }
      {
        assertion =
          if cfg.rootEpoch == 1
          then cfg.registry == "andyl/main" || cfg.registry == "andyl/testing"
          else cfg.registry == "andyl/testing-v${toString cfg.rootEpoch}";
        message = "release registry identity must encode every trust-root epoch after epoch one";
      }
      {
        assertion = cfg.tier != "testing" || cfg.warning != "";
        message = "testing artifacts require a non-empty user-visible warning";
      }
    ];

    aos.apm.registries = lib.mkForce {${cfg.clientName} = registry;};

    environment.etc = {
      "aos/release-profile".text = ''
        tier=${cfg.tier}
        registry=${cfg.registry}
        client_name=${cfg.clientName}
        channel=${cfg.channel}
        root_epoch=${toString cfg.rootEpoch}
      '';
      issue = lib.mkIf (cfg.warning != "") {text = cfg.warning;};
      "issue.net" = lib.mkIf (cfg.warning != "") {text = cfg.warning;};
    };

    aos.services.ssh.banner = lib.mkIf (cfg.warning != "") "/etc/issue.net";

    aos.containers.definitions.aos = {
      filesystem.files =
        [
          {
            path = "/etc/aos/release-profile";
            mode = "0444";
            text = config.environment.etc."aos/release-profile".text;
          }
          {
            path = "/etc/apm/registries.d/${cfg.clientName}.toml";
            mode = "0444";
            text = registryToml;
          }
          {
            path = "/etc/apm/trusted-keys.d/${cfg.clientName}.pub";
            mode = "0444";
            text = trustedKeys;
          }
        ]
        ++ lib.optional (cfg.warning != "") {
          path = "/etc/issue";
          mode = "0444";
          text = cfg.warning;
        };
      runtime.environment = {
        AOS_RELEASE_TIER = cfg.tier;
        AOS_REGISTRY = cfg.registry;
        AOS_CHANNEL = cfg.channel;
      };
      annotations = {
        "org.opencontainers.image.title" = lib.mkForce (
          if cfg.tier == "testing"
          then "AOS Testing"
          else "AOS"
        );
        "org.opencontainers.image.description" = lib.mkForce (
          if cfg.tier == "testing"
          then "Experimental AOS testing userland; not for production workloads or important data"
          else "AOS base userland built entirely from AOS packages"
        );
        "dev.andyl.aos.release.tier" = cfg.tier;
        "dev.andyl.aos.registry" = cfg.registry;
        "dev.andyl.aos.channel" = cfg.channel;
        "dev.andyl.aos.registry-root-epoch" = toString cfg.rootEpoch;
      };
      publication.repository = lib.mkForce (
        if cfg.tier == "testing"
        then "aos-testing"
        else "aos"
      );
      publication.referenceTag = lib.mkForce cfg.channel;
      publication.releaseIdentity = lib.mkForce config.aos.system.version;
    };
  };
}
