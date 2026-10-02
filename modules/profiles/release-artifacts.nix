##! modules/profiles/release-artifacts.nix — Shared release artifact identity
##!
##! Projects one release profile into both bootable images and their associated
##! OCI container. Disk-only behavior remains under `aos.image`; container-only
##! behavior remains under `aos.containers`; the registry, channel, support tier,
##! trust anchor, and warning are shared inputs evaluated exactly once.
{
  config,
  lib,
  options,
  ...
}: let
  cfg = config.aos.release;
  sshBannerAvailable = builtins.hasAttr "banner" (lib.submoduleOptions options.aos.services.type._elementType ["aos" "services" "ssh"]);
  registryRenderer = import ../base/_apm-registry-renderer.nix {inherit lib;};
  registry = {
    url = cfg.url;
    channel = cfg.channel;
    trustKeys = cfg.trustKeys;
    rootOwnerSigners = cfg.rootOwnerSigners;
    required = true;
    priority = 100;
    caches = [];
    sbDbCerts = [];
  };
  registryToml = registryRenderer.registryToml cfg.clientName registry;
  trustedKeys = registryRenderer.trustedKeys registry;
  experimentalRegistryPattern = "andyl/experimental(-v([2-9]|[1-9][0-9]+))?";
  expectedClientName =
    if cfg.registry == "andyl/main"
    then "andyl"
    else builtins.replaceStrings ["/"] ["-"] cfg.registry;
  expectedUrl = "${cfg.registryOrigin}/${cfg.registry}/";
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

    registryOrigin = lib.mkOption {
      type = lib.types.str;
      default = "https://cdn.aos.andyl.org";
      description = "HTTPS delivery origin of the Hub deployment receiving these artifacts.";
    };

    hubUrl = lib.mkOption {
      type = lib.types.str;
      default = "https://aos.andyl.org";
      description = "HTTPS control origin of the Hub deployment receiving these artifacts.";
    };

    url = lib.mkOption {
      type = lib.types.str;
      default = expectedUrl;
      description = "Canonical registry delivery URL baked into disk and OCI artifacts.";
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

    rootOwnerSigners = lib.mkOption {
      type = lib.types.listOf lib.types.nonEmptyStr;
      default = [];
      description = "Provenance key IDs authorized for shared-root ownership in disk and OCI artifacts.";
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
        assertion = builtins.all (origin: builtins.match "https://[A-Za-z0-9.-]+(:[0-9]+)?" origin != null) [cfg.registryOrigin cfg.hubUrl];
        message = "release delivery and Hub origins must be HTTPS origins without credentials or paths";
      }
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
          else builtins.match experimentalRegistryPattern cfg.registry != null;
        message = "production artifacts use andyl/main; experimental artifacts use an epoch-scoped andyl/experimental identity";
      }
      {
        assertion = cfg.clientName == expectedClientName;
        message = "release artifact client alias must match its signed registry identity";
      }
      {
        assertion = cfg.url == expectedUrl;
        message = "release artifacts must use their deployment delivery origin and signed registry path";
      }
      {
        assertion =
          if cfg.rootEpoch == 1
          then cfg.registry == "andyl/main" || cfg.registry == "andyl/experimental"
          else cfg.registry == "andyl/experimental-v${toString cfg.rootEpoch}";
        message = "release registry identity must encode every trust-root epoch after epoch one";
      }
      {
        # Neither a experimental artifact nor an edge artifact comes with a support
        # promise, so both tell the user before they rely on it.
        assertion = (cfg.tier != "testing" && cfg.channel != "edge") || cfg.warning != "";
        message = "experimental and edge artifacts require a non-empty user-visible warning";
      }
    ];

    aos.apm.registries = lib.mkForce {${cfg.clientName} = registry;};
    environment.sessionVariables.AOS_HUB = cfg.hubUrl;

    environment.etc = {
      "aos/release-profile".text = ''
        tier=${cfg.tier}
        registry=${cfg.registry}
        registry_url=${cfg.url}
        hub_url=${cfg.hubUrl}
        client_name=${cfg.clientName}
        channel=${cfg.channel}
        root_epoch=${toString cfg.rootEpoch}
      '';
      issue = lib.mkIf (cfg.warning != "") {text = cfg.warning;};
      "issue.net" = lib.mkIf (cfg.warning != "") {text = cfg.warning;};
    };

    aos.services.ssh.banner = lib.mkIf (cfg.warning != "" && sshBannerAvailable) "/etc/issue.net";

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
        AOS_HUB = cfg.hubUrl;
        AOS_CHANNEL = cfg.channel;
      };
      annotations = {
        "org.opencontainers.image.title" = lib.mkForce (
          if cfg.tier == "testing"
          then "AOS Experimental"
          else "AOS"
        );
        "org.opencontainers.image.description" = lib.mkForce (
          if cfg.tier == "testing"
          then "Experimental AOS experimental userland; not for production workloads or important data"
          else "AOS base userland built entirely from AOS packages"
        );
        "dev.andyl.aos.release.tier" = cfg.tier;
        "dev.andyl.aos.registry" = cfg.registry;
        "dev.andyl.aos.registry-url" = cfg.url;
        "dev.andyl.aos.hub-url" = cfg.hubUrl;
        "dev.andyl.aos.channel" = cfg.channel;
        "dev.andyl.aos.registry-root-epoch" = toString cfg.rootEpoch;
      };
      publication.repository = lib.mkForce (
        if cfg.tier == "testing"
        then "aos-experimental"
        else "aos"
      );
      publication.referenceTag = lib.mkForce cfg.channel;
      publication.releaseIdentity = lib.mkForce config.aos.system.version;
    };
  };
}
