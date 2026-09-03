# tests/fleet/_native-hub-production.nix -- Shared native-Hub fleet fixtures.
#
# This helper builds the production roles used by the native Hub qualification
# suites.  In particular, package closures live only on the publisher: a
# consumer can acquire them only through the Hub's public registry route.
{
  lib,
  mkSystem,
  pkgs,
}: let
  mkTool = {
    pname,
    version,
    message,
    dependency ? null,
    dependencyProgram ? null,
  }:
    pkgs.mkDerivation {
      inherit pname version;
      src = null;
      runtimeDeps = lib.optional (dependency != null) dependency;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/share/${pname}"
            cat > "$out/bin/${pname}" <<'EOF'
            #!${pkgs.bash}/bin/bash
            set -euo pipefail
            ${lib.optionalString (dependency != null) "${dependency}/bin/${dependencyProgram}"}
            printf '%s\n' '${message}'
            EOF
            chmod +x "$out/bin/${pname}"
            printf '%s\n' '${pname} ${version}' > "$out/share/${pname}/version"
          '';
        }
      ];
    };

  helperV1 = mkTool {
    pname = "hub-helper";
    version = "1.0.0";
    message = "hub-helper 1.0.0";
  };
  helperV2 = mkTool {
    pname = "hub-helper";
    version = "2.0.0";
    message = "hub-helper 2.0.0";
  };
  toolV1 = mkTool {
    pname = "hub-tool";
    version = "1.0.0";
    message = "hub-tool 1.0.0";
    dependency = helperV1;
    dependencyProgram = "hub-helper";
  };
  toolV2 = mkTool {
    pname = "hub-tool";
    version = "2.0.0";
    message = "hub-tool 2.0.0";
    dependency = helperV2;
    dependencyProgram = "hub-helper";
  };

  # These are deterministic test identities, not deployment credentials. The
  # service receives them through systemd's credential directory, exercising
  # the same file interfaces used with an operator secret provider.
  routeKeys = pkgs.writeTextFile {
    name = "native-hub-fleet-route-keys.json";
    destination = "/value";
    text = builtins.toJSON {
      activeVersion = 1;
      keys = [
        {
          version = 1;
          keyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        }
      ];
    };
  };
  probeSigners = pkgs.writeTextFile {
    name = "native-hub-fleet-probe-signers.json";
    destination = "/value";
    text = builtins.toJSON [
      {
        endpointId = "fleet-native-hub";
        endpointGeneration = 1;
        signerSecretRef = "fleet-probe-v1";
        # RFC 8032 test-vector seed whose public key is probePublicKey below.
        signingSeed = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
      }
    ];
  };
  jwtSecret = pkgs.writeTextFile {
    name = "native-hub-fleet-jwt-secret";
    destination = "/value";
    text = "native-hub-fleet-stable-jwt-secret-v1";
  };

  # The qualification images intentionally carry operator and publishing
  # tooling that the slim production golden image omits. Keep the production
  # integrity and boot path while scoping the larger root artifact contract to
  # these test systems.
  qualificationImage = {
    aos.image.budgets = {
      maxRuntimeClosureMiB = 912;
      maxDownloadMiB = 816;
      maxRootMiB = 768;
    };
    # Fleet assertions and the publisher runbook use the same small Unix
    # inspection toolkit an operator image carries. These are AOS-built tools;
    # they do not provide package payloads or seeded Hub state.
    environment.systemPackages = [
      pkgs.diffutils
      pkgs.gawk
      pkgs.grep
      pkgs.sed
    ];
  };

  consumerTools = {
    environment.systemPackages = [
      pkgs.aos
      pkgs.nix
    ];
  };

  consumerBaseline = {
    # The user journey installs nginx from the signed Hub registry. Its exposed
    # service requests host networking and a bounded capability, so the
    # qualification consumer must exercise normal permission admission with an
    # explicit host policy instead of bypassing the package policy gate.
    environment.etc."aos/policy.toml" = {
      text = "tier = \"privileged\"\n";
      mode = "0644";
    };

    systemd.services.aos-upgrade-removed = {
      description = "Upgrade qualification service removed by generation two";
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.coreutils}/bin/true";
        ExecStop = "${pkgs.coreutils}/bin/touch /run/removed-stop-ran";
        RemainAfterExit = true;
      };
    };
  };

  consumerUpgrade = {...}: {
    aos.system.version = "test-2";
    environment.etc."aos/upgrade-test/marker.conf".text = "marker = 1\n";
    systemd.services.dbus.serviceConfig.LimitNOFILE = "16384";
    systemd.services.aos-upgrade-test-marker = {
      description = "Upgrade qualification generation-two marker";
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.coreutils}/bin/true";
        RemainAfterExit = true;
      };
    };
  };

  hubSystem = mkSystem [
    ../../systems/server-test.nix
    qualificationImage
    {
      aos.registry-hub = {
        enable = true;
        # The cleartext listener is deliberate in the first qualification
        # layer: the topology records and explicitly acknowledges it.  A
        # separate TLS-edge suite fronts this loopback listener.
        listen = "0.0.0.0:8420";
        externalUrl = "http://hub:8420";
        credentials = {
          jwtSecret = "native-hub-jwt-secret";
          routeReservationKeys = "native-hub-route-reservation-keys";
          domainProbeSignerManifest = "native-hub-probe-signers";
        };
      };
      # The server profile is default-deny. A production operator must admit
      # the native listener explicitly when it is bound beyond loopback.
      aos.firewall.allowedTCP = [8420];
      # Deterministic fixture bytes are copied into the platform credential
      # namespace at boot. The hub module owns the LoadCredential bindings and
      # file-environment contract exactly as it does in production.
      environment.etc."tmpfiles.d/native-hub-credentials.conf".text = ''
        d /run/credentials/@system 0700 root root -
        C /run/credentials/@system/native-hub-jwt-secret 0600 root root - ${jwtSecret}/value
        C /run/credentials/@system/native-hub-route-reservation-keys 0600 root root - ${routeKeys}/value
        C /run/credentials/@system/native-hub-probe-signers 0600 root root - ${probeSigners}/value
      '';
    }
  ];

  publisherSystem = mkSystem [
    ../../systems/server-test.nix
    qualificationImage
    {
      # Publication exercises full Git, including its optional Python-backed
      # helpers. Keep that payload on the publisher rather than inflating the
      # Hub and consumer images, which need only server-test's git-minimal.
      aos.image.testArtifactRoots = [pkgs.git];
      environment.systemPackages = [
        pkgs.aos
        pkgs.git
        pkgs.nix
        pkgs.openssh
      ];
      aos.kernel.modules = ["9pnet_virtio" "9p"];
    }
  ];

  consumerSystem = mkSystem [
    ../../systems/server-test.nix
    qualificationImage
    consumerTools
    consumerBaseline
  ];

  consumerUpgradeSystem = mkSystem [
    ../../systems/server-test.nix
    qualificationImage
    consumerTools
    consumerUpgrade
  ];
in {
  inherit
    consumerSystem
    consumerUpgradeSystem
    helperV1
    helperV2
    hubSystem
    publisherSystem
    toolV1
    toolV2
    ;

  hubUrl = "http://hub:8420";
  registryUrl = "http://192.168.50.11:8420/acme/production/";
  probePublicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
}
