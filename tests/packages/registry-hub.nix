##! Focused evaluation contract for the system-owned native registry Hub.
{
  pkgs,
  lib,
  mkSystem,
  serverModule,
}: let
  abilityEnvironment = {
    aos.abilities.environment = {
      authority = "test";
      key = "registry-hub-module-check";
      stage = "host";
    };
  };
  evaluated = mkSystem {
    modules = [
      serverModule
      abilityEnvironment
      {
        aos.registry-hub = {
          enable = true;
          listen = "127.0.0.1:18420";
          externalUrl = "https://hub.example.test";
          reindexInterval = 15;
          deploymentId = "hub-production-v1";
          releaseReceiptKeyId = "hub-publication-v1";
          channelReceiptKeyId = "hub-channel-v1";
          credentials = {
            jwtSecret = "hub-jwt";
            domainProbeSignerManifest = "hub-probe-signers";
            routeReservationKeys = "hub-route-keys";
            cloudflareApiToken = "hub-cloudflare-token";
            releaseReceiptKey = "hub-release-receipt-key";
            channelReceiptKey = "hub-channel-receipt-key";
            releasePublicationKeys = "hub-publication-keys";
            qualificationKeys = "hub-qualification-keys";
          };
        };
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  requests = abilities.requests;
  lifecycle = requests."aos-hub:hub-lifecycle".parameters;
  credentialViews = requests."aos-hub:hub-credentials".parameters.views;
  credentialViewsByName = builtins.listToAttrs (map (view: {
      name = view.name;
      value = view;
    })
    credentialViews);
  stateStorage = requests."aos-hub:state-storage".parameters;
  serviceStorage = requests."aos-hub:hub-storage".parameters;
  invalid = mkSystem {
    modules = [
      serverModule
      abilityEnvironment
      {aos.registry-hub.enable = true;}
    ];
  };
  invalidReleaseEvidence = mkSystem {
    modules = [
      serverModule
      abilityEnvironment
      {
        aos.registry-hub = {
          enable = true;
          deploymentId = "incomplete-release-authority";
          credentials = {
            domainProbeSignerManifest = "hub-probe-signers";
            routeReservationKeys = "hub-route-keys";
          };
        };
      }
    ];
  };
  command = builtins.head lifecycle.start;
  contract = assert abilities.instances ? "aos-hub:service";
  assert lib.elem "127.0.0.1:18420" command.executable.arguments;
  assert lib.elem "15" command.executable.arguments;
  assert command.executable.artifact == lib.abilities.packageOutput {
    package = "aos-hub";
    output = "out";
  };
  assert credentialViewsByName.jwt-secret.reference.request == "aos-hub:credential-jwtSecret";
  assert credentialViewsByName.jwt-secret.reference.output == "credential-path";
  assert credentialViewsByName.domain-probe-signers.reference.request == "aos-hub:credential-domainProbeSignerManifest";
  assert credentialViewsByName.domain-probe-signers.reference.output == "credential-path";
  assert credentialViewsByName.route-reservation-keys.reference.request == "aos-hub:credential-routeReservationKeys";
  assert credentialViewsByName.route-reservation-keys.reference.output == "credential-path";
  assert credentialViewsByName.cloudflare-api-token.environment_variable == "HUB_CLOUDFLARE_API_TOKEN_FILE";
  assert credentialViewsByName.release-receipt-key.environment_variable == "HUB_RELEASE_RECEIPT_KEY_FILE";
  assert credentialViewsByName.channel-receipt-key.environment_variable == "HUB_CHANNEL_RECEIPT_KEY_FILE";
  assert credentialViewsByName.release-publication-keys.environment_variable == "HUB_RELEASE_PUBLICATION_KEYS_FILE";
  assert credentialViewsByName.qualification-keys.environment_variable == "HUB_QUALIFICATION_KEYS_FILE";
  assert stateStorage.requested_path == "/var/lib/aos-hub";
  assert (builtins.head serviceStorage.mounts).source.request == "aos-hub:state-storage";
  assert (builtins.head serviceStorage.mounts).source.output == "planned-path";
  assert !(lib.hasInfix "/run/credentials" (builtins.toJSON requests));
  assert !(builtins.all (entry: builtins.getAttr "assertion" entry) (builtins.getAttr "assertions" invalid.config));
  assert !(builtins.all (entry: builtins.getAttr "assertion" entry) (builtins.getAttr "assertions" invalidReleaseEvidence.config)); true;
in
  pkgs.mkDerivation {
    pname = "registry-hub-module-check";
    version = "0";
    src = null;
    inherit contract;
    phases = [
      {
        name = "check";
        script = ''
          : "$contract"
          mkdir -p "$out"
          printf '%s\n' ok > "$out/result"
        '';
      }
    ];
  }
